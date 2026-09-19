#!/usr/bin/env bash
set -euo pipefail
shopt -s nullglob

version=${1:?usage: build-repositories.sh VERSION [PACKAGE_DIRECTORY] [OUTPUT_DIRECTORY]}
packages=${2:-dist}
output=${3:-dist/package-site}
: "${PACKAGE_APK_KEY_FILE:?set PACKAGE_APK_KEY_FILE to the Alpine RSA private key}"

for command in dpkg-scanpackages apt-ftparchive gpg rpmsign createrepo_c openssl docker; do
  command -v "$command" >/dev/null || { echo "missing command: $command" >&2; exit 1; }
done

packages=$(cd "$packages" && pwd)
mkdir -p "$output"
output=$(cd "$output" && pwd)
mkdir -p "$output"/{apt/pool/main,apt/dists/stable/main,rpm,apk,arch,keys}

fingerprint=$(gpg --batch --with-colons --list-secret-keys | awk -F: '$1 == "fpr" { print $10; exit }')
test -n "$fingerprint" || { echo 'no package signing key in GPG keyring' >&2; exit 1; }
test "$fingerprint" = "$(cat packaging/public-keys/gpg-fingerprint.txt)" || { echo 'unexpected GPG signing key' >&2; exit 1; }
gpg --batch --export "$fingerprint" | cmp - packaging/public-keys/sshstate.gpg
gpg --batch --armor --export "$fingerprint" | cmp - packaging/public-keys/sshstate.asc
openssl pkey -in "$PACKAGE_APK_KEY_FILE" -pubout | cmp - packaging/public-keys/sshstate.rsa.pub
gpg --batch --export "$fingerprint" > "$output/keys/sshstate.gpg"
gpg --batch --armor --export "$fingerprint" > "$output/keys/sshstate.asc"
openssl pkey -in "$PACKAGE_APK_KEY_FILE" -pubout -out "$output/keys/sshstate.rsa.pub"
cp packaging/sshstate.repo "$output/sshstate.repo"

for arch in amd64 arm64; do
  case "$arch" in
    amd64) native=x86_64 ;;
    arm64) native=aarch64 ;;
  esac
  stem="sshstate_${version}_linux_${arch}"
  for format in deb rpm apk; do
    test -f "$packages/$stem.$format" || { echo "missing $stem.$format" >&2; exit 1; }
  done
  test -f "$packages/$stem.pkg.tar.zst" || { echo "missing $stem.pkg.tar.zst" >&2; exit 1; }

  mkdir -p "$output/rpm/$native" "$output/apk/$native" "$output/arch/$native"
  for file in "$packages"/sshstate_*_linux_"$arch".deb; do
    cp "$file" "$output/apt/pool/main/"
  done
  for file in "$packages"/sshstate_*_linux_"$arch".rpm; do
    cp "$file" "$output/rpm/$native/"
  done
  for file in "$packages"/sshstate_*_linux_"$arch".apk; do
    filename=${file##*/}
    package_version=${filename#sshstate_}
    package_version=${package_version%_linux_"$arch".apk}
    cp "$file" "$output/apk/$native/sshstate-${package_version}-r1.apk"
  done
  for file in "$packages"/sshstate_*_linux_"$arch".pkg.tar.zst; do
    cp "$file" "$output/arch/$native/"
  done

  mkdir -p "$output/apt/dists/stable/main/binary-$arch"
  (
    cd "$output/apt"
    dpkg-scanpackages --multiversion --arch "$arch" pool/main /dev/null > "dists/stable/main/binary-$arch/Packages"
    gzip -n -9 -c "dists/stable/main/binary-$arch/Packages" > "dists/stable/main/binary-$arch/Packages.gz"
  )

  for package in "$output/rpm/$native/"*.rpm; do
    rpmsign --addsign --define "__gpg $(command -v gpg)" \
      --define "_gpg_name $fingerprint" "$package"
  done
  createrepo_c "$output/rpm/$native"
  gpg --batch --yes --local-user "$fingerprint" --armor --detach-sign \
    --output "$output/rpm/$native/repodata/repomd.xml.asc" \
    "$output/rpm/$native/repodata/repomd.xml"

  for package in "$output/arch/$native/"*.pkg.tar.zst; do
    gpg --batch --yes --local-user "$fingerprint" --detach-sign \
      --output "$package.sig" "$package"
  done
done

(
  cd "$output/apt"
  apt-ftparchive \
    -o APT::FTPArchive::Release::Origin=sshstate \
    -o APT::FTPArchive::Release::Label=sshstate \
    -o APT::FTPArchive::Release::Suite=stable \
    -o APT::FTPArchive::Release::Codename=stable \
    -o APT::FTPArchive::Release::Architectures='amd64 arm64' \
    -o APT::FTPArchive::Release::Components=main \
    release dists/stable > dists/stable/Release
  gpg --batch --yes --local-user "$fingerprint" --clearsign \
    --output dists/stable/InRelease dists/stable/Release
  gpg --batch --yes --local-user "$fingerprint" --detach-sign \
    --output dists/stable/Release.gpg dists/stable/Release
)

key_dir=$(cd "$(dirname "$PACKAGE_APK_KEY_FILE")" && pwd)
key_name=$(basename "$PACKAGE_APK_KEY_FILE")
docker run --rm --platform linux/amd64 \
  -v "$output/apk:/repo" -v "$key_dir:/keys:ro" \
  alpine@sha256:1f3591b8a02ea153f41c5bba878ad477f63ab3d19349762cb77504db02a23e15 \
  sh -eu -c 'apk add --no-cache alpine-sdk >/dev/null; for arch in x86_64 aarch64; do cd "/repo/$arch"; apk index --allow-untrusted -o APKINDEX.tar.gz ./*.apk; abuild-sign -k "/keys/'"$key_name"'" -p sshstate.rsa.pub APKINDEX.tar.gz; done'

docker run --rm --platform linux/amd64 \
  --user "$(id -u):$(id -g)" \
  -e PACKAGE_VERSION="$version" -v "$output/arch:/repo" \
  archlinux@sha256:421f8732de4338c86c204a2af2d62d650f46e3a667744ab8dc5e88853481a4aa \
  sh -eu -c '
    for arch in x86_64 aarch64; do
      cd "/repo/$arch"
      repo-add sshstate.db.tar.gz ./sshstate_"$PACKAGE_VERSION"_linux_*.pkg.tar.zst
      for package in ./*.pkg.tar.zst; do
        filename=${package##*/}
        version=${filename#sshstate_}
        version=${version%%_linux_*}
        mkdir -p "releases/$version"
        cp "$package" "$package.sig" "releases/$version/"
        (cd "releases/$version"; repo-add sshstate.db.tar.gz ./*.pkg.tar.zst)
      done
    done
  '

for arch in x86_64 aarch64; do
  for repo in "$output/arch/$arch" "$output/arch/$arch"/releases/*; do
    for kind in db files; do
      target="$repo/sshstate.$kind.tar.gz"
      gpg --batch --yes --local-user "$fingerprint" --detach-sign \
        --output "$target.sig" "$target"
      rm -f "$repo/sshstate.$kind"
      cp "$target" "$repo/sshstate.$kind"
      cp "$target.sig" "$repo/sshstate.$kind.sig"
    done
  done
done

touch "$output/.nojekyll"
