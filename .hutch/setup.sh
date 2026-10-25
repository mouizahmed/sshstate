# Toolchain for building and testing sshstate: Go from go.mod's toolchain line,
# and gcc for the race tests CI runs (they need cgo).
go_version=1.27.1
go_sha256=63d339f0da5ab53635a56f2490a7984dfe12dfcff22ad749f63edaf590168445

apt-get update -qq
apt-get install -y -qq --no-install-recommends gcc libc6-dev >/dev/null
rm -rf /var/lib/apt/lists/*

curl -fsSL -o /tmp/go.tgz "https://go.dev/dl/go${go_version}.linux-amd64.tar.gz"
echo "${go_sha256}  /tmp/go.tgz" | sha256sum -c --quiet
rm -rf /usr/local/go
tar -C /usr/local -xzf /tmp/go.tgz
rm /tmp/go.tgz
ln -sf /usr/local/go/bin/go /usr/local/go/bin/gofmt /usr/local/bin/

# Warm the module and build caches so boxes start ready.
sudo -u dev go mod download
sudo -u dev go build ./...
