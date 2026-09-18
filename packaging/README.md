# Linux package repositories

Tagged releases build amd64 and arm64 `.deb`, `.rpm`, `.apk`, and Arch packages
from the same binaries as the release archives. The release workflow attaches
them to GitHub Releases, signs apt, RPM, Alpine, and Arch repositories, and
deploys the five most recent stable versions to GitHub Pages at
`https://mouizahmed.github.io/sshstate/`. Package managers discover upgrades
on their normal refresh cycle. Older versions remain downloadable from GitHub
Releases. Prerelease packages are attached to their GitHub releases but do not
enter the stable repositories.

Arch's main `sshstate` database selects the newest release. Each retained
version also has its own signed database under `arch/$arch/releases/<version>/`
so an older version can be selected by configuring that path as a temporary
repository named `sshstate`. The package files themselves remain in the main
Arch directory. A local two-version build was 213 MiB, including the extra Arch
copies; five versions are expected to use about 535 MiB of the 1 GB Pages
site limit.

The root [README](../README.md#linux) has installation commands. Those URLs
become live after the first tag containing the packaging workflow. Pages is
configured for a workflow deployment and the repository variable
`PACKAGE_REPOS_ENABLED` is set to `true`. The `github-pages` environment allows
`v*` tags to deploy.

## Signing keys

The GPG fingerprint is `C1E40ECEEA6F0117A52F1E70D16B79E07BBE57AA`.
The SHA-256 of the Alpine public key is
`db487d22b47c13cb5c363101853a74e22eee52cf8044f2a948ebdd7cfc781fbe`.
The committed files in [public-keys](public-keys/) are the trust anchors for
repository metadata and packages. The build checks the binary GPG export,
armored GPG export, and Alpine public key against these files before publishing
them. It also copies the [dnf repository file](sshstate.repo) to the site root.

The `.rpm` attached to GitHub Releases is unsigned. The repository builder
signs its copy before generating RPM metadata. Verify a manually downloaded
`.rpm` with the release `SHA256SUMS` and cosign bundle.

The private keys are stored locally in ignored `packaging/keys/private.asc`
and `packaging/keys/sshstate.rsa`, and as GitHub Actions secrets
`PACKAGE_GPG_PRIVATE_KEY_B64` and `PACKAGE_APK_PRIVATE_KEY_B64`. Back up the
local private keys securely outside the repository. Losing them means rotating
the keys and asking users to trust the replacements before updates can resume.
Do not commit the private keys. The local `packaging/keys/gnupg` directory is
only the key generation workspace.

## Release and verification

Push the packaging changes before tagging a new release. The existing release
workflow publishes the packages first, then deploys the repositories. Check
that the `package-repositories` job succeeds and that the Pages URL serves
`apt/dists/stable/InRelease`, `rpm/x86_64/repodata/repomd.xml.asc`,
`apk/x86_64/APKINDEX.tar.gz`, and `arch/x86_64/sshstate.db.sig`.

The repo builder is `build-repositories.sh`; `nfpm.yaml` defines package
contents. To rebuild locally, provide `VERSION`, Docker, `GNUPGHOME` pointing
to a keyring with the matching GPG private key, and `PACKAGE_APK_KEY_FILE`
pointing to the matching Alpine RSA private key, then run:

```sh
bash packaging/build-repositories.sh "$VERSION" dist dist/package-site
```

The Alpine and Arch helper images in the builder are pinned by digest. Update
those digests deliberately when the package tooling needs an update.

Keep the version scope on the main `repo-add`. `repo-add` replaces
unconditionally, so with an unscoped `./*.pkg.tar.zst` the main Arch database
advertises whichever retained version sorts last by glob order rather than the
newest: staging 0.1.4, 0.1.9 and 0.1.10 globs as `0.1.10, 0.1.4, 0.1.9` and
published 0.1.9. Scoped to `$PACKAGE_VERSION` it published 0.1.10. Verified by
local mutation test on 2026-09-17, with retained-version installs checked from
clean Debian, Fedora, Alpine and Arch containers.
