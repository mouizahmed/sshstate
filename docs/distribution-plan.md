# Distribution plan — v0.1.0

Written 2026-09-15. Closes the last M3a deliverable: an install path that is not
`go build`.

Decisions taken before starting:

| | |
|---|---|
| First tag | `v0.1.0` — M3a is a usable checkpoint, not stable v1. `v1.0.0` waits for rotation in M3b. |
| Artifact signing | Sigstore cosign, keyless. Signs the checksum file with the workflow's OIDC identity, so there is no private key to hold or rotate. |
| Container registry | GHCR, `ghcr.io/mouizahmed/sshstate-server`. Pushes with the built-in token; no secret to add. |
| macOS notarization | Out of scope — no Apple Developer account. Manual downloads need a documented quarantine step; `brew install` is unaffected. |

Checksums alone were rejected deliberately. They prove a download is intact, not
that it came from this project: whoever can replace a tarball can replace the
`SHA256SUMS` beside it. The cosign signature is what closes that, and it is what
R14 means by "signed".

---

## 1. Release workflow

`.github/workflows/release.yml`, triggered by a `v*` tag.

**The build matrix cannot be one job.** Linux binaries are `CGO_ENABLED=0` and
static. macOS binaries cannot be: `launch_activate_socket` is a C library call
with no syscall equivalent, so darwin needs cgo and must build on a macOS
runner. A `CGO_ENABLED=0` darwin build compiles and then cannot adopt launchd
sockets at all — the brief warns against exactly this, and the existing
`cross-build` CI job currently makes that mistake. It gets corrected here.

| target | runner | cgo |
|---|---|---|
| darwin/arm64 | `macos-latest` | on, native |
| darwin/amd64 | `macos-latest` | on, `-arch x86_64` |
| linux/amd64 | `ubuntu-latest` | off, static |
| linux/arm64 | `ubuntu-latest` | off, static |

Every job pins `GOTOOLCHAIN=local` with Go 1.27.1, matching `ci.yml`, so the
released binary is built by the toolchain the tests ran under.

Each artifact is a `.tar.gz` holding the binary, `LICENSE` and `README.md`.
`-trimpath` and an explicit `-ldflags -X .../buildinfo.Version=<tag>` make the
output independent of the build path and stamp the version.

Then: one `SHA256SUMS` over all four, `cosign sign-blob` over that file, and a
`gh release create` carrying the archives, the sums, the signature and the
certificate. The job needs `id-token: write` for keyless signing and
`contents: write` for the release.

## 2. A verification step someone will actually follow

README gets the exact commands, not a description of them: download, check the
SHA-256, verify the cosign signature against the workflow identity, move the
binary onto `PATH`.

macOS downloads arrive quarantined and Gatekeeper refuses them, because the
binary is unsigned. The remedy is one `xattr -d com.apple.quarantine` line and
it belongs next to the download instructions rather than in an issue thread.
`brew install` does not hit this.

## 3. Server image

Multi-arch `linux/amd64,linux/arm64` via buildx, published to
`ghcr.io/mouizahmed/sshstate-server` as both `:v0.1.0` and `:latest`, and signed
with cosign the same way. `deploy/README.md` switches from "build this
Dockerfile" to "pull this image", keeping the build instructions as the
alternative.

## 4. Homebrew tap

A second repository, `mouizahmed/homebrew-sshstate`, because `brew tap x/y`
resolves to `github.com/x/homebrew-y` and no other name works.

The formula installs the **prebuilt binary**, not source. Building from source
in the formula would mean `depends_on "go"`, and this project needs Go 1.27 or
later — if Homebrew's `go` is behind that, every install fails at compile time
with a `crypto/mldsa` error. It would also discard the pinned-toolchain build
the tests actually ran against.

`update-tap.yml` in this repository rewrites the version and the four SHA-256
values on each published release and pushes to the tap.

**This needs one secret.** The built-in `GITHUB_TOKEN` cannot push to another
repository, so a fine-grained PAT with contents write on `homebrew-sshstate`
has to exist as `TAP_TOKEN`. It is the only credential this plan introduces.

## 5. Proving it works on a machine nobody prepared

The brief asks for reproducible artifacts, verifying checksums, and a documented
install path that works on a clean macOS and Linux machine. All three get
checked against the published release, not against a local build:

- Build twice and compare digests; `-trimpath` is what should make that hold.
- On the Linux VM, with Go removed from `PATH` and every trace of sshstate
  deleted: download, verify, install, `sshstate setup`, `ssh` somewhere.
- On macOS in a fresh `HOME`, including the quarantine step.
- `brew install` from the tap on both.

Every defect this session came from running something rather than reading it.
A clean machine is the one environment nothing has been run on yet, so this
step is where the next one is most likely to appear.

## Order

1. `release.yml` and the corrected cross-build matrix
2. README verification section
3. Tag `v0.1.0`, confirm the release
4. Server image and `deploy/README.md`
5. Tap repository, formula, `update-tap.yml`
6. Clean-machine and reproducibility checks
7. M3a closed; M3b is rotation
