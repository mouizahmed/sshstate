# Contributing to sshstate

Contributions to sshstate are welcome, including bug fixes, documentation
improvements, tests, and well scoped features. This project manages SSH
credentials and host trust, so changes to security sensitive behavior need
careful review and verification.

## Reporting issues

Search the [issue tracker](https://github.com/mouizahmed/sshstate/issues) before
opening a new issue. For a bug, describe the expected and actual behavior,
your operating system and sshstate version, and steps to reproduce it. For a
feature request, explain the use case and how it fits the
[roadmap](docs/roadmap.md). Do not post private keys, recovery material,
passwords, or unredacted SSH configuration in a public issue.

## Building and testing

Requires **Go 1.27 or later**: `crypto/mldsa` is not present in Go 1.26.

```sh
make check      # gofmt, vet, build, test, test -race
```

Native integration tests touch the real system, so they are opt-in and skipped
unless their variable is set. Run the ones that apply to a change in native SSH
or service-manager behavior:

```sh
# Register a real service in your own session. Not run by CI.
SSHSTATE_LAUNCHD_TEST=1 go test ./internal/service/ -run Launchd   # macOS
SSHSTATE_SYSTEMD_TEST=1 go test ./internal/service/ -run Systemd   # Linux

# Start a real sshd and log into it with native OpenSSH. CI runs this on Linux.
SSHSTATE_SSHD_TEST=1 go test ./internal/cli/ -run NativeSSH
```

## Submitting pull requests

1. Fork the repository and create a branch for your change.
2. Make a focused change that follows the project's existing Go style and
   design decisions. Start with the [README](README.md), the
   [threat model](docs/threat-model.md), and the
   [sync protocol](docs/protocol.md).
3. Add or update tests where behavior changes. Run `make check` before
   submitting, plus the applicable opt-in integration tests above.
4. Open a pull request against `main`. Explain the problem, your solution,
   how you verified it, and any related issue numbers. Call out security or
   compatibility implications when relevant.

## Conduct

All contributors are expected to follow the
[Code of Conduct](CODE_OF_CONDUCT.md) in project spaces.

## AI-assisted contributions

LLM-generated code is allowed. The author remains responsible for every line
submitted and must understand how it works. Review security sensitive changes,
especially cryptography, key handling, and host trust, yourself; an AI review
does not replace human review. Run the relevant tests and verify behavior
manually where automated coverage is insufficient. AI use does not need to be
disclosed, though you may disclose it if you wish.

## Questions

Ask in the [issue tracker](https://github.com/mouizahmed/sshstate/issues) if
you have questions about a contribution.
