# sshstate v0.1.3

## Upgrade the relay with the clients

This release streams the pairing snapshot and the recovery archive on their own
endpoints instead of embedding them in JSON, so a vault past about 150 hosts can
connect, pair, and recover. Those endpoints are new on both sides: a v0.1.3
client talking to an older relay fails at the recovery upload and at pairing
delivery, and an older client talking to a v0.1.3 relay fails the same way.
Upgrade the relay and every machine together.

## Master-key rotation is still not implemented

`rotate-master-key` is specified in `docs/rotation.md` and ships in the next
milestone. Until then a vault key that leaks cannot be rotated; the fallback is a
fresh vault and a reviewed migration. Keep all three of these, apart from each
other:

- the recovery kit, which is the only way back into the vault if every enrolled
  device is gone
- encrypted exports taken with `sshstate export`, which restore without a relay
- a backup of the relay's volume, which is what the kit alone cannot replace

## Changes

- Large vaults connect, pair, and recover: the pairing snapshot and recovery
  archive travel as raw bodies under the 256 MiB streamed bound (D40).
- `sshstate export` is written by the CLI, not the daemon: exclusive create, mode
  0600, fsynced, and removed if the write fails, so a launchd-started daemon no
  longer writes into the folders macOS protects and an existing file is never
  overwritten (D41).
- A daemon reply larger than the 1 MiB control limit reports that it exceeds the
  limit instead of failing as `unexpected end of JSON input`.
- `uninstall` stops the daemon before it unregisters the service, so no daemon or
  agent socket is left behind.
- The launchd integration check accepts a job that current macOS starts as soon
  as it registers the sockets, and the service messages no longer promise
  on-demand start there.
- A skewed clock is reported with how far it is from the relay (D39).
- Import refuses `ProxyJump` loops with the same check as `add` and `edit` (D38).
- `status` shows a device as revoked when its own chain says so.
- `devices` says how each device joined and which one is this machine.
- `conflicts` shows what each kept edit changes, and `resolve --discard` drops
  one.
- Host keys are shared only when the approved keys agree, and disagreeing ones
  are reported with the revoke that settles them.
- `change-password` re-encrypts this device's local keys under a new unlock
  password.

## Verify a download

```sh
sha256sum -c SHA256SUMS --ignore-missing

cosign verify-blob SHA256SUMS \
  --bundle SHA256SUMS.cosign.bundle \
  --certificate-identity "https://github.com/mouizahmed/sshstate/.github/workflows/release.yml@refs/tags/v0.1.3" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

This is a 0.x release. It is tested against real `sshd`, launchd, systemd, and a
real relay, and it has not been independently audited or used by anyone but its
author.
