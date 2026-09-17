# sshstate v0.1.4

## Upgrade the relay with the clients

The relay gained a route for putting a machine's records back, and it now tells
clients which numbering its changes belong to. A v0.1.4 client cannot start or
rejoin a v0.1.3 relay, and a v0.1.3 client cannot tell that a v0.1.4 relay was
started again from another machine, so it would skip records without saying so.
Upgrade the relay and every machine together, and sync every machine before you
start a new relay from one of them.

## Losing the relay is no longer the end of the vault

Until now the relay's data volume was the only copy of the vault's history that
could be rebuilt from: an empty relay refused an existing vault, and a relay
restored from a backup older than your machines stopped them from syncing. Your
machines hold the vault too, and now they can put it back.

On the machine that is most up to date:

```sh
sshstate connect https://relay.example.com --bootstrap-secret /path/to/new.secret
```

The vault already had a relay, so this asks before it starts a new one; answer
yes only if the old relay is gone for good, because two relays taking changes for
one vault drift apart. It uploads the device list, every revocation included, and
every host, key, and trust record the machine holds.

Then, on every other machine, before editing anything:

```sh
sshstate connect https://relay.example.com --rejoin
```

A relay restored from an older backup needs no new secret: rejoin every machine,
the most up-to-date one first. Each machine's `sync` says which command to run.

Nothing is overwritten silently. Every machine remembers the fingerprint of each
version of a record it has seen, so it can tell a version the relay holds that it
already built on from one that went a different way. Where the two diverged, the
relay's version stays current and this machine's is kept aside for
`sshstate conflicts`. Versions from before this release can be kept aside even
when they did not really diverge; `sshstate resolve <id> --discard` drops one.

Rejoining relaxes one check: while a machine reloads a relay's changes from the
start it has no revocation positions, so a relay that holds a revoked device's
signing key could slip that device's writes in. Rejoin only a relay you started
or restored yourself.

A relay backup is still worth keeping. It saves every machine a rejoin, and it
is the only copy of history older than what your machines still hold.

## Master-key rotation is still not implemented

Rotation is specified in `docs/rotation.md`. It is not implemented and not
scheduled; a vault key that leaks still means a fresh vault and a reviewed
migration. Keep the recovery kit and encrypted `sshstate export` archives, apart
from each other and from the relay.

## Changes

- A machine can start a new relay for a vault that already had one, and the
  others rejoin it with `sshstate connect <url> --rejoin`.
- A relay restored from a backup older than your machines is rejoined the same
  way instead of stopping sync for good.
- A removal that loses to another machine's edit is kept as a conflict instead of
  failing every later sync with `conflict record preserves nothing` (D42).
  `sshstate conflicts` names the host or key, `resolve` removes it, and
  `resolve --discard` keeps it.
- A relay that is down behind its reverse proxy is reported as unreachable,
  naming the proxy's status, instead of "the relay returned HTTP 502 with an
  unrecognized body".
- `connect` prints complete next commands: `sshstate pair <url> <vault-id>` for a
  new machine, and how machines already in the vault follow a move or a rejoin.
- Moving a relay to another host or address has a runbook in `deploy/README.md`,
  verified with Compose and nginx.
- The documentation states the project's status in one place and drops the
  milestone schedule; `docs/roadmap.md` records what is left.

## Verify a download

```sh
sha256sum -c SHA256SUMS --ignore-missing

cosign verify-blob SHA256SUMS \
  --bundle SHA256SUMS.cosign.bundle \
  --certificate-identity "https://github.com/mouizahmed/sshstate/.github/workflows/release.yml@refs/tags/v0.1.4" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

This is a 0.x release. It is tested against real `sshd`, launchd, systemd, and a
real relay, and it has not been independently audited or used by anyone but its
author.
