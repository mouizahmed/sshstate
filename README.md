# sshstate

Open-source, self-hostable, CLI-first synchronization for an SSH environment.

sshstate keeps your managed SSH hosts, connection options, trusted host keys and
credentials available across every machine you use, including headless ones,
while native `ssh`, `scp` and editor remote integrations keep working unchanged.

> **Status: pre-v1, Milestone 1.** Local operation works end to end on macOS: a
> vault, a recovery kit, a daemon with an agent socket, generated configuration,
> reviewed import of the host-key trust you already have, and a real `ssh` login
> authenticated by a key that is never written to disk.
> Milestone 2 is largely in place: the sync protocol is frozen, the relay runs,
> and two machines pair, sync, resolve conflicts, revoke each other and restore
> from an encrypted backup with the relay unavailable. Not yet done: master-key
> rotation (specified, ships in M3b), conflict resolution as a command, Linux
> systemd, and strict SSH config import. This is an implementation in progress,
> not a released tool, and it has not been independently audited.

## What it is, and is not

It is a configuration and credential manager. It is **not** an SSH client or a
terminal. OpenSSH owns the connection, key exchange and authentication exchange;
sshstate supplies configuration and agent signatures. There is deliberately no
`sshstate ssh` command.

```
sshstate  →  sync/configure  →  native OpenSSH  →  ssh prod
```

Generated configuration lives under `~/.ssh/sshstate/`, reached by a single
`Include` line at the top of `~/.ssh/config`. Your hand-written entries are
never rewritten.

## Design decisions worth knowing

**Private keys are never written to disk.** A per-user daemon implements the SSH
agent protocol on its own socket; hosts are pointed at it with `IdentityAgent`.
Only public keys reach the filesystem. Your global `SSH_AUTH_SOCK` is untouched.

**The relay is treated as hostile.** It stores ciphertext, signatures and
cursors. It never receives a vault key, a password wrapper or a password
verifier. Device enrollment is authenticated by comparing a full transcript
fingerprint out of band, so a malicious relay cannot substitute its own key
during pairing.

**The vault is locked by default and expires.** Unlock is explicit. Idle expiry
is 15 minutes, refreshed by signing and by explicit vault commands but never by
status polling; hard expiry is 8 hours from password entry and cannot be
extended. A restarted or crashed daemon comes back locked.

**Host key trust is synchronized and reviewed, not overwritten.** A changed or
conflicting host key is held as a pending candidate requiring explicit
resolution. Conflicts never silently change what a machine trusts.

**No last-write-wins.** Records carry per-record revisions with exact parent
matching. A rejected edit survives as a conflict record for explicit resolution
rather than being discarded or silently winning.

**Post-quantum from genesis.** ML-DSA-65 for signatures, age hybrid recipients
(ML-KEM-768 + X25519) for every envelope reaching a vault key. See
[decision record 0001](docs/decisions/0001-post-quantum-device-cryptography.md).

**No telemetry, ever.** Nothing is reported anywhere. Stated explicitly because
this tool holds SSH keys.

## Scope of the post-quantum claim

This protects your **synchronized infrastructure map** — hostnames, usernames,
ports, jump-host topology — which is a long-lived secret with no public
counterpart.

It does **not** meaningfully protect your SSH private keys. An adversary able to
break X25519 can equally derive an Ed25519, ECDSA or RSA private key from its
public half, which sits in `~/.ssh/sshstate/public/`, in `authorized_keys` on
every destination, and often in a public profile. SSH credentials are only as
post-quantum as the algorithms OpenSSH supports for authentication.

## Why this rather than a password manager or encrypted dotfiles

Password managers solve SSH *key storage*. Encrypted dotfile tools sync SSH
*files*. Neither gives you a structured model of the environment — aliases,
usernames, ports, jump-host topology, ordered key references and host trust
travelling together — with a headless agent and real conflict handling.

Key storage alone would not justify building this. Configuration
synchronization, reviewed host trust and headless operation are the reason.

Windows is not supported and is not planned for v1 (see the project brief). An
agent-and-daemon design costs considerably more there than a client that writes
files, and that tradeoff is deliberate.

## Trying it

One machine, nothing leaving it:

```sh
go build -o sshstate ./cmd/sshstate

./sshstate init --kit ~/sshstate-recovery-kit.txt
./sshstate daemon &                    # or: ./sshstate install --service
./sshstate unlock
./sshstate add-key ~/.ssh/id_ed25519
./sshstate add prod --hostname 10.0.0.5 --user ubuntu --key <record-id>
./sshstate edit prod --hostname 10.0.0.9   # revises the record, does not add one
./sshstate import ~/.ssh/config --dry-run  # then again without --dry-run
./sshstate install                     # adds the Include to ~/.ssh/config
./sshstate doctor
ssh prod
./sshstate trust                           # host keys ssh captured, and what is pending
```

A second machine, through a relay you run (`deploy/README.md` sets one up):

```sh
# on the first machine
./sshstate connect https://relay.example.com --bootstrap-secret ./bootstrap.secret
./sshstate export ~/sshstate-backup.age

# on the second machine
./sshstate pair https://relay.example.com <vault-id>
# both screens show the same 13-group fingerprint; compare it out of band,
# then answer on both. Nothing is transferred before you do.

./sshstate sync
./sshstate devices
./sshstate revoke <device-id>          # stops that device on an honest relay
```

If every device is gone, the kit and a backup are enough, with no relay at all:

```sh
./sshstate restore ~/sshstate-backup.age --kit ~/sshstate-recovery-kit.txt
```

`init` prints a recovery kit and asks you to type its checksum back. That is
deliberate: the kit is the only way into the vault if every device is lost, and
it is not stored anywhere else. If that check fails, the vault is created but
refuses changes until you run `sshstate confirm-recovery --kit <path>`.

`install` shows the entries in your existing `~/.ssh/known_hosts` that match
managed hosts — fingerprints, markers, and any conflict with trust already in
the vault — and asks whether to import them, continue without them, or cancel.
Nothing is imported without that answer, and your own `known_hosts` is never
modified. Trust is published before the Include is activated, so a host you have
already accepted does not prompt again. Scripts pass `--import-trust` or
`--skip-trust`; without one, a noninteractive install refuses rather than
choosing for you.

`uninstall` removes the `Include` and leaves the vault, your keys, your SSH
config and your `known_hosts` alone. If the vault is connected to a relay it
offers to deregister this device first, and says plainly when it could not.
`--purge` additionally deletes the vault, and only after you have taken a backup
that is still on disk and typed the vault id back.

`install --service` registers the daemon with the platform's service manager,
so it starts on demand when SSH or the CLI connects, and starts locked. On macOS
that is a launchd agent; on Linux it is three systemd user units — one service
and one socket unit per socket, because systemd names every descriptor in a
socket unit alike and the daemon adopts its two sockets by name, never by
position. Everywhere else, run `sshstate daemon` in the foreground.

## Building

Requires **Go 1.27 or later** — `crypto/mldsa` is not present in Go 1.26.

```sh
make check      # gofmt, vet, build, test, test -race
go build ./...

# Register a real service in your own session; opt-in, and not run by CI.
SSHSTATE_LAUNCHD_TEST=1 go test ./internal/service/ -run Launchd   # macOS
SSHSTATE_SYSTEMD_TEST=1 go test ./internal/service/ -run Systemd   # Linux

# Start a real sshd and log into it with native OpenSSH. CI runs this on Linux.
SSHSTATE_SSHD_TEST=1 go test ./internal/cli/ -run NativeSSH
```

## Documentation

- [Project brief and milestones](docs/project-brief.md)
- [Threat model](docs/threat-model.md)
- [Defects found during implementation](docs/defects.md)
- [CLI review](docs/cli-review.md) — gaps in the command surface, and the plan
- [Protocol](docs/protocol.md) — draft, frozen before Milestone 2
- [Decision records](docs/decisions/)

## What is not claimed

No audited security. No complete key erasure in memory. No complete rollback
prevention against a withholding relay. No universal SSH config fidelity.

## License

AGPL-3.0-only. See [LICENSE](LICENSE).
