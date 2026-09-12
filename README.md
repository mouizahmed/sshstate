# sshstate

Open-source, self-hostable, CLI-first synchronization for an SSH environment.

sshstate keeps your managed SSH hosts, connection options, trusted host keys and
credentials available across every machine you use, including headless ones,
while native `ssh`, `scp` and editor remote integrations keep working unchanged.

> **Status: pre-v1, Milestone 0.** The module, cryptographic suite and CI exist.
> Nothing user-facing is implemented yet. This is an implementation in progress,
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

## Building

Requires **Go 1.27 or later** — `crypto/mldsa` is not present in Go 1.26.

```sh
make check      # gofmt, vet, build, test, test -race
go build ./...
```

## Documentation

- [Threat model](docs/threat-model.md)
- [Protocol](docs/protocol.md) — draft, frozen before Milestone 2
- [Decision records](docs/decisions/)

## What is not claimed

No audited security. No complete key erasure in memory. No complete rollback
prevention against a withholding relay. No universal SSH config fidelity.

## License

AGPL-3.0-only. See [LICENSE](LICENSE).
