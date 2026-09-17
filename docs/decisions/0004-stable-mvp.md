# 0004 — Stable MVP without a v1 target

Accepted 2026-09-17.

## Context

The brief planned a stable v1 gated on master-key rotation. M3a then shipped and
three releases followed it. Those releases were driven by operational findings
from dogfooding, not by the remaining milestone label. Rotation has not been
started, and no current use has required it.

The implementation is stable within its supported scope: single-user
self-hosting on macOS and Linux. Local and multi-device workflows, native SSH,
pairing, recovery, revocation, conflict handling, distribution, launchd,
systemd, and a real relay are exercised. Stability does not imply an independent
security audit, broad deployment evidence, or compatibility between every
`0.x` client and relay. Releases may still require a coordinated client and
relay upgrade.

The old framing disagrees with itself. Rotation is variously described as
shipping in M3b, required before stable v1, already implemented in M3b, and
merely planned. CLI help and relay errors repeat the schedule even though no
schedule exists.

## Decision

sshstate is a **stable, iterating MVP**. There is no v1 target and no milestone
roadmap. Releases remain on the `0.x` line and are cut when there is something
worth shipping. A version number does not gate a feature.

Milestones 0 through 3a remain in the brief as implementation history. They
record work that was completed and evidence that still matters. The future M3b
release gate is removed.

Master-key rotation remains specified and unimplemented. It is not scheduled.
Implementation starts only when at least one condition is real:

- a vault key is suspected exposed and fresh-vault migration is operationally
  unacceptable;
- a cryptographic-suite transition is required;
- a user requires in-place vault-key replacement.

Until rotation exists, a leaked vault key requires a fresh vault and reviewed
migration. Rotation cannot erase ciphertext or SSH private keys already captured.
The recovery kit, encrypted exports, and relay-data backup remain load-bearing
because each protects different state.

Living documents are updated in place. Dated release notes, distribution plans,
defect records, and earlier decisions retain their original text and receive a
dated amendment when a commitment was superseded.

## Consequences

`README.md` is the canonical project-status summary. `docs/rotation.md` is the
canonical rotation design. `docs/roadmap.md` orders the remaining work.

The word `v1` remains wherever it identifies a wire format, domain, route
namespace, dependency, or external standard. Examples include `/v1/records`,
`sshstate.suite.v1`, `sshstate.record-sig.v1`, and age v1. Those identifiers are
unrelated to a 1.0 release and do not change.

The reserved rotation routes, protocol types, state machines, and error codes
remain. They prepare storage and readers for an atomic transition and are not a
partially usable feature.

Recovering from a lost relay is higher-priority operational work than rotation.
