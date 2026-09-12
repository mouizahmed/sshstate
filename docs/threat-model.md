# Threat model

Status: current as of Milestone 0. Mechanisms described here are specified in
the project brief and mostly not yet implemented. Nothing here has been
independently audited.

## Posture

The sync relay is treated as hostile. SSH credentials are encrypted and
authenticated on the client. Vault keys never leave a trusted device in
plaintext. The unlock password is a **local device** password: it is never sent
to the relay, and no password-wrapped key or password verifier is uploaded.

## What a fully compromised relay obtains

Ciphertext; device and recovery recipient envelopes; public genesis and
membership data; public keys; record types and identifiers; revisions; epochs;
deletion flags; request metadata; cursors; and timing and size information.

It does **not** obtain SSH private keys, passphrases, hostnames, usernames,
ports, vault encryption keys, any device unlock password, or any password
wrapper or verifier to attack offline.

Stable per-record identifiers do leak vault size and which records change, when,
and how often. "The relay learns nothing" would be false. Padding and batching
are not worth the cost at this scale.

## What a compromised relay can still do

- Deny service, and withhold updates indefinitely.
- Maintain isolated forks of history that never converge.

It cannot substitute enrollment keys without defeating out-of-band full
fingerprint verification, forge an authorized writer's signature, or alter
authenticated record fields undetected.

Freshness has explicit limits. Clients detect *observed regression* — a lower
revision, a differing digest at a revision already seen, a broken parent chain —
against state they already hold. A freshly enrolled or recovered client has no
prior baseline beyond the checkpoint transferred to it. Server sequence numbers
are transport bookkeeping, never trusted time. Complete rollback prevention is
not claimed.

## Local compromise

Disk theft exposes generated hostnames, options, public keys, captured host-key
data, and an encrypted database vulnerable to offline guessing of the local
password. Locking does not erase generated metadata from disk.

A compromised unlocked device, a malicious process running as the same user, a
privileged debugger, or a stolen recovery kit defeats the relevant local
boundary. Socket permissions cannot distinguish the legitimate CLI from another
process owned by the same user. Agent-only key storage narrows the window and
removes the on-disk artifact; it does not prevent unauthorized use of an unlocked
signing socket.

Go cannot guarantee erasure of every copy of a secret held by the runtime or by
SSH and crypto libraries, nor prevent paging or memory inspection. The heap
collector is non-moving; the difficulty is untracked copies and the absence of
locked memory, not heap relocation. Buffers we own are wiped on lock and exit,
core dumps are disabled where supported, and decrypted key lifetime is bounded.
Complete zeroization is not claimed.

## Agent forwarding

Generated configuration sets `ForwardAgent no`. v1 does not claim reliable
protocol-level detection of every forwarded request. Explicit overrides and
forwarding of our socket are unsupported. Destination constraints and
per-signature confirmation are deferred. Normal lock expiry does not terminate
SSH sessions that have already authenticated.

## Device compromise and revocation

A stolen device already holds vault keys and can decrypt anything it previously
synchronized. Signed revocation stops that device's requests on an honest relay
and causes informed clients to reject its later writes; it does not erase what
that device already learned, and a hostile relay can withhold the revocation.

Resumable master-key rotation issues fresh vault keys and re-encrypts current
state under a new epoch, excluding revoked devices from new bundles. Rotation
cannot erase ciphertext an attacker already captured, and new encryption keys do
not revoke an already stolen SSH private key — replace affected SSH credentials
at their destinations.

## Post-quantum scope

Hybrid recipient encryption protects the metadata key's payloads, which are
long-lived secrets with no public counterpart. It gives little protection to SSH
private keys, because an adversary capable of breaking X25519 can derive an
Ed25519, ECDSA or RSA private key from its widely published public half. See
[decision record 0001](decisions/0001-post-quantum-device-cryptography.md).
