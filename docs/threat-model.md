# Threat model

Status: current for the stable MVP. Mechanisms described as implemented are
covered by the repository verification; rotation is planned for a future
iteration.

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

Freshness has explicit limits. Clients detect *observed regression* (a lower
revision, a differing digest at a revision already seen, a broken parent chain)
against state they already hold. A freshly enrolled or recovered client has no
prior baseline beyond the checkpoint transferred to it. Server sequence numbers
are transport bookkeeping, never trusted time. Complete rollback prevention is
not claimed.

## Transport

Clients refuse a relay URL that is not `https`, except for a loopback host used
in development. Certificate validation is the platform's and is not relaxed, so
an active network attacker cannot present a substitute relay without a
certificate the client already trusts.

TLS is terminated by a reverse proxy, not by the relay, which speaks plain HTTP
behind it. That proxy is inside the trust boundary for
availability and traffic metadata. It is not an authorization boundary: the
relay does not trust forwarded identity headers, and every mutation carries its
own signature covering method, authority, path, query, body digest and
idempotency key. A proxy that rewrites any covered field invalidates the
signature rather than silently altering an accepted request.

TLS is not what protects record contents. Payloads are encrypted before they
leave the client, so a terminating proxy sees ciphertext.

## Enrollment

Registration is opened once, by a 256-bit bootstrap secret the relay generates
on first start and prints once, or one the operator supplies. The relay stores
only its SHA-256 hash, compares in constant time, and records when it was
consumed; a spent bootstrap cannot be reopened by issuing or supplying another.
There is no other account-creation path, so a relay reachable on the network is
not a relay anyone can register against.

Whoever holds an unspent bootstrap secret before the legitimate first client
becomes the vault's first device. It is therefore read from the relay's log,
transferred privately, and deleted afterwards. Anyone who can read those logs
can take the vault before its owner does, until it is spent.

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

Generated configuration sets `ForwardAgent no`. The primary sshstate agent does
not claim reliable protocol-level detection of every forwarded request.
Explicit overrides and forwarding of that socket are unsupported.

Per-signature confirmation is not planned. Normal lock or session expiry does
not terminate SSH sessions that already authenticated.

## Device compromise and revocation

A stolen device already holds vault keys and can decrypt anything it previously
synchronized. Signed revocation stops that device's requests on an honest relay
and causes informed clients to reject its later writes; it does not erase what
that device already learned, and a hostile relay can withhold the revocation.

Resumable master-key rotation is planned for a future iteration. It would issue
fresh vault keys and re-encrypt current state under a new epoch,
excluding revoked devices from new bundles. Rotation cannot erase ciphertext an
attacker already captured, and new encryption keys do not revoke an already
stolen SSH private key; replace affected SSH credentials at their destinations.

## Post-quantum scope

Hybrid recipient encryption protects the metadata key's payloads, which are
long-lived secrets with no public counterpart. It gives little protection to SSH
private keys, because an adversary capable of breaking X25519 can derive an
Ed25519, ECDSA or RSA private key from its widely published public half.
