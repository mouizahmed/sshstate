# Protocol

Status: **draft**. Nothing in this document is frozen. Request and response
schemas, error codes and canonical encodings are specified and frozen before any
network code is written in Milestone 2 (project brief §5.5).

The relay is unaware of SSH payload semantics. It stores ciphertext, signatures,
revisions and cursors.

## Frozen at Milestone 0

The cryptographic suite, by decision record 0001. Implemented in
`internal/crypto`.

| Role | Algorithm |
|---|---|
| Signatures | ML-DSA-65 (FIPS 204), domain-separated via ML-DSA context |
| Recipient encryption | age v1 hybrid, ML-KEM-768 + X25519 |
| Record AEAD | XChaCha20-Poly1305, fresh 24-byte random nonce per encryption |
| Local KDF | Argon2id v19, 64 MiB, 3 iterations, 4 lanes |
| Hash | SHA-256 |
| Suite identifier | `sshstate.suite.v1` |

One suite per vault per epoch. No mixed mode, no negotiation, no fallback.
Unknown suite identifiers fail closed. Changing suite is an epoch transition, not
an in-place substitution.

The current `crypto.Seal` and `crypto.Open` helpers are for small key bundles.
Both enforce a 1 MiB serialized-ciphertext cap, including recipient and framing
overhead; the maximum plaintext size therefore depends on the recipient set.
Large enrollment snapshots and exports need a separate bounded streaming API
before implementation. Secret identity serialization uses explicit
`ExportSecret()`; ordinary key formatting is redacted.

## To be specified before Milestone 2

- Canonical encoding: RFC 8785 JCS, with golden vectors. No delimiter
  concatenation.
- Record envelope: the `context` object bound as AEAD associated data —
  protocol domain, format version, vault and record identifiers, record type,
  key epoch, revision, parent digest, mutation identifier, writer device
  identifier, deletion flag. The deletion flag is authenticated, not encrypted.
- Record digest: SHA-256 over the canonical signed envelope, excluding the
  server-assigned sequence number.
- Counters: `rev` is per-record optimistic concurrency state; `seq` is
  per-vault server acceptance order used only for pagination. They are never
  conflated.
- Membership chain: signed device authorization events rooted in the first
  device, each referencing its predecessor's digest.
- Pairing transcript schema, with adversarial test vectors.
- HTTP signature profile (RFC 9421). Note the constraint: the IANA HTTP
  Signature Algorithms registry has no post-quantum entry, so the profile omits
  `alg` and derives the algorithm from `keyid`. No off-the-shelf library
  implements this; the profile and its vectors are ours to write.
- Idempotency, pagination bounds and transactional cursor application.
- Private-key on-record serialization: OpenSSH private-key format string inside
  the record AEAD, plus its public-key fingerprint.

## Local control protocol

Separate from the sync protocol and versioned independently. HTTP/JSON over a
Unix socket, bounded request sizes, no TCP listener, no request-body logging.
The SSH agent socket never exposes administrative operations.
