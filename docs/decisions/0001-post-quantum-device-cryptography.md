# 0001 — Post-quantum device cryptography

- Status: **Accepted** (adopt hybrid post-quantum suite for v1)
- Date: 2026-09-12
- Gate: brief §4.8, Milestone 0. Blocks freezing persistent device/recovery formats and network enrollment.
- Supersedes: the classical-only Ed25519 + age X25519 baseline described in §4.1.

## Decision

Adopt a hybrid post-quantum suite for all device and recovery cryptography:

| Role | Selection |
|---|---|
| Recipient encryption (device bundles, recovery envelopes, exports, rotation bundles) | age v1 hybrid recipient, ML-KEM-768 + X25519 (`filippo.io/age` `HybridRecipient`/`HybridIdentity`) |
| Signatures (records, membership, pairing transcripts, export manifests, request auth) | ML-DSA-65 (`crypto/mldsa`, FIPS 204) |
| Record AEAD | unchanged: XChaCha20-Poly1305 |
| Local KDF | unchanged: Argon2id |

Record AEAD and KDF are unchanged: symmetric primitives at these sizes are not the
quantum-vulnerable component, and §4.8 only ever scoped this gate to the routes that reach
vault keys.

## Why the assessment passes

All §4.8 acceptance criteria were exercised. Measurements below are from a spike on
macOS 26 / arm64 (Apple silicon), Go 1.27.1, `filippo.io/age` v1.3.2.

### Maintained libraries, first-party where it matters

`crypto/mlkem` (FIPS 203) is Go standard library as of the 1.26 line; `crypto/mldsa`
(FIPS 204) lands in 1.27. Compiling against go1.26.8 fails with `package crypto/mldsa is
not in std`, so this decision sets the project's minimum Go version at **1.27**, the newest
release line. That is a real narrowing — no older line to fall back to, and contributors must
be current — and is accepted rather than taking a third-party ML-DSA dependency. `crypto/mldsa` implements `crypto.Signer`, uses 32-byte seed private keys
(`PrivateKeySize = 32`), and exposes an `Options.Context` field that maps directly onto our
existing domain separation. No third-party signature dependency is required. age hybrid
recipients are upstream in `filippo.io/age` v1.3.0+, not a plugin.

### Sizes and latency are acceptable

```
suite               pub       seed        sig         sign       verify
Ed25519              32         32         64     0.019 ms     0.032 ms
ML-DSA-44          1312         32       2420     0.215 ms     0.058 ms
ML-DSA-65          1952         32       3309     0.347 ms     0.090 ms
ML-DSA-87          2592         32       4627     0.370 ms     0.143 ms

                             X25519    hybrid PQ
recipient string chars           62         1959
identity string chars            74           77
ciphertext bytes (128B in)      328         1787
encrypt                    0.116 ms     0.090 ms
decrypt                           -     0.076 ms
```

Signing is ~18x slower than Ed25519 in relative terms and still sub-millisecond in absolute
terms. At our write volumes this is not a factor. Hybrid encryption is *faster* than X25519
here, because ML-KEM operations are cheaper than an X25519 scalar multiplication.

### The recovery kit stays practical — §4.8's stated worry does not materialise

The 1959-character hybrid value is the **public recipient**. The **secret identity** is 77
characters (`AGE-SECRET-KEY-PQ-1...`), barely longer than the 74-character classical one, and
the recipient is derivable from it. The printed recovery kit therefore carries a short
secret, exactly as under the classical baseline. The long recipient lives in genesis and on
enrolled devices and is never hand-copied.

### Downgrade protection is enforced by the library, not by our discipline

§4.8 requires that no classical-only envelope exist for the same keys. Attempting to encrypt
to a hybrid and an X25519 recipient together is refused:

```
incompatible recipients: can't mix post-quantum and classic recipients,
or the file would be vulnerable to quantum computers
```

This is age's `postquantum` recipient label. It converts our stated requirement into a
structural property. Note it can be bypassed by wrapping `HybridRecipient` in a type that
hides `WrapWithLabels`; we must not do that, and a test should assert we never do.

### Tampering and context separation reject correctly

For all three ML-DSA parameter sets, a single flipped signature bit is rejected, and a
signature verified under a different `Options.Context` is rejected. Context therefore
carries our domain separation directly.

### Portability

`CGO_ENABLED=0` builds succeed for linux/amd64, linux/arm64, darwin/arm64, darwin/amd64.
The crypto introduces no cgo requirement. (§8's launchd activation adapter is a separate,
later cgo dependency on darwin.)

## Why ML-DSA-65 rather than ML-DSA-44

`crypto/mldsa` documentation suggests ML-DSA-44 for most applications, and 44 is smaller and
faster. We select 65 for category parity with ML-KEM-768: both are NIST Category 3, so the
suite has one security level rather than a Category 2 signature protecting a Category 3
key exchange. The cost is 889 additional signature bytes and ~0.13 ms per signature, and
both remain within the HTTP header budget below. If profiling later shows signature size
dominating sync payloads, ML-DSA-44 is a defensible downgrade — but it must be a recorded
amendment with a new suite identifier, never a silent change.

## Constraints this creates — record these, they are not blockers

### 1. RFC 9421 has no registered post-quantum algorithm

The IANA HTTP Signature Algorithms registry (checked 2026-09-12) contains exactly six
entries: `rsa-pss-sha512`, `rsa-v1_5-sha256`, `hmac-sha256`, `ecdsa-p256-sha256`,
`ecdsa-p384-sha384`, `ed25519`. There is no ML-DSA identifier, and registration is
Specification Required.

Size is not the problem — a base64 ML-DSA-65 signature in a `Signature:` header is 4430
bytes, about 54% of the 8190-byte single-header limit commonly deployed by Apache and nginx
(verify against the actual proxy in use; ML-DSA-87 at 6190 bytes would be uncomfortably
close):

```
suite         sig bytes   b64 header
Ed25519              64          106
ML-DSA-44          2420         3246
ML-DSA-65          3309         4430
ML-DSA-87          4627         6190
```

The problem is identification. Our profile must omit the `alg` parameter and derive the
algorithm from the key identified by `keyid`, which RFC 9421 permits, or use a clearly
private-use identifier. Either way **no off-the-shelf RFC 9421 library will support this**,
which compounds §4.7's existing instruction to budget for implementing the profile with our
own vectors. The independent cross-check §4.7 requires must then be done against the
classical parts of the profile plus our own ML-DSA vectors, since no second implementation
exists to interoperate with.

### 2. FIPS 140-3 module interaction

`crypto/mldsa` is unavailable under the FIPS 140-3 Go Cryptographic Module v1.0.0;
v1.26.0 or later is required. If anyone runs the client or server with `GODEBUG=fips140=on`
against an older module, key generation, parsing, and verification will error. Document it;
do not silently fall back to Ed25519.

### 3. What this does and does not protect

Post-quantum confidentiality here protects the **metadata key** payloads — hostnames, users,
ports, ProxyJump topology — which are long-lived secrets with no public counterpart.

It gives little protection to **SSH private keys**, because an adversary capable of breaking
X25519 can equally derive an Ed25519, ECDSA, or RSA SSH private key from its public key,
which is on disk in `~/.ssh/sshstate/public/`, in `authorized_keys` on every destination, and
often published. The vault is the harder path to a secret reachable by an easier one.

Say this explicitly in the README and threat model. The honest claim is *"your synchronized
infrastructure map stays confidential against future quantum attack; your SSH credentials are
only as post-quantum as the algorithms OpenSSH supports for authentication."* Claiming the
SSH keys themselves are protected would be false.

## Pinned dependencies

- Go 1.27 minimum (`crypto/mldsa` is not present in 1.26); developed and measured on 1.27.1
- `filippo.io/age` v1.3.2 (pulls `filippo.io/hpke` v0.4.0, `golang.org/x/crypto` v0.55.0)

Pin exact versions in `go.mod` at M0 and do not float them.

## Verification policy

- Suite identifiers are bound into genesis, membership events, pairing transcripts, envelope
  context, signatures, and export manifests, per §4.8.
- Unknown suite identifiers fail closed. No relay-selected negotiation, no fallback.
- A single suite is required per vault at a given epoch. There is no mixed-suite mode, and no
  classical compatibility envelope for the same keys.
- Changing suite is an epoch transition under §7.1, not an in-place substitution.

## Migration constraints

There is no in-place upgrade path from a classical vault, and none is needed: no vault has
been created, so v1 ships post-quantum from genesis. Should a future suite change be
required, §7.1's staged rotation is the mechanism, and the §4.8 limit stands — rotating keys
cannot retroactively protect ciphertext an attacker already captured.

## Follow-up

Amend brief §4.1, §4.2, §4.5, §4.6, §4.7, and §12 R12 to state this suite as the baseline
rather than as a pending assessment. Port the spike into `internal/crypto` tests at M0 so the
downgrade-rejection and context-separation assertions run in CI.

## Amendment, 2026-09-17: release framing

The project shipped this suite from genesis and now describes itself as a stable
MVP with no v1 target. The release label in the migration constraint is
historical; the suite, downgrade rejection, and epoch-transition decision are
unchanged. See decision record 0004.
