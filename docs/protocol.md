# sshstate sync protocol — v1

Status: **frozen for Milestone 2.** Every schema, encoding and error code below is
fixed before network code is written, as project brief §5.5 requires. Changing
anything here after M2 ships is a format-version change or an epoch transition,
not an edit.

The relay is unaware of SSH payload semantics. It stores ciphertext, signatures,
revisions and cursors, and validates structure and authorization only.

Section references in the form §x.y are to `docs/project-brief.md`.

---

## 1. Conventions

### 1.1 Suite

One suite per vault per epoch, identified by `sshstate.suite.v1` and bound into
genesis, membership events, pairing transcripts, bundles, export manifests and
record context. An unknown suite identifier fails closed: the reader stops, and
never falls back to another algorithm. See decision record 0001.

| Role | Algorithm |
|---|---|
| Signatures | ML-DSA-65 (FIPS 204), domain-separated through ML-DSA `Options.Context` |
| Recipient encryption | age v1 hybrid, ML-KEM-768 + X25519 |
| Record AEAD | XChaCha20-Poly1305, fresh 24-byte random nonce per encryption |
| Local KDF | Argon2id v19, 64 MiB, 3 iterations, 4 lanes |
| Hash | SHA-256 |

### 1.2 Encodings

- **Canonical JSON**: RFC 8785 JCS. This is the only form that is ever hashed,
  signed, or used as AEAD associated data. No delimiter-concatenation format
  appears anywhere in this protocol.
- **Binary fields**: base64url, no padding. Padded or standard-alphabet base64 is
  rejected rather than accepted and normalized.
- **Counters** (`rev`, `seq`, `key_epoch`): decimal strings, no leading zeros, no
  sign. JSON numbers are not used for counters: they are doubles in several
  languages, which loses precision above 2^53, and `1` versus `1.0` would give one
  value two canonical encodings.
- **Identifiers**: 128 random bits as 32 lowercase hex characters. Uppercase is
  rejected. No type prefix — a vault, record, device, mutation, session or event
  ID is indistinguishable to a relay, and none of them encodes a meaning that
  could later be relied on.
- **Timestamps**: RFC 3339 with a `Z` offset and second precision.
- **Absent versus empty**: inside any object that is hashed, signed, or used as
  AEAD associated data, a field that may be absent is encoded as JSON `null` and
  never omitted. JCS orders keys, so an omitted key and a null key are different
  canonical documents; the choice is fixed here rather than left to whichever
  marshaller a given implementation uses. Outside those objects the rule does not
  apply, which is why `seq` — excluded from every canonical form — is simply
  absent from a submission rather than sent as null.

### 1.3 Parsing rules

Every parser in this protocol, on both sides:

- rejects duplicate JSON keys at any depth;
- rejects unknown fields;
- rejects trailing data after the first JSON value;
- rejects an unknown mandatory `format_version` or `domain`;
- bounds the input before allocating.

### 1.4 Size bounds

| Object | Bound |
|---|---|
| Any single parsed JSON object | 1 MiB |
| Record envelope | 1 MiB |
| Response page | 4 MiB |
| Request body | 4 MiB |
| `Signature` / `Signature-Input` header | configured, default 16 KiB |
| age key bundle (non-streamed) | 1 MiB |
| Streamed snapshot or export archive | configured, default 256 MiB |

An oversized object is rejected with a code naming the bound. Nothing is
truncated.

### 1.5 Signature domains

Each signed structure has its own ML-DSA context string. A signature made for one
domain never verifies under another, so no signed object can be replayed as a
different kind of object.

| Structure | Context |
|---|---|
| Record envelope | `sshstate.record-sig.v1` |
| Membership event | `sshstate.membership-sig.v1` |
| Pairing offer | `sshstate.pairing-offer.v1` |
| Pairing confirmation | `sshstate.pairing-confirm.v1` |
| Key bundle | `sshstate.bundle-sig.v1` |
| Export manifest | `sshstate.export-sig.v1` |
| Recovery admission | `sshstate.recovery-admit.v1` |
| Rotation transition manifest | `sshstate.rotation-sig.v1` |
| Recovery kit confirmation (local) | `sshstate.recovery-kit-confirm.v1` |
| HTTP request | `sshstate.request.v1` |

---

## 2. Genesis

Immutable, public, created once by `sshstate init`. A recovering or enrolling
device pins its digest before trusting anything else, so "is this the same vault?"
is one digest comparison rather than a judgement about a set of fields.

```json
{
  "domain": "sshstate.genesis.v1",
  "format_version": 1,
  "suite": "sshstate.suite.v1",
  "vault_id": "<id>",
  "created_at": "2026-09-12T00:00:00Z",
  "first_device_id": "<id>",
  "first_device_verify_key": "<mldsa65-public-base64url>",
  "first_device_recipient": "age1pq1...",
  "recovery_verify_key": "<mldsa65-public-base64url>",
  "recovery_recipient": "age1pq1..."
}
```

Genesis is unsigned. It needs no signature: it is self-rooting, and its digest is
what every other structure binds to. A substituted genesis is a different vault,
detected by the kit's pinned digest and by every device's stored copy.

`genesis_digest` throughout this document means SHA-256 over the canonical
genesis.

---

## 3. Records

### 3.1 Context

The authenticated, unencrypted header. Its canonical encoding is the record
payload's AEAD associated data, so no field here can be altered by a relay
without making the record undecryptable.

```json
{
  "domain": "sshstate.record.v1",
  "format_version": 1,
  "vault_id": "<id>",
  "record_id": "<id>",
  "record_type": "host",
  "key_epoch": "1",
  "rev": "8",
  "parent_digest": "<sha256-base64url>",
  "mutation_id": "<id>",
  "updated_by": "<device-id>",
  "deleted": false
}
```

`deleted` is plaintext because it is authenticated. A relay that cannot decrypt
anything must still be able to see that a record is a tombstone; a client verifies
the envelope before acting on the flag. There is no unauthenticated bare DELETE
operation in this protocol.

`parent_digest` is `null` if and only if `rev` is 1.

### 3.2 Envelope, signing input, digest

```json
{
  "context": { ... },
  "nonce": "<24-bytes-base64url>",
  "ciphertext": "<xchacha20poly1305-ciphertext-and-tag-base64url>",
  "signature": "<mldsa65-signature-base64url>",
  "seq": "441"
}
```

- **Signing input**: JCS over `{context, nonce, ciphertext}` — no `signature`, no
  `seq`. Signed under `sshstate.record-sig.v1`.
- **Record digest**: SHA-256 over JCS of `{context, nonce, ciphertext, signature}`
  — still no `seq`. A child names this value as its `parent_digest`.
- **`seq`** is assigned by the relay and excluded from both. A value the relay
  chooses must never be able to change a record's identity. It is present in
  responses and absent in submissions.

### 3.3 Record types and payloads

Record type is visible metadata. `host`, `known_host` and `conflict_metadata`
payloads are encrypted under the vault **metadata** key; `key` and
`conflict_secret` under the vault **secret** key (§4.1).

**host**

```json
{
  "format_version": 1,
  "alias": "prod",
  "hostname": "10.0.0.5",
  "user": "ubuntu",
  "port": 22,
  "proxy_jump": null,
  "key_ids": ["<id>"]
}
```

`proxy_jump` null and the string `"none"` are different statements: null means
this host declares no jump host, and the generated config writes `ProxyJump none`
so an outer pattern cannot supply one. `key_ids` is ordered — OpenSSH tries
identities in the order given, so it is a user preference, not a set.

**key**

```json
{
  "format_version": 1,
  "private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\n...",
  "public_key": "ssh-ed25519 AAAA... comment",
  "fingerprint": "SHA256:...",
  "algorithm": "ssh-ed25519",
  "comment": ""
}
```

The private key is an unencrypted OpenSSH private-key format string **inside the
record AEAD**. It is unencrypted at this layer because the record AEAD is the
encryption; a second passphrase here would be another secret to lose protecting
the same bytes. v1 accepts Ed25519, RSA of at least 2048 bits, and standard NIST
ECDSA. Hardware-backed keys and certificates are deferred.

**known_host**

```json
{
  "format_version": 1,
  "line": "10.0.0.5 ssh-ed25519 AAAA...",
  "key_type": "ssh-ed25519",
  "fingerprint": "SHA256:...",
  "marker": "",
  "status": "approved",
  "line_digest": "<sha256-base64url>"
}
```

The original line is preserved verbatim. Markers (`@revoked`, `@cert-authority`)
and hashed hostname tokens carry meaning this program does not fully interpret,
and rebuilding a line from parsed fields would quietly drop whatever parsing
missed. Flattening a `@revoked` line into ordinary trust would turn a prohibition
into permission. `status` is `approved` or `pending`; only `approved` is
generated. `line_digest` is SHA-256 over the line with runs of whitespace
collapsed to single spaces, used to deduplicate exact duplicates — deduplication
is by full line, never by (hostname, key type), because a host may legitimately
have several keys of one algorithm.

**conflict_metadata / conflict_secret**

```json
{
  "format_version": 1,
  "source_record_id": "<id>",
  "source_record_type": "host",
  "source_mutation_id": "<id>",
  "observed_head_digest": "<sha256-base64url>",
  "preserved_at": "2026-09-12T00:00:00Z",
  "candidate": { ... }
}
```

`candidate` is the rejected payload, verbatim, inside the encryption boundary
appropriate to `source_record_type`. A conflict over a `key` record is a
`conflict_secret`; everything else is a `conflict_metadata`.

### 3.4 Deterministic conflict identifiers

A conflict record's ID is derived, not random, so that two devices preserving the
same rejected candidate converge on one record instead of creating two:

```
conflict_id = lowercase_hex(
    SHA-256(JCS({
      "domain": "sshstate.conflict-id.v1",
      "vault_id": <vault id>,
      "source_record_id": <source record id>,
      "source_mutation_id": <candidate's original mutation id>
    }))[0:16]
)
```

If that ID already exists with **differing** content, it is not overwritten: the
collision is surfaced as an error. The local outbox copy of a candidate is
retained until its preservation is acknowledged.

### 3.5 Revisions

`rev` is per-record optimistic concurrency state. `seq` is per-vault server
acceptance order used only for pagination. They are never conflated.

- Creation uses parent rev 0 (expressed as `parent_digest: null`) and `rev` 1.
- An update names the exact current parent rev and digest, with `rev = parent + 1`.
- The client knows the rev before encrypting, because the rev is inside the AAD.
- The relay rejects both an older parent and a future one.

---

## 4. Membership chain

Who may write is decided by the signed chain, never by the relay's device table.
A client validates the chain itself and treats the relay's view as a hint.

### 4.1 Event

```json
{
  "domain": "sshstate.membership.v1",
  "format_version": 1,
  "suite": "sshstate.suite.v1",
  "vault_id": "<id>",
  "event_id": "<id>",
  "chain_seq": "2",
  "parent_digest": "<sha256-base64url>",
  "action": "enroll",
  "device_id": "<id>",
  "device_verify_key": "<mldsa65-public-base64url>",
  "device_recipient": "age1pq1...",
  "transcript_digest": "<sha256-base64url>",
  "authority": "device",
  "authorized_by": "<device-id>",
  "created_at": "2026-09-12T00:00:00Z"
}
```

Carried as `{"event": {...}, "signature": "<base64url>"}`, signed under
`sshstate.membership-sig.v1` by the key named in `authorized_by`.

- `action` is `enroll` or `revoke`.
- `authority` is `device` or `recovery`. With `recovery`, `authorized_by` is the
  vault ID and the signature verifies under the genesis-pinned recovery verify
  key; reading an encrypted envelope alone never grants write access.
- On `revoke`, `device_verify_key`, `device_recipient` and `transcript_digest`
  are `null`.
- `transcript_digest` is non-null on an `enroll` with `authority: device`, and
  null on an `enroll` with `authority: recovery`. The root event is the one
  device-authorized enrolment with no pairing behind it, and carries 32 zero
  bytes rather than null. A nullable exception for exactly one event would put a
  branch in the validator for an attacker to aim at; an all-zero digest keeps the
  rule absolute and can match no real transcript.
- Event digest: SHA-256 over JCS of `{event, signature}`.

### 4.2 Chain validation

1. `chain_seq` 1 is the root: `action: enroll`, `parent_digest: null`,
   `authority: device`, `authorized_by == device_id == genesis.first_device_id`,
   and its key fields equal the genesis first-device keys exactly. A chain whose
   root disagrees with genesis is rejected outright.
2. Each later event has `chain_seq` exactly one greater than its predecessor and
   `parent_digest` equal to the predecessor's event digest.
3. The signer must be authorized **at that point in the chain** — enrolled
   earlier and not revoked earlier — or the recovery authority.
4. A device ID is never reused. Enrolling an ID that has appeared before is
   rejected, so a revocation cannot be undone by re-enrolment of the same name.
5. A `revoke` naming the last remaining authorized device is rejected. That would
   leave the recovery kit as the only write path.
6. `suite` and `vault_id` must match genesis on every event.

A client that fails validation keeps its previously validated chain and reports
the failure. It does not adopt a partially valid prefix.

---

## 5. Pairing

Out-of-band verification of a full SHA-256 transcript fingerprint (§4.5). Both
devices must have a trusted display.

### 5.1 Transcript

```json
{
  "domain": "sshstate.pairing.v1",
  "format_version": 1,
  "suite": "sshstate.suite.v1",
  "vault_id": "<id>",
  "session_id": "<id>",
  "approver_device_id": "<id>",
  "approver_verify_key": "<base64url>",
  "approver_recipient": "age1pq1...",
  "joiner_device_id": "<id>",
  "joiner_verify_key": "<base64url>",
  "joiner_recipient": "age1pq1...",
  "approver_challenge": "<32-bytes-base64url>",
  "joiner_challenge": "<32-bytes-base64url>",
  "created_at": "2026-09-12T00:00:00Z",
  "expires_at": "2026-09-12T00:10:00Z"
}
```

`expires_at` is `created_at` plus exactly 10 minutes. Each endpoint enforces its
own elapsed timeout; a hostile relay's clock is not relied on.

### 5.2 Fingerprint display

The fingerprint is SHA-256 over the canonical transcript: 32 bytes, displayed as
uppercase RFC 4648 base32 without padding — 52 characters in 13 numbered groups
of four, identically on both devices.

```
 1 ABCD   2 EFGH   3 IJKL   4 MNOP
 5 QRST   6 UVWX   7 YZ23   8 4567
 9 ABCD  10 EFGH  11 IJKL  12 MNOP
13 QRST
```

All 13 groups are displayed, never elided or collapsed. The user is instructed to
compare every group; comparing the beginning or end is insufficient. Group
numbers are presentation only, and are not part of the value — `2` through `7`
are base32 data characters, so a reader must never try to strip digits. The
final character encodes 1 bit of the digest and 4 unused bits, which must be
zero; a reader re-encodes and compares rather than trusting a base32 decoder to
reject a non-zero remainder, since otherwise 16 distinct strings decode to one
digest. The signed transcript and digest bytes are not affected by this
encoding.

This improves readability. It does not eliminate human comparison error.

### 5.3 Sequence

1. The joiner generates its signing and encryption keys, a 256-bit challenge, and
   a **self-signed offer** under `sshstate.pairing-offer.v1`. A self-signed offer
   alone never authorizes a device; it proves possession of the offered key and
   nothing more.
2. The approver — unlocked, already authorized — generates its own challenge and
   builds the transcript. Both devices display the same fingerprint.
3. The user compares the fingerprints over a channel independent of the relay and
   confirms explicitly on both devices. No vault secret is sent and no membership
   is finalized before both confirmations. Replacing a key or restarting the
   attempt invalidates any prior confirmation.
4. Both devices sign the transcript digest under
   `sshstate.pairing-confirm.v1`. The approver then signs the membership
   enrolment event and a key bundle, and seals the bundle to the joiner.
5. The joiner verifies the approver's confirmation against its own computed
   transcript, decrypts the bundle, validates the bundle and the membership chain,
   installs the snapshot at the bundle's checkpoint, and persists everything under
   its own local password.

age supplies recipient confidentiality, not sender authentication. The signatures
and the verified transcript supply the latter.

Accepted session IDs and challenges are persisted so a session cannot be
completed twice.

### 5.4 Confirmation

What each device signs once its user has compared the fingerprint:

```json
{
  "domain": "sshstate.pairing-confirm.v1",
  "format_version": 1,
  "vault_id": "<id>",
  "session_id": "<id>",
  "device_id": "<id>",
  "transcript_digest": "<sha256-base64url>",
  "created_at": "2026-09-12T00:00:00Z"
}
```

It carries the digest rather than the transcript, so a confirmation cannot be
lifted onto a differently assembled transcript that happens to share a field.
Carried as `{"confirmation": {...}, "signature": "<base64url>"}`, signed under
`sshstate.pairing-confirm.v1`.

---

## 6. Key bundles, checkpoints and snapshots

### 6.1 Checkpoint

```json
{
  "domain": "sshstate.checkpoint.v1",
  "format_version": 1,
  "vault_id": "<id>",
  "key_epoch": "1",
  "seq": "441",
  "membership_digest": "<sha256-base64url>",
  "heads": [
    {"record_id": "<id>", "rev": "3", "digest": "<sha256-base64url>", "deleted": false}
  ],
  "created_at": "2026-09-12T00:00:00Z"
}
```

`heads` is sorted by `record_id` ascending, so one state has one encoding.
`membership_digest` is the digest of the membership chain's head event.

A checkpoint states what the issuing device had accepted. It is not a claim that
the relay has nothing newer. `seq` is transport bookkeeping, not trusted time.

### 6.2 Bundle

The only structure that carries vault keys. Signed first, then age-sealed to the
recipient, so that the recipient identity and epoch are inside the signed content
rather than asserted by whoever encrypted it.

```json
{
  "domain": "sshstate.bundle.v1",
  "format_version": 1,
  "suite": "sshstate.suite.v1",
  "vault_id": "<id>",
  "genesis_digest": "<sha256-base64url>",
  "purpose": "enrollment",
  "recipient_device_id": "<id>",
  "recipient": "age1pq1...",
  "key_epoch": "1",
  "metadata_key": "<32-bytes-base64url>",
  "secret_key": "<32-bytes-base64url>",
  "transcript_digest": "<sha256-base64url>",
  "checkpoint": { ... },
  "snapshot_digest": "<sha256-base64url>",
  "snapshot_length": "182344",
  "created_at": "2026-09-12T00:00:00Z"
}
```

`purpose` is `enrollment`, `recovery` or `rotation`. `transcript_digest` is
non-null only for `enrollment`. `snapshot_digest` and `snapshot_length` are null
when no snapshot accompanies the bundle.

Sealed form: `{"bundle": {...}, "signature": "<base64url>"}` under
`sshstate.bundle-sig.v1`, JCS-encoded, then age-sealed to `recipient`. The
recipient verifies the signature against the sender's verify key **from the
membership chain**, and checks that `recipient` matches its own, before using any
key material.

### 6.3 Snapshot stream

A full record snapshot does not fit the 1 MiB bundle bound, so it travels
separately: JSON Lines of record envelopes, one per line, in ascending
`record_id` order, age-sealed to the same recipient as a separate object. Its
SHA-256 and length are bound inside the signed bundle, so the stream needs no
signature of its own and cannot be substituted.

A snapshot contains **accepted** records only. Pending local edits stay outbox
candidates on the sending device and are never transferred as accepted heads.

The receiving device installs the snapshot and the bundle's checkpoint in one
transaction before resuming incremental sync, and must reach at least that
checkpoint before publishing anything it fetched from the relay.

---

## 7. Recovery

Admission proves possession of the genesis-pinned recovery **signing** key. The
recovery signing key and the recovery encryption identity are independent roles of
one kit; holding the encryption identity alone lets a party read envelopes, never
write.

```json
{
  "domain": "sshstate.recovery-admit.v1",
  "format_version": 1,
  "vault_id": "<id>",
  "genesis_digest": "<sha256-base64url>",
  "nonce": "<32-bytes-base64url>",
  "device_id": "<id>",
  "device_verify_key": "<base64url>",
  "device_recipient": "age1pq1...",
  "created_at": "2026-09-12T00:00:00Z"
}
```

Signed under `sshstate.recovery-admit.v1` by the recovery signing key. The relay's
nonce expires after 10 minutes and is consumed once. Before proof of authority, a
recovery caller can retrieve only the public genesis and the encrypted recovery
material — nothing else.

On success the relay records the caller's replacement-device registration; the
recovery-authorized `enroll` membership event is published separately through
`POST /v1/membership`, signed by the recovery key, so the chain remains the single
source of authorization.

Recovery with the relay unavailable uses a local export instead (§8), which is why
an export carries its own checkpoint.

---

## 8. Export

An age-encrypted full export, encrypted **only** to the recovery recipient. There
is no plaintext and no password-encrypted export mode in v1. Device private keys
and local password wrappers are excluded.

```json
{
  "domain": "sshstate.export.v1",
  "format_version": 1,
  "suite": "sshstate.suite.v1",
  "vault_id": "<id>",
  "genesis_digest": "<sha256-base64url>",
  "key_epoch": "1",
  "exported_by": "<device-id>",
  "created_at": "2026-09-12T00:00:00Z",
  "checkpoint": { ... },
  "members": [
    {"name": "bundle.json",     "length": "2043",   "digest": "<sha256-base64url>"},
    {"name": "conflicts.jsonl", "length": "0",      "digest": "<sha256-base64url>"},
    {"name": "genesis.json",    "length": "812",    "digest": "<sha256-base64url>"},
    {"name": "membership.jsonl","length": "4210",   "digest": "<sha256-base64url>"},
    {"name": "records.jsonl",   "length": "182344", "digest": "<sha256-base64url>"}
  ]
}
```

**Recorded amendment.** `bundle.json` was added to this member set when
implementing restore showed the archive could not do its job without it. It holds
a signed recovery-purpose §6.2 bundle carrying the vault keys.

Every record in an export is encrypted under those keys, and the relay's copy of
them is precisely what is unreachable in the case an export exists for: "explicit
recovery can use a local export if the relay is unavailable" (§4.6) is not true
without it. Including them is safe because the archive is sealed to the recovery
recipient and to nothing else, so they are reachable by exactly the party that
could already open the relay's copy. The bundle is signed by the exporting
device, because encryption to a published recipient is not evidence of who
produced it.

Every member is named even when empty: a missing member and an empty member are
different statements, and a reader must not have to guess which it is looking
at.

Signed under `sshstate.export-sig.v1` by an authorized device, binding genesis,
the checkpoint, and the digest and length of every member. `members` is sorted by
`name`.

A restore verifies the manifest against the kit-pinned genesis before treating the
checkpoint as trusted, verifies every member's digest and length, and verifies
record signatures and context before installation. It restores into a **new** local
store with fresh device keys and a new local password, and never overwrites an
existing vault implicitly.

A stale backup cannot establish later freshness.

---

## 9. Request authentication

RFC 9421 HTTP Message Signatures, restricted to the closed profile in decision
record 0002. In summary, and normative there:

- one signature, label `sshstate`;
- covered components, in order:
  `"@method" "@authority" "@path" "@query" "content-digest" "sshstate-vault" "sshstate-device" "idempotency-key"`,
  where `content-digest` is covered if and only if there is a body and
  `idempotency-key` if and only if the request is a mutation;
- parameters `created`, `expires`, `nonce`, `keyid`, `tag="sshstate.request.v1"`;
  **no `alg`** — the algorithm comes from the key named by `keyid`, resolved
  through the membership chain;
- `expires - created` at most 300 s, 60 s skew tolerance either way;
- `nonce` 128 random bits, base64url; `(device, nonce)` stored until expiry plus
  tolerance and rejected on repeat;
- `Content-Digest: sha-256=:…:` over the raw body bytes as received;
- a retry reuses the mutation ID and identical body with a fresh nonce and
  signature.

The verifier computes the expected covered-component list from the request itself
and compares it to `Signature-Input` before any cryptography, so a signer cannot
choose to leave a component uncovered. It also re-serializes `Signature-Input`
and rejects anything that is not byte-identical to what arrived: the signature
base is rebuilt from parsed values, so one spelling per signature is what keeps
the signer's string and the verifier's string the same one.

Headers: `SSHState-Vault: <vault id>`, `SSHState-Device: <device id>`,
`Idempotency-Key: <mutation id>` on mutations. `Idempotency-Key` must equal the
`mutation_id` inside the submitted envelope.

TLS certificate validation is mandatory. Development HTTP is loopback-only and
opt-in. Signed mutations are never redirected and no proxy-supplied header is
trusted.

Three callers are not registered devices and authenticate otherwise:

| Caller | Mechanism | Access |
|---|---|---|
| Bootstrap | `Authorization: Bootstrap <base64url secret>` | create the single account, once |
| Pending joiner | offer signature under `sshstate.pairing-offer.v1` | its own pairing session only |
| Recovery | `sshstate.recovery-admit.v1` signature | public genesis and recovery material, then admission |

---

## 10. HTTP API

Base path `/v1`. All bodies are `application/json` unless stated. Request bodies
are never logged.

### 10.1 Bootstrap

```
POST /v1/bootstrap
```

Auth: the one-time bootstrap secret, 256 bits, supplied to the relay in an
operator-mounted secret file. The file and the header carry the same base64 text;
both base64 alphabets are accepted, padded or not, since the value compared is
the decoded 256 bits. The relay stores only the hash of those bytes, compares in
constant time, consumes it atomically when the single account is created, and
disables bootstrap permanently thereafter. Changing the secret afterwards does
not reopen registration. There is no open registration and the secret is never
written to routine logs.

Request: `{"genesis": {...}, "membership_root": {"event": {...}, "signature": "..."}}`

Response `201`: `{"vault_id": "<id>"}`

Subsequent calls return `bootstrap_consumed`.

Connecting an existing local vault uploads genesis, public membership, ciphertext
and device/recovery recipient envelopes through the ordinary routes. It does not
regenerate the vault.

### 10.2 Pairing

```
POST /v1/pairings
```

Auth: the joiner's own offer signature. A pending joiner has no record access.

Request:
```json
{
  "vault_id": "<id>",
  "offer": {
    "domain": "sshstate.pairing-offer.v1",
    "format_version": 1,
    "suite": "sshstate.suite.v1",
    "vault_id": "<id>",
    "joiner_device_id": "<id>",
    "joiner_verify_key": "<base64url>",
    "joiner_recipient": "age1pq1...",
    "joiner_challenge": "<32-bytes-base64url>",
    "created_at": "..."
  },
  "signature": "<base64url>"
}
```

Response `201`: `{"session_id": "<id>", "expires_at": "..."}`

An honest relay allows one active attempt per pending device and rate-limits
offers. Cryptographic safety does not depend on a hostile relay enforcing either.

```
GET /v1/pairings/:id
```

Auth: the joiner of that session, or any authorized device. Capability is
restricted to the named session.

Response `200`:
```json
{
  "session_id": "<id>",
  "state": "offered",
  "offer": { ... },
  "offer_signature": "<base64url>",
  "approver": { ... },
  "approver_confirmation": "<base64url>",
  "joiner_confirmation": "<base64url>",
  "bundle": "<age-ciphertext-base64url>",
  "membership_event": { ... },
  "expires_at": "..."
}
```

`state` is `offered`, `confirming`, `confirmed`, `completed` or `expired`. Fields
not yet posted are `null`.

```
POST /v1/pairings/:id/confirm
```

Auth: the approver (an authorized device) or the joiner. The relay identifies the
caller by `keyid` and rejects a third party.

The approver's first call carries its half of the transcript and its
confirmation; the joiner's call carries only its confirmation.

Approver request:
```json
{
  "approver": {
    "approver_device_id": "<id>",
    "approver_verify_key": "<base64url>",
    "approver_recipient": "age1pq1...",
    "approver_challenge": "<32-bytes-base64url>",
    "created_at": "...",
    "expires_at": "..."
  },
  "confirmation": { ... },
  "signature": "<base64url>"
}
```

Joiner request: `{"confirmation": {...}, "signature": "<base64url>"}`

Response `200`: the session as in `GET`.

The relay stores both confirmations and checks that the two
`confirmation.transcript_digest` values are equal, but it cannot verify the
transcript itself and is not trusted to. Each device recomputes the transcript from the session and compares the
fingerprint the user approved.

```
POST /v1/pairings/:id/complete
```

Auth: the approver, then the joiner.

Approver request:
```json
{
  "membership_event": {"event": {...}, "signature": "..."},
  "bundle": "<age-ciphertext-base64url>",
  "snapshot": "<age-ciphertext-base64url>"
}
```

Rejected with `pairing_incomplete` unless both confirmations are present and the
session has not expired.

Joiner request: `{"acknowledged": true}` — the session moves to `completed` and is
consumed. A completed or expired session is never reopened.

### 10.3 Membership

```
GET  /v1/membership
POST /v1/membership
```

`GET` returns the full chain: `{"events": [{"event": {...}, "signature": "..."}]}`,
ascending by `chain_seq`. It is unauthenticated in content terms — the chain is
public — but still requires a valid signed request from a registered device, the
recovery authority, or a joiner within its session.

`POST` appends exactly one event. The relay checks `chain_seq`, `parent_digest`,
the signature, and that the signer is authorized at that point, then appends
atomically. A gap or a fork is rejected with `parent_mismatch`; the response
carries the current head so the caller can refetch.

The relay's own device table is derived from the chain and is never authoritative
for a client.

### 10.4 Key envelopes

```
GET /v1/envelopes
PUT /v1/envelopes/:id
```

`GET` returns the sealed bundles addressed to the calling device:
`{"envelopes": [{"id": "<id>", "purpose": "enrollment", "key_epoch": "1", "recipient_device_id": "<id>", "ciphertext": "<base64url>"}]}`.
Capability is restricted to the calling recipient: a device cannot list another
device's envelopes.

`PUT` stores one, by an authorized device, for a named recipient. A revoked device
is never a valid recipient, and the relay rejects a `PUT` naming one.

### 10.5 Recovery

```
POST /v1/recovery/challenge
POST /v1/recovery/complete
```

`challenge` request: `{"vault_id": "<id>"}`.
Response `200`:
```json
{
  "nonce": "<32-bytes-base64url>",
  "expires_at": "...",
  "genesis": { ... },
  "recovery_envelope": "<age-ciphertext-base64url>"
}
```

That is the entire pre-authority surface: public genesis and the encrypted
recovery material, nothing else.

`complete` request: `{"admission": {...}, "signature": "<base64url>"}`.
Response `200`: `{"device_id": "<id>", "membership_head_digest": "<sha256-base64url>"}`.

The nonce is consumed once, whatever the outcome.

### 10.6 Records

```
GET /v1/records?since=<seq>&through=<seq>&limit=<n>
PUT /v1/records/:id
```

`GET` captures a snapshot upper bound on the first page. Subsequent pages carry
`through=<snapshot_cursor>` and return only changes after `since` through that
bound, in `seq` order.

Response `200`:
```json
{
  "changes": [ { "context": {...}, "nonce": "...", "ciphertext": "...", "signature": "...", "seq": "439" } ],
  "next_cursor": "441",
  "snapshot_cursor": "512",
  "has_more": true
}
```

`limit` defaults to 200 and is capped at 500; the 4 MiB page bound takes
precedence and may return fewer. An invalid bound — `since` above `through`, a
`through` above the relay's current head, a non-numeric cursor — is rejected
rather than clamped.

`PUT /v1/records/:id` submits one envelope. `:id` must equal
`context.record_id`, and `Idempotency-Key` must equal `context.mutation_id`.

Response `200`: `{"accepted": true, "seq": "442", "digest": "<sha256-base64url>"}`

Response `409` on a parent mismatch, carrying the current head so the client can
preserve its candidate as a conflict record:
```json
{
  "error": {"code": "parent_mismatch", "message": "..."},
  "head": { "context": {...}, "nonce": "...", "ciphertext": "...", "signature": "...", "seq": "440" }
}
```

The relay checks idempotency **before** parent comparison and returns the original
outcome for identical bytes — including a stable rejection. Reuse of a mutation ID
with different bytes is `idempotency_mismatch`. Mutation outcomes are retained in
v1; there is no garbage collection of tombstones or the accepted log.

An accepted write atomically updates the head, appends the log with a fresh `seq`,
and stores the idempotency outcome.

### 10.7 Rotation

```
POST   /v1/rotations
GET    /v1/rotations/:id
PUT    /v1/rotations/:id/staged/:item
POST   /v1/rotations/:id/commit
DELETE /v1/rotations/:id
```

Specified in `docs/rotation.md` and implemented in Milestone 3b. The routes are
listed here so the relay's storage and the sync reader are built to accommodate
them from the start; a transition that has to be atomic cannot be bolted onto
storage that never anticipated it. A relay that does not implement rotation
returns `not_implemented`, and must still reject old-epoch writes once an epoch
has advanced.

`DELETE /v1/rotations/:id` is an amendment to this list. §7.1 requires an
explicit authenticated abort that discards staging and releases the write freeze,
and the list as frozen had no route for it. It is a new method on an existing
path, accepted from any currently authorized device — §7.1 requires a remaining
device to be able to clear a rotation stranded by a lost initiator, which is
exactly the case where the initiator cannot ask.

---

## 11. Client obligations

These are not optional client-side niceties; a client that skips them breaks the
guarantees the rest of the document makes.

**Before sending.** Persist each outbound candidate and its random mutation ID
locally before transmission. A retry reuses the exact signed envelope bytes.

**On receiving a page.** Validate signatures, authorization against the membership
chain, AEAD decryption, and parent chains before committing anything. Apply the
page, the trusted heads and the next cursor in **one** SQLite transaction. Do not
advance the cursor on failure.

**Before rendering.** Render generated SSH configuration only after reaching the
snapshot boundary and validating every referenced dependency — a host that names a
key ID needs that key record. If the snapshot is incomplete or inconsistent, keep
the previously generated state rather than publishing a partial one.

**Persisted head state.** Record each observed head, digest, tombstone and the
highest known epoch transactionally. Reject a lower revision, a different digest at
an already observed revision, or a broken parent chain.

**Conflicts.** No last-write-wins. A rejected candidate survives as a conflict
record; a dirty client preserves its candidate before installing an incoming head.
This is acceptance order, not a claim about which edit happened later. Resolution
creates a new ordinary mutation against the current head and tombstones the
conflict after success; a new race is a new conflict. A delete/edit race preserves
the edit as a candidate without resurrecting a tombstoned record. Alias and trust
conflicts never generate automatic "copy" host entries.

**Sync timing.** Sync explicitly, and once after unlock when configured. There is
no periodic background sync in v1, and a network failure never blocks local SSH
use.

---

## 12. Error codes

Every error response is:

```json
{"error": {"code": "parent_mismatch", "message": "human-readable", "detail": {}}}
```

`code` is stable and machine-readable; `message` is not. `detail` carries
structured context where a client can act on it, and is `{}` otherwise. Some
responses carry additional top-level fields, as noted above for
`parent_mismatch`.

| Code | HTTP | Meaning |
|---|---|---|
| `invalid_request` | 400 | Structurally wrong: missing field, bad type, failed validation |
| `malformed_encoding` | 400 | Bad base64url, bad counter, duplicate JSON key, trailing data |
| `unsupported_version` | 400 | Unknown mandatory `format_version` or `domain` |
| `unknown_suite` | 400 | Suite identifier is not `sshstate.suite.v1`; fails closed |
| `digest_mismatch` | 400 | `Content-Digest` does not match the raw body |
| `id_mismatch` | 400 | Path ID, `Idempotency-Key` and envelope disagree |
| `signature_invalid` | 401 | Signature does not verify, or the profile was not followed |
| `signature_expired` | 401 | Outside the 300 s window plus 60 s tolerance |
| `signature_replayed` | 401 | `(device, nonce)` already seen |
| `device_unknown` | 401 | `keyid` is not in the membership chain |
| `device_revoked` | 403 | Signer was revoked by the chain |
| `not_authorized` | 403 | Authenticated but not permitted for this resource |
| `bootstrap_consumed` | 403 | The one-time secret was already used |
| `not_found` | 404 | No such vault, record, session or envelope |
| `pairing_expired` | 410 | The 10-minute session window has passed |
| `pairing_consumed` | 409 | The session already completed |
| `pairing_incomplete` | 409 | `complete` before both confirmations |
| `parent_mismatch` | 409 | Parent rev or digest is not the current head |
| `idempotency_mismatch` | 409 | Mutation ID reused with different bytes |
| `conflict_content_mismatch` | 409 | A conflict ID exists with differing content |
| `chain_mismatch` | 409 | Membership `chain_seq` or `parent_digest` is not the head |
| `rotation_in_progress` | 409 | Writes are frozen during staging |
| `epoch_mismatch` | 409 | `key_epoch` is not the vault's current epoch |
| `body_too_large` | 413 | Body above 4 MiB, or an envelope above 1 MiB |
| `header_too_large` | 431 | `Signature` or `Signature-Input` above the configured bound |
| `rate_limited` | 429 | Honest-relay throttling |
| `not_implemented` | 501 | A reserved route this relay does not serve |
| `internal` | 500 | Unexpected failure; no detail is disclosed |

`epoch_mismatch` is an amendment to this table, added while specifying rotation.
Most stale writes are already caught as `parent_mismatch`, because rotation
advances every record's `rev`. A record *creation* has no parent digest to
mismatch, so without this code an old-epoch create would be accepted into a vault
that had moved on, and would be undecryptable to every migrated device.

A 431 is deliberately distinct from a 401. An ML-DSA-65 `Signature` header is
4430 bytes, roughly 54% of the 8190-byte single-header limit Apache and nginx
commonly deploy; an operator who has hit a proxy limit must see a size error, not
a signature failure. The header is never truncated to fit.

---

## 13. What this protocol does not promise

A compromised relay can deny service, withhold updates, and maintain isolated
forks that never meet. It cannot substitute enrollment keys without defeating
full-fingerprint verification, forge an authorized writer's signature, or alter an
authenticated record field undetectably.

`seq` is transport bookkeeping, not trusted time. A recovery kit without a recent
export has no recent checkpoint, so it cannot prove the relay supplied the latest
vault. Clients detect observed regressions; no part of this protocol claims
globally complete freshness.

---

## Local control protocol

Separate from this protocol and versioned independently: HTTP/JSON over a Unix
socket, bounded request sizes, no TCP listener, no request-body logging. The SSH
agent socket never exposes administrative operations.
