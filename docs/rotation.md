# Master-key rotation — staged transition and recovery

Status: **specified, not implemented, and not scheduled.** This document was
written at Milestone 2 because the relay's transactions, the freeze semantics
and the sync reader all have to accommodate it from the start; a rotation bolted
onto storage that never anticipated it cannot be made atomic afterwards.

Section references in the form §x.y are to `docs/project-brief.md`.
`docs/protocol.md` is the frozen wire specification this extends.

---

## 1. What rotation is

`rotate-master-key` replaces the vault's metadata and secret keys with fresh
random values and increments the key epoch. It is **not**:

- changing a local unlock password, which rewraps local secrets only and touches
  no vault key;
- remote SSH host-key rotation, which stays manual;
- a way to undo a compromise of the SSH private keys themselves. Those must be
  replaced at their destinations. New vault keys protect new ciphertext; they do
  nothing for a key an attacker already read.

Rotation is also the mechanism for a suite change (§4.8): a new suite is an epoch
transition, never an in-place substitution.

## 2. The shape of the problem

A naive rotation re-encrypts each record in turn. Halfway through, the vault
holds two epochs at once, every reader sees an inconsistent mixture, and a crash
leaves no defined state to resume from.

So rotation is **staged**: everything is uploaded first and nothing is visible,
then one commit makes the whole transition current atomically. Three properties
follow, and everything below exists to hold them:

1. **No mixed-epoch publication.** A reader sees the old snapshot or the new one.
2. **No new key material to a revoked device**, even if that device retries a
   session that was valid when it started.
3. **No lost offline work.** A device that was offline throughout keeps its
   pending edits and replays them after catching up.

---

## 3. Preconditions

Before creating a rotation, the initiating device must, in this order:

1. Sync to the relay's current head and establish the epoch, the full accepted
   head map, and the membership head.
2. Resolve membership divergence. A rotation that starts from a contested
   membership chain cannot decide who the recipients are.
3. **Revoke excluded devices first.** Recipients are chosen from the membership
   chain as it stands when the rotation is created. Revoking after staging would
   mean a revoked device already has a bundle.
4. Preserve pending local edits as encrypted outbox candidates. They are not
   uploaded; they are replayed after the transition (§8).

The relay permits **one active rotation per vault**. A second `POST /v1/rotations`
while one is staging is rejected with `rotation_in_progress` and the response
carries the active rotation so the caller can inspect or abort it.

---

## 4. Server state machine

```
                POST /v1/rotations
       (none) ─────────────────────────▶ staging
                                            │
                     PUT …/staged/:item     │  (idempotent, repeatable)
                            ┌───────────────┤
                            └──────────────▶│
                                            │
              POST …/commit                 │            DELETE /v1/rotations/:id
        ┌───────────────────────────────────┤───────────────────────────┐
        ▼                                   ▼                           ▼
    committed                          (rejected:                    aborted
    (terminal)                      incomplete staging,             (terminal)
                                   stale preconditions)
                                            │
                          staging timeout   │
                                            └──────────────▶ aborted
```

`staging` is the only state that accepts writes to the rotation. `committed` and
`aborted` are terminal: a committed epoch cannot be un-committed, and an aborted
rotation ID is never reused.

### 4.1 Write freeze

While a rotation is `staging`, the relay rejects:

- `PUT /v1/records/:id` — `rotation_in_progress`
- `POST /v1/membership` — `rotation_in_progress`

Reads continue and are served **from the previous committed snapshot**. Staged
replacements are not visible to `GET /v1/records` at any cursor, and
`snapshot_cursor` never advances past the pre-rotation head while staging.

The freeze is an honest-relay behaviour, not a security control. A hostile relay
can accept writes it should have frozen; clients detect the result through
ordinary parent-digest and epoch checks.

### 4.2 Staging timeout

A staging rotation that receives no successful request for
**`rotation_staging_timeout` (default 24 hours)** is aborted by the relay, which
releases the freeze. The window slides on each accepted staged item.

Without this, an initiator that dies mid-rotation freezes the vault until a human
intervenes. With it, the worst case is one day of refused writes.

### 4.3 Abort

**Recorded amendment to §5.5.** The frozen route list has no abort route, but
§7.1 requires that "an explicit authenticated abort can discard staging and
release the write freeze". `DELETE /v1/rotations/:id` is added for it. It is a
new method on an existing path rather than a new path.

Abort is accepted from **any** currently authorized device, not only the
initiator. §7.1 is explicit that a remaining device must be able to clear a
stranded pre-commit operation when the initiator is lost — which is precisely the
case where the initiator cannot ask.

Aborting a `committed` rotation is refused with `invalid_request`, and the
response body carries the rotation object showing `committed`, so the caller
learns the real state from the same round trip rather than having to ask again.

---

## 5. Objects

### 5.1 Staged items

Each staged item has a name that is stable across retries, so a resumed rotation
can ask what is already uploaded rather than re-deriving an ordering:

| Item name | Content |
|---|---|
| `record:<record_id>` | the replacement record envelope, re-encrypted under the new epoch |
| `bundle:device:<device_id>` | the age-sealed key bundle for one non-revoked device |
| `bundle:recovery` | the age-sealed key bundle for the current recovery recipient |

Every current record is replaced: live records, retained conflict records,
tombstones, and revoked-host trust records. A tombstone is re-encrypted like any
other record — its payload is an encrypted empty object, and leaving it at the
old epoch would make the one record type an attacker most wants to suppress the
one record type readable with an old key.

Each replacement increments its record's `rev`, names the previous envelope's
digest as its `parent_digest`, carries `key_epoch` of the **new** epoch, a fresh
nonce, and is signed by the initiator.

### 5.2 Rotation bundles

A rotation bundle is a §6.2 bundle with `purpose: "rotation"`, extended with the
epoch history:

```json
{
  "domain": "sshstate.bundle.v1",
  "format_version": 1,
  "suite": "sshstate.suite.v1",
  "vault_id": "<id>",
  "genesis_digest": "<sha256-base64url>",
  "purpose": "rotation",
  "recipient_device_id": "<id>",
  "recipient": "age1pq1...",
  "key_epoch": "2",
  "metadata_key": "<32-bytes-base64url>",
  "secret_key": "<32-bytes-base64url>",
  "transcript_digest": null,
  "checkpoint": { ... },
  "snapshot_digest": null,
  "snapshot_length": null,
  "rotation_id": "<id>",
  "epoch_history": [
    {"key_epoch": "1", "metadata_key": "<32-bytes-base64url>", "secret_key": "<32-bytes-base64url>"}
  ],
  "created_at": "2026-09-12T00:00:00Z"
}
```

**`epoch_history` carries every epoch from 1 to `key_epoch - 1`, always.**

The alternative is to send each device only the epochs it is missing, which
requires the initiator to know what each device already holds — and it cannot
know that for a device that has been offline for months. Sending everything makes
an offline device's catch-up correct by construction. The cost is bounded and
small: 64 bytes per epoch, so a vault rotated a hundred times carries 6.4 KB,
against a 1 MiB bundle limit.

Retained history stays readable because of this, which is the point: old log
entries are not re-encrypted in place, and a device that could no longer decrypt
them could no longer verify the chain it already accepted.

A bundle is **never staged for a revoked device**, and the relay rejects a
`bundle:device:<id>` naming one. The recipient list is fixed when the rotation is
created, from the membership chain at that moment.

### 5.3 Transition manifest

```json
{
  "domain": "sshstate.rotation.v1",
  "format_version": 1,
  "suite": "sshstate.suite.v1",
  "vault_id": "<id>",
  "genesis_digest": "<sha256-base64url>",
  "rotation_id": "<id>",
  "from_epoch": "1",
  "to_epoch": "2",
  "initiated_by": "<device-id>",
  "created_at": "2026-09-12T00:00:00Z",
  "preconditions": {
    "membership_digest": "<sha256-base64url>",
    "checkpoint_digest": "<sha256-base64url>",
    "seq": "441"
  },
  "items": [
    {"name": "record:2222…", "digest": "<sha256-base64url>", "length": "1184"},
    {"name": "bundle:device:4444…", "digest": "<sha256-base64url>", "length": "2043"},
    {"name": "bundle:recovery", "digest": "<sha256-base64url>", "length": "2043"}
  ]
}
```

Signed under `sshstate.rotation-sig.v1` by the initiating device. `items` is
sorted by `name`, so one staging set has one manifest encoding.

`preconditions.checkpoint_digest` is the digest of the §6.1 checkpoint describing
the head map the replacements were derived from. `membership_digest` is the
membership head at that moment. Together they say: *this transition is valid only
from exactly this state.*

`to_epoch` is always `from_epoch + 1`. Rotation never skips an epoch, so an
epoch number is a count of transitions and not merely an ordering.

---

## 6. Commit

`POST /v1/rotations/:id/commit` carries `{"manifest": {...}, "signature": "..."}`.

The relay commits only if **all** of the following hold:

1. The rotation is `staging`.
2. The manifest's signature verifies under the initiator's chain key, and the
   initiator is still authorized.
3. `rotation_id`, `from_epoch`, `to_epoch`, `vault_id` and `genesis_digest` match
   the rotation as created.
4. The staged set matches `items` **exactly**: every named item is present with
   the named digest and length, and there is nothing staged that the manifest does
   not name. An extra staged item is a rejection, not something to ignore.
5. Every current record in the head map has a `record:` replacement, and every
   non-revoked device plus the recovery recipient has a bundle. A partial
   transition is never committable, only abortable.
6. The preconditions still hold: `membership_digest` is still the membership head
   and `checkpoint_digest` still describes the current head map. Since writes are
   frozen this normally holds trivially; it is checked anyway, because "normally"
   is not a property.

Then, in **one** transaction: append every replacement to the accepted log with
fresh `seq` values, update every head, store the bundles, set the vault epoch to
`to_epoch`, record the transition, and mark the rotation `committed`.

Commit is idempotent. Committing an already-committed rotation with the identical
manifest returns the original outcome. A different manifest for the same rotation
ID is `idempotency_mismatch`.

### 6.1 Old-epoch writes after commit

**Recorded amendment to §12.** A new error code, `epoch_mismatch` (HTTP 409), is
added.

Most stale writes are caught without it: every record's `rev` advanced during
rotation, so an old-epoch update's `parent_digest` no longer matches and
`parent_mismatch` falls out naturally, carrying the current head so the client can
re-encrypt. But a **creation** has no parent to mismatch. A record created at
`rev` 1 under the old epoch would otherwise be accepted into a vault that has
moved on, and would be undecryptable to every device that has migrated.

So the relay rejects any record whose `key_epoch` is not the vault's current
epoch with `epoch_mismatch`, and the response carries the current epoch. A
`key_epoch` *above* the current epoch is rejected by the same check: a client
cannot announce an epoch the vault has not transitioned to.

---

## 7. Client state machine

The client keeps a durable, encrypted rotation journal. Every state below is
written to disk **before** the action that leaves it, so a crash is always
recoverable to a known point.

```
 planning ──▶ staging ──▶ staged ──▶ committing ──▶ committed ──▶ finalizing ──▶ finalized
     │            │           │           │
     └────────────┴───────────┴───────────┴──▶ aborting ──▶ aborted
                                    (only before the relay commits)
```

| State | Durable before entering | Resume action |
|---|---|---|
| `planning` | rotation ID, new keys, preconditions, item list | re-derive replacements; nothing was sent |
| `staging` | rotation created on the relay | ask the relay which items exist; upload the rest |
| `staged` | every item uploaded, manifest signed | re-send commit |
| `committing` | commit request sent, outcome unknown | **ask the relay** (§7.1) |
| `committed` | relay confirmed the transition | continue local finalization |
| `finalizing` | new keys installed locally, migration in progress | finish migration, replay candidates |
| `finalized` | local state consistent at the new epoch | none; discard the journal |

### 7.1 The committing state

`committing` is the only genuinely ambiguous state: the request was sent and the
response was lost, so the client does not know whether the epoch advanced.

It is never resolved by guessing, and never by retrying blindly into a different
outcome. `rotation resume` issues `GET /v1/rotations/:id` and believes the answer:

- `committed` → move to `committed` and finish locally.
- `staging` → the commit never landed; re-send it. Commit is idempotent, so a
  duplicate that did land returns the same outcome.
- `aborted` → another device cleared a stranded rotation. Discard the staged
  work, keep the preserved candidates, and report it.
- not found → the relay lost it or is not the relay we staged to. Refuse to
  proceed and surface it; this is not a state to recover from automatically.

### 7.2 Local finalization

After a confirmed commit, while **both** key sets are still in memory:

1. Install the new keys and the signed checkpoint.
2. Re-encrypt local pending candidates under the new epoch.
3. Replay those candidates through ordinary conflict detection, against the new
   head map, with fresh mutation IDs wherever the context changed — a mutation ID
   identifies a specific envelope, and a re-encrypted candidate is a different
   envelope.
4. Only then discard the journal. Retaining it until local recovery is confirmed
   is what makes step 2 restartable.
5. Produce a fresh recovery export. The previous export is at the old epoch, and
   §7.2 of the brief is explicit that a stale backup cannot establish later
   freshness.

`rotation status` distinguishes **staging**, **committed** and **locally
finalized**. The distinction is not cosmetic: a vault can be committed on the
relay and unfinalized locally, and a user who cannot see that difference cannot
tell a stuck rotation from a finished one.

---

## 8. Devices that were offline

A remaining device need not be online for any of this. On its next unlock or
reconnect it:

1. Fetches its `bundle:device:<id>` from `GET /v1/envelopes`.
2. Verifies the bundle's signature against the initiator's key **from the
   membership chain**, and checks that `recipient` is its own.
3. Verifies the transition manifest and every replacement digest before advancing
   its epoch. A client that advanced first and verified afterwards would have
   published state it had not checked.
4. Installs `epoch_history` so retained history stays verifiable.
5. Migrates its own pending edits to the new epoch and replays them, exactly as
   in §7.2.

Its old-epoch writes are rejected (§6.1) until it does this, which is the intended
prompt rather than a failure.

---

## 9. Reader rules

- A client rejects an epoch regression: once it has accepted epoch *n*, a
  checkpoint or record at an epoch below *n* is a rollback attempt, not news.
- Pagination cannot expose a partial rotation. The commit assigns every
  replacement `seq` inside one transaction, and `GET /v1/records` pins
  `snapshot_cursor` on the first page, so a snapshot contains all of a commit or
  none of it.
- A client verifies the manifest **and every replacement** before advancing its
  epoch or publishing generated SSH configuration. If the snapshot is incomplete
  or inconsistent, it keeps the previously generated state rather than writing a
  partial one.

---

## 10. Limits

Rotation cannot erase old ciphertext, and the retained accepted log and any
backups still contain old-epoch ciphertext by design. An attacker who captured
ciphertext before the rotation keeps it, and now holds the old keys' plaintext if
they ever had them.

New vault keys do not revoke a stolen SSH private key. Replace the affected
credentials at their destinations.

If the **recovery kit** is compromised, rotating vault keys while keeping the same
recovery recipient protects nothing: the kit's recipient receives the new bundle
too. v1's containment for that case is a fresh vault and kit, a reviewed
migration, and SSH credential replacement. Preserve the old evidence and backups
rather than deleting them during that migration.

A hostile relay can still withhold the transition or fork history, within the
limits §4.3 already states. Rotation narrows what a *future* reader of stolen
ciphertext can do; it does not change what the relay can do today.

---

## 11. Recorded amendments

Both are amendments to `docs/protocol.md`, made here because specifying rotation
is what revealed them. §12 of the brief anticipates exactly this.

| Amendment | Reason |
|---|---|
| `DELETE /v1/rotations/:id` added to the §5.5 route list | §7.1 requires an explicit authenticated abort; the frozen list had no route for it |
| `epoch_mismatch` (409) added to the §12 error table | a record *creation* has no parent digest to mismatch, so nothing else rejects an old-epoch create |

A third amendment, unrelated to rotation, is recorded in `docs/protocol.md` §8:
an export carries the vault keys in a `bundle.json` member.
