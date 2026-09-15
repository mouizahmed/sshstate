# sshstate — Project Brief

> Open-source, self-hostable, CLI-first synchronization for an SSH environment.
> Status: pre-build. v1 architecture decisions accepted on 2026-09-12; implementation and protocol verification remain to be done.
> Last updated: 2026-09-12
>
> This revision replaces the earlier alternatives with decisions. §12 records their rationale. Imported from the working brief in Downloads; future project amendments belong in this repository copy. The historical pre-decision draft remains in Downloads and is not part of this repository. This is an implementation plan, not a claim that the design or code has been independently audited.

## 1. Problem and product boundary

Make a user's managed SSH hosts, connection options, trusted host keys, and credentials available across machines, including headless systems. Keep native OpenSSH, scp, and editor integrations working.

sshstate is not a terminal or an SSH transport implementation. OpenSSH owns the connection, key exchange, and authentication exchange; sshstate supplies configuration and agent signatures. There is no `sshstate ssh` command.

“Identical environment” means identical values for the fields sshstate manages. Unmanaged machine preferences can differ; accumulated OpenSSH identities and command-line overrides remain outside that guarantee.

## 2. Why this exists

The product focus is structured SSH environment synchronization: aliases, users, ports, jump-host relationships, ordered key references, and host trust travelling together. Key storage alone is insufficient justification.

Password managers and encrypted dotfile tools are adjacent solutions. Avoid unsupported claims that none support headless operation, conflict handling, or configuration synchronization. Verify any feature comparison before publishing it.

For “doesn't Bitwarden already do this?”, the distinction is the intended workflow: Bitwarden documents an SSH agent in its desktop application for authentication and Git signing; chezmoi documents age-encrypted file management. sshstate combines structured host definitions, ordered key references, explicit host-trust decisions, and a headless agent in one synchronization workflow. These sources establish adjacent capabilities, not proof that either product cannot be extended to cover a use case. Recheck this paragraph before release. Sources checked 2026-09-12: [Bitwarden SSH agent](https://bitwarden.com/help/ssh-agent/), [chezmoi age integration](https://www.chezmoi.io/user-guide/encryption/age/).

v1 is single-user, self-hosted, CLI-first, with no telemetry. Tunnels, reverse proxies, and VPNs are deployment choices. The client consumes an HTTPS URL and does not implement a tunnel service, identity-based certificate issuer, team system, or generic secrets manager.

## 3. Native SSH integration

### 3.1 CLI surface and local-first operation

A vault can be created and used before a server exists.

```text
sshstate init
sshstate unlock
sshstate add-key /path/to/key
sshstate add prod
sshstate import /path/to/config --dry-run
sshstate install
sshstate status
sshstate doctor
sshstate lock

sshstate connect https://sync.example.com
sshstate pair
sshstate devices
sshstate revoke <device-id>
sshstate sync
sshstate conflicts
sshstate resolve <conflict-id>
sshstate export /path/to/backup.age
sshstate restore /path/to/backup.age
sshstate recover
sshstate rotate-master-key
sshstate rotation-status
sshstate rotation-resume
sshstate uninstall
sshstate uninstall --purge
```

These are the command boundaries; individual flags are specified alongside implementation. Verb shape — flat verbs, positional subjects, prefix matching — is decision record 0003, which amends this list. Passwords, recovery secrets, and bootstrap secrets are read from a protected terminal or explicitly supplied file descriptor, never required as command-line arguments.

The post-v1 Git integration adds `sshstate git-sign -- <ssh-keygen arguments>` (§3.5).

**Withdrawn on 2026-09-15: `sshstate tui`.** A focused TUI was a v1 requirement (R11). It is now out of v1 scope entirely, not deferred pending a frontend: the CLI is the interface. Everything the TUI was to provide — host browsing, key references and fingerprints, lock and sync status, conflict review and resolution, rotation progress — must therefore be legible from the CLI, which is where that obligation now sits.

### 3.2 Config ownership, generation, and import

Ordinary generation writes only under `~/.ssh/sshstate/`. Explicit installation adds one marked Include at the top of `~/.ssh/config`; uninstall removes only that exact managed entry. Preserve all other bytes, check for concurrent changes, reject symlink surprises, and make a recoverable backup before an installer edit.

Before activating that Include, installation previews existing known_hosts entries matching managed destinations (including non-default ports and matchable hashed entries) and offers explicit import. Show fingerprints, trust markers, conflicts, and entries that cannot be matched confidently; never silently discard or reinterpret them. The user chooses to import the reviewed entries, continue without import, or cancel. Explain that continuing without import may prompt again for previously trusted hosts because the generated UserKnownHostsFile does not include the original user file. Noninteractive installation requires an explicit trust-import or skip choice. Publish selected trust before activating the Include, preserve the source file, and leave the Include inactive if import validation fails. This initial trust-import path is part of M1; continuous reconciliation follows in M3.

```sshconfig
Include ~/.ssh/sshstate/config
```

Generate complete values for managed connection fields: HostName, User, Port (22 when omitted in a newly created record), ProxyJump (none when absent), ordered IdentityFile entries, IdentityAgent, IdentitiesOnly, ForwardAgent, and the managed host-trust policy. Resolve an omitted new-host User to the creating machine's username once and store it; do not reinterpret it on every device. Other options inherit local OpenSSH settings in v1. Do not freeze all OpenSSH defaults.

```sshconfig
Host prod
    HostName 10.0.0.5
    User ubuntu
    Port 22
    ProxyJump none
    IdentityAgent ~/.ssh/sshstate/agent.sock
    IdentityFile ~/.ssh/sshstate/public/prod-01-<fingerprint>.pub
    IdentitiesOnly yes
    ForwardAgent no
    StrictHostKeyChecking ask
    UpdateHostKeys no
    UserKnownHostsFile ~/.ssh/sshstate/known_hosts.capture ~/.ssh/sshstate/known_hosts
```

IdentityFile directives accumulate; IdentitiesOnly does not erase identities configured elsewhere. No reset directive is assumed. `doctor` uses explicit `ssh -G <alias>` inspection to report effective managed-field mismatches and extra identities. It explains that inspecting an existing config can evaluate its Match exec commands. Import parsing itself never executes config commands. Validate generated configurations in an isolated fixture and verify authentication against a test SSH server.

v1 imports a strict subset: literal single-alias Host blocks, HostName, User, Port, a single literal ProxyJump alias or none, and repeated IdentityFile paths. Resolve supported omitted defaults into stored values. Reject wildcard/negated/multiple Host patterns, Match, nested Include, unknown directives, executable directives, certificates, and unsupported tokens with line-specific diagnostics. Validate the whole input before committing; no partial import. Users can prepare a supported extract. Broader fidelity-preserving import is deferred.

Repeated import of the same normalized alias and same effective definition is a no-op. A differing definition becomes an explicit conflict without overwriting the existing host. Use ordered `key_ids`; deduplicate keys by public-key fingerprint. Alias rules: lowercase ASCII letters/digits plus dot, underscore, and hyphen; start with a letter/digit; maximum 64 characters; reject case-normalization collisions. Public filenames use that validated alias, a stable key slot, and the full public-key SHA-256 digest in hexadecimal (the config example abbreviates it). Key replacement gets a new filename so in-flight readers retain the old public key. Detect dangling references and jump cycles before generation.

Publish referenced public-key files first, then atomically replace the config with temp-file + fsync + rename + directory fsync where supported. Keep obsolete public files through the current daemon lifetime so an in-flight SSH reader is not broken. Private keys are never generated as plaintext files.

### 3.3 Agent, daemon, and local control

One per-user daemon exclusively owns SQLite access, vault mutations, unlocked keys, synchronization, and generated files. The CLI is a client of a separate versioned local control protocol over `control.sock`; the SSH agent protocol uses `agent.sock`. Never expose administrative operations on the agent socket.

The v1 reason to own the agent is control over decrypted-key lifetime and signing availability, keeping private keys out of plaintext files, and leaving the user's global agent selection alone. Automatic prompt-on-sign is deferred and must not lead the v1 README or demo.

Private directories use mode 0700; database, generated metadata files, and sockets use 0600 where applicable. Check peer user identity on both sockets. Same-user malicious processes remain in the threat model's trusted-endpoint boundary; socket permissions cannot distinguish them from the CLI.

Use HTTP/JSON over the control Unix socket with bounded request sizes, no TCP listener, and no request-body logging. Unlock uses a dedicated request, not a URL/query parameter. Version this protocol independently from server sync.

Use upstream Go agent protocol support with a restricted implementation: list public identities and sign while unlocked; reject adding/removing keys and other mutations through the agent protocol. Support modern RSA signature flags as well as Ed25519 and ECDSA. While locked, report no identities and refuse signing. Stock SSH sees generic failure; `status` and `doctor` provide the unlock instruction.

Explicit unlock is v1. Idle expiry is 15 minutes, refreshed by successful signing or explicit interactive vault operations; background work and status polling do not refresh it. Hard expiry is 8 hours from password entry. Check expiry before every secret operation. Explicit lock prevents new operations, drains already admitted operations before acknowledging, then drops key references and wipes owned buffers. Already emitted signatures cannot be recalled.

Use launchd named socket activation on macOS via its activation API, and systemd user socket activation with named inherited descriptors on Linux. Provide both sockets. Service-manager lifetime is the user session unless configured otherwise; do not claim boot-time availability for every account. Never assume launchd uses systemd's FD-3 convention. Crash restart starts locked. Provide a foreground daemon mode for development and headless environments without a supported service manager, with an exclusive instance lock and safe socket ownership checks.

### 3.4 Known-host trust and file ownership

Use two files: OpenSSH owns `known_hosts.capture`, listed first; the daemon owns the generated `known_hosts`, listed second. The daemon never rewrites or truncates the capture file during normal operation. This removes the daemon-versus-OpenSSH overwrite race, not races between multiple OpenSSH processes or all reconciliation hazards. Verify first-file append behavior, concurrent first-use accepts, file replacement detection, and incomplete-line handling on supported versions with integration tests. Do not infer safety from the ownership split alone.

Capture applies to managed aliases. Ad-hoc unmanaged destinations do not automatically join the vault. The user's original known_hosts file remains untouched; importing its trust is an explicit action. OpenSSH system-wide trust sources can still apply and are reported by doctor.

Explicitly set UpdateHostKeys no for v1. Custom UserKnownHostsFile changes its default anyway; automatic rotation and capture-file compaction are deferred. A host-key change requires explicit trust review. Successful verification against a previously trusted key is distinct from accepting a new TOFU key.

Watch the capture file as a hint; rescan on unlock, before sync, and after changes while unlocked. Retain an encrypted local baseline. Locked operation leaves observations in that already-public local file until unlock; it does not encrypt or sync metadata. Incomplete lines are retried. Capture-file removal alone never becomes a synced deletion.

Represent each observation with an opaque random record ID and preserve the original known_hosts line, including markers and hostname tokens. Parsed data includes key type and key fingerprint. Exact duplicate lines deduplicate by a canonical full-line digest, not by (hostname, keytype). Multiple keys of one algorithm are allowed. Match salted hashes against known candidate destinations using established parsing/matching code; unknown hashed destinations remain opaque and no semantic deduplication is claimed. Preserve @revoked and @cert-authority semantics; do not flatten them into ordinary trust.

A changed or conflicting trust decision is retained as a pending candidate and does not replace approved trust. Explicit conflict/trust resolution is required before publishing that candidate. Initial imports and locally accepted first-use keys can sync as approved observations; a compromised authorized endpoint can therefore still poison trust. Conflict handling is not a defense against an authorized malicious writer.

Trust removal uses an explicit signed `revoke` update producing a retained @revoked record, not a tombstone that silently drops a generated line while an old copy remains in capture. Generic deletion of known_host records is rejected in v1. Apply revocation for all represented matching tokens and verify with OpenSSH that a retained capture entry cannot override it. A key already stored under unknown salted tokens on an unseen destination cannot be claimed revoked there without identifying that destination; surface that limit during review.

### 3.5 Git signing — post-v1 integration

Use a small `sshstate git-sign` helper configured through repository-local `gpg.ssh.program`. It forwards arguments and exit status to the system ssh-keygen and sets SSH_AUTH_SOCK only for that child. It never implements signatures itself and never changes the shell's global agent environment. Set gpg.format=ssh and user.signingkey to a managed public-key path. Installation into a Git repository is explicit. Test signing and verification before advertising support.

This design is accepted, but the helper does not gate the core v1 release. Implement it after the three-machine SSH workflow is complete.

### 3.6 Uninstall

Stop/unregister the service and remove the exact managed Include and runtime integration files. Preserve the encrypted vault and capture file by default. `sshstate uninstall --purge` additionally requires the exact vault target and export confirmation; it never deletes the user's source private keys, SSH config, or original known_hosts. Normal uninstall ships in M1. Enable purge only once export/restore is verified in M2; earlier builds reject that flag without deleting data.

Once a vault is connected to a relay, uninstall also offers server-side deregistration: publish a signed revocation for this device before removing local integration, so a decommissioned machine does not remain an authorized writer in the membership chain. Deregistration requires unlock and a reachable relay. When either is unavailable, complete the local uninstall, state plainly that the device remains authorized, and direct the user to `sshstate revoke <device-id>` from another device. Never skip deregistration silently or report success for a revocation the relay did not accept. Deregistration ships with the M2 revocation work; M1 uninstall is local-only because no relay exists yet.

## 4. Cryptographic architecture

### 4.1 Keys, envelopes, and password scope

Each vault has independent random 256-bit metadata and secret keys, plus a monotonically increasing key epoch starting at 1. Host, known_host, and metadata conflict payloads use the metadata key; private-key payloads and private-key conflict copies use the secret key.

Each device has separate signing and recipient-encryption key roles, using independent keypairs with no cross-algorithm conversion: ML-DSA-65 for signatures and an age hybrid (ML-KEM-768 + X25519) identity for recipient encryption. The §4.8 assessment is complete and this suite is adopted for v1; see decision record 0001. Devices receive vault keys in signed recipient-encrypted bundles.

The password is a **local device unlock password**, not a server account password or a vault recovery factor. Different devices may use different passwords. Argon2id derives a local KEK that encrypts the local device secrets and vault keys. Changing that password rewraps local secrets only.

The server never receives password-wrapped keys, password verifiers, local KDF headers, or device private keys. A server dump plus a device's unlock password is insufficient to decrypt the vault. A stolen local database remains an offline password-guessing target.

### 4.2 Primitive and encoding choices

- Local KDF: Argon2id v19, 16-byte random salt, 32-byte output, default 64 MiB memory, 3 iterations, 4 lanes. Store parameters locally per wrapper. This selects RFC 9106's lower-memory profile; do not silently weaken it on small machines.
- Local wrappers and records: XChaCha20-Poly1305, 32-byte keys, fresh 24-byte crypto/rand nonce for every encryption, including retries that change plaintext or context.
- Device/recovery bundles and encrypted exports: age v1 hybrid recipient encryption (ML-KEM-768 + X25519) using filippo.io/age v1.3.2 or later. Age's internal algorithms are defined by age, not replaced with the record AEAD. Never wrap a hybrid recipient in a type that hides WrapWithLabels; age's postquantum label is what prevents a classical recipient riding along, and a test must assert the mixed-recipient rejection still holds.
- Signatures: ML-DSA-65 (FIPS 204) through Go standard `crypto/mldsa`, 32-byte seed private keys, using Options.Context for domain separation. Hashes: SHA-256. `crypto/mldsa` is unavailable under FIPS 140-3 Go Cryptographic Module v1.0.0; require v1.26.0 or later and fail clearly rather than falling back to a classical algorithm.
- Canonical signed/AAD objects: RFC 8785 JSON Canonicalization Scheme through a conforming implementation, with golden vectors. No delimiter-concatenation format.
- Binary JSON fields: base64url without padding. Unsigned counters are decimal strings without leading zeros, avoiding cross-language JSON number precision issues.
- IDs: random 128-bit values represented as lowercase hexadecimal; no host/key type prefix in IDs.

Reject duplicate JSON keys, unknown mandatory format versions, malformed encodings, and oversized objects. v1 local KDF readers bound allocation to 1 GiB, iterations to 10, and lanes to 16; unsupported headers fail clearly rather than allocate without limit. Writers use the specified default until an explicit migration changes it.

Use maintained libraries and pinned dependencies. Composing reviewed primitives does not make the sshstate protocol independently audited.

### 4.3 Authenticated envelopes and freshness

Record AAD is the JCS encoding of the full `context` object in §5.2. It binds a protocol domain, format, vault/record IDs, rev, parent digest, record type, epoch, mutation ID, writer device ID, and deletion flag. A plaintext deleted flag is acceptable because it is authenticated; clients verify before applying it.

A persistent ML-DSA-65 signature covers a separate domain plus context, nonce, and ciphertext. This binds writer identity after the HTTP request is gone. Define the record digest as SHA-256 of that canonical signed envelope, excluding server seq. The server can validate signatures and shape without interpreting SSH payloads.

Persist each observed record head, digest, tombstone, and highest known epoch transactionally. Reject a lower revision, a different digest at an already observed revision, or a broken parent chain. Sync uses an append-only change log so clients can verify intermediate revisions. Store signed device authorization events rooted in the first device; each membership event references its predecessor digest.

Enrollment transfers the approving device's complete accepted record snapshot, trusted head map, membership chain, epoch, and cursor inside the signed encrypted bundle. Pending edits remain outbox candidates and are not mislabeled as accepted heads. B validates and installs the snapshot with that checkpoint before resuming incremental sync. A fresh client must reach at least that checkpoint before publishing server-fetched state. Exports carry the exporting client's checkpoint.

Limits are explicit: a server can withhold updates, deny service, or maintain forks that never meet. The seq is transport bookkeeping, not trusted time. A recovery kit without a recent export has no recent record checkpoint, so it cannot prove the server supplied the latest vault. Detect observed regressions; do not claim globally complete freshness.

### 4.4 Local secret handling and storage

Use `$XDG_DATA_HOME/sshstate` or `~/.local/share/sshstate` on both supported platforms for a consistent documented layout. SQLite stores ciphertext, the self-describing local wrapper header, public membership information, encrypted pending operations/conflicts, and cursors. Secret plaintext is never passed into SQL, including SQLite journals/WAL or temporary tables.

Store local KDF salt, parameters, format version, wrapper nonce and ciphertext together. Authenticated local wrapper context binds its format, vault/device IDs, and KDF header. Startup and unlock work entirely offline.

Both device private keys are encrypted under the local KEK. Sync and reconciliation require unlock. Sync explicitly and once after unlock when configured; no periodic background sync in v1. Network failure never blocks local SSH use.

Keep parsed signers in daemon memory only while unlocked. Wipe owned mutable buffers on lock/exit, avoid secret strings and logs where APIs permit, disable core dumps where supported, and use restrictive file permissions. Go cannot guarantee erasure of every library/runtime copy or prevent privileged memory inspection or all swap exposure. memguard and OS keychain integration are deferred. Do not claim a moving Go heap GC or complete zeroization.

### 4.5 Pairing and device authorization

Choose out-of-band verification of a **full SHA-256 transcript fingerprint**, not a six-digit pairing code or a new PAKE. Both devices must have a trusted display/terminal. A relay locator only routes messages; its secrecy is not the authentication mechanism.

Display all 32 digest bytes as uppercase RFC 4648 base32 without padding: 52 characters, arranged into 13 numbered groups of four. Display every group without ellipses or collapsed content, using the same layout on both devices. Instruct the user to compare all 13 groups; comparing only the beginning or end is insufficient. Group numbers are presentation only, and the last symbol's unused padding bits must be zero. The signed transcript and digest bytes are unchanged by this encoding. This improves readability but does not eliminate human comparison errors. Include full-length encoding and last-group mismatch tests in the pairing vectors.

1. B generates its signing and encryption keys, a random 256-bit challenge, and a self-signed enrollment offer.
2. Unlocked A generates its own fresh challenge and a transcript containing the protocol version, vault ID, both device IDs and both pairs of public keys, both challenges, and a 10-minute session lifetime. Both devices display the full 256-bit SHA-256 fingerprint of the identical canonical transcript.
3. The user compares the full fingerprints through a channel independent of the relay and explicitly confirms on both devices. Do not send vault secrets or finalize membership before confirmation. Replacing keys or restarting the attempt invalidates confirmation.
4. Both devices sign their confirmation of that transcript. A signs the membership authorization and the vault-key/checkpoint bundle; encrypt the bundle to B using age. Include the transcript digest, recipient IDs, and epoch inside the signed content.
5. B verifies A against the confirmed transcript, decrypts, validates the bundle and membership chain, persists it under its own local password, then signs an acknowledgement.

age provides recipient confidentiality, not sender authentication; the signatures and verified transcript supply the latter. Self-signing an offer alone never authorizes a device. Accepted session IDs/challenges are persisted to prevent repeated completion. Each endpoint enforces its own 10-minute elapsed timeout. Honest servers allow one active attempt per pending device and rate-limit offers; cryptographic safety does not depend on a hostile server enforcing those limits.

Write the exact transcript schema and adversarial test vectors before implementing this application-level protocol. This selects the mechanism; it does not label the custom composition an established audited pairing protocol.

### 4.6 Bootstrap and recovery kit

Local init creates the vault keys, first-device keys, and the immutable genesis document. Generate an offline recovery kit containing an independent age hybrid secret identity, an independent ML-DSA-65 recovery signing seed, vault ID, genesis digest, and format/checksum. Both secrets are short: the hybrid identity encodes to 77 characters and the signing seed to 32 bytes. The ~1959-character hybrid public recipient is derived from the identity, pinned by genesis, and never transcribed by the user. This is one kit with two independent key roles, not a human-chosen password. The kit's public encryption recipient and signing key are pinned by genesis. Do not retain the recovery private keys in ordinary local or server storage after the user saves and verifies the kit.

Store an age-encrypted vault-key bundle for the recovery recipient on the server. All key bundles are signed by an authorized device and bind genesis, vault ID, recipient, format, and epoch; encryption to a public recipient alone is not proof of origin. Ordinary devices retain the recovery public recipient so future exports can target it. Recovery signing authority can authorize a replacement device through a signed membership event; reading an encrypted envelope alone must not grant write access. Restoring with the kit pins genesis and verifies the membership chain. Explicit recovery can use a local export if the relay is unavailable.

For server setup, use a 256-bit one-time bootstrap secret in an operator-supplied mounted secret file. Store only its hash after initialization, consume it atomically when creating the single account, and disable bootstrap permanently thereafter. No open registration and no secret in routine logs. Connecting an existing local vault uploads genesis, public membership, ciphertext, and device/recovery recipient envelopes; it does not regenerate the vault.

Recovery admission proves possession of the genesis-pinned recovery signing key and signs a fresh server challenge plus the replacement device keys and vault ID. Nonces expire after 10 minutes and are consumed once on an honest server. The replacement chooses a new local password. The kit grants full recovery authority and must be treated accordingly.

### 4.7 Request authentication

Registered devices use ML-DSA-65 HTTP Message Signatures (RFC 9421). The IANA HTTP Signature Algorithms registry contains no post-quantum entry as of 2026-09-12, so omit the `alg` parameter and derive the algorithm from the key identified by `keyid`, as RFC 9421 permits; do not invent a registry name. A base64 ML-DSA-65 signature is a 4430-byte `Signature` header, roughly 54% of the 8190-byte single-header limit commonly deployed by Apache and nginx — verify against the deployed proxy and reject oversized headers explicitly rather than truncating. Fix the profile to cover method, authority, path, query, SHA-256 Content-Digest, device/vault identifiers, and Idempotency-Key on mutations, plus signed created/expires/nonce parameters. Verify content digest against raw body bytes. No implicit proxy header trust or redirects for signed mutations.

Use a maximum five-minute validity interval with 60 seconds of clock skew tolerance. Store accepted (device, nonce) pairs through expiry plus tolerance; reject replay. Retries use a fresh request nonce/signature with the same persisted mutation ID and body. TLS certificate validation remains mandatory; development HTTP is loopback-only and opt-in.

Bootstrap uses its one-time secret. Pending pairing offers prove possession but have no record access. Recovery uses the recovery authority. Devices are authorized against the signed membership chain; the server's device table alone is not the client's source of trust.

Before implementing the network API, complete a small interoperability exercise for this exact RFC 9421 profile. Validate base construction against applicable published vectors and cross-check profile-specific requests with an independent implementation. Note the limit created by the algorithm choice: no off-the-shelf RFC 9421 library implements ML-DSA, so the independent cross-check can only cover canonical base construction and the classical parts of the profile, with our own ML-DSA vectors covering the rest. Budget for implementing the profile rather than adopting one. Cover authority/path/query encoding, body digests, missing signed fields, expiry, replay, and proxy behavior. A round trip through only our signer and verifier is insufficient. Budget explicitly for profile implementation and test vectors if a suitable Go library is unavailable; retain the selected standard rather than silently substituting a custom scheme.

### 4.8 Post-quantum device cryptography — assessment complete, suite adopted

The M0 feasibility gate is complete and passed. Decision record 0001 holds the measurements, pinned dependencies, verification policy, and migration constraints; this section states the outcome and the limits that survive it. Measured 2026-09-12 on macOS 26 / arm64, Go 1.27.1, filippo.io/age v1.3.2.

Adopted suite: age hybrid recipients (ML-KEM-768 + X25519) for every envelope reaching vault keys, and ML-DSA-65 for every signature. `crypto/mlkem` is Go standard library from the 1.26 line and `crypto/mldsa` from 1.27, verified by compiling against both toolchains; ML-DSA therefore sets the minimum supported Go version at 1.27. age hybrid recipients are upstream in v1.3.0+, not a plugin. ML-DSA-65 is chosen over the smaller ML-DSA-44 for category parity with ML-KEM-768, so the suite holds one NIST security level rather than a Category 2 signature guarding a Category 3 exchange; the cost is 889 signature bytes and roughly 0.13 ms per signature. Record AEAD and local KDF are unchanged, since symmetric primitives at these sizes are not the quantum-vulnerable component. Sources: [age library](https://pkg.go.dev/filippo.io/age), [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final), [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final).

The suite covers all routes to vault keys: device enrollment and retained recipient envelopes, recovery envelopes, exports, rotation bundles, and any migration copies. A classical-only recovery or compatibility envelope for the same keys would undermine the claimed confidentiality. age enforces this structurally — its postquantum recipient label refuses to encrypt to hybrid and classical recipients in the same file — so the requirement is a library property rather than a matter of discipline, provided nothing wraps a hybrid recipient to hide WrapWithLabels. Adding only post-quantum signatures does not protect previously captured classical-encrypted bundles, and removing a classical wrapper later cannot undo an earlier capture.

Use explicit suite/version identifiers bound into genesis, membership, pairing transcripts, envelope context, signatures, and exports. Unknown suites fail closed. No relay-selected downgrade or silent fallback. One suite per vault per epoch; there is no mixed-suite mode. Changing suite is an epoch transition under §7.1, not an in-place substitution. Because no vault has been created, v1 ships post-quantum from genesis and needs no classical-to-hybrid migration path.

**Scope the confidentiality claim honestly.** This protects the metadata key's payloads — hostnames, users, ports, ProxyJump topology — which are long-lived secrets with no public counterpart. It protects SSH private keys very little: an adversary able to break X25519 can equally derive an Ed25519, ECDSA, or RSA private key from its public key, which sits in `~/.ssh/sshstate/public/`, in `authorized_keys` on every destination, and often in a public profile. The vault is the harder path to a secret reachable by an easier one. The supportable claim is that a synchronized infrastructure map stays confidential against future quantum attack, not that the SSH credentials themselves are quantum-safe. Native SSH transport and server-side authorized key algorithms remain OpenSSH's responsibility and are not made post-quantum by device enrollment choices.

Residual constraint carried into §4.7: RFC 9421 has no registered post-quantum algorithm, so the profile omits `alg` and derives the algorithm from `keyid`, and no off-the-shelf library will implement it.

## 5. Sync protocol

### 5.1 Storage and counters

Use SQLite for the single-user relay too, in a persistent container volume. Maintain current record heads plus an immutable accepted-change log. No tombstone or accepted-log garbage collection in v1. Master-key rotation publishes a staged, authenticated epoch transition and re-encrypted current snapshot (§7.1); old log entries remain historical and are not overwritten in place.

rev is per-record optimistic concurrency state. seq is monotonically increasing per-vault server acceptance order, used only for pagination. New records use parent rev 0 and rev 1. Updates require exact current parent rev and digest, with new rev = parent + 1. The client knows the rev before encrypting. The server rejects both older and future parents.

### 5.2 Record examples

Decrypted host payload; these IDs are illustrative values:

```json
{
  "format_version": 1,
  "alias": "prod",
  "hostname": "10.0.0.5",
  "user": "ubuntu",
  "port": 22,
  "proxy_jump": null,
  "key_ids": ["44444444444444444444444444444444"]
}
```

Server change representation; base64 fields below are placeholders, not test vectors:

```json
{
  "context": {
    "domain": "sshstate.record.v1",
    "format_version": 1,
    "vault_id": "11111111111111111111111111111111",
    "record_id": "22222222222222222222222222222222",
    "record_type": "host",
    "key_epoch": "1",
    "rev": "8",
    "parent_digest": "<sha256-base64url>",
    "mutation_id": "33333333333333333333333333333333",
    "updated_by": "55555555555555555555555555555555",
    "deleted": false
  },
  "nonce": "<24-bytes-base64url>",
  "ciphertext": "<aead-ciphertext-and-tag-base64url>",
  "signature": "<mldsa65-signature-base64url>",
  "seq": "441"
}
```

parent_digest is null only on creation. A tombstone uses the same authenticated and signed envelope with deleted=true, a fresh nonce, and encrypted empty-object payload. There is no unauthenticated bare DELETE operation.

Record types are host, key, known_host, conflict_metadata, and conflict_secret. A conflict payload references the source record/mutation and retains the candidate plaintext inside the appropriate encryption boundary. Record type is visible metadata. Private-key payloads contain an unencrypted OpenSSH private-key format string **inside the record AEAD**, plus its public-key fingerprint. Normalize imported PEM/PKCS#8/OpenSSH software keys through upstream parsers; prompt for source passphrases, never retain them. v1 supports Ed25519, RSA of at least 2048 bits, and standard NIST ECDSA; hardware-backed keys and certificates are deferred.

### 5.3 Transactions, retries, and pagination

Persist each outbound candidate and its random mutation ID locally before transmission. Reuse the exact signed envelope for a retry. The server keys idempotency by (vault, mutation ID), checks it before parent comparison, and returns the original outcome for identical bytes. Reuse with different bytes is rejected.

An accepted write atomically updates the head, appends the log with seq, and stores its idempotency outcome. Rejected conflict outcomes are also stable for that mutation ID. Retain mutation outcomes in v1.

`GET /v1/records?since=438&limit=200` captures a snapshot upper bound. Subsequent pages carry `through=<snapshot>`; return only changes after since through that bound, in seq order. Return next_cursor, snapshot_cursor, and has_more. Limit record envelopes to 1 MiB and pages to 4 MiB; reject invalid bounds and truncation.

The client validates signatures, authorization, AEAD, and chains before committing each page. Apply the page, trusted heads, and next cursor in one SQLite transaction. Do not advance on failure. Render after reaching the snapshot boundary and validating all referenced dependencies. Keep the previous generated state if the snapshot is incomplete or inconsistent.

### 5.4 Conflict policy

No last-write-wins. An honest relay keeps the first accepted version. A rejected candidate survives as a separate encrypted conflict record; a dirty client preserves its candidate before installing an incoming head. This is acceptance order, not a claim about which edit happened later.

Derive conflict IDs deterministically from a domain-separated hash of vault ID, source record ID, and the candidate's original mutation ID. Concurrent attempts to preserve the same candidate converge on that ID and verify matching content. Retain the local outbox copy until preservation is acknowledged. Do not overwrite a conflict-ID collision with differing content.

`conflicts` and a minimal `resolve` command ship in v1. Resolution creates a new ordinary mutation against the current head and tombstones the conflict after success. A new race remains a conflict. Delete/edit races preserve the edit as a candidate without automatically resurrecting a tombstoned record. Host alias and trust conflicts never generate automatic “copy” host entries.

### 5.5 API boundaries

```text
POST /v1/bootstrap
POST /v1/pairings
GET  /v1/pairings/:id
POST /v1/pairings/:id/confirm
POST /v1/pairings/:id/complete
GET  /v1/membership
POST /v1/membership
GET  /v1/envelopes
PUT  /v1/envelopes/:id
POST /v1/recovery/challenge
POST /v1/recovery/complete
GET  /v1/records
PUT  /v1/records/:id
POST /v1/rotations
GET  /v1/rotations/:id
PUT  /v1/rotations/:id/staged/:item
POST /v1/rotations/:id/commit
```

Pairing/envelope route capabilities are restricted to the named session/recipient. Recovery can retrieve only its public genesis and encrypted recovery material before proof of authority. Freeze request/response schemas and error codes in the protocol specification before network implementation; the server remains unaware of SSH payload semantics.

## 6. Threat model and limits

A compromised relay holds ciphertext, device/recovery recipient envelopes, public genesis and membership, public keys, record types and IDs, revisions, epochs, deletion flags, request metadata, cursors, and timing/size information. It does not hold local password wrappers or a password verifier to attack.

Its permitted remaining attacks include denial of service, withholding, and undetected isolated forks. It cannot substitute enrollment keys without defeating full-fingerprint verification, forge an authorized writer's signature, or alter authenticated record fields undetected.

A local disk theft exposes generated hostnames, options, public keys, capture data, and an encrypted database susceptible to offline guessing of the local password. Lock does not erase generated metadata. A compromised unlocked device, same-user malicious process, privileged debugger, or stolen recovery kit can defeat the relevant local boundary. Agent-only storage does not prevent unauthorized use of an unlocked signing socket.

Set ForwardAgent no in generated config. v1 does not claim reliable protocol-level detection of every forwarded request. Explicit overrides and forwarding of our socket are unsupported; destination constraints and per-signature confirmation are deferred. Normal lock expiry does not end SSH sessions already authenticated.

## 7. Recovery, revocation, and deliberate limits

### 7.1 Revocation and rotation

Ship signed device revocation to stop that device's requests on an honest relay and reject subsequent unauthorized writes on informed clients. This does not erase previously learned vault/SSH keys or defeat server withholding of the revocation.

`devices` lists authorized devices with membership status, enrollment event, and last accepted sequence; `revoke <device-id>` publishes the signed membership revocation. Both require unlock and ship in M2 with the membership chain. Revoking the device currently in use is the deregistration path in §3.6 and must warn explicitly before proceeding. Refuse to revoke the last remaining authorized device, which would leave only the recovery kit as a write path.

Resumable master-key rotation is required before the stable v1 release. `rotate-master-key` rotates both metadata and secret keys to fresh random values and increments the epoch; it is separate from changing a local unlock password. It also differs from remote SSH host-key rotation, which remains manual.

Use a staged epoch transition, not partially visible per-record replacement:

1. Sync and establish the current epoch, full accepted head map, and membership head. Resolve membership divergence first. Revoke excluded devices before choosing recipients. Preserve pending edits as encrypted outbox candidates.
2. Persist a rotation ID, encrypted progress journal, and new keys locally before uploading. On an honest relay, permit one active rotation per vault and freeze record and membership writes during staging; ordinary reads remain on the previous committed snapshot. Competing/stale callers receive an explicit rotation-in-progress or parent-mismatch response.
3. Re-encrypt every current record, retained conflict, tombstone, and revoked-host trust record under the new epoch with fresh nonces. Each replacement increments its record revision, links to the previous digest, and is signed by the initiator. Stage new key bundles only for non-revoked devices and the current recovery recipient. Include the signed epoch/checkpoint and the historical decryption material remaining devices need to verify retained history; never expose new keys to excluded devices.
4. Sign a transition manifest binding old/new epochs, previous membership/head-map digests, every replacement digest, and the exact recipient-bundle digests. The relay commits only if the frozen preconditions and complete staging set match, publishing the transition and new snapshot atomically. Clients verify the manifest and all replacements before advancing the epoch or publishing generated state; pagination must not expose a partially applied rotation.
5. Finish local state installation and re-encrypt local pending candidates while both key sets are available. Replay those candidates through ordinary conflict detection after the new checkpoint, with fresh mutation IDs where context changed. Retain encrypted progress until commit and local recovery are confirmed. Produce a fresh recovery export after completion.

Rotation requests and uploads are idempotent. `rotation status` distinguishes staging, committed, and locally finalized states; `rotation resume` continues the recorded operation after interruption or a lost response. Before commit, an explicit authenticated abort can discard staging and release the write freeze; it cannot undo an already committed epoch. A remaining authorized device must be able to abort a stranded pre-commit operation if the initiator is lost. After commit, readers reject regressions and recovery completes forward. Define and test the exact manifest, transaction, timeout, and recovery state machine before implementation.

Remaining devices need not be online during rotation: on unlock/reconnect they decrypt their new bundle, validate the transition/checkpoint, migrate their pending edits, and resume. Old-epoch writes are rejected. New keys and bundles must never be sent to revoked devices, even if those devices retry a previously valid session. A hostile relay can still withhold the transition or fork history within the stated threat-model limits.

Rotation cannot erase old ciphertext or keys an attacker already captured, and the retained log/backups still contain old-epoch ciphertext. New encryption keys do not revoke an already stolen SSH private key: replace affected SSH credentials at their destinations. If the recovery kit itself is compromised, rotating only vault keys while keeping that recipient is insufficient. v1's containment fallback for that case is a fresh vault and recovery kit, reviewed migration, and SSH credential replacement. Preserve old evidence/backups explicitly rather than deleting them during migration.

### 7.2 Backup and restore

Recovery kit restores access to retained ciphertext; it is not a backup of deleted/lost server storage. Ship age-encrypted full exports containing vault records, keys, membership, pending conflicts, and a trusted checkpoint, encrypted only to the recovery recipient. An authorized exporting device signs a domain-separated manifest binding genesis, the checkpoint, and the digest and length of every archive member. Verify it against the kit-pinned genesis before treating the checkpoint as trusted. Exclude device private keys and local password wrappers. No plaintext or password-encrypted export mode in v1.

Restore into a new local store and generate fresh device keys and a new local password. Verify archive integrity, genesis, record signatures and context before installation. Never overwrite an existing vault implicitly. Require saving and re-entering/checking the recovery kit during initialization. Loss of all unlocked devices and the kit is unrecoverable. A stale backup cannot establish later freshness.

### 7.3 Deferred features

Automatic TTY/desktop prompts, OS keychain unlock, per-signature confirmation, forwarding constraints, periodic sync, automatic remote host-key rotation, capture-file compaction, any TUI, broad config import, the Git signing helper, Windows, Linux distribution package repositories and OS package signing, GUI/mobile, teams, and field-level merging are out of v1 scope. Resumable vault master-key rotation is a v1 requirement. Post-quantum implementation follows the mandatory early assessment in §4.8. Scoped agent sessions for autonomous tooling are a post-v1 direction recorded in §13 and are not v1 scope.

Metadata-only clients are deferred. The two-key split limits the secrets they can decrypt, but a maliciously served browser can still steal metadata. Read-only UI and metadata-only encryption do not make server-delivered JavaScript trustworthy.

## 8. Implementation and verification

### Milestone 0 — foundation

Keep client and server in this repository, with one Go module `github.com/mouizahmed/sshstate` and independently built entrypoints `cmd/sshstate` and `cmd/sshstate-server`. Share wire formats and validation through `internal/protocol`; keep client/vault and server dependencies separate. Introduce implementation packages as needed and keep container/deployment assets under `deploy/`. README, threat model, protocol draft, and decision records precede network code.

Use Go 1.27 as the minimum supported language/toolchain line and the latest supported patch for builds. `crypto/mldsa` is absent from Go 1.26 — confirmed by compiling against go1.26.8, which fails with `package crypto/mldsa is not in std` — so the §4.8 suite forces 1.27 as the floor. Accept the consequence: v1 supports only the newest Go release line, contributors must be on 1.27 or later, and there is no older line to fall back to. Revisit only if that becomes a real obstacle; a third-party ML-DSA dependency is not worth 1.26 compatibility. Pin exact toolchain and dependency versions in setup. The development machine was upgraded from Go 1.25.1 to 1.27.1 on 2026-09-12.

Use modernc.org/sqlite through database/sql to avoid a SQLite C dependency. Use platform build tags and a small native adapter where launchd activation requires it. Linux server distribution targets a static binary; macOS client builds may require cgo and native runners. Do not promise that arbitrary cross-compilation is just GOOS/GOARCH.

The §4.8 post-quantum feasibility exercise is complete and its suite decision is recorded in decision record 0001; persistent device/recovery formats and network enrollment are unblocked. Pin filippo.io/age v1.3.2 or later and the Go 1.27 minimum that provides `crypto/mldsa`. Port the feasibility spike into `internal/crypto` tests so mixed-recipient rejection, signature tampering, and Options.Context separation are asserted in CI. Keep storage/envelope interfaces versioned without introducing unrestricted algorithm negotiation.

### Milestone 1 — working local SSH on macOS

Implement local init and recovery-kit verification, self-describing encrypted storage, CLI/control daemon, explicit unlock/lock, one key and host, generated config, and a real native SSH login. Ship basic doctor with effective-config inspection, installation with the inline existing-trust import/skip flow, and data-preserving uninstall. Use foreground mode for the first smoke test, then verify launchd activation before declaring the milestone complete.

Prove locked signing refusal, expiry, restart-locked behavior, source-passphrase import, restrictive permissions, doctor detection of pre-existing identities and managed-field mismatches, preservation of selected existing host trust, safe uninstall, and no plaintext secret writes. macOS/arm64 is the primary development platform. Portable unit tests run on Linux CI from the start. M1 is a development milestone; daily use of valuable credentials waits for verified backup/restore in M2.

### Milestone 2 — working two-device sync

Specify and test enrollment transcripts, complete the independent HTTP signature interoperability exercise, and verify canonical envelopes, membership authorization, bootstrap, recovery, and sync transactions; then implement the API. Ship encrypted export/restore, signed device revocation with the `devices` and `revoke` verbs, uninstall-time server-side deregistration, and a runnable non-root server container with a persistent volume and basic setup instructions in this milestone. Enable guarded purge after backup/restore passes. Demonstrate identical managed configuration on two devices, offline conflict preservation/resolution, interrupted retries, a deletion returning to a long-offline device, recovery from export with the relay unavailable, and rejection of revoked-device requests by an honest relay.

Use the §4.8 suite consistently across enrollment, recovery, exports, record signatures, and request authentication. Downgrade rejection and header-size handling for ML-DSA-65 signatures are M2 completion criteria. Specify rotation's staged transition and crash-recovery state machine here so the server transactions and sync reader can support it.

### Milestone 3a — three-machine SSH workflow

Finish strict SSH-config import and known-host capture/reconciliation/trust resolution, extending the M1 trust-import path. Complete Linux systemd integration and the remaining doctor diagnostics. Test actual Linux SSH/activation in addition to portable unit tests, concurrent OpenSSH capture writers, and locked-to-unlocked reconciliation. Begin three-machine dogfooding. This is a usable CLI checkpoint, not yet the stable v1 release.

Ship client distribution in this milestone; a tool installed on every machine a user owns needs an install path that is not `go build`. Publish tagged GitHub releases built by pinned-toolchain CI, covering darwin/arm64, darwin/amd64, linux/amd64, and linux/arm64, with per-artifact checksums and a documented verification step. Provide a Homebrew tap for macOS and Linux. Publish the server container image alongside. Linux distribution package repositories, OS package signing infrastructure, and Windows packaging are out of v1 scope (§7.3); state that rather than implying broader coverage.

### Milestone 3b — rotation; stable v1

Implement the M2 rotation state machine and prove interruption/resumption, atomic publication, revoked-recipient exclusion, offline-device catch-up, pending-edit migration, and recovery from a post-rotation export. Rotation progress must be readable from the CLI while it runs, since there is no second frontend to show it. Complete three-machine dogfooding and release documentation before declaring stable v1.

Post-v1 refinements include the Git helper and additional container/deployment convenience. Capture compaction and automatic remote host-key rotation remain separately deferred; they are distinct from the required vault master-key rotation. Backup/restore, revocation, and a usable server container are already delivered by M2.

### Required evidence

- Crypto and canonicalization vectors; reject altered context, deletion, nonce, ciphertext, signature, and oversized KDF headers.
- Pairing substitution, mismatched transcript, expiry, replay, and unfinished approval never release keys or authorize a device.
- Full-fingerprint base32 vectors preserve every digest bit; differences in any group, including the final group, invalidate comparison.
- RFC 9421 published vectors and independent profile cross-checks cover canonical request handling, body tampering, missing covered fields, and replay/expiry rejection.
- Recovery on a fresh machine without an existing device, including unavailable relay with an export.
- Page/cursor crash recovery, lost upload responses, deterministic conflict preservation, exact parent matching, and delete/edit races.
- Rollback detection against known heads; explicit tests documenting withheld/forked histories outside the guarantee.
- OpenSSH integration across managed defaults, accumulating identities, actual signing algorithms, installation trust-import/skip/cancel, capture append semantics and concurrent writers, hashed hostnames, markers, and pending host-key changes.
- Daemon concurrent lock/sign/control calls, activation, encrypted SQLite/WAL/outbox content, and uninstall preservation.
- Device lifecycle: `devices` reflects the signed membership chain rather than the relay's device table; revocation and uninstall-time deregistration leave no authorized writer for the removed device; a revoked device receives no new key or rotation bundle; an unreachable relay or locked vault reports deregistration as incomplete instead of succeeding; the last authorized device cannot be revoked.
- Release artifacts build reproducibly from the pinned toolchain, checksums verify, and the documented install path works on a clean macOS and Linux machine.
- Rotation crash/retry tests around every staging, commit, and local-finalization boundary; no mixed-epoch publication, no new envelope for a revoked device, and no loss of offline pending edits.
- Recovery from a post-rotation export and offline-device catch-up across multiple committed epochs; stale writes and epoch regressions are rejected.
- Post-quantum suite: mixed hybrid/classical recipient sets are rejected, recipient coverage includes recovery and backup envelopes, unknown suite identifiers fail closed, key/signature/envelope parsing is bounded to the fixed sizes of the selected parameter sets, and an ML-DSA-65 `Signature` header is rejected explicitly rather than truncated when a proxy limit is exceeded.

CI runs formatting checks, build, vet, tests, race checks where supported, and dependency vulnerability checks. Fuzz bounded config, record, and control-message parsers. Validate each milestone in proportion to its risks; do not substitute mocks for the native SSH demo.

## 9. License and distribution

AGPLv3 is selected, consistent with the repository LICENSE. Use AGPL-3.0-only as the project identifier; do not assume an “or later” grant from the standard license's example text. Preserve the existing license text and add project notices during setup.

Self-hosted server: one non-root container, persistent data volume, configurable HTTPS reverse proxy, no telemetry. License choice is not a prohibition on commercial use or hosting. No monetization, hosted service, or enterprise support commitment is part of v1.

## 10. Rejected directions

Do not build an SSH transport/terminal, hosted tunnel/public-endpoint service, identity-based certificate issuer, enterprise migration platform, or general API/database secrets manager. Keep the product centered on managed SSH environment synchronization.

## 12. Accepted decision register

All entries below are accepted on 2026-09-12 with the delivery conditions shown. Their mechanisms are specified above; implementation may reveal defects requiring a recorded amendment. R12's assessment is complete, so R1 and R12 now state the same adopted suite rather than a baseline pending a decision.

| Review item | Decision | Reason |
|---|---|---|
| R1: pairing | Separate ML-DSA-65 signing and age hybrid encryption keys; mutual full-transcript fingerprint verification in 13 numbered base32 groups and signed enrollment | Authenticate both endpoints without treating a relay code or a fingerprint prefix as proof of identity |
| R2: password/recovery | Local-only password wrappers; independent offline recovery kit and server recipient envelopes | Remove a password-guessing target from the server while retaining loss recovery |
| R3: freshness | Authenticate deletion/context, sign records, verify parent chains and transferred checkpoints; document fork limits | Provide concrete detection without trusting server sequence as proof of freshness |
| R4: daemon/agent | Daemon owns SQLite; separate control/agent sockets; explicit unlock with 15-minute idle and 8-hour hard expiry | Establish one state owner and implementable native SSH behavior |
| R5: sync/conflicts | Exact parent matching, durable idempotency, snapshot pagination, transactional cursors, preserve candidates and resolve explicitly | Avoid data loss and an ambiguous last-write-wins policy |
| R6: config/trust | Explicit managed defaults, strict import, ordered keys, doctor, separate capture and generated trust files | Respect OpenSSH accumulation and avoid two writers replacing one file |
| R7: Git | Post-v1 repository-local helper routes only ssh-keygen to our socket | Reuse signing without changing global agent selection or delaying core SSH delivery |
| R8: memory | Go, bounded secret lifetime, best-effort owned-buffer wiping and core-dump controls | Make achievable protections explicit without promising complete erasure |
| R9: setup | One repo/two binaries; macOS-first with doctor/install/uninstall in M1; recovery/revocation/container in M2; Linux and three-machine workflow in M3; supported Go and AGPLv3 | Spread release requirements across working milestones |
| R10: master-key rotation | Required in v1; staged atomic epoch transition, durable resume, new envelopes only for remaining devices/recovery | Make revocation and ongoing vault maintenance practical without losing offline work |
| R11: TUI | ~~Focused v1 frontend over the daemon control API~~ — **withdrawn 2026-09-15**; no TUI in v1, and the CLI carries what it was to show | A second frontend is cost this project does not need to pay to be usable |
| R12: post-quantum devices | Assessment complete and passed; adopt age hybrid ML-KEM-768+X25519 and ML-DSA-65 from genesis, per decision record 0001 | Stdlib and upstream support, library-enforced downgrade rejection, short recovery secrets, acceptable sizes; claim scoped to metadata rather than SSH keys |
| R13: device lifecycle | `devices` and `revoke` verbs in M2; uninstall performs server-side deregistration or reports the device still authorized; refuse revoking the last device | Make the specified revocation invocable and stop uninstall from leaving an authorized writer in the chain |
| R14: distribution | Signed multi-arch release artifacts and a Homebrew tap for macOS/Linux in M3a; distribution repositories and Windows packaging stay deferred | A tool installed on every machine needs a real install path; scope it to what M3a can verify |

## 13. Post-v1 direction — scoped agent sessions

Status: direction only. Nothing here is accepted v1 scope, no milestone depends on it, and §12 deliberately records no decision for it. Evaluate after stable v1 ships and is dogfooded.

**Problem.** Autonomous coding tools increasingly need SSH access to development and staging infrastructure. Today the options are to hand such a tool the user's `SSH_AUTH_SOCK` or let it read `~/.ssh`, both of which grant the user's entire SSH identity for as long as the process runs. Narrowing that is a general systems problem, not a property of any one vendor's product.

**Not the pitch.** "sshstate lets AI agents connect over SSH" is not a differentiator. Remote SSH features in coding tools already detect hosts from the user's SSH configuration and connect with the credentials present on that machine. Because §3.2 generates native OpenSSH config, such tools already see sshstate-managed hosts without knowing sshstate exists; that is an interaction, not a competition. The contribution is delegation, not connectivity.

**Non-goals.** No MCP server, no LLM or AI SDK dependency, no vendor-specific integration, no command execution, no remote session brokering, and no hosted service. The deliverable is an SSH-agent capability primitive that any process capable of using OpenSSH can consume unchanged.

**Mechanism.** A scoped session is a separate short-lived agent socket presenting a restricted identity view: a named principal, an explicit identity subset, destination constraints, a TTL, an approval policy, and an audit record. The consuming process receives only that socket path. The user's primary agent socket and global `SSH_AUTH_SOCK` are untouched, consistent with §3.3.

**Destination enforcement is by host key, not hostname pattern.** A signing request does not carry the destination hostname and the agent cannot infer it, so a host-pattern policy is not enforceable from the request alone. Enforcement requires the OpenSSH agent extensions: `session-bind@openssh.com` supplies the server host public key, the exchange-hash session identifier, the host key's signature over that identifier, and an `is_forwarding` flag, all verifiable by the agent before any signing decision; `restrict-destination-v00@openssh.com` expresses constraints carrying `to_username`, `to_hostname`, and `to_hostkeys`. A policy written as an alias pattern must therefore resolve to a concrete set of host keys when the session is created.

**This depends on v1's known-host work.** §3.4 already holds reviewed, approved host keys for managed aliases, so a session can populate `to_hostkeys` from the vault instead of trusting whatever key a destination presents. Without synchronized host trust, destination restriction is materially weaker. Treat that as the enabling dependency, and as the reason this belongs to this project rather than to a standalone broker.

**Prerequisites and limits to state before building:**

- Interactive approval requires the prompt-delivery work deferred in §7.3. An approval-required session policy is not implementable while explicit unlock is the only path.
- An audit record of principal, identity, destination, and time is new sensitive persistence with no home in §4.4, and it inherits the §3.4 locked-vault problem: observations made while locked cannot be written under a vault key.
- Scoping constrains what a process can *sign with*. A process that can execute arbitrary commands can still read `~/.ssh` or locate the primary socket. The honest claim is defense in depth for a process already sandboxed from the user's filesystem and primary agent, not containment of arbitrary code execution. State this rather than letting a demo imply otherwise.
- Expiry does not terminate already authenticated SSH sessions, matching the §6 limit recorded for lock expiry.
- Socket placement is platform-specific; do not assume a Linux runtime-directory layout on macOS.
- `is_forwarding` interacts with the §6 forwarding stance and must be decided, not defaulted into.
- Verify the minimum OpenSSH version providing both extensions, and define behavior when a client sends no `session-bind@openssh.com` at all: an unbound connection must fail closed against a destination-constrained identity, never fall back to unrestricted signing.

Source: [OpenSSH agent extensions](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.agent).

## Appendix: Technical references

These sources support underlying behavior and primitive choices, not an audit of the application protocol.

- [OpenSSH configuration semantics](https://man.openbsd.org/ssh_config)
- [OpenSSH agent extensions](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.agent)
- [Go agent implementation](https://github.com/golang/crypto/blob/master/ssh/agent/server.go)
- [age v1 specification](https://age-encryption.org/v1)
- [Argon2 RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html)
- [XChaCha20-Poly1305 nonce guidance](https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction)
- [JSON canonicalization RFC 8785](https://www.rfc-editor.org/rfc/rfc8785.html)
- [HTTP Message Signatures RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html)
- [Go GC guide](https://go.dev/doc/gc-guide)
- [Go release history and support policy](https://go.dev/doc/devel/release)
- [Go age library](https://pkg.go.dev/filippo.io/age)
- [Pure-Go SQLite driver](https://pkg.go.dev/modernc.org/sqlite)
- [ML-KEM standard, FIPS 203](https://csrc.nist.gov/pubs/fips/203/final)
- [ML-DSA standard, FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)
