# Defects found during implementation

The brief's decision register (§12) says implementation may reveal defects
requiring a recorded amendment. This is that record: problems found after the
code was written, what caused them, and what now prevents a recurrence.

An entry earns its place by having been **found**, not by having been
anticipated. Each one names the check that caught it, because a defect that only
a human noticed is a defect the next one will slip past.

---

## D1 — `sshstate add <alias> --hostname <host>` parsed no flags

- Found: Milestone 1, by `internal/cli.TestLocalWorkflow`
- Severity: the command was unusable in its documented form
- Fixed in: `internal/cli/commands.go` (`splitPositional`)

### What happened

`sshstate add prod --hostname 10.0.0.5` reported `--hostname is required`. Go's
`flag` package stops parsing at the first non-flag argument, so `prod` ended
parsing and `--hostname 10.0.0.5` was left sitting in the positional list,
unread.

Every command taking a subject was affected: `add` and `add-key`.

### Why it survived until a test found it

The unit tests for host creation called the vault API directly, and the daemon
integration tests called the control client directly. Neither went through
argument parsing. The CLI layer had no test at all until the workflow test
existed, and the first thing that test did was fail.

### Fix

Leading non-flag arguments are split off before `flag.Parse`. Requiring the user
to write flags first would have been the wrong fix: verb, subject, then options
is the ordering every comparable tool accepts, and a tool that silently drops
options in that ordering is broken regardless of what its help text says.

---

## D2 — A launchd-activated daemon could not find its vault

- Found: Milestone 1, by running launchd for real (`internal/service.TestLaunchdSocketActivation`)
- Severity: socket activation did not work at all; the daemon exited on every connection
- Fixed in: `internal/cli/daemon.go`, `internal/service/launchd_darwin.go`

### What happened

The daemon exited immediately with `no vault here; run: sshstate init`, once per
connection attempt, fifteen times before launchd gave up. The sockets existed and
were correct; the process behind them could not start.

`paths.Default()` resolves the layout from `$HOME` and `$XDG_DATA_HOME`. launchd
starts a LaunchAgent with a minimal environment — `launchctl print` showed a
bare `PATH`, `XPC_SERVICE_NAME`, and nothing else — so the daemon resolved a
different layout than the CLI that had created the vault, and looked for it
somewhere it had never been.

### Why it survived until a real launchd run

The in-process daemon tests construct a `paths.Layout` explicitly and hand it to
the daemon, so they never exercise environment-derived path resolution. Nothing
short of a real service-manager start would have caught this: the defect is
specifically that the daemon's environment differs under launchd, and every test
that builds the layout itself is immune to it by construction.

### Fix

The service definition pins the layout. `sshstate daemon` accepts `--data`,
`--ssh-dir`, `--runtime` and `--user-config`, and `RenderPlist` writes the
resolved absolute paths into `ProgramArguments`. A daemon started by a service
manager is now told where its vault is rather than guessing from an environment
the service manager controls.

### Guard

`TestLaunchdSocketActivation` bootstraps a real launchd job, asserts the daemon
was not running beforehand, connects, and checks the daemon answers for the
right vault and comes up locked. It also compares the control socket's inode
before and after, so a daemon that removed launchd's socket and bound its own
would fail: that would break the *next* activation, because launchd would still
be watching the file it created.

It is opt-in (`SSHSTATE_LAUNCHD_TEST=1`) and CI does not run it. GitHub's macOS
runners have no GUI session domain to bootstrap into, and a test that silently
passed there would be worse than one that is honestly absent.

---

## D3 — `go mod tidy` silently downgraded two pinned dependencies

- Found: Milestone 1, by `govulncheck`
- Severity: two advisories reachable from this code; a documented pin violated
- Fixed in: `go.mod`, with a guard in `internal/crypto/pins_test.go`

### What happened

`filippo.io/age` was at **v1.3.1**. Decision record 0001 pins **v1.3.2 or
later**, and the brief §4.2 repeats it.

`golang.org/x/crypto` was at **v0.46.0**, carrying two advisories that
`govulncheck` traced into this code rather than merely into imported packages:

| Advisory | Reachable from |
|---|---|
| GO-2026-5033 — client panic on pathological input to `ssh/agent` | `daemon.serveAgent` → `agent.ServeAgent` |
| GO-2026-5018 — DoS from pathological RSA/DSA parameters in `ssh` | `sshkeys.Import`, `sshkeys.Signer`, `sshkeys.PublicKeyDigest`, and the agent's public-key parsing |

Both are denial of service rather than disclosure, and both sit on paths that
handle attacker-influenced input: an agent client's protocol messages, and a key
file a user imports.

### Cause

The versions were set correctly at Milestone 0 and then lost.

While adding `golang.org/x/term` for password prompts, a `go get` named an older
version by mistake and reported `downgraded golang.org/x/term v0.45.0 =>
v0.38.0`. `age` v1.3.2 requires `golang.org/x/term v0.45.0`, so that version was
no longer reachable in the module graph. Go's downgrade algorithm resolves that
by lowering whatever requires the version being removed — so it downgraded
`filippo.io/age` itself, to v1.3.1, whose requirements the older `term`
satisfies.

The alarming part is that **`age` was a direct requirement at a pinned version
and was downgraded anyway.** Writing a version into `go.mod` is not a floor:
`go get` will move a direct requirement down to keep the graph consistent with
an explicitly requested older version elsewhere. `x/crypto` came down in the
same cascade, and was carried as an indirect requirement, so nothing held it up
either.

Correcting `x/term` back to v0.45.0 a minute later did not restore `age`: an
upgrade of one module does not re-raise something a previous downgrade lowered.
No build failed, no test failed, and the `go.mod` line still read like a pin.

### Fix

Both are now direct requirements at explicit versions: `filippo.io/age v1.3.2`,
`golang.org/x/crypto v0.57.0`. `govulncheck` reports zero vulnerabilities
reachable from this code.

### Guard

`TestPinnedDependencyMinimums` reads `runtime/debug.ReadBuildInfo()` and fails if
either module is below its recorded minimum. Verified by mutation: raising the
pin to a version that does not exist makes it fail.

The pin guard is not the primary defence for `age`. The property v1.3.2 is
pinned *for* — that a classical recipient cannot ride along beside a
post-quantum one — is asserted directly and version-independently by
`TestClassicalRecipientCannotRideAlong`. The guard catches the pin drifting; the
behavioural test catches the behaviour disappearing. Neither substitutes for the
other.

### What this says about CI

CI ran `govulncheck` from Milestone 0 and would have caught the `x/crypto`
downgrade on the next push. It would **not** have caught the `age` downgrade:
v1.3.1 has no advisory, so nothing distinguishes it from the pinned version
except the pin itself. That is the gap `TestPinnedDependencyMinimums` closes.

---

## D4 — `doctor` reported a problem on every correctly generated host

- Found: Milestone 1 completion, by `internal/daemon.TestDoctorReportsNoProblemsOnGeneratedConfig`
- Severity: a false alarm on the normal case, which is how a diagnostic becomes noise
- Fixed in: `internal/daemon/doctor.go`

### What happened

The generated config writes `UpdateHostKeys no`. Doctor compared the effective
value against that same string and reported:

```
problem  effective configuration
         host "prod": updatehostkeys is "false", the vault says "no"
```

`ssh -G` does not echo the configured word. It renders `UpdateHostKeys` as a
boolean: `yes` prints `true`, `no` prints `false`, and only `ask` prints itself
(verified against OpenSSH_10.0p2). So every host generated exactly as intended
was reported as misconfigured.

`ProxyJump` has a second version of the same problem in the opposite direction:
when it resolves to `none`, `ssh -G` omits the keyword entirely rather than
printing `proxyjump none`, so a check that expected to read a value back would
have reported a missing setting on every host without a jump host.

### Why it survived

There were no tests for `doctor` at all. Its output was read by a human during
development, where one wrong line among a dozen correct ones is easy to accept
as "something about host keys". Nothing compared the whole report against an
expectation, so nothing had to be right.

The deeper cause is that `ssh -G` output was treated as an echo of the config
rather than as its own rendering with its own spellings. That assumption held
for `hostname`, `user`, `port` and `identityagent`, which is why it survived.

### Fix

`updatehostkeys` is compared against the rendered value. `proxyjump` is checked
as three cases: absent means none, present must match the vault, and a jump host
appearing where the vault declares none is a problem in itself. The remaining
managed fields — `stricthostkeychecking` and the ordered
`UserKnownHostsFile` pair — are now checked too, so every field the generator
writes explicitly is a field doctor verifies.

### Guard

`TestDoctorReportsNoProblemsOnGeneratedConfig` runs the real `ssh` binary
against a real generated config and fails on any `problem` finding.
`TestDoctorDetectsManagedFieldOverrides` overrides each managed field in turn
from a Host block placed ahead of the managed Include, and requires each one to
be reported. Verified by mutation: restoring the `"no"` expectation makes the
first test fail with the original message.

Doctor tests need a seam. OpenSSH resolves `~/.ssh/config` from the passwd
entry and ignores `$HOME`, so a test cannot point it at a temporary config by
setting an environment variable; the daemon carries an unexported
`effectiveConfigArgs` that tests set to `-F <path>`. It is empty in production,
where inspecting the user's real configuration is the entire purpose.

---

## D5 — A failed recovery-kit check stranded the vault

- Found: Milestone 1 completion, during review of the init flow
- Severity: an unrecoverable state reachable by mistyping, with advice that could not work
- Fixed in: `internal/cli/commands.go`, `internal/vault/manager.go`

### What happened

`init` creates the vault, prints the recovery kit, and asks the user to type its
checksum back (§7.2). After three wrong answers it failed with:

```
recovery kit not confirmed; run sshstate init again after saving the kit
```

`init` refuses to run against an existing vault, so that advice could not be
followed. The vault existed, held its keys, and refused every mutation until
confirmed — and nothing could confirm it. The blocking error pointed at
`sshstate init --confirm-recovery`, a flag that was never implemented.

Three wrong answers is not an unlikely path: the checksum is ten transcribed
characters, and the whole point of asking for it is that people get it wrong.

### Fix

`sshstate confirm-recovery --kit <path>` completes the check against an existing
vault. It asks for the saved kit rather than the checksum, which is both
stronger evidence that the kit was saved and the only evidence still available
once the terminal has scrolled.

The kit never crosses the control socket (§4.6). The CLI reads and verifies it
locally, the daemon issues a nonce, and the CLI answers with an ML-DSA-65
signature over that nonce under the domain
`sshstate.recovery-kit-confirm.v1`, which the daemon verifies against the
recovery verify key already pinned in genesis. A kit belonging to a different
vault therefore proves nothing about this one. The command also works with no
daemon running, because a stopped daemon is a common part of being stranded.

Both error messages now name the command that exists, and `init`'s failure adds
what to do if the kit really was lost: delete the database and start over.

### Guard

A mistyped checksum was only the most obvious way to reach this state. Review
found two more: a recovery kit that cannot be written (`--kit` naming a
directory that does not exist) and a closed stdin both returned their own error
after the vault was already on disk, saying nothing about what had been left
behind. Every exit after vault creation now explains the state, and the advice
depends on whether the kit survived — a vault whose kit reached nowhere is not
recoverable, and telling its owner to "confirm it later" would be false.
Kit creation also refuses an existing path instead of overwriting it or
inheriting permissions that could expose the recovery secret.

`TestFailedConfirmationPointsAtAWorkingCommand` asserts that the advice names a
command in the command table and not the flag that never existed.
`TestInitExplainsItselfWhenTheKitCannotBeWritten` and
`TestInitExplainsItselfWhenTheConfirmationCannotBeRead` cover the other two
exits. `TestInitRefusesExistingRecoveryKitPathWithoutChangingIt` proves an
existing destination keeps both its contents and permissions.
`TestConfirmRecoveryWithoutDaemon` walks the stranded path end to end and then
adds a host, which is the property that actually matters.
`TestConfirmRecoveryRejectsAnotherVaultsKit`, `TestRecoveryChallengeIsSingleUse`,
`TestRecoveryChallengeExpires` and `TestRecoveryProofIsDomainSeparated` cover the
proof itself.

---

## D6 — The cross-user socket test had never once run

- Found: Milestone 3a, by running it on a Linux VM with a second account
- Severity: the agent socket's only real guard had no evidence behind it
- Fixed in: `internal/peercred/peercred_test.go`

`TestCrossUserConnectionIsRefused` is the test for the check that stops another
user on the machine from asking the agent to sign with keys they cannot read.
It needs a second uid, so it skips when one is not configured. It had skipped
every time it had ever been run, on every machine, and the package still
reported `ok`.

Given a second account it failed twice before it passed. `go test` builds the
test binary into a 0700 directory, so `sudo -u other <binary>` could not find a
file it was not allowed to traverse to — reported as a skip, because the test
treats "could not run as that user" as an environment problem. Once the binary
was copied somewhere reachable, sudo's default `env_reset` stripped
`SSHSTATE_PEER_SOCKET`, so the helper skipped, connected to nothing, and the
listener timed out.

### Why it survived until a second uid existed

A skip is not a failure. The test was written carefully, reviewed, and committed
in a package whose other three tests pass, and nothing in `go test` output
distinguishes a guard that was proven from a guard that was never exercised.
Two machines had run it; neither had a second account.

### Fix

The binary is copied to the world-traversable directory the test already
creates, and the socket path is passed through `env(1)` rather than an
environment sudo will not forward. Mutation-checked: with `uid != self` forced
false, the test reports that a connection from another user was accepted.

The skip stays — CI has no second account and a test that failed there would be
noise — but the refusal is now something that has actually been observed:
`peer runs as uid 1001, this daemon serves uid 1000`.

---

## D7 — Revoking a device made another device's earlier work unreadable

- Found: Milestone 3a, by `internal/cli.TestThreeDevicesShareOneVault`
- Severity: a routine revocation could wedge sync permanently on the device that performed it
- Fixed in: `internal/syncengine/engine.go`

A revoked device's writes are refused from the point the local device learned of
the revocation; its earlier writes stay valid, because they are history every
device already accepted. The position of that boundary was taken from the local
record cursor at the moment the membership chain was applied — which is before
the pull that fetches the records the boundary is meant to divide.

So on a device that was behind, the boundary landed below records the revoked
device had legitimately published earlier. Those records arrived on the very next
page and were refused as writes from a revoked device. The refusal failed the
whole pull, the cursor never advanced, and every later sync failed the same way
at the same record.

With three devices the window is wide enough to hit on a first attempt: B adds a
host, C adds a host, then A revokes B without having pulled B's host first. A's
`revoke` failed reporting a record it had itself just asked for.

### Why two devices never showed it

With two devices the revoker is almost always the only other writer, so it has
already pulled everything the revoked device published. The two-device test
revokes immediately after a sync, so its cursor is at the head and the boundary
is correct by accident. Nothing in it can distinguish a boundary taken before
the pull from one taken after.

### Fix

The boundary is recorded after the pull completes, from the snapshot bound the
relay reported, and only when the pull reached that bound. Everything at or
below it was on the relay when the revocation was observed and is accepted;
anything above it is a write from after and is refused.

Mutation-checked: moving the boundary back to before the pull fails the
three-device test with the original error. Note that changing only the *value*
passed does not fail it — after a complete pull the local cursor equals the
bound — so it is the ordering, not the argument, that carries the fix.

---

## D8 — A foreground daemon silently broke socket activation

- Found: Milestone 3a, by running both on the Linux VM to answer "what if I run both?"
- Severity: on-demand start stopped working, and the error told the user to repeat the mistake
- Fixed in: `internal/cli/daemon.go`

Two daemons can never serve at once: the second fails on the exclusive instance
lock. That guard works and is tested. It is also not the interesting case.

The service starts on demand, so most of the time it is *not running* — the
sockets exist, created by systemd or launchd, with nothing behind them. A
`sshstate daemon` started then takes the lock unopposed, finds no activated
descriptors, and falls through to binding the paths itself. Binding unlinks the
existing socket files, so the service manager is left watching descriptors on
inodes nothing can reach.

Observed on the VM: socket inodes 1181709 and 1181714 became 1181717 and
1181718. The next activation attempt failed with `sshstate.service: Failed with
result 'exit-code'` because the manual daemon held the lock. When that daemon
exited it unlinked its own sockets, leaving the socket unit reporting `active`
with no file on disk. Every command then reported:

    the sshstate daemon is not running (socket .../control.sock)
    start it with: sshstate daemon

which is advice to do the thing that caused it. Recovery needs
`systemctl --user restart` on both socket units, or `sshstate install --service`
again — neither of which that message suggests.

### Why the instance lock did not cover it

The lock answers "are two daemons running", and the answer was no. Nothing asked
"does something else own these socket paths", which is a different question and
the one that mattered. The activation test starts the daemon *through* the
service manager, so it never exercises a foreground start on a machine where a
service is registered.

### Fix

`sshstate daemon` refuses when a service definition is installed and this
process was not started by the service manager. The two ways forward are named:
use the service, or `sshstate uninstall` to unregister it first. A daemon that
was activated has descriptors passed to it and is allowed through, as is one
given an explicit `--runtime` directory, which is not the service's.

---

## D9 — An imported host kept authenticating with the key it was meant to replace

- Found: Milestone 3a, by running the everyday path against a real sshd and locking the vault
- Severity: the vault's agent was not what authenticated, and nothing said so
- Fixed in: `internal/cli/import.go`, `internal/sshconfig/generate.go`

`import` copies hosts out of `~/.ssh/config` into the vault. It does not remove
them from that file, and nothing warned that it had not. OpenSSH then reads both
definitions: the user's own block and the generated one behind the Include.

§3.2 already records why that matters — IdentityFile accumulates across every
matching block, and `IdentitiesOnly` does not erase identities configured
elsewhere. So the user's own `IdentityFile ~/.ssh/id_ed25519` kept being offered
alongside the agent's. With the vault locked, the login still succeeded, using
the plaintext key on disk. The whole premise, that the private key lives only in
the vault, was quietly false for every host imported this way.

A second problem surfaced in the same run. Generated public key files were
written 0644 inside a 0700 directory. That is ordinary for a public key, but
OpenSSH applies its private-key permission check to whatever `IdentityFile`
names, and answered:

    It is required that your private key files are NOT accessible by others.
    This private key will be ignored.
    Load key ".../demo-01-<digest>.pub": bad permissions

It then authenticated with something else. Unlocked, this was invisible: ssh
uses the file as an agent hint without loading it. It appeared only when the
agent had nothing to offer, which is exactly when the user is trying to work out
why they cannot log in.

### Why the tests did not show it

`TestNativeSSHLogin` builds a config containing nothing but the managed Include,
because that is the claim being tested. A real user's config still has their own
blocks in it, and the test could not have had them without ceasing to test the
thing it is named after. It also asserts a successful login and a refusal when
locked; both were true here, for the wrong reason.

### Fix

Public key files are written 0600, so OpenSSH stops rejecting them. `import`
now names the hosts the source file still defines with an IdentityFile, says
that OpenSSH offers the user's own key first, and points at `doctor`, which
compares the effective configuration and reports extra identities.

`import` still does not edit the user's config. §3.2 permits exactly one managed
edit to that file, the Include, and removing blocks the user wrote is not it.

---

## D10 — Reading a password from a file descriptor closed the caller's file

- Found: Milestone 3a, by `internal/cli.TestSetupRefusesAnExistingVault` failing as `locking protocol (15)`
- Severity: an unrelated open file, including the vault database, could be closed underneath its owner
- Fixed in: `internal/cli/secretfd.go`

`unlock --password-fd N` wrapped the caller's descriptor with `os.NewFile`.
That constructor attaches a finalizer, so when the wrapper became unreachable
the runtime closed the descriptor — one this program never opened and does not
own. The number is then free for the next `open` to reuse.

It surfaced as a SQLite error in a test that has nothing to do with passwords:

    init: locking protocol (15)

The test suite opens many descriptors, one of them SQLite's. A garbage
collection between the password read and the next database call closed it, and
SQLite saw its own file vanish. It passed in isolation and failed in the full
run, which is what a use-after-close looks like.

### Why it was not obvious

Every test of the feature passed. The read returns the right bytes, refuses an
empty secret, strips only the terminator, and takes one line rather than the
whole stream. None of that touches ownership. The damage happens later, to
something else, when the collector runs — so the failure appears in an unrelated
test, attributed to an unrelated subsystem.

### Fix

The descriptor is duplicated with `dup(2)` and the copy is what gets wrapped, so
the finalizer closes a descriptor this program owns. The copy is marked
close-on-exec.

`TestSecretFromFDDoesNotCloseTheCallersDescriptor` reads a secret, drops the
reader, forces collection, and then requires the caller's pipe to still stat and
still accept a write. Mutation-checked: adopting the original descriptor fails it
with `bad file descriptor`.

## D11 — A vault with edited hosts could not be restored or paired

- Found: live audit on macOS and an Ubuntu VM, after `go test ./...` passed
- Severity: backups and pairing failed for any vault used past its first day
- Fixed in: `internal/vault/store_install.go` (`Store.Install`), `internal/vault/restore.go`

### What happened

`sshstate restore` failed with `put record … at rev 4: no stored head to build
on`. An export, a relay recovery copy, and a pairing snapshot all carry each
record's current head. Restore and join installed those heads through
`ApplyRemoteBatch`, which enforces the revision chain and so only accepts rev 1
into an empty store.

The failure also left a half-written vault: the genesis, wrappers, membership,
and devices were each committed separately before the records failed, so a
retry refused with `a vault already exists`.

### Why it survived until a test found it

Every restore, recover, and pairing test snapshotted hosts that had only been
created, never edited, so every head was rev 1.

### Fix

`Store.Install` writes the whole vault, heads included, in one transaction.
Heads go in as heads; the snapshot's signatures and digests are verified before
it reaches the store. `TestRestoreInstallsHostsAtTheirEditedRevision`,
`TestPairingInstallsHostsAtTheirEditedRevision`, and
`TestInstallAcceptsHeadsPastTheirFirstRevision` fail when heads go through the
chain check. `TestAFailedInstallLeavesNoVault` fails when the genesis is written
outside the transaction.

## D12 — A failed recovery left an authorized device behind

- Found: live audit, recovering against a relay
- Severity: a device nobody holds stayed authorized to write
- Fixed in: `internal/vault/store_install.go`, `internal/vault/restore.go`

### What happened

Restore published the replacement device's enrolment to the relay before it
wrote anything locally. When the local install then failed (D11), the relay kept
the enrolment and every other device learned of an active device that did not
exist.

### Fix

The enrolment is published from inside the install transaction, after every
local write has succeeded and before commit; if the relay refuses, the
transaction rolls back. `TestAFailedInstallLeavesNoVault` fails when the
announcement runs before the writes, and
`TestAnInstallWhoseAnnouncementFailsLeavesNoVault` fails when it runs after
commit.

### Not guarded

Both tests exercise `Store.Install`. Moving the `Publish` call in `Restore` back
above `store.Install` passes every test: making `Restore` fail locally needs an
archive that verifies yet cannot be installed, and no test builds one.

## D13 — The relay's recovery copy went stale

- Found: live audit, recovering after pairing
- Severity: recovery failed with `chain_seq is 2, expected 3` once the vault had changed
- Fixed in: `internal/daemon/sync.go` (`refreshRecovery`), `internal/relay/envelopes.go`

### What happened

The daemon uploaded recovery material only on `connect`. A later pairing or
revocation left the copy with an old membership chain, so the recovered device's
enrolment did not extend the relay's chain, and later edits were missing from
it. Each `connect` also added another copy at the same epoch, and the relay
served whichever had the highest random id.

### Fix

Sync, approve, and revoke refresh the copy whenever the chain head or record
cursor has moved since the last upload. An upload replaces older recovery copies
at the same or an earlier epoch. `TestRecoveryAfterPairingKnowsTheJoinedDevice`,
`TestRecoveryCarriesWhatTheLastSyncPublished`, and
`TestRecoveryAfterARevocationKnowsOfIt` each fail when their site stops
refreshing, or when the state key drops the chain or the cursor.
`TestTheNewestRecoveryUploadIsTheOneServed` fails without the replacement.

## D14 — A joining device could give up mid-delivery

- Found: live audit, a second pairing on the same relay
- Severity: pairing failed after both fingerprints matched
- Fixed in: `internal/enroll/pairing.go` (`ErrNotDelivered`)

### What happened

The approver stores the key bundle on the pairing session, then appends the
enrolment to the chain: two requests. A joiner polling between them saw the
bundle, asked for the chain as a device the relay did not yet know, got
`device_unknown`, and the CLI treated that as final.

### Why it survived until a test found it

The protocol tests deliver and then receive in sequence, so the window never
opened. The CLI tests poll, but the window is one round trip wide.

### Fix

`device_unknown` while fetching the chain means the delivery is still in
progress, and `Receive` reports it as `ErrNotDelivered` so the poll continues.
Reordering the approver instead would leave an enrolled device with no keys
whenever the session expired between the two requests.
`TestAJoinerPollingMidDeliveryKeepsWaiting` runs the joiner from inside the
relay's handler for the delivery request, which holds the window open, and fails
without the mapping.

## D15 — A vault with no hosts could not be paired

- Found: while writing the regression tests for D16 and D17
- Severity: `approve` failed for any vault whose snapshot was empty
- Fixed in: `internal/daemon/pair.go`, `internal/vault/manager_sync.go` (`EnrollmentBundle`)

### What happened

`approve` failed with `snapshot_length is zero`. The approver sealed and bound a
snapshot even when it held no records, and the bundle validator correctly
refuses a zero length: the protocol says an empty snapshot is sent as no
snapshot, with digest and length both null.

### Why it survived until a test found it

Every pairing test started from a vault with at least one host in it.

### Fix

With no records, no snapshot is sealed and the bundle carries neither field.
`TestPairingAVaultWithNoHostsYet` fails if either side goes back to always
binding one.

## D16 — A device that joined after a removal could not follow a resurrection

- Found: while fixing D11, by reading `Manager.Snapshot`
- Severity: sync stopped for good on devices restored or paired after a removal
- Fixed in: `internal/vault/manager_sync.go` (`Snapshot`), `internal/vault/store_records.go` (`AllRecords`)

### What happened

Snapshots were built from live records only, so a removed host's tombstone never
reached a device that joined later. When another device resurrected the host,
the next revision arrived with nothing to build on, and every sync after that
failed with `no stored head to build on`.

### Fix

Snapshots carry every head, tombstones included, which is what the checkpoint's
`deleted` flag was for. The counts shown to the user still count only live
records. `TestADeviceThatJoinsAfterARemovalFollowsItsResurrection` fails when
snapshots go back to live records only, and `TestRestoreKeepsARemovedHostRemoved`
fails when restore counts the tombstone.

## D17 — An unsynced edit dropped its host from a pairing snapshot

- Found: while fixing D16
- Severity: the joined device never received the host, and could not sync once the edit was published
- Fixed in: `internal/daemon/pair.go` (`handlePairDeliver`)

### What happened

A pairing snapshot holds only accepted records, so a head still waiting in the
outbox was skipped. The store keeps only heads, so when an existing host had an
unsynced edit, the whole host was dropped. Once the edit was published, the
joined device received a revision it had no parent for.

### Fix

The approver syncs before it builds the snapshot.
`TestPairingWhileAnEditIsUnsyncedStillGivesTheJoinerThatHost` fails without the
sync.

An edit could still land between that sync and the snapshot. An accepted-only
snapshot now refuses with `ErrUnsyncedEdit` when an unsynced head edits an
existing record, and the approver syncs again, up to three times, before giving
up. The joiner's bundle is checkpointed against that same snapshot rather than a
second one taken later. `TestAnAcceptedSnapshotRefusesAnUnsyncedEditToAnExistingHost`
fails without the refusal, and also fails if a brand-new unsynced host is
refused, since the joiner can pull that from its first revision.

### Not guarded

The retry loop in `syncedSnapshot` is not exercised: no test lands an edit
between its sync and its snapshot, so returning on the first refusal passes
every test.

## D18 — Bootstrapping a second relay broke `connect` and spent the secret

- Found: while writing the recovery-refresh tests for D13
- Severity: the new relay's one-time bootstrap secret was consumed and the vault was left half-connected
- Fixed in: `internal/daemon/sync.go` (`handleConnect`)

### What happened

`connect <new-relay> --bootstrap-secret` on a vault already connected elsewhere
created the vault on the new relay and then failed with
`since=1 is past through=0`, because the record cursor belonged to the old relay.
The move could never have worked. A relay accepts a record only from its first
revision, and a device keeps only each record's latest revision, so there is
nothing to replay.

### Fix

Bootstrapping is refused before the secret is sent whenever the vault already
has a relay. `connect` without a secret still switches the address, for a relay
that has only moved. `TestBootstrappingASecondRelayIsRefusedBeforeTheSecretIsSpent`
fails without the refusal, and `TestConnectingToTheSameRelayAtANewAddress` fails
if the refusal also blocks a plain address change. Moving a vault to a new relay
remains unsupported.

## D19 — A restored vault could spend a new relay's secret and strand itself

- Found: checking `docs/cli-flows.md` against the code before v0.1.1
- Severity: the documented way to publish a restored vault left it attached to a relay that could never accept it
- Fixed in: `internal/daemon/sync.go` (`handleConnect`)

### What happened

The draft CLI guide said a restored vault could be published to a new, empty
relay with `connect --bootstrap-secret`. Bootstrap uploads only the genesis
device's root event, so the relay did not know the restored device, and every
request after that failed with `device_unknown`. By then the secret was spent
and the relay URL recorded. The restored device also holds only each record's
latest revision, which a new relay would refuse anyway (D18).

### Fix

Bootstrapping is refused before the secret is sent whenever the local
membership chain has more than its root event. Only the machine that created
the vault, before it first connected, can start a relay; a restored, recovered,
or paired device cannot. The guide now says so.
`TestARestoredVaultCannotStartANewRelay` fails without the refusal, and then
starts the relay from the original machine and recovers from it, so the refusal
cannot also block the flow that works.
