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
