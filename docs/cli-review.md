# CLI review — what the command surface was missing

Written 2026-09-15, after Milestone 3a and before client distribution.
All three phases were implemented the same day; see the status column below.

Distribution is the point at which strangers meet this CLI cold, with no author
sitting next to them. This is an audit of all 25 verbs against that moment: what
cannot be done at all, what can only be done by knowing something undocumented,
and where the surface contradicts itself.

Three of the findings are functional gaps, not polish. They are grouped first
because they change what the tool can do, not how pleasant it is.

---

## A. Things the CLI cannot do

### A1 — There is no way to list hosts or keys

`status` reports counts:

```
hosts        3
keys         2
known hosts  7
```

There is no verb that shows *which*. The control API already answers both
(`GET /v1/hosts`, `GET /v1/keys`) and the daemon already serves them; only the
CLI surface is absent.

This is not cosmetic, because of A2.

It is also now a spec obligation. Withdrawing the TUI (§3.1, 2026-09-15) moved
its responsibilities onto the CLI in as many words: *host browsing, ordered key
references and public fingerprints, lock and sync status, conflict review and
resolution*. Two of those five have no command.

### A2 — A key's record id cannot be recovered, and `add` demands one

`add-key` prints the id once:

```
Added ssh-ed25519 SHA256:1U/cIC1wrcXFpSS8n1E18gk0b8Y2T9TrITpfAcaJ4T8
record a3f91c2d4e5b6789a3f91c2d4e5b6789
```

`add --key` accepts nothing else: the daemon validates 32 lowercase hex digits
and rejects everything else. Close the terminal and that key can never be
attached to a host again. The vault still holds it, the agent still serves it,
and there is no path back to its identifier.

Every id-taking verb has the same shape — `resolve <conflict-id>`,
`revoke <device-id>`, `trust --approve <id>` — but those at least have a listing
command to copy from (`conflicts`, `devices`, `trust`). Keys do not.

### A3 — A host or a key can be added but never removed

There is no `remove`, `rm`, or `delete` for either. The brief's §3.1 command list
never contained one, so this was not dropped; it was never specified.

The storage layer is ready for it. Tombstones are defined (§5.2: an encrypted
empty object, so a deletion is the same shape as any other revision), and
deletion is handled on read in six places across the vault store, the sync
engine and the relay. `resolve --resurrect` exists specifically for *"the record
this edit belonged to was deleted"* — a state no command can currently produce.
The only writer of `Deleted: true` anywhere is conflict retirement.

So the machinery is built and exercised; the verb is missing.

Known-host records are a deliberate exception and must stay one: §3.4 rejects
generic deletion of them in v1, requiring a signed `@revoked` record instead.
That reasoning does not extend to hosts and keys.

---

## B. The setup flow

### B1 — `install --service` requires a daemon, then kills it

Registering a service needs no daemon: it resolves the binary path, writes the
definition, and runs `launchctl bootstrap` or `systemctl --user enable --now`.
No vault, no socket, no keys.

But `--service` is a flag on `install`, and `install` first calls `Generate`,
which needs an unlocked vault and therefore a running daemon. So the user must
start a foreground daemon, unlock it, and then watch `installService` shut it
down — which silently drops the unlock, because the keys lived in that process.

The fix is ordering: when `--service` is set, register first, then let the
generate step activate the daemon through the socket the service just created.

### B2 — First run is five ordered commands and the order is not guessable

```
sshstate init --kit ~/kit.txt
sshstate daemon &
sshstate unlock
sshstate add-key ~/.ssh/id_ed25519
sshstate install --service
```

Nothing tells the user that `install --service` must come last, or that the
daemon they started is temporary. `init` ends by suggesting
`sshstate daemon, then sshstate add-key`, which leads directly into the
throwaway-daemon path.

---

## C. Contradictions in the surface

### C1 — The subject of a command is sometimes positional, sometimes a flag

| verb | subject |
|---|---|
| `resolve <conflict-id>` | positional |
| `revoke <device-id>` | positional |
| `trust --approve <id>` | flag |

`trust` is the newest of the three and the odd one out. Approving an observation
and resolving a conflict are the same kind of act.

### C2 — `--yes` exists on two destructive verbs out of several

`revoke` and `uninstall` take `--yes`. `uninstall --purge` additionally requires
typing the vault id. Nothing else has a confirmation bypass, which matters for
scripting, and A3's removal verbs will need one on day one.

### C3 — Verb names have drifted from the brief

The brief §3.1 lists `sshstate server connect <url>`; the implementation is
`sshstate connect <url>`. The brief also plans `sshstate rotation status` and
`rotation resume` — two-word subcommands, where every other verb is flat.

Either is defensible. Neither is recorded as a decision, and rotation is still
unwritten, so the shape should be settled before it is built rather than after.

---

## Plan

Ordered by whether it blocks distribution. All done.

### Phase 1 — close the functional gaps

1. **Done — `sshstate hosts`** — alias, hostname, user, port, jump, key count, record id.
2. **Done — `sshstate keys`** — record id, fingerprint, algorithm, comment.
3. **Done — accept a unique prefix** wherever a record id is taken, plus a fingerprint
   or comment match for keys. Ambiguity is an error that lists the candidates.
   Full ids keep working.
4. **Done — `sshstate remove <alias>` and `sshstate remove-key <id>`**, writing
   tombstones. `remove-key` refuses while a host still references the key, and
   names the hosts. Both take `--yes`. Known-host records stay undeletable.

Gate: `resolve --resurrect` gets a test that reaches it through `remove`, which
is the path it was written for and has never had.

### Phase 2 — setup

5. **Done — reorder `install --service`** to register before generating.
6. **Done — `sshstate setup`**, plus a standalone `sshstate service` verb so
   registration no longer has to travel with `install` — one guided command: init, kit confirmation, service
   registration, unlock, offer to import `~/.ssh/config`, install the Include.
   The five-command sequence becomes one, and the individual verbs stay for
   people who want them.

### Phase 3 — consistency

7. Done — subjects positional everywhere; `trust <id>...` alongside `--all`.
8. Done — `--yes` on `remove` and `remove-key`, alongside `revoke` and
   `uninstall`.
9. Done — decision record 0003 settles flat verbs, positional subjects and
   prefix matching, and amends the brief's command list.

### Not in scope

- OS keychain unlock and prompt-on-sign: deferred past v1 by §7.3.
- The 15-minute idle and 8-hour hard expiry: deliberate, §3.3.
- Anything that would let a secret be passed as a command-line argument: §3.1
  forbids it. An explicit file descriptor is the allowed alternative and is not
  implemented, which is worth revisiting for headless use, separately.
