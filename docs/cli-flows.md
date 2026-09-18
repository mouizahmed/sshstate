# CLI flows, from first run to recovery

This is a map of the ways to use `sshstate`, followed by commands for each path.
Start with **one machine**. A relay is optional; it is only needed to share the
vault with other machines or recover from the relay. Connections themselves use
ordinary `ssh`, `scp`, or an editor that uses OpenSSH. There is no `sshstate ssh`.

Commands below assume `sshstate` is installed on your `PATH`. If you built it
locally with `go build -o sshstate ./cmd/sshstate`, use `./sshstate` instead.
Values such as `<alias>`, `<vault-id>`, and `<device-id>` are placeholders. Run
`sshstate <command> --help` for the full flags of any command.

## Choose a path

| Situation | Start here | Then |
| --- | --- | --- |
| Fresh machine, existing SSH config | [Import during setup](#1a-first-machine-import-existing-ssh-config) | Check native SSH and trust |
| Fresh machine, adding hosts yourself | [Create a local vault](#1b-first-machine-add-hosts-yourself) | Check native SSH and trust |
| Vault already exists on this machine | `sshstate setup` | It resumes unfinished setup |
| Want another machine | [Run a relay](#4-self-host-a-relay-and-connect-the-first-machine), then [pair](#5-pair-another-machine) | Sync edits on both |
| Lost a machine, another survives | [Pair a replacement](#5-pair-another-machine) | Revoke the lost device |
| All devices lost, have an export | [Restore from an export](#8a-restore-from-an-encrypted-export) | Set up the new machine |
| All devices lost, relay survives | [Recover from the relay](#8b-recover-from-a-relay) | Set up and revoke lost devices |
| Relay data lost, or restored from an older backup | [Restart it from a machine](#9-lose-or-restore-the-relay) | Rejoin the others |
| Stop using sshstate on a machine | [Uninstall](#10-stop-using-sshstate-on-a-machine) | Vault remains unless purged |

The common path is:

```text
install CLI → setup vault + recovery kit → unlock → add/import hosts
            → install SSH Include → native ssh → review trust
                                  │
                                  └→ optional relay → pair machines → sync
                                                            │
                                                            └→ export/recover
```

## 1A. First machine: import existing SSH config

Use this if `~/.ssh/config` already has hosts and `IdentityFile` paths that you
want sshstate to manage.

```sh
sshstate setup --import ~/.ssh/config
sshstate status
sshstate hosts
sshstate keys
sshstate doctor
ssh <alias>
```

`setup` creates a vault, asks for a password for **this device**, writes the
recovery kit to `~/sshstate-recovery-kit.txt` by default, and asks you to type
the kit's checksum. It then registers the daemon, unlocks the vault, imports
hosts and their keys, installs the managed `Include` in `~/.ssh/config`, and
comments out successfully imported source host blocks after backing up the
config. It may ask how to handle matching entries in your existing
`~/.ssh/known_hosts`. Review that choice; your own `known_hosts` is not edited.

Store the kit separately from the device. The device password unlocks this
device; the kit is what lets you recover when all devices are gone. `setup` is
safe to rerun when a step was interrupted. If the kit checksum was not
confirmed, save the kit and finish with:

```sh
sshstate confirm-recovery --kit ~/sshstate-recovery-kit.txt
sshstate setup
```

The SSH config importer accepts a strict subset of OpenSSH configuration. If
it reports unsupported directives or a host that differs from the vault, fix
those entries or resolve the reported conflict and rerun `setup`. It stops
before retiring conflicting source blocks. To see the proposed import first on
an initialized and unlocked vault:

```sh
sshstate import ~/.ssh/config --with-keys --dry-run
```

## 1B. First machine: add hosts yourself

Start the same setup without an import:

```sh
sshstate setup
sshstate add-key ~/.ssh/id_ed25519
sshstate keys
sshstate add prod --hostname 10.0.0.5 --user ubuntu --key <key-id-or-comment>
sshstate setup
sshstate doctor
ssh prod
```

The first `setup` creates and unlocks the vault. With no hosts yet, it pauses
before installing the SSH `Include`; add a host and rerun it. `add-key` imports
the private key into the encrypted vault and leaves the original file alone.
`keys` shows its ID, fingerprint, and comment. `--key` accepts an unambiguous
ID, ID prefix, fingerprint, or comment. For several keys, give a comma-separated
list in the order OpenSSH should offer them. A host can also use `--port` and
`--jump <managed-alias>`; add the jump host first.

You can add a host without `--key`, but the managed agent then has no identity
to offer for that host. After adding a key, use `sshstate edit <alias> --key
<key-id-or-comment>` to attach it.

### Check SSH and host trust

```sh
sshstate status       # vault, unlock state, host/key counts, relay, Include
sshstate doctor       # inspect OpenSSH integration
ssh -G prod           # see the effective OpenSSH settings, if needed
ssh prod              # use native OpenSSH
sshstate trust        # review host-key observations
```

On a first connection, verify the server's host-key fingerprint by your usual
independent channel before accepting OpenSSH's prompt. sshstate captures the
keys you accept. A first key for a host is recorded as approved and reaches your
other machines on the next sync. A key that differs from one already approved
for that host is recorded as **pending**: your other machines do not trust it
until you approve it with `sshstate trust <observation-id>`, but OpenSSH on the
machine where you answered yes already uses it. `sshstate trust --all` approves
every pending observation, so use it only after checking them all.

When a server's host key changes, OpenSSH refuses to connect and names the
capture file. Confirm the new fingerprint out of band, then:

```sh
ssh-keygen -f ~/.ssh/sshstate/known_hosts.capture -R <host>   # as OpenSSH suggests
ssh <alias>                                                    # accept the new key
sshstate trust                                                 # the new key is pending
sshstate trust <new-observation-id>
sshstate trust <old-observation-id> --revoke
sshstate sync
```

`--revoke` publishes the key as `@revoked`, so OpenSSH refuses it on every
machine, including one whose capture file still holds it. Use it for a retired
key, or for anything approved by mistake. A revoked observation cannot be
approved again.

Only keys that agree are shared. If two approved keys of the same type disagree
for one host, because you approved a replacement or because two machines each
saw a different key first, neither is shared until one is revoked. Each machine
keeps using the key it accepted itself. `trust`, `status`, and `doctor` point
this out. A host that genuinely serves several keys of one type can therefore
only be trusted machine by machine.

## 2. Manage hosts, keys, and imports later

```sh
sshstate hosts
sshstate keys
sshstate add-key ~/.ssh/new_key --comment new-key
sshstate add staging --hostname staging.example.com --user ubuntu --key new-key
sshstate edit staging --port 2222
sshstate edit staging --jump prod
sshstate edit staging --jump none
sshstate edit staging --key <first-key>,<second-key>
sshstate remove staging
sshstate remove-key <key-id-or-comment>
```

`edit` can also change `--alias`, `--hostname`, and `--user`. A key that a host
still references cannot be removed; edit or remove those hosts first. If other
hosts use a host as a jump, update those dependencies before removing it.
Removing a host leaves its keys in the vault. These changes regenerate the
managed SSH configuration.

For an additional SSH config file, preview the import and then apply it:

```sh
sshstate import /path/to/other-config --with-keys --dry-run
sshstate import /path/to/other-config --with-keys
```

`--with-keys` imports referenced `IdentityFile` private keys. Without it, the
keys must already be in the vault. If the file is **your own** `~/.ssh/config`
and the managed `Include` is active, `--comment-source` backs up that file and
comments out successfully imported host blocks so OpenSSH uses the managed
version. It cannot edit another config file. Plain `import` leaves source
blocks active, which can affect which SSH identity OpenSSH offers; run `doctor`
afterward.

## 3. Locking, unlocking, and the daemon

```sh
sshstate lock
sshstate status
sshstate unlock
sshstate change-password
```

`change-password` asks for the current password and re-encrypts this device's
local keys under the new one. Other devices keep their own passwords, and the
recovery kit does not change.

The daemon holds keys while unlocked. It locks after 15 minutes idle or 8
hours after password entry, and starts locked after a restart. Existing SSH
sessions continue after `lock`; new authentication through its agent needs an
unlock. For a headless password source, `sshstate unlock --password-fd <n>`
reads from an already open file descriptor; the password is not a command-line
argument.

`setup` registers the daemon with launchd on macOS or systemd user units on
Linux. The service does not inherit your shell, so registration copies
`SSL_CERT_FILE`, `SSL_CERT_DIR`, and the `*_PROXY` variables from the shell
that ran it. If those values change, register again with `sshstate service`.
Use `sshstate service --remove` to unregister it, or `sshstate daemon` to run
it in the foreground.

For manual setup, `sshstate init --kit <path>` creates the vault. Start the
daemon, unlock, add or import hosts, then run `sshstate install` to activate
the SSH `Include`. Add `--service` to register the daemon. For unattended
installation, choose `--import-trust` or `--skip-trust` when matching entries
already exist in `known_hosts`.

## 4. Self-host a relay and connect the first machine

A single-machine vault works without this section. To share it, run the relay
on a server with persistent storage and put HTTPS in front of it, either with
the bundled Caddy profile or with a proxy you already run. The complete
instructions are in [deploy/README.md](../deploy/README.md). A proxy you manage
must preserve the signed request's `Host` header. Back up the relay's persistent
volume and keep encrypted exports.

On the server, with no checkout needed:

```sh
curl -fsSLO https://github.com/mouizahmed/sshstate/releases/latest/download/compose.yaml
DOMAIN=relay.example.com docker compose --profile tls up -d
docker compose exec relay /usr/local/bin/sshstate-server new-bootstrap-secret
```

The last command prints a one-time bootstrap secret to your terminal. Drop
`--profile tls` if you are putting it behind a proxy you already run.

Save the printed secret to a file **locally on the first client** through a
private transfer, then on that client run:

```sh
sshstate unlock
sshstate connect https://relay.example.com --bootstrap-secret /path/to/bootstrap.secret
sshstate status    # copy the vault ID for pairing and recovery
sshstate sync
```

The bootstrap secret is spent when the first vault connects. Later `connect`
calls for this vault do not use it. Public relay URLs need HTTPS; loopback HTTP
is for local development. Deploying the relay is a server operation; the CLI's
`connect` enrolls an **existing** vault and uploads its records. There is no
CLI command that installs the server remotely.

## 5. Pair another machine

Keep the first machine available and unlocked. On a **fresh second machine**
that has no vault, start:

```sh
sshstate pair https://relay.example.com <vault-id> --label laptop
```

It prints a pairing session ID and waits. On the first machine:

```sh
sshstate approve <session-id>
```

Compare **all 13 groups** of the displayed fingerprint through a channel other
than the relay, then confirm on both machines. The second machine chooses its
own device password. After pairing completes, on the second machine:

```sh
sshstate setup
sshstate sync
sshstate doctor
sshstate devices
ssh <alias>
```

`setup` registers its local daemon, unlocks, and installs the SSH `Include`.
Its password is specific to that machine. Do not run `init` or create a second
vault before `pair`: pairing requires an empty local vault location. The same
flow adds a third or later machine; any authorized, unlocked machine can
approve. If a device is lost but another survives, pair a replacement and
revoke the lost device as described below. If the new machine already has
hand-written SSH host blocks, use `sshstate setup --import ~/.ssh/config` to
bring them into the paired vault, then check for conflicts and run `doctor`.

## 6. Day-to-day sync and conflicts

After changing hosts, keys, or trust on one machine, publish the changes there
and pull them on the others:

```sh
sshstate sync
sshstate status
```

`status` shows the relay and unpublished local changes. A local-only vault
reports that there is nothing to sync. If `sync` says the relay has more changes
than one run could take, run it again. Sync is an explicit command; edits do
not automatically appear on every machine.

If two devices changed the same record from the same parent, the losing edit is
kept for review:

```sh
sshstate conflicts
sshstate resolve <conflict-id>             # apply the preserved edit
sshstate resolve <conflict-id> --discard   # or drop it and keep the current version
sshstate sync
```

`conflicts` names each host and lists the fields where the kept edit differs
from the current version.

If the record was deleted, `resolve` will explain that applying the edit would
bring it back; use `sshstate resolve <conflict-id> --resurrect` only if that is
what you want. Review the result with `hosts`, `keys`, or `trust` as appropriate,
then sync the other machines.

Two machines can also make changes that are each fine alone but clash when
merged: one removes a key while the other gives it to a host, both add the same
alias, or two jump hosts end up pointing at each other. Sync still succeeds.
Every host that is still consistent stays in the SSH config. A host whose alias
is ambiguous, or whose jump host is missing or loops, is left out until fixed. A
key that is gone is no longer offered. `sync`, `status`, `hosts`, and
`doctor` list each problem with the command that fixes it. Where two hosts share
an alias, name one by its record id, as `sshstate hosts` shows it:

```sh
sshstate edit <record-id> --alias <new-alias>
sshstate sync
```

## 7. Remove access for a lost or retired machine

On another authorized and unlocked machine:

```sh
sshstate devices
sshstate revoke <device-id>
sshstate sync
```

Revocation prevents the device from writing and makes an honest relay refuse
its requests. It does not erase the vault or SSH keys that device already has;
replace SSH credentials it could use if the device is lost or compromised.
The last authorized device cannot be revoked. Revoking the device you are using
requires explicit confirmation (`--yes` is available for scripts).

## 8. Back up and recover

Take encrypted exports after important changes, choosing a **new filename**
each time:

```sh
sshstate export ~/sshstate-backup-2026-09-16.age
```

`export` refuses to overwrite a file. Store the export and recovery kit apart.
An export contains a checkpoint and can restore with the relay unavailable.
The kit alone recovers access only to ciphertext that still exists on a relay;
it does not replace a backup of that relay's storage. Test a restore on a
disposable, fresh machine before relying on a backup.

### 8A. Restore from an encrypted export

On a **fresh machine with no local vault**, with the export and matching kit:

```sh
sshstate restore /path/to/sshstate-backup.age --kit /path/to/sshstate-recovery-kit.txt
sshstate setup
sshstate doctor
ssh <alias>
```

`restore` asks for a new device password and authorizes the new device using
the kit. `setup` starts its service, unlocks, and installs its SSH `Include`.
The restored data is as current as the export. If the original relay is gone,
the restored machine can start a new one; see
[Lose or restore the relay](#9-lose-or-restore-the-relay).

### 8B. Recover from a relay

Use this when all enrolled machines are gone but the relay still holds the
vault's recovery material. On a fresh machine:

```sh
sshstate recover https://relay.example.com <vault-id> --kit /path/to/sshstate-recovery-kit.txt
sshstate setup
sshstate sync
sshstate doctor
sshstate devices
```

`recover` creates a new authorized device and device password. Its success
depends on the relay retaining valid recovery material and records. Revoke
devices you no longer control, then take a new encrypted export.


## 9. Lose or restore the relay

The relay's data is one copy of the vault's history, and every enrolled machine
holds another. If the relay's data is lost, or the relay is restored from a
backup older than your machines, start from the **most up-to-date machine**:

```sh
# on the relay host: start an empty relay; it prints a fresh bootstrap secret
# on your most up-to-date machine:
sshstate connect https://relay.example.com --bootstrap-secret /path/to/bootstrap.secret
```

The vault already had a relay, so `connect` asks before it starts a new one.
Answer yes only if the old relay is gone for good: two relays taking changes for
one vault drift apart. The machine uploads its device list, including every
revocation, and every host, key, and trust record it holds.

For a relay **restored from an older backup** there is no new secret: run the
rejoin below on the most up-to-date machine first. Its `sync` already says so:

```text
the relay's history ends at change 41, but this machine has already seen change 57, ...
to put this machine's changes back on the relay, run: sshstate connect https://relay.example.com --rejoin
```

Then, on **every other machine**, before editing anything:

```sh
sshstate connect https://relay.example.com --rejoin
```

Rejoining uploads what the relay is missing: newer versions of records, edits
not yet synced, and device-list changes such as a revocation made after the
backup. Each machine remembers the fingerprint of every version of a record it
has seen, so it can tell a version the relay has that it already built on from
one that went a different way. Nothing is overwritten silently: when the relay
holds a different version of a record, the relay's copy stays current and this
machine's copy is kept aside, listed by `sshstate conflicts`. Versions from before
this machine recorded fingerprints can be kept aside even when they did not
really diverge; `sshstate resolve <id> --discard` drops such a copy.

Once one machine rejoins a restored relay, every other machine's `sync` says the
relay was started again and names the same command. A machine revoked after the
backup stays revoked once any machine that saw the revocation rejoins. A machine
enrolled after the backup is unknown to the restored relay until a machine that
was enrolled earlier rejoins; its error says so.

`--rejoin` on a machine that already matches the relay changes nothing.

## 10. Stop using sshstate on a machine

```sh
sshstate uninstall
```

This stops the daemon, removes the managed `Include` from `~/.ssh/config`,
unregisters the local service, and preserves the encrypted vault and your SSH
files. Host blocks that
`setup --import` or `import --comment-source` commented out are reactivated, so
those aliases keep working through your own config. They are your definitions
from before sshstate managed them; edits made in sshstate since then are not in
them. Every change to `~/.ssh/config` is backed up first. For a connected vault, uninstall
offers to deregister this device. Check its result; if deregistration cannot
finish, revoke the device from another machine.

For permanent deletion of this machine's local vault:

```sh
sshstate export /path/to/new-backup.age
sshstate uninstall --purge
```

`--purge` requires the most recent export to still exist and asks you to type
the vault ID. `--yes` bypasses prompts, so use it only when that outcome is
already intended. Purging a local vault does not delete the relay's storage or
other devices. It also does not erase copies of credentials already present on
other machines.

## Command coverage at a glance

| Job | Commands |
| --- | --- |
| Guided setup and health | `setup`, `status`, `doctor`, `unlock`, `lock`, `change-password` |
| Hosts and SSH keys | `hosts`, `keys`, `add`, `edit`, `remove`, `add-key`, `remove-key`, `import`, `trust` |
| Multiple machines | `connect`, `pair`, `approve`, `sync`, `devices`, `revoke`, `conflicts`, `resolve` |
| Backup and recovery | `export`, `restore`, `recover`, `confirm-recovery` |
| Manual setup and removal | `init`, `service`, `daemon`, `install`, `uninstall` |

`sshstate --help` lists the commands; `sshstate version` prints the version.
Master-key rotation is planned for a future iteration.
