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
| Stop using sshstate on a machine | [Uninstall](#9-stop-using-sshstate-on-a-machine) | Vault remains unless purged |

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
independent channel before accepting OpenSSH's prompt. sshstate captures host
keys for review; approve a verified pending observation with `sshstate trust
<observation-id>`. `sshstate trust --all` approves every pending observation,
so use it only after checking them all. Changed or conflicting host keys remain
pending until reviewed.

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
```

The daemon holds keys while unlocked. It locks after 15 minutes idle or 8
hours after password entry, and starts locked after a restart. Existing SSH
sessions continue after `lock`; new authentication through its agent needs an
unlock. For a headless password source, `sshstate unlock --password-fd <n>`
reads from an already open file descriptor; the password is not a command-line
argument.

`setup` registers the daemon with launchd on macOS or systemd user units on
Linux. The manual controls are `sshstate service` to register, `sshstate service
--remove` to unregister, and `sshstate daemon` to run in the foreground. The
foreground daemon is useful on a platform without service integration. If you
choose the manual route, `sshstate init --kit <path>` creates only the vault;
then start the daemon, `unlock`, add/import hosts, and `sshstate install` to
activate the SSH `Include`. `sshstate install --service` can register the
service as part of that manual route. For unattended installation, choose
`install --import-trust` or `install --skip-trust` explicitly when matching
entries already exist in `known_hosts`.

## 4. Self-host a relay and connect the first machine

A single-machine vault works without this section. To share it, run the relay
on a server with persistent storage and put HTTPS in front of it. The complete
Compose and reverse-proxy instructions are in [deploy/README.md](../deploy/README.md).
The container exposes port 8080 on server loopback; the proxy must preserve
the signed request's `Host` header. Keep a backup of the relay's persistent
volume as well as encrypted exports.

On the server, from the repository root, the documented Compose path starts
with a one-time secret:

```sh
head -c 32 /dev/urandom | base64 > deploy/bootstrap.secret
chmod 600 deploy/bootstrap.secret
cd deploy && docker compose up -d
```

Once `https://relay.example.com` reaches the relay, make the bootstrap secret
file available **locally to the first client** through a private transfer, then
on that client run:

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
sshstate resolve <conflict-id>   # apply the preserved edit if you choose it
sshstate sync
```

If the record was deleted, `resolve` will explain that applying the edit would
bring it back; use `sshstate resolve <conflict-id> --resurrect` only if that is
what you want. Review the result with `hosts`, `keys`, or `trust` as appropriate,
then sync the other machines.

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
The restored data is as current as the export. If the original relay is still
available and you want to rejoin it, use the relay recovery path below on a
fresh machine instead. To publish the restored vault to a **new, empty relay**,
set up that relay with a new bootstrap secret and use `sshstate connect
<relay-url> --bootstrap-secret <secret-file>`.

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

## 9. Stop using sshstate on a machine

```sh
sshstate uninstall
```

This removes the managed `Include` from `~/.ssh/config`, unregisters the local
service, and preserves the encrypted vault and your SSH files. If `setup
--import` commented out host blocks in your config, `uninstall` does not
reactivate them; restore the relevant blocks from the config backup or edit
them back before relying on those aliases. For a connected vault, uninstall
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
| Guided setup and health | `setup`, `status`, `doctor`, `unlock`, `lock` |
| Hosts and SSH keys | `hosts`, `keys`, `add`, `edit`, `remove`, `add-key`, `remove-key`, `import`, `trust` |
| Multiple machines | `connect`, `pair`, `approve`, `sync`, `devices`, `revoke`, `conflicts`, `resolve` |
| Backup and recovery | `export`, `restore`, `recover`, `confirm-recovery` |
| Manual setup and removal | `init`, `service`, `daemon`, `install`, `uninstall` |

`sshstate --help` lists the commands; `sshstate version` prints the version.
Master-key rotation is planned but is not yet a CLI flow.
