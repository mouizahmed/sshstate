# Roadmap

sshstate is a stable MVP for single-user self-hosting on macOS and Linux.
Releases stay on the `0.x` line and may require upgrading clients and the relay
together.

## Next: recovering from a lost relay

Today a relay's data volume is the only copy of its history. A new, empty relay
refuses an existing vault, and a relay restored from an older backup stops every
device that synced after the backup.

The planned fix:

- start a new or restored relay from the most up-to-date device, which uploads
  the vault's genesis, membership chain and current records;
- let every other device rejoin it explicitly, uploading what the relay lacks
  and keeping differing edits aside as conflicts.

## Parked until needed

- Master-key rotation, specified in [rotation.md](rotation.md). It starts when a
  vault key is suspected exposed, a suite transition is required, or a user
  needs in-place key replacement.
- Narrowly scoped agent sockets for delegating one host to a tool.
