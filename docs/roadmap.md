# Roadmap

sshstate is a stable MVP for single-user self-hosting on macOS and Linux.
Releases stay on the `0.x` line and may require upgrading clients and the relay
together.

Recovering from a lost relay, or one restored from an older backup, is done:
see [Lose or restore the relay](cli-flows.md#8c-lose-or-restore-the-relay).

## Parked until needed

- Master-key rotation, specified in [rotation.md](rotation.md). It starts when a
  vault key is suspected exposed, a suite transition is required, or a user
  needs in-place key replacement.
- Narrowly scoped agent sockets for delegating one host to a tool.
