# Roadmap

sshstate is a stable MVP for single-user self-hosting on macOS and Linux.
Releases stay on the `0.x` line and may require upgrading clients and the relay
together.

## Parked until needed

- Master-key rotation, planned for a future iteration. It starts when a vault
  key is suspected exposed, a suite transition is required, or a user needs
  in-place key replacement.
- Narrowly scoped agent sockets for delegating one host to a tool.
