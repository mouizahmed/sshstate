# deploy

Container and service-manager assets.

- `Dockerfile` / `compose.yaml` — the sync relay.
- launchd `.plist` and systemd user `.socket`/`.service` units for socket
  activation — launchd ships with the client in Milestone 1; systemd is
  Milestone 3a.

## Running the relay

The relay stores ciphertext, signatures and cursors. It never holds a vault key
and cannot read anything it stores, so the security of your hosts does not
depend on the security of this container. What it does hold is availability: the
volume is the only copy of the synchronized ciphertext this relay has.

### 1. Create the one-time bootstrap secret

```sh
head -c 32 /dev/urandom | base64 > deploy/bootstrap.secret
chmod 600 deploy/bootstrap.secret
```

256 bits, used exactly once to connect your vault. The relay stores only its
hash and disables bootstrap permanently afterwards; changing the file later does
not reopen registration. There is no other account creation path.

### 2. Start it

```sh
cd deploy && docker compose up -d --build
```

The container runs as UID 65532 with a read-only root filesystem, no
capabilities, and `no-new-privileges`. It binds `127.0.0.1:8080` on the host,
not a public interface.

### 3. Put HTTPS in front of it

The relay speaks plain HTTP and expects a terminating reverse proxy. TLS
certificate validation is mandatory on the client side, so the relay must be
reachable over `https://`.

Two proxy settings matter:

- **Header size.** An ML-DSA-65 `Signature` header is about 4.4 KB, roughly 54%
  of the 8190-byte single-header limit Apache and nginx commonly deploy. That
  fits, but verify it against the proxy you actually run rather than trusting
  the arithmetic. nginx: `large_client_header_buffers 4 16k;`.
- **Body size.** Requests are capped at 4 MiB by the relay. nginx:
  `client_max_body_size 4m;`.

Do not let the proxy rewrite the request path, query, or the `Content-Digest`,
`Idempotency-Key`, `SSHState-Vault` and `SSHState-Device` headers: all of them
are covered by the request signature, and a rewrite invalidates it. Do not
redirect signed requests.

If you are running without a proxy for development, pass `-public-http` so
signatures are verified against an `http` authority, and keep the listener on
loopback.

### 4. Connect your vault

Not yet available. The client-side command that consumes the bootstrap secret
lands with the sync client; until then the relay starts, serves, and waits. When
it exists, connecting uploads genesis, public membership, ciphertext and the
device and recovery envelopes from an unlocked device — it does not create or
regenerate a vault.

### Backups

Back up the `relay-data` volume. The recovery kit restores *access* to retained
ciphertext — it is not a backup of storage that no longer exists (project brief
§7.2). Keep an encrypted export as well; it carries its own checkpoint and works
with the relay unavailable.

### No telemetry

The relay makes no outbound connections and never logs request bodies.
