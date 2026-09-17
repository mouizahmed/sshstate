# deploy

Container and service-manager assets.

- `Dockerfile` / `compose.yaml` — the sync relay.
- launchd `.plist` and systemd user `.socket`/`.service` units for socket
  activation — launchd ships with the client in Milestone 1; systemd is
  Milestone 3a.

## Running the relay

The supported packaged topology is:

```text
clients --HTTPS--> operator reverse proxy --HTTP/loopback--> relay container --> SQLite volume
```

A relay holds exactly one vault for one user, so it needs no separate database
service: the relay container and its SQLite volume are the whole deployment.

The production path requires a Linux host with Docker Compose, a persistent
disk, a DNS name, and an existing reverse proxy or ingress that can obtain a
valid certificate. sshstate deliberately does not bundle nginx, Caddy, DNS, or
certificate automation. Running the static server binary directly is possible,
but its service supervision, user, filesystem permissions, TLS proxy, and
updates are operator-owned rather than a second supported deployment recipe.

The relay stores ciphertext, signatures and cursors. Compromising it does not
reveal vault plaintext or permit record forgery without an authorized device
key, but it can destroy availability, observe traffic metadata, withhold
updates, or maintain isolated forks. The persistent volume is the relay's only
complete copy of accepted history and must be backed up.

### 1. Create the one-time bootstrap secret

```sh
head -c 32 /dev/urandom | base64 > deploy/bootstrap.secret
chmod 600 deploy/bootstrap.secret
cp deploy/bootstrap.secret ~/bootstrap.secret.for-first-client
sudo chown 65532:65532 deploy/bootstrap.secret
```

The container runs as UID 65532 and reads the file through a bind mount, so the
file has to belong to that user. With any other owner, mode 600 keeps the relay
out too, and it restarts in a loop with
`read bootstrap secret: open /run/secrets/sshstate_bootstrap: permission denied`.
Keep the copy for the first client (step 4) before changing the owner, move it
there privately, and delete it afterwards.

256 bits, used exactly once to connect your vault. The relay stores only its
hash and disables bootstrap permanently afterwards; changing the file later does
not reopen registration. There is no other account creation path.

### 2. Start it

The Compose file defaults to the current release tag, never `latest`:

```sh
cd deploy && docker compose up -d
```

For a production deployment, verify the image and pin `SSHSTATE_IMAGE` to the
digest as shown below. Release tags are easier to read, but a registry tag can
move while a digest cannot. `0.x` client and relay versions may require a
coordinated upgrade.

To build from the checked-out source instead:

```sh
cd deploy
SSHSTATE_IMAGE=sshstate-server:local docker compose up -d --build
```

The container runs as UID 65532 with a read-only root filesystem, no
capabilities, and `no-new-privileges`. It binds `127.0.0.1:8080` on the host,
not a public interface. Logs use Docker's bounded local driver and the
30-second stop grace period exceeds the relay's 15-second graceful HTTP
shutdown deadline. The image is about 21 MB: a static binary on distroless,
with no shell and no package manager inside.

#### Verifying the image

Each release signs the image by digest with Sigstore cosign, using the release
workflow's own identity. A tag can later be moved to different content; a digest
cannot, so the signature is over the digest.

```sh
digest=$(docker buildx imagetools inspect \
  ghcr.io/mouizahmed/sshstate-server:v0.1.4 --format '{{.Manifest.Digest}}')

cosign verify "ghcr.io/mouizahmed/sshstate-server@${digest}" \
  --certificate-identity-regexp '^https://github.com/mouizahmed/sshstate/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Pin the verified digest for Compose:

```sh
printf 'SSHSTATE_IMAGE=ghcr.io/mouizahmed/sshstate-server@%s\n' "$digest" > .env
docker compose up -d
```

The `.env` file contains no credential. Keep it with the deployment so a later
`docker compose up` cannot silently switch the relay image.

### 3. Put HTTPS in front of it

The relay speaks ordinary HTTP/1.1 on host loopback and expects an
operator-managed terminating reverse proxy. TLS certificate validation is
mandatory on clients, so the public relay URL must be `https://`. WebSocket
upgrade headers are unnecessary: the relay has no WebSocket endpoint.

Place this location inside the proxy's HTTPS `server` block:

```nginx
location / {
    proxy_pass http://127.0.0.1:8080;

    # REQUIRED. The request signature covers the authority, so the Host the
    # client signed has to reach the relay unchanged. nginx's default rewrites
    # it to the upstream name, and every signed request then fails with
    # "signature does not verify" — which looks like a cryptography problem and
    # is not one.
    proxy_set_header Host $http_host;

    proxy_http_version 1.1;
    client_max_body_size 256m;        # pairing snapshots and recovery archives stream up to 256 MiB
    # large_client_header_buffers 4 8k is nginx's default and is enough; see below.
}
```

**Measured, not assumed.** With this configuration and nginx's default header
buffers, a real signed request went through: the `Signature` header is **4423
bytes**, which fits the default 8 KB buffer with room to spare. Dropping to
`large_client_header_buffers 4 4k` makes nginx answer `400` with its own error
page before the relay sees anything; the client detects that case and says so,
but the request does not arrive. Apache's `LimitRequestFieldSize` defaults to
8190 bytes and is likewise sufficient.

Do not let the proxy rewrite the request path, query, or the `Content-Digest`,
`Idempotency-Key`, `SSHState-Vault` and `SSHState-Device` headers: all of them
are covered by the request signature, and a rewrite invalidates it. Do not
redirect signed requests.

The proxy is not an authorization boundary and the relay does not trust
`X-Forwarded-For` or similar identity headers. Restrict the upstream listener to
loopback as Compose does; do not publish port 8080 on a public interface.

If you are running without a proxy for development, pass `-public-http` so
signatures are verified against an `http` authority, and keep the listener on
loopback.

### 4. Connect your vault

On the first client, create and unlock a vault with `sshstate setup`. Make the
bootstrap secret file available locally to that client through a private
transfer, then connect it to the relay:

```sh
sshstate connect https://relay.example.com --bootstrap-secret /path/to/bootstrap.secret
```

This uploads genesis, public membership, ciphertext, and the device and recovery
envelopes from the existing vault. The bootstrap secret is then spent. See the
[CLI flows](../docs/cli-flows.md) for pairing another machine and recovery.

### 5. Update safely

Read the release notes first. If they require coordinated versions, update the
clients and relay as one operation.

1. Back up the relay data volume (see below).
2. Verify the new image and replace `SSHSTATE_IMAGE` in `.env` with its digest.
3. Run `docker compose pull && docker compose up -d`.
4. Confirm `docker compose ps` shows the relay running and an existing client can complete `sshstate sync`.

Never run `docker compose down -v` for an update; `-v` deletes the named data
volume. Do not replace the database with an empty relay and bootstrap again.

### Backups, moves, and rebuilds

Back up the complete `relay-data` volume while the relay is stopped, or use a
storage-native transactionally consistent snapshot. Copying only `relay.db`
while its WAL may contain committed writes is not a valid backup.

#### Moving the relay to another host or address

The vault is not tied to the relay's host, address, or certificate, so a move is
a copy of the stopped volume:

1. Sync every machine: `sshstate sync`.
2. Stop the old relay so it accepts no more writes: `docker compose stop`.
3. Copy the volume to the new host, for example:
   ```sh
   docker run --rm -v deploy_relay-data:/from -v "$PWD":/to busybox \
     tar -C /from -czf /to/relay-data.tgz .
   ```
   and on the new host, into a volume named for its Compose project:
   ```sh
   docker volume create deploy_relay-data
   docker run --rm -v deploy_relay-data:/to -v "$PWD":/from busybox \
     tar -C /to -xzpf /from/relay-data.tgz
   ```
   Keep the owner `65532:65532`; `tar -p` preserves it.
4. Start the new relay with the same Compose file and its HTTPS proxy. It does
   not need a new bootstrap secret: bootstrap was already spent and stays spent.
5. If the address changed, run `sshstate connect <new-url>` on every machine,
   **without** `--bootstrap-secret`. If only DNS or the proxy moved and the URL
   is the same, the machines need nothing.
6. Remove the old relay once every machine has synced with the new one. Never
   run both: two relays accepting writes for one vault diverge.

While the old relay is down and a machine still points at it, `sshstate sync`
says it cannot reach the relay at the old address; that machine only needs the
`connect` in step 5.

#### Losing the relay's data, or restoring an older backup

The machines hold the vault too. Give the relay an empty volume and a new
bootstrap secret, start it, and run `sshstate connect <url> --bootstrap-secret
<file>` on the most up-to-date machine; then `sshstate connect <url> --rejoin`
on every other machine. A relay restored from a backup older than your machines
needs no secret: rejoin every machine, most up-to-date first. See
[Lose or restore the relay](../docs/cli-flows.md#8c-lose-or-restore-the-relay).

The recovery kit restores *access* to retained ciphertext — it is not a backup
of storage that no longer exists (project brief §7.2). Keep an encrypted client
export as well; it carries its own checkpoint and works with the relay
unavailable. A relay backup is no longer the only way back after losing the
relay: your machines can start a new one. It still saves every machine a rejoin.

### No telemetry

The relay makes no outbound connections and never logs request bodies.
