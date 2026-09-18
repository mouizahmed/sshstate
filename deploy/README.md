# deploy

`Dockerfile` and `compose.yaml` for the sync relay.

## Running the relay

```text
clients --HTTPS--> reverse proxy (bundled or your own) --HTTP--> relay container --> SQLite volume
```

A relay holds exactly one vault for one user, so it needs no separate database
service: the relay container and its SQLite volume are the whole deployment.

It needs a Linux host with Docker Compose, a persistent disk, and a DNS name.
TLS is either the bundled Caddy or your own ingress; the default binds no public
port, so a host that already runs a proxy is left alone. Running the static
binary directly works but is not a supported recipe: supervision, permissions,
TLS and updates are then yours.

The relay stores ciphertext, signatures and cursors. Compromising it does not
reveal vault plaintext or permit record forgery without an authorized device
key, but it can destroy availability, observe traffic metadata, withhold
updates, or maintain isolated forks. The persistent volume is the relay's only
complete copy of accepted history and must be backed up.

### 1. Start it

Point a DNS record at the host. `compose.yaml` is self-contained, so it is the
only file the server needs:

```sh
curl -fsSLO https://github.com/mouizahmed/sshstate/releases/latest/download/compose.yaml
DOMAIN=relay.example.com docker compose --profile tls up -d
```

That runs the relay and a Caddy in front of it, which obtains and renews the
certificate itself. Drop `--profile tls` and the `DOMAIN` if you are bringing
your own proxy; see [step 2](#2-bring-your-own-proxy-instead) for its
configuration.

That URL serves the newest release's Compose file, which pins that release's
image by tag. The image itself is never `latest`, because `0.x` clients and
relays may need a coordinated upgrade. For production, verify the image and pin
`SSHSTATE_IMAGE` to its digest as shown below.

To build from source instead, clone the repository and, from `deploy/`:

```sh
SSHSTATE_IMAGE=sshstate-server:local docker compose up -d --build
```

The container runs as UID 65532 on distroless with a read-only root filesystem,
no capabilities, and `no-new-privileges`. It binds `127.0.0.1:8080`, not a
public interface.

#### The one-time bootstrap secret

The relay issues its own on first start and prints it once:

```console
$ docker compose logs relay
sshstate-server: bootstrap is open; this one-time secret is shown once and cannot be reprinted:

    mamdh50Jkt_txDSZlSxnfxQv8omux7U1kLViU7RSRMU

copy it to the first client now; replace it with the new-bootstrap-secret command if it is lost
```

256 bits, used exactly once to connect your vault. Only its hash is stored, so a
restart does not reprint it. If it scrolls away before you copy it, issue a
replacement — harmless while no vault has connected, and it invalidates the
previous one:

```sh
docker compose exec relay /usr/local/bin/sshstate-server new-bootstrap-secret
```

Once a vault has connected, the secret is spent and neither a restart nor a
replacement reopens registration. There is no other account creation path.

To supply your own secret instead, mount a file and pass
`-bootstrap-secret <path>` in the container's command.

#### Verifying the image

Each release signs the image by digest with Sigstore cosign, using the release
workflow's own identity. A tag can later be moved to different content; a digest
cannot, so the signature is over the digest.

```sh
release=v0.1.4   # the release you are deploying
digest=$(docker buildx imagetools inspect \
  ghcr.io/mouizahmed/sshstate-server:"$release" --format '{{.Manifest.Digest}}')

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

### 2. Bring your own proxy instead

Skip this if you started with `--profile tls`; Caddy already covers it.

The relay speaks ordinary HTTP/1.1 on host loopback. TLS certificate validation
is mandatory on clients, so the public relay URL must be `https://`. WebSocket
upgrade headers are unnecessary: the relay has no WebSocket endpoint.

<details>
<summary>nginx configuration</summary>

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

The `Signature` header is 4423 bytes, so nginx's default 8 KB header buffers
and Apache's 8190-byte `LimitRequestFieldSize` both fit it. Do not lower them:
at `large_client_header_buffers 4 4k` nginx answers `400` from its own error
page and the request never reaches the relay.

Do not let the proxy rewrite the request path, query, or the `Content-Digest`,
`Idempotency-Key`, `SSHState-Vault` and `SSHState-Device` headers: all of them
are covered by the request signature, and a rewrite invalidates it. Do not
redirect signed requests.

</details>

The proxy is not an authorization boundary and the relay does not trust
`X-Forwarded-For` or similar identity headers. Restrict the upstream listener to
loopback as Compose does; do not publish port 8080 on a public interface.

If you are running without a proxy for development, pass `-public-http` so
signatures are verified against an `http` authority, and keep the listener on
loopback.

### 3. Connect your vault

On the first client, create and unlock a vault with `sshstate setup`. Write the
secret the relay printed to a file on that client, moving it there privately,
then connect:

```sh
sshstate connect https://relay.example.com --bootstrap-secret /path/to/bootstrap.secret
```

It takes a file rather than the secret itself, which would be visible in `ps`
to every user on that machine. Delete the file afterwards.

This uploads genesis, public membership, ciphertext, and the device and recovery
envelopes from the existing vault. The bootstrap secret is then spent. See the
[CLI flows](../docs/cli-flows.md) for pairing another machine and recovery.

### 4. Update safely

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
   docker run --rm -v sshstate_relay-data:/from -v "$PWD":/to busybox \
     tar -C /from -czf /to/relay-data.tgz .
   ```
   and on the new host, into a volume named for its Compose project:
   ```sh
   docker volume create sshstate_relay-data
   docker run --rm -v sshstate_relay-data:/to -v "$PWD":/from busybox \
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

The machines hold the vault too. Give the relay an empty volume and start it;
it issues a fresh bootstrap secret because the empty database has no spent one.
Run `sshstate connect <url> --bootstrap-secret <file>` on the most up-to-date
machine, then `sshstate connect <url> --rejoin` on every other machine. A relay
restored from a backup older than your machines needs no secret: rejoin every
machine, most up-to-date first. See
[Lose or restore the relay](../docs/cli-flows.md#9-lose-or-restore-the-relay).

The recovery kit restores *access* to retained ciphertext — it is not a backup
of storage that no longer exists. Keep an encrypted client export as well; it
carries its own checkpoint and works with the relay unavailable. A relay backup
is not the only way back, since your machines can start a new relay, but it
saves every machine a rejoin.
