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

```sh
cd deploy && docker compose up -d
```

That pulls `ghcr.io/mouizahmed/sshstate-server`, published for linux/amd64 and
linux/arm64 by the release workflow. To build it yourself instead:

```sh
cd deploy && docker compose up -d --build
```

The container runs as UID 65532 with a read-only root filesystem, no
capabilities, and `no-new-privileges`. It binds `127.0.0.1:8080` on the host,
not a public interface. The image is about 21 MB: a static binary on
distroless, with no shell and no package manager inside.

#### Verifying the image

Each release signs the image by digest with Sigstore cosign, using the release
workflow's own identity. A tag can later be moved to different content; a digest
cannot, so the signature is over the digest.

```sh
digest=$(docker buildx imagetools inspect \
  ghcr.io/mouizahmed/sshstate-server:v0.1.3 --format '{{.Manifest.Digest}}')

cosign verify "ghcr.io/mouizahmed/sshstate-server@${digest}" \
  --certificate-identity-regexp '^https://github.com/mouizahmed/sshstate/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

### 3. Put HTTPS in front of it

The relay speaks plain HTTP and expects a terminating reverse proxy. TLS
certificate validation is mandatory on the client side, so the relay must be
reachable over `https://`.

A working nginx location, with the parts that matter marked:

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

### Backups

Back up the `relay-data` volume. The recovery kit restores *access* to retained
ciphertext — it is not a backup of storage that no longer exists (project brief
§7.2). Keep an encrypted export as well; it carries its own checkpoint and works
with the relay unavailable.

### No telemetry

The relay makes no outbound connections and never logs request bodies.
