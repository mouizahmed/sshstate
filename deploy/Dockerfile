# syntax=docker/dockerfile:1

# Build the relay. modernc.org/sqlite is pure Go, so CGO stays off and the
# result is a static binary with no runtime image to keep patched.
FROM golang:1.27.1-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

ARG VERSION=devel
ENV CGO_ENABLED=0
RUN go build -trimpath \
      -ldflags "-s -w -X github.com/mouizahmed/sshstate/internal/buildinfo.Version=${VERSION}" \
      -o /out/sshstate-server ./cmd/sshstate-server

# The data directory is created here because the final image has no shell to
# create it in, and its ownership has to match the unprivileged user below.
RUN mkdir -p /out/data

FROM gcr.io/distroless/static-debian12:nonroot

# 65532 is distroless's "nonroot" user. The relay never needs root: it binds an
# unprivileged port and writes one directory.
USER 65532:65532

COPY --from=build --chown=65532:65532 /out/data /var/lib/sshstate
COPY --from=build /out/sshstate-server /usr/local/bin/sshstate-server

# The volume holds the only state that matters. Losing it loses the vault's
# ciphertext; a recovery kit restores access to retained ciphertext, not to
# storage that is gone (project brief §7.2).
VOLUME ["/var/lib/sshstate"]

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/sshstate-server"]
CMD ["serve", \
     "-addr", "0.0.0.0:8080", \
     "-data", "/var/lib/sshstate/relay.db", \
     "-bootstrap-secret", "/run/secrets/sshstate_bootstrap"]
