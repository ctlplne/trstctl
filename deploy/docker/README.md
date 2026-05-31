# certctl container distribution

Reproducible, signed, SBOM-bearing container images for the certctl control
plane, plus a one-command evaluation stack.

## Evaluate with Docker Compose

```bash
docker compose -f deploy/docker/docker-compose.yml up --build
```

This brings up three services:

- **postgres** — PostgreSQL 16 (the read store; AN-1), health-gated.
- **nats** — NATS 2.10 with JetStream enabled (the event spine; AN-2).
- **certctl** — the control plane, built from `deploy/docker/Dockerfile`,
  starting only once Postgres and NATS report healthy.

The control plane is wired to Postgres and NATS through the **external** datastore
configuration (`CERTCTL_POSTGRES_MODE=external`, `CERTCTL_NATS_MODE=external`),
so the eval stack exercises the same code path a production deployment uses.

## Point at your own external datastores

The bundled `postgres`/`nats` services are a convenience. To run certctl against
managed datastores, set the connection variables and drop the bundled services:

```bash
export CERTCTL_POSTGRES_MODE=external
export CERTCTL_POSTGRES_DSN='postgres://user:pass@db.internal:5432/certctl?sslmode=require'
export CERTCTL_NATS_MODE=external
export CERTCTL_NATS_URL='nats://nats.internal:4222'

docker run --rm -e CERTCTL_POSTGRES_MODE -e CERTCTL_POSTGRES_DSN \
  -e CERTCTL_NATS_MODE -e CERTCTL_NATS_URL -p 8443:8443 \
  ghcr.io/imfeelingtheagi/certctl:latest
```

The binary validates configuration on boot and **fails fast** on a bad
combination (for example, external Postgres with no DSN). Verify a configuration
without starting the server:

```bash
docker run --rm -e CERTCTL_POSTGRES_MODE=external -e CERTCTL_POSTGRES_DSN=... \
  ghcr.io/imfeelingtheagi/certctl:latest -check-config
```

`-check-config` prints the effective configuration with datastore credentials
redacted; it is also the container's health check.

## The image

- **Base:** `gcr.io/distroless/static-debian12:nonroot` — no shell, no package
  manager, runs as uid/gid 65532. The image stays **well under 20 MB**, enforced
  in CI.
- **Contents:** both `certctl` and `certctl-signer`. In single-node mode the
  control plane supervises the signer as a child process (AN-4); shipping both in
  one image keeps that boundary intact.
- **Reproducible:** built with `CGO_ENABLED=0`, `-trimpath`, `-buildid=`, and
  `-buildvcs=false`; version metadata is injected via `--build-arg`, and the
  release pipeline rewrites layer timestamps to `SOURCE_DATE_EPOCH`. Rebuilding
  the same commit yields identical binaries (`make reproducible-check`).

## Release pipeline

`.github/workflows/release.yml` runs on a `v*` tag:

1. builds the multi-arch image reproducibly,
2. enforces the < 20 MB size budget,
3. pushes to **GHCR** (primary) and **Docker Hub** (mirror),
4. generates a **CycloneDX** SBOM, and
5. **cosign**-signs the image and attests the SBOM (keyless, via OIDC).

Verify a published image:

```bash
cosign verify ghcr.io/imfeelingtheagi/certctl:<tag> \
  --certificate-identity-regexp '^https://github.com/.*/certctl/.github/workflows/release.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```
