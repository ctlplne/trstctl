# syntax=docker/dockerfile:1.7

# trstctl control-plane image.
#
# Reproducible, minimal (distroless "static", under 80 MB), and
# unprivileged. It carries the control plane, the isolated signing service
# (AN-4), the in-network agent, AND the Kubernetes Operator: in single-node mode
# trstctl supervises trstctl-signer as a child process; the Kubernetes
# DaemonSet runs trstctl-agent from this same image (overriding the entrypoint);
# and the operator Deployment runs trstctl-operator from it the same way. So one
# image serves every topology and there is no separate per-binary image to build
# (OPS-002). All four are tiny static Go binaries.
#
# Reproducibility: CGO is disabled, paths are trimmed, the build id is pinned
# empty, and VCS stamping is turned off (the build context excludes .git — see
# .dockerignore). Version metadata is injected via --build-arg, and the release
# pipeline rewrites layer timestamps to SOURCE_DATE_EPOCH.

ARG GO_VERSION=1.26.6

# Web-build, Go-build, and runtime base images. Declared in the GLOBAL scope
# (before the first FROM) so every FROM can resolve them — a variable in a FROM is
# only substituted from globally-scoped ARGs. Defaults use tags for local builds;
# the release pipeline overrides all three with immutable @sha256 digests (see
# .github/workflows/release.yml).
ARG WEB_BUILD_IMAGE=node:22-bookworm-slim
ARG BUILD_IMAGE=golang:1.26.6-bookworm
ARG BASE_IMAGE=gcr.io/distroless/static-debian12:nonroot

# Fast audit target used by scripts/ci/docker-context-audit.sh. It exports the
# exact filtered context Docker gives every COPY instruction without pulling a
# build image or compiling code.
FROM scratch AS context-audit
COPY . /context

# ---- web build stage ------------------------------------------------------
# Build the React console from the same source context as the Go binaries. The
# Go embed below must never freeze a stale, previously generated dist directory.
FROM ${WEB_BUILD_IMAGE} AS web-build
WORKDIR /src

# Keep npm's dependency layer independent of application-source changes.
COPY web/package.json web/package-lock.json ./web/
RUN npm --prefix web ci

# The feature-contract generator validates every referenced evidence path, so
# this stage needs the complete Docker-filtered repository context. The final
# image still receives only the built dist directory from this stage.
COPY . .
RUN npm --prefix web run build

# ---- build stage ----------------------------------------------------------
FROM ${BUILD_IMAGE} AS build
WORKDIR /src

# Resolve modules first so they cache independently of source changes.
COPY go.mod go.sum ./
RUN go mod download

COPY . .
# Vite writes the verified production bundle here; assets.go embeds this exact
# directory when each Go binary is compiled.
COPY --from=web-build /src/internal/webui/dist ./internal/webui/dist

ARG VERSION=dev
ARG COMMIT=none
ARG DATE=1970-01-01T00:00:00Z
# BuildKit defines these automatic platform arguments for each build target.
# Redeclare them without defaults so a native arm64 image cannot accidentally
# contain amd64 Go binaries (and vice versa).
ARG TARGETOS
ARG TARGETARCH

ENV CGO_ENABLED=0 \
    GOOS=${TARGETOS} \
    GOARCH=${TARGETARCH} \
    GOFLAGS=-mod=readonly

# The shipped reproducible flags. Build the control plane and the signer with
# identical flags so a rebuild of the same commit yields identical binaries.
ARG LDFLAGS="-s -w -buildid= -X trstctl.com/trstctl/internal/buildinfo.version=${VERSION} -X trstctl.com/trstctl/internal/buildinfo.commit=${COMMIT} -X trstctl.com/trstctl/internal/buildinfo.date=${DATE}"
RUN go build -trimpath -buildvcs=false -ldflags "${LDFLAGS}" -o /out/trstctl          ./cmd/trstctl
RUN go build -trimpath -buildvcs=false -ldflags "${LDFLAGS}" -o /out/trstctl-signer   ./cmd/trstctl-signer
RUN go build -trimpath -buildvcs=false -ldflags "${LDFLAGS}" -o /out/trstctl-agent    ./cmd/trstctl-agent
RUN go build -trimpath -buildvcs=false -ldflags "${LDFLAGS}" -o /out/trstctl-operator ./cmd/trstctl-operator

# Stage the persistent mount points OWNED BY the nonroot uid (65532). Docker
# initializes an empty named volume from the image's directory at the mount path,
# INCLUDING its ownership — so creating these dirs as 65532 here makes a fresh
# `secrets`/`signer`/`data`/UDS volume writable by the unprivileged process. Without
# it a new named volume is root:root and the nonroot control plane / signer cannot
# create the KEK ("provision credential KEK: open /data/secrets/kek.bin: permission
# denied"). Distroless has no shell, so we stage the tree here and COPY --chown it in.
# 0700 keeps the secret-bearing dirs owner-only; signer and control plane share the
# same uid, so they can both read the shared KEK and reach the UDS.
RUN install -d -m 0700 -o 65532 -g 65532 \
      /mnt-skel/data /mnt-skel/data/secrets /mnt-skel/data/signer /mnt-skel/data/ca /mnt-skel/data/tls \
      /mnt-skel/run/trstctl /mnt-skel/run/trstctl-spiffe
RUN install -d -m 0750 -o 65532 -g 65532 /mnt-skel/public-trust

# The local click-through demo exercises the real offline-license seam. Its
# image-only target creates a throw-away signing key, bakes only that key's
# public half into the demo control/signer binaries, signs one Provider license,
# and deletes the signing material before the layer is committed. The ordinary
# runtime/release target below never inherits this stage, key, or license.
FROM build AS demo-build
ARG DEMO_LICENSE_EXPIRES_AT=2036-01-01T00:00:00Z
RUN set -eu; \
    GOOS="$(go env GOHOSTOS)" GOARCH="$(go env GOHOSTARCH)" go build -trimpath -buildvcs=false -o /tmp/trstctl-license ./cmd/trstctl-license; \
    /tmp/trstctl-license gen-key --private-key /tmp/demo-license-private.pem --public-key /tmp/demo-license-public.pem; \
    /tmp/trstctl-license sign \
      --private-key /tmp/demo-license-private.pem \
      --out /out/demo-provider-license.json \
      --id trstctl-local-provider-demo \
      --customer "Local Provider demo" \
      --tier provider \
      --managed-customer-band 25 \
      --production-deployment-id trstctl-local-provider-demo-production \
      --non-production-deployment-ids trstctl-local-demo \
      --issued-at 2026-01-01T00:00:00Z \
      --expires-at "${DEMO_LICENSE_EXPIRES_AT}"; \
    license_keys_b64="$(base64 -w 0 /tmp/demo-license-public.pem)"; \
    demo_ldflags="${LDFLAGS} -X trstctl.com/trstctl/internal/license.builtinPubKeysB64=${license_keys_b64}"; \
    go build -trimpath -buildvcs=false -ldflags "${demo_ldflags}" -o /out/trstctl ./cmd/trstctl; \
    go build -trimpath -buildvcs=false -ldflags "${demo_ldflags}" -o /out/trstctl-signer ./cmd/trstctl-signer; \
    rm -f /tmp/trstctl-license /tmp/demo-license-private.pem /tmp/demo-license-public.pem

# ---- runtime stage --------------------------------------------------------
# Distroless "static" is ~2 MB and ships only CA certificates, tzdata, and a
# nonroot user — no shell, no package manager. The base defaults to the :nonroot
# tag for local builds; the release pipeline resolves it to an immutable @sha256
# digest and builds with that via BASE_IMAGE, so released images pin the exact
# runtime base. BASE_IMAGE is declared in the global scope at the top of this file
# (it must be, to be usable here). See .github/workflows/release.yml ("Resolve …
# by digest").
FROM ${BASE_IMAGE} AS runtime

# Distroless defaults to /home/nonroot. The application deliberately uses
# relative data/* defaults for a local binary, while containers mount persistent
# state at /data. Root makes those same defaults resolve into that mount instead
# of the disposable container layer (AUD-100).
WORKDIR /

COPY --from=build /out/trstctl          /usr/local/bin/trstctl
COPY --from=build /out/trstctl-signer   /usr/local/bin/trstctl-signer
# The agent ships in the same image; the DaemonSet runs it by overriding the
# entrypoint to /usr/local/bin/trstctl-agent (deploy/kubernetes/daemonset.yaml).
COPY --from=build /out/trstctl-agent    /usr/local/bin/trstctl-agent
# The Kubernetes Operator ships in the same image too; its Deployment runs it by
# overriding the entrypoint to /usr/local/bin/trstctl-operator
# (deploy/operator/operator.yaml). One image still serves every topology (OPS-002).
COPY --from=build /out/trstctl-operator /usr/local/bin/trstctl-operator

# Persistent mount points, owned by the nonroot uid (staged in the build stage). A
# Docker named volume mounted over one of these inherits 65532 ownership on first
# mount, so the unprivileged signer/control plane can create the KEK, the signer
# keystore, and the UDS. (Kubernetes uses fsGroup/securityContext instead; these
# pre-created dirs are harmless there.)
COPY --from=build --chown=65532:65532 /mnt-skel/data /data
COPY --from=build --chown=65532:65532 /mnt-skel/run/trstctl /run/trstctl
COPY --from=build --chown=65532:65532 /mnt-skel/run/trstctl-spiffe /run/trstctl-spiffe
COPY --from=build --chown=65532:65532 /mnt-skel/public-trust /public-trust

# 65532 is distroless' "nonroot" uid:gid — the process never runs as root.
USER 65532:65532
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/trstctl"]

# Explicit demo-only image target. Only deploy/demo selects this target; ordinary
# evaluation and release builds select the clean `release` alias below.
FROM runtime AS demo
COPY --from=demo-build /out/trstctl /usr/local/bin/trstctl
COPY --from=demo-build /out/trstctl-signer /usr/local/bin/trstctl-signer
COPY --from=demo-build --chown=65532:65532 /out/demo-provider-license.json /etc/trstctl/demo-provider-license.json

# Keep the clean production image as Docker's default final stage. This alias is
# deliberately after `demo`: a bare Docker build must never inherit the demo trust
# anchor or its Provider entitlement just because Docker selects the last stage.
FROM runtime AS release
