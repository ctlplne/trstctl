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

ARG GO_VERSION=1.25

# Runtime base image. Declared in the GLOBAL scope (before the first FROM) so the
# runtime stage's `FROM ${BASE_IMAGE}` can resolve it — a variable in a FROM is
# only substituted from globally-scoped ARGs. Defaults to the :nonroot tag for
# local builds; the release pipeline overrides it with an immutable @sha256 digest
# via --build-arg BASE_IMAGE (see .github/workflows/release.yml).
ARG BASE_IMAGE=gcr.io/distroless/static-debian12:nonroot

# ---- build stage ----------------------------------------------------------
FROM golang:${GO_VERSION}-bookworm AS build
WORKDIR /src

# Resolve modules first so they cache independently of source changes.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
ARG COMMIT=none
ARG DATE=1970-01-01T00:00:00Z
ARG TARGETOS=linux
ARG TARGETARCH=amd64

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
      /mnt-skel/data /mnt-skel/data/secrets /mnt-skel/data/signer /mnt-skel/data/ca \
      /mnt-skel/run/trstctl

# ---- runtime stage --------------------------------------------------------
# Distroless "static" is ~2 MB and ships only CA certificates, tzdata, and a
# nonroot user — no shell, no package manager. The base defaults to the :nonroot
# tag for local builds; the release pipeline resolves it to an immutable @sha256
# digest and builds with that via BASE_IMAGE, so released images pin the exact
# base. BASE_IMAGE is declared in the global scope at the top of this file (it must
# be, to be usable here). See .github/workflows/release.yml ("Resolve … by digest").
FROM ${BASE_IMAGE}

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

# 65532 is distroless' "nonroot" uid:gid — the process never runs as root.
USER 65532:65532
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/trstctl"]
