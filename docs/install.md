# Install

certctl has two binaries you install depending on the role:

- **Control plane** (`certctl`) — the API, web UI, orchestrator, and event spine.
  In single-node mode it also supervises the isolated signing service
  (`certctl-signer`) as a child process.
- **Agent** (`certctl-agent`) — runs inside your network to discover, deploy, and
  monitor credentials on a host.

Pick the platform you are installing on.

## Docker (control plane)

The published image is distroless, unprivileged, and under 80 MB. Run it
against your datastores:

```bash
docker run --rm -p 8443:8443 \
  -e CERTCTL_POSTGRES_MODE=external \
  -e CERTCTL_POSTGRES_DSN='postgres://user:pass@db:5432/certctl?sslmode=require' \
  -e CERTCTL_NATS_MODE=external \
  -e CERTCTL_NATS_URL='nats://nats:4222' \
  ghcr.io/imfeelingtheagi/certctl:latest
```

For a self-contained evaluation that brings up Postgres and NATS for you, use the
Compose stack from [Getting started](getting-started.md):

```bash
docker compose -f deploy/docker/docker-compose.yml up --build
```

Verify a published image before you run it — its keyless cosign signature and its
CycloneDX SBOM attestation — with the helper:

```bash
scripts/verify-image.sh ghcr.io/imfeelingtheagi/certctl:<tag>
```

That wraps the underlying cosign check (only an image built by this repo's release
workflow verifies):

```bash
cosign verify ghcr.io/imfeelingtheagi/certctl:<tag> \
  --certificate-identity-regexp '^https://github.com/.*/certctl/.github/workflows/release.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

See [Supply chain](supply-chain.md) for the full signing, SBOM, provenance, and
dependency-scanning story.

## Kubernetes (control plane via Helm)

The control plane installs with the Helm chart under `deploy/helm/certctl`. It
deploys the API/UI with the **signing service isolated** as a locked-down sidecar
that has **no network listener** (it talks to the control plane only over a shared
in-memory socket — AN-4), against **external PostgreSQL and NATS**, behind a
default-deny `NetworkPolicy`, with TLS on by default (R1.3):

```bash
helm install certctl deploy/helm/certctl \
  --namespace certctl --create-namespace \
  --set postgres.dsn='postgres://user:pass@pg-host:5432/certctl?sslmode=require' \
  --set nats.url='nats://nats-host:4222' \
  --set kek.generate=true   # eval only; set kek.existingSecret in production
```

```bash
kubectl -n certctl rollout status deploy/certctl
kubectl -n certctl port-forward svc/certctl 8443:8443   # https://localhost:8443 (-k)
```

See [`deploy/helm/certctl/README.md`](https://github.com/imfeelingtheagi/certctl/tree/main/deploy/helm/certctl)
for the full values reference. A Kubernetes **Operator** and multi-replica HA (a
fully separate signer pod over mTLS) are **planned for S15.1** — see
[limitations](limitations.md); today the Helm chart is the supported control-plane
install.

## Kubernetes (agent)

The certctl agent runs as a **DaemonSet** so every node is covered. The manifests
live under `deploy/kubernetes` (namespace, RBAC, and the DaemonSet):

```bash
kubectl apply -f deploy/kubernetes/namespace.yaml
kubectl apply -f deploy/kubernetes/rbac.yaml
kubectl apply -f deploy/kubernetes/daemonset.yaml
```

Point the DaemonSet at your control plane and provide its bootstrap token through
the referenced secret; see `deploy/kubernetes/README.md` for the exact env and
secret wiring.

## Linux (control plane or agent)

Install from a release binary or build from source.

**From source** (requires Go 1.25+):

```bash
git clone https://github.com/imfeelingtheagi/certctl
cd certctl
make build           # builds ./bin/certctl, certctl-signer, and certctl-agent
sudo install -m 0755 bin/certctl /usr/local/bin/certctl
sudo install -m 0755 bin/certctl-agent /usr/local/bin/certctl-agent
```

Run the agent under systemd so it restarts on failure and on boot. A minimal
unit:

```ini
# /etc/systemd/system/certctl-agent.service
[Unit]
Description=certctl agent
After=network-online.target

[Service]
ExecStart=/usr/local/bin/certctl-agent
Restart=on-failure
User=certctl

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now certctl-agent
```

## macOS (agent)

Build the agent (or download the macOS release) and run it as a `launchd` agent.

```bash
make build
sudo install -m 0755 bin/certctl-agent /usr/local/bin/certctl-agent
```

Create a `launchd` job at
`/Library/LaunchDaemons/io.certctl.agent.plist` with a `ProgramArguments` entry
of `/usr/local/bin/certctl-agent` and `KeepAlive` set, then load it:

```bash
sudo launchctl load /Library/LaunchDaemons/io.certctl.agent.plist
```

The agent installs certificates into the login/keychain destinations you
configure and never moves private keys off the host.

## Windows (agent)

On Windows the agent runs as a **Service Control Manager (SCM) service** and
installs certificates into the Windows certificate store (CryptoAPI / CNG). Build
the signed MSI:

```bash
make dist-windows     # cross-compiles certctl-agent.exe and packages the MSI
```

Install it (elevated PowerShell):

```powershell
msiexec /i certctl-agent.msi /qn
```

The MSI registers and starts the `certctl-agent` service. See
`deploy/windows/README.md` for Authenticode signing and the WiX/msitools build
details.

## Verify the install

On any platform:

```bash
certctl --version
certctl -check-config        # prints the effective configuration; non-zero on a bad config
```

Next: [Configuration](configuration.md) to point certctl at your datastores, then
[Getting started](getting-started.md) to issue a certificate. To remove certctl,
see [Uninstall](uninstall.md).
