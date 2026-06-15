# Install

trustctl has two binaries you install depending on the role:

- **Control plane** (`trustctl`) — the API, web UI, orchestrator, and event spine.
  In single-node mode it also supervises the isolated signing service
  (`trustctl-signer`) as a child process.
- **Agent** (`trustctl-agent`) — runs inside your network to discover, deploy, and
  monitor credentials on a host.

Pick the platform you are installing on.

## Docker (control plane)

The published image is distroless, unprivileged, and under 80 MB. Run it
against your datastores:

```bash
docker run --rm -p 8443:8443 \
  -e TRUSTCTL_POSTGRES_MODE=external \
  -e TRUSTCTL_POSTGRES_DSN='postgres://user:pass@db:5432/trustctl?sslmode=require' \
  -e TRUSTCTL_NATS_MODE=external \
  -e TRUSTCTL_NATS_URL='nats://nats:4222' \
  ghcr.io/imfeelingtheagi/trustctl:latest
```

For a self-contained evaluation that brings up Postgres and NATS for you, use the
Compose stack from [Getting started](getting-started.md):

```bash
docker compose -f deploy/docker/docker-compose.yml up --build
```

Verify a published image before you run it — its keyless cosign signature and its
CycloneDX SBOM attestation — with the helper:

```bash
scripts/verify-image.sh ghcr.io/imfeelingtheagi/trustctl:<tag>
```

That wraps the underlying cosign check (only an image built by this repo's release
workflow verifies):

```bash
cosign verify ghcr.io/imfeelingtheagi/trustctl:<tag> \
  --certificate-identity-regexp '^https://github.com/.*/trustctl/.github/workflows/release.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

See [Supply chain](supply-chain.md) for the full signing, SBOM, provenance, and
dependency-scanning story.

## Kubernetes (control plane via Helm)

The control plane installs with the Helm chart under `deploy/helm/trustctl`. It
deploys the API/UI with the **signing service isolated** as a locked-down sidecar
that has **no network listener** (it talks to the control plane only over a shared
in-memory socket — AN-4), against **external PostgreSQL and NATS**, behind a
default-deny `NetworkPolicy`, with TLS on by default (R1.3):

```bash
helm install trustctl deploy/helm/trustctl \
  --namespace trustctl --create-namespace \
  --set postgres.dsn='postgres://user:pass@pg-host:5432/trustctl?sslmode=require' \
  --set nats.url='nats://nats-host:4222' \
  --set kek.generate=true   # eval only; set kek.existingSecret in production
```

```bash
kubectl -n trustctl rollout status deploy/trustctl
kubectl -n trustctl port-forward svc/trustctl 8443:8443   # https://localhost:8443 (-k)
```

The release pipeline also publishes the **packaged chart as a cosign-signed OCI
artifact** to GHCR (SUPPLY-007), so you can verify the chart's provenance before
installing — the same keyless-OIDC identity that signs the image:

```bash
cosign verify ghcr.io/imfeelingtheagi/trustctl/charts/trustctl:<chart-version> \
  --certificate-identity-regexp '^https://github.com/.*/trustctl/.github/workflows/release.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

See [`deploy/helm/trustctl/README.md`](https://github.com/imfeelingtheagi/trustctl/tree/main/deploy/helm/trustctl)
for the full values reference. The chart runs the signer co-located (sidecar, over
an in-memory UDS) by default; set `signer.mode=isolated` to run it as a **fully
separate pod reached over mTLS** (TLS 1.3, both-ways certificate pinning,
SIGNER-005). A Kubernetes **Operator** is still **planned for S15.1** — see
[limitations](limitations.md); today the Helm chart is the supported control-plane
install.

## Kubernetes (agent)

The trustctl agent runs as a **DaemonSet** so every node is covered. The manifests
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
git clone https://github.com/imfeelingtheagi/trustctl
cd trustctl
make build           # builds ./bin/trustctl, trustctl-signer, and trustctl-agent
sudo install -m 0755 bin/trustctl /usr/local/bin/trustctl
sudo install -m 0755 bin/trustctl-agent /usr/local/bin/trustctl-agent
```

Run the agent under systemd so it restarts on failure and on boot. A minimal
unit:

```ini
# /etc/systemd/system/trustctl-agent.service
[Unit]
Description=trustctl agent
After=network-online.target

[Service]
ExecStart=/usr/local/bin/trustctl-agent
Restart=on-failure
User=trustctl

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now trustctl-agent
```

## macOS (agent)

Build the agent (or download the macOS release) and run it as a `launchd` agent.

```bash
make build
sudo install -m 0755 bin/trustctl-agent /usr/local/bin/trustctl-agent
```

Create a `launchd` job at
`/Library/LaunchDaemons/io.trustctl.agent.plist` with a `ProgramArguments` entry
of `/usr/local/bin/trustctl-agent` and `KeepAlive` set, then load it:

```bash
sudo launchctl load /Library/LaunchDaemons/io.trustctl.agent.plist
```

The agent installs certificates into the login/keychain destinations you
configure and never moves private keys off the host.

## Windows (agent)

On Windows the agent runs as a **Service Control Manager (SCM) service** and
installs certificates into the Windows certificate store (CryptoAPI / CNG). Build
the MSI:

```bash
make dist-windows     # cross-compiles trustctl-agent.exe and packages the MSI
```

`make dist-windows` Authenticode-signs both the `.exe` and the `.msi` when a
code-signing identity is provided (`SIGN_PFX`/`SIGN_PASS`); without one it builds
them unsigned and says so. The official release pipeline (the `agent-windows` job
in `.github/workflows/release.yml`) signs them on every version tag and **fails
the release if either artifact is unsigned**, so the published Windows agent is
always Authenticode-signed.

Install it (elevated PowerShell):

```powershell
msiexec /i trustctl-agent.msi /qn
```

The MSI registers and starts the `trustctl-agent` service. See
`deploy/windows/README.md` for Authenticode signing and the WiX/msitools build
details.

### Verify the agent download

Before installing a downloaded agent, authenticate it. On Windows, confirm the
Authenticode signature and inspect the signer:

```powershell
Get-AuthenticodeSignature .\trustctl-agent.msi   # Status must be 'Valid'
```

On any platform you can also verify the published checksums against the release
asset, and (when present) the signature with `osslsigncode`:

```bash
sha256sum -c SHA256SUMS                    # the agent .exe/.msi hashes match the release
osslsigncode verify -in trustctl-agent.msi # reports a valid Authenticode signature
```

The control-plane and agent **container** image is additionally cosign-signed;
see "Verify a published image" above for `scripts/verify-image.sh` / `cosign
verify`.

## Verify the install

On any platform:

```bash
trustctl --version
trustctl -check-config        # prints the effective configuration; non-zero on a bad config
```

Next: [Configuration](configuration.md) to point trustctl at your datastores, then
[Getting started](getting-started.md) to issue a certificate. To remove trustctl,
see [Uninstall](uninstall.md).
