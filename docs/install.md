# Install

trstctl has two binaries you install depending on the role:

- **Control plane** (`trstctl`) — the API, web UI, orchestrator, and event spine.
  In single-node mode it also supervises the isolated signing service
  (`trstctl-signer`) as a child process.
- **Agent** (`trstctl-agent`) — runs inside your network to discover, deploy, and
  monitor credentials on a host.

Pick the platform you are installing on.

## Docker (control plane)

The published image is distroless, unprivileged, and under 80 MB. Run it
against your datastores by digest, after verifying the release image:

```bash
export TRSTCTL_IMAGE_REF='ghcr.io/imfeelingtheagi/trstctl@sha256:<release-image-digest>'

docker run --rm -p 8443:8443 \
  -e TRSTCTL_POSTGRES_MODE=external \
  -e TRSTCTL_POSTGRES_DSN='postgres://user:pass@db:5432/trstctl?sslmode=require' \
  -e TRSTCTL_NATS_MODE=external \
  -e TRSTCTL_NATS_URL='nats://nats:4222' \
  "$TRSTCTL_IMAGE_REF"
```

For a self-contained evaluation that brings up Postgres and NATS for you, use the
Compose stack from [Getting started](getting-started.md):

```bash
docker compose -f deploy/docker/docker-compose.yml up --build
```

Verify a published image before you run it — its keyless cosign signature and its
CycloneDX SBOM attestation — with the helper:

```bash
scripts/verify-image.sh "$TRSTCTL_IMAGE_REF"
```

That wraps the underlying cosign check (only an image built by this repo's release
workflow verifies):

```bash
cosign verify "$TRSTCTL_IMAGE_REF" \
  --certificate-identity-regexp '^https://github.com/.*/trstctl/.github/workflows/release.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

See [Supply chain](supply-chain.md) for the full signing, SBOM, provenance, and
dependency-scanning story. For Kubernetes admission-time enforcement, start from
`deploy/kubernetes/sigstore-policy.yaml`; it admits only digest-pinned trstctl
images signed by this repository's release workflow identity.

## Kubernetes (control plane via Helm)

The control plane installs with the Helm chart under `deploy/helm/trstctl`. It
deploys the API/UI with the **signing service isolated** as a locked-down sidecar
that has **no network listener** (it talks to the control plane only over a shared
in-memory socket, so the private keys stay in their own isolated process),
against **external PostgreSQL and NATS**, behind a default-deny `NetworkPolicy`,
with TLS on by default (R1.3):

```bash
helm install trstctl deploy/helm/trstctl \
  --namespace trstctl --create-namespace \
  --set image.digest='sha256:<release-image-digest>' \
  --set postgres.dsn='postgres://user:pass@pg-host:5432/trstctl?sslmode=require' \
  --set nats.url='nats://nats-host:4222' \
  --set kek.generate=true   # eval only; set kek.existingSecret in production
```

```bash
kubectl -n trstctl rollout status deploy/trstctl
kubectl -n trstctl port-forward svc/trstctl 8443:8443   # https://localhost:8443 (-k)
```

The release pipeline also publishes the **packaged chart as a cosign-signed OCI
artifact** to GHCR, so you can verify the chart's provenance before
installing — the same keyless-OIDC identity that signs the image:

```bash
cosign verify ghcr.io/imfeelingtheagi/trstctl/charts/trstctl:<chart-version> \
  --certificate-identity-regexp '^https://github.com/.*/trstctl/.github/workflows/release.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

See [`deploy/helm/trstctl/README.md`](https://github.com/imfeelingtheagi/trstctl/tree/main/deploy/helm/trstctl)
for the full values reference. The chart runs the signer co-located (sidecar, over
an in-memory UDS) by default; set `signer.mode=isolated` plus the required
`signer.mtls.*` values to render a **separate signer pod reached over mutually
pinned mTLS** (TLS 1.3, both-ways certificate pinning). A minimal
Kubernetes **Operator** binary (`cmd/trstctl-operator`) ships for CRD-driven
Deployment replica/image reconciliation; Helm remains the supported full
control-plane install for services,
secrets, network policy, signer topology, PostgreSQL, and NATS — see
[limitations](limitations.md).

## Kubernetes (agent)

The trstctl agent runs as a **DaemonSet** so every node is covered. The manifests
live under `deploy/kubernetes` (namespace, RBAC, and the DaemonSet):

```bash
helm upgrade --install trstctl deploy/helm/trstctl \
  --namespace trstctl --create-namespace \
  --set agentChannel.enabled=true \
  --set agentChannel.serverName=trstctl

export TRSTCTL_AGENT_IMAGE='ghcr.io/imfeelingtheagi/trstctl@sha256:<release-image-digest>'
TOKEN="$(trstctl-cli agents enroll-token | jq -r .token)"
rendered_agent_daemonset="$(mktemp)"
kubectl apply -f deploy/kubernetes/namespace.yaml
kubectl -n trstctl create secret generic trstctl-agent-bootstrap \
  --from-literal=token="$TOKEN" \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl -n trstctl create configmap trstctl-ca-bundle \
  --from-file=ca-bundle.pem=/path/to/agent-channel-ca.pem \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -f deploy/kubernetes/rbac.yaml
scripts/release/render-kubernetes-agent-daemonset.sh "$TRSTCTL_AGENT_IMAGE" > "$rendered_agent_daemonset"
kubectl apply -f "$rendered_agent_daemonset"
```

The DaemonSet points at the in-namespace `trstctl` Service and reads the
single-use bootstrap token from `Secret/trstctl-agent-bootstrap`. It also sets
`--server-name=trstctl`, so the Helm value above is required for the
agent-channel certificate SAN. `TRSTCTL_AGENT_IMAGE` must be an immutable
`.../trstctl@sha256:<release-image-digest>` reference; the render script refuses
tags and the all-zero placeholder. Create `ConfigMap/trstctl-ca-bundle` with
`ca-bundle.pem` before applying the rendered DaemonSet; the agent uses that bundle
to pin bootstrap HTTPS before posting the one-time token and to verify the
steady-state mTLS channel. See `deploy/kubernetes/README.md` for the exact env and
Secret wiring.

## Linux (control plane or agent)

Install from a release binary or build from source.

**From source** (requires Go 1.26.4+):

```bash
git clone https://github.com/imfeelingtheagi/trstctl
cd trstctl
make build           # builds ./bin/trstctl, trstctl-signer, and trstctl-agent
sudo install -m 0755 bin/trstctl /usr/local/bin/trstctl
sudo install -m 0755 bin/trstctl-agent /usr/local/bin/trstctl-agent
```

Run the agent under systemd so it restarts on failure and on boot. A minimal
unit:

```ini
# /etc/systemd/system/trstctl-agent.service
[Unit]
Description=trstctl agent
After=network-online.target

[Service]
ExecStart=/usr/local/bin/trstctl-agent
Restart=on-failure
User=trstctl

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now trstctl-agent
```

## macOS (agent)

Build the agent (or download the macOS release) and run it as a `launchd` agent.

```bash
make build
sudo install -m 0755 bin/trstctl-agent /usr/local/bin/trstctl-agent
```

Create a `launchd` job at
`/Library/LaunchDaemons/io.trstctl.agent.plist` with a `ProgramArguments` entry
of `/usr/local/bin/trstctl-agent` and `KeepAlive` set, then load it:

```bash
sudo launchctl load /Library/LaunchDaemons/io.trstctl.agent.plist
```

The agent installs certificates into the login/keychain destinations you
configure and never moves private keys off the host.

## Windows (agent)

On Windows the agent runs as a **Service Control Manager (SCM) service** and
installs certificates into the Windows certificate store (CryptoAPI / CNG). Build
the MSI:

```bash
make dist-windows     # cross-compiles trstctl-agent.exe and packages the MSI
```

`make dist-windows` Authenticode-signs both the `.exe` and the `.msi` only when
`WINDOWS_CODESIGN_URL` points at the remote signing service used by the release
pipeline; otherwise it builds them unsigned and says so. The official
`agent-windows` release job runs in the protected `windows-code-signing`
environment, authenticates to that remote signer with GitHub OIDC, and verifies
the Authenticode signature before upload. No long-lived code-signing PKCS#12 is
decoded or written on the CI runner. That means any published Windows agent
artifact from the release pipeline is Authenticode-signed.

Install it (elevated PowerShell):

```powershell
$token = (trstctl-cli agents enroll-token | ConvertFrom-Json).token
Set-Content -Path C:\ProgramData\trstctl\bootstrap-token.txt -Value $token -NoNewline

msiexec /i trstctl-agent.msi /qn `
  ENROLLURL=https://cp:8443 `
  SERVER=cp:9443 `
  SERVERNAME=cp `
  CABUNDLE=C:\ProgramData\trstctl\ca-bundle.pem `
  BOOTSTRAPTOKENFILE=C:\ProgramData\trstctl\bootstrap-token.txt
```

The MSI registers and starts the service only after the first-boot settings are
present: enrollment base URL, bootstrap token file, CA bundle, agent-channel
endpoint, and server name. The token is single-use; after the service enrolls and
persists its certificate, rotate or delete the file. See
`deploy/windows/README.md` for Authenticode signing, direct service install, and
the WiX/msitools build details.

### Verify the agent download

Before installing a downloaded agent, authenticate it. On Windows, confirm the
Authenticode signature and inspect the signer:

```powershell
Get-AuthenticodeSignature .\trstctl-agent.msi   # Status must be 'Valid'
```

The protected release workflow publishes the signed Windows agent files as durable
GitHub Release assets: `trstctl-agent.exe`, `trstctl-agent.msi`, and `SHA256SUMS`.
On any platform you can verify the published checksums against those release assets,
and (when present) the signature with `osslsigncode`:

```bash
sha256sum -c SHA256SUMS                    # the agent .exe/.msi hashes match the release
osslsigncode verify -in trstctl-agent.msi # reports a valid Authenticode signature
```

The control-plane and agent **container** image is additionally cosign-signed;
see "Verify a published image" above for `scripts/verify-image.sh` / `cosign
verify`.

## Verify the install

On any platform:

```bash
trstctl --version
trstctl -check-config        # prints the effective configuration; non-zero on a bad config
```

Next: [Configuration](configuration.md) to point trstctl at your datastores, then
[Getting started](getting-started.md) to issue a certificate. To remove trstctl,
see [Uninstall](uninstall.md).
