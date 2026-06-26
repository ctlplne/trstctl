# Air-gapped install and no-phone-home mode

trstctl can run in a disconnected network: certificate issuance, the native secret
store, audit, policy, and the web/API surface keep working with no public outbound
network path. The air-gap mode has two layers:

- **Runtime egress guard:** set `TRSTCTL_AIRGAP_ENABLED=true`. Public outbound
  HTTP(S) is denied unless you explicitly allow a host or CIDR. Private and loopback
  destinations are allowed when `TRSTCTL_AIRGAP_ALLOW_PRIVATE=true`.
- **Kubernetes network policy:** use `deploy/helm/trstctl/values-airgap.yaml`.
  It keeps the chart's default-deny posture and scopes PostgreSQL/NATS egress to
  operator-owned private CIDRs instead of leaving datastore ports open to any IP.

Air-gap mode also fails closed for product telemetry and cloud AI model egress:
`TRSTCTL_TELEMETRY_ENABLED=true` and `TRSTCTL_AI_MODEL_MODE=cloud` are rejected when
air-gap is enabled. Local OTLP collectors, local AI runtimes, PostgreSQL, and NATS
can still be used when they live on private addresses or explicit allowlists.

## Build the transfer bundle

On a connected build host, verify the release image first, then build the bundle:

```bash
export VERSION=v0.5.0
export IMAGE=ghcr.io/ctlplne/trstctl:v0.5.0

scripts/verify-image.sh "$IMAGE"
make airgap-bundle VERSION="$VERSION" IMAGE="$IMAGE"
```

The output is `dist/airgap/trstctl-<version>-airgap.tar.gz` plus a `.sha256`
checksum. The bundle contains:

- the Helm chart and `values-airgap.yaml`;
- `docs/airgap.md`, `docs/install.md`, `docs/configuration.md`, and
  `docs/telemetry.md`;
- a `docker save` tarball for the trstctl release image;
- `CHECKSUMS.txt` for every file inside the bundle.

Move both the archive and `.sha256` file into the disconnected environment and
verify them there:

```bash
shasum -a 256 -c trstctl-0.5.0-airgap.tar.gz.sha256
tar -xzf trstctl-0.5.0-airgap.tar.gz
cd trstctl-0.5.0-airgap
shasum -a 256 -c CHECKSUMS.txt
```

## Load and install

Load the image into the offline registry or directly onto each node:

```bash
docker load -i images/trstctl-image.tar
docker tag ghcr.io/ctlplne/trstctl:v0.5.0 registry.airgap.local/trstctl:v0.5.0
docker push registry.airgap.local/trstctl:v0.5.0
```

Install with private PostgreSQL and NATS endpoints. Replace the CIDRs in
`manifests/values-airgap.yaml` with the cluster/VPC ranges that contain your
datastores, DNS, ingress controller, and optional local OTLP collector:

```bash
helm upgrade --install trstctl charts/trstctl \
  --namespace trstctl --create-namespace \
  -f manifests/values-airgap.yaml \
  --set image.repository=registry.airgap.local/trstctl \
  --set image.tag=v0.5.0 \
  --set postgres.dsn='postgres://user:pass@pg.internal:5432/trstctl?sslmode=require' \
  --set nats.url='nats://nats.internal:4222' \
  --set kek.existingSecret=trstctl-kek
```

The rendered control-plane ConfigMap sets:

```bash
TRSTCTL_AIRGAP_ENABLED=true
TRSTCTL_AIRGAP_ALLOW_PRIVATE=true
TRSTCTL_AIRGAP_ALLOW_CIDRS=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16
TRSTCTL_TELEMETRY_ENABLED=false
```

Use an operator-managed KEK Secret in production. `kek.generate=true` is only for
short-lived evaluation because losing that generated key makes the sealed CA key
unrecoverable.

## Verify zero public egress

Before opening the service to users, prove the no-phone-home posture:

1. Render the chart and inspect egress:

   ```bash
   helm template trstctl charts/trstctl -f manifests/values-airgap.yaml \
     --set image.repository=registry.airgap.local/trstctl \
     --set image.tag=v0.5.0 \
     --set postgres.dsn='postgres://user:pass@pg.internal:5432/trstctl?sslmode=require' \
     --set nats.url='nats://nats.internal:4222' \
     --set kek.existingSecret=trstctl-kek |
     grep -A20 'kind: NetworkPolicy'
   ```

   The PostgreSQL/NATS rule should have `ipBlock` CIDRs that match your private
   network. Do not allow `0.0.0.0/0`.

2. Confirm runtime config:

   ```bash
   kubectl -n trstctl exec deploy/trstctl -c trstctl -- trstctl --check-config | grep air_gap
   ```

3. Issue a certificate and manage a secret through the served API or CLI while your
   network monitor watches for public egress. The COMP-03 served integration test
   drives the same path: create owner, create identity, transition it to issued,
   create a native secret, rotate it, and assert the egress guard trip counter stays
   zero after a synthetic public-endpoint tripwire proves the guard is armed.

## Allowing local collectors or local AI

Local observability is compatible with air-gap mode:

```bash
export TRSTCTL_OTLP_ENABLED=true
export TRSTCTL_OTLP_ENDPOINT=http://otel-collector.observability.svc:4318
export TRSTCTL_OTLP_INSECURE=true
export TRSTCTL_AIRGAP_ALLOW_HOSTS=otel-collector.observability.svc
```

Local model runtimes are also compatible when they run on a private host:

```bash
export TRSTCTL_AI_MODEL_MODE=local
export TRSTCTL_AI_MODEL_RUNTIME=ollama
export TRSTCTL_AI_MODEL_ENDPOINT=http://ollama.ai.svc:11434
export TRSTCTL_AIRGAP_ALLOW_HOSTS=ollama.ai.svc
```

Cloud AI mode remains rejected under air-gap mode even if the cloud host is listed.
That is deliberate: an air-gapped install should not depend on a public SaaS model.

## Updating later

Build a new bundle on a connected workstation, transfer it in, verify the archive
checksum and internal `CHECKSUMS.txt`, load the new image into the offline registry,
then run a normal Helm upgrade with the same `values-airgap.yaml`. Do not let cluster
nodes pull directly from a public registry; the point of the bundle is that all
artifact movement is explicit, checked, and auditable.
