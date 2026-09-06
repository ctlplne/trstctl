# Getting started

This walkthrough is for a first-time evaluator on a disposable workstation. It
takes a fresh machine to a healthy blank control plane and its first issued
certificate. It does not prepare a production deployment.

**Outcome:** verified HTTPS, local single sign-on (SSO), a signer-backed
certificate, and visible inventory/audit readback. **Time:** about 10 minutes after
the first image build. **Safest next diagnostic:** if a step fails, keep the stack
running and use [Troubleshooting](troubleshooting.md); do not delete volumes before
you preserve the error and inspect service health.

New to the product? Read the [six-tool product map](product-map.md) first.

One Compose command builds and starts the blank evaluation services. You then trust
one certificate-only file, sign in through the loopback-only local identity
provider, and follow the in-product wizard. The control plane is usually ready
about two minutes after a cached build; a first image download/build takes
longer. Issuance itself is sub-second (measured under
[Issue your first cert](#issue-your-first-cert)). Most of the remaining time is
the optional agent-install step.

If you want a pre-populated demo environment instead of a blank
first-run, use the demo stack: `docker compose -f deploy/demo/docker-compose.yml up --build`
serves a seeded UI (owners, certificates, secrets, transit keys, managed keys)
with local SSO at <https://127.0.0.1:9443>. Everything below uses the blank
stack at <https://localhost:8443>; the two can run side by side. The demo seed
stores a terminal version checkpoint and reads lifecycle state before acting,
so repeating `up --build` with the same volumes preserves the exact seeded
inventory. `scripts/ci/demo-seed-convergence.sh` waits for the first seed and
proves a second pass changes neither logical inventory nor event/outbox counts.
The different loopback hostnames are deliberate: browser cookies ignore port
numbers, so `localhost` for blank and `127.0.0.1` for demo keep both sessions
alive in one normal browser profile.
For a read-only, click-by-click product tour, open the
**[beginner demo walkthrough](demo-click-through.html)** beside the seeded UI.

## Prerequisites

- Docker with the Compose plugin (`docker compose version` works). Use a current
  release that supports `--wait` and health-gated `depends_on` conditions.
- `curl` and `openssl` for certificate inspection and verified health checks.
  The command-line appendix also uses `jq` and standard `awk`.
- At least **8 GB** of free disk for a first source-image build and the named
  PostgreSQL, NATS, signer, and identity-provider volumes; 12 GB leaves safer
  build-cache headroom.
- `trstctl-agent` before the optional agent-enrollment step. Install it from a
  release or build it with the other binaries as described in [Install](install.md).
- `trstctl-cli` only if you choose the command-line appendix. `make build` puts
  it at `./bin/trstctl-cli`; it is not installed on the host by Compose.
- A patched Go
  1.26.6+ toolchain only when building host binaries from source.

## Shortest safe path

1. Start the blank Compose project and wait for its health gates.
2. Copy and inspect the public certificate-only trust file.
3. Verify `/healthz` with that certificate.
4. Trust the certificate in the evaluation browser; never bypass the warning.
5. Sign in with the loopback identity provider and complete the wizard.
6. Confirm the issued certificate appears in **Certificate Lifecycle** and its
   creation appears in change history.

The detailed commands and recovery notes follow in the same order.

## 1. Bring up the control plane (about 2 minutes)

```bash
docker compose -f deploy/docker/docker-compose.yml up --build --detach --wait --wait-timeout 180
```

Compose starts PostgreSQL and NATS JetStream, generates a stable local OIDC
keypair, starts the signing service in its own container, and then starts the
control plane through the external-datastore path. A loopback-only local identity provider (IdP)
gives this disposable blank evaluation one first operator. The signer remains a
separate process and service; the control plane reaches it only over the shared
Unix-domain socket.

Copy the certificate-only trust file and verify the health endpoint with it:

```bash
docker compose -f deploy/docker/docker-compose.yml cp \
  trstctl:/public-trust/control-plane.crt ./trstctl-eval-control-plane.crt
openssl x509 -in ./trstctl-eval-control-plane.crt \
  -noout -subject -issuer -dates -fingerprint -sha256
curl -fsS --cacert ./trstctl-eval-control-plane.crt \
  https://localhost:8443/healthz   # {"status":"ok"}
```

The web UI is served by the same binary at <https://localhost:8443>. The
blank stack also enables the agent mTLS gRPC channel for the wizard at
`localhost:19443` (container `:9443`; the demo stack's UI uses
`127.0.0.1:9443`, so both browser sessions and projects coexist).

!!! tip "Transport encryption"
    Default is `server.tls.mode=internal` (self-signed). For production, set
    `server.tls.mode=file` with your own certificate
    (`TRSTCTL_SERVER_TLS_CERT_FILE` / `TRSTCTL_SERVER_TLS_KEY_FILE`).
    Internal mode stores its combined private identity at
    `data/tls/internal-server.pem` (`/data/tls/internal-server.pem` in Compose,
    mode `0600`), so the inspected public pin survives a restart with the same
    data volume. Never copy that private state file to a client.
    Plaintext is local-dev only: it requires `server.tls.mode=disabled`,
    `TRSTCTL_DEV_ALLOW_PLAINTEXT=true`, and a loopback `server.addr`, and it
    logs a loud warning. See [Configuration](configuration.md#transport-encryption-tls).

!!! note "Compose, the single binary, or your own datastores"
    Compose is the recommended eval path: explicit PostgreSQL and NATS
    containers, the same external-datastore wiring as production. The bare
    `trstctl` binary can run single-node with bundled PostgreSQL
    (`TRSTCTL_POSTGRES_MODE=bundled`, default) and embedded NATS
    (`TRSTCTL_NATS_MODE=embedded`, default); the bundled runtime downloads
    once on first use against the provenance pins in
    `deploy/supply-chain/embedded-postgres.json` (`linux-amd64`,
    `linux-arm64v8`, `darwin-arm64v8`) and fails closed if the host archive
    is unsupported, unpinned, or hash-mismatched. To use managed datastores,
    set the same env vars the Compose file sets
    (`TRSTCTL_POSTGRES_MODE=external` / `TRSTCTL_POSTGRES_DSN`,
    `TRSTCTL_NATS_MODE=external` / `TRSTCTL_NATS_URL`) — for production,
    always external, exactly as the Compose stack and Helm chart wire up.
    See [Configuration](configuration.md#datastores) and
    [Supply chain](supply-chain.md).

## 2. Trust the certificate, then sign in

Import `trstctl-eval-control-plane.crt` into the trust store used by your
evaluation browser. Follow [Trust the local evaluation certificate](local-evaluation-tls.md)
for macOS, Windows, Linux, and cleanup instructions. Do not bypass the browser
warning.

Visit <https://localhost:8443>, choose **Continue with SSO**, and the local IdP
signs in `eval-admin@trstctl.local` for the evaluation tenant. Both the UI/API
and the automatic IdP bind to host loopback; another machine cannot use this
evaluation administrator. A fresh install lands on a **Get started** prompt
that launches the setup wizard. The wizard has six screens: prove signer
health, activate the evaluation enrollment profile, issue the first certificate,
optionally prove configured integrations, optionally connect an agent, and
review setup.

## 3. Run the wizard (about 10 minutes)

### Check signing health

Choose **Check signing health**. The wizard reads the same separate-signer probe
shown on System health plus the issuer catalog. A named issuer is reported only
when a real catalog row exists. On a fresh blank stack, the UI says that the
built-in setup issuer is selected and that the next certificate step is the
end-to-end proof; it does not invent an “Internal CA” row. External X.509 issuers require a certificate chain and are added after setup from the
issuers/API surface.

### Enable enrollment protocols

The blank stack assembles the explicit `eval` profile for its evaluation
tenant. Review the seven shipped responders and click **Activate eval
protocol profile**. The UI calls the authenticated mutation
`POST /api/v1/setup/protocols/activate`; the server records the activation in
the event log before opening ACME, EST, SCEP, CMP, SSH, TSA, and SPIFFE. The
state survives restart and cannot activate another tenant's profile. A
production deployment using individual protocol toggles reports the eval
profile unavailable, and the wizard continues without changing operator
configuration.

### Issue your first cert

Name the service the certificate belongs to and click **Issue**. The action
uses your signed-in operator credential, which carries certificate-issuance
authority; setup bootstrap tokens and agent enrollment tokens cannot issue.
trstctl creates the [owner](glossary.md#owner) and identity and issues the certificate through the
internal signer-backed CA, then links you to the certificate inventory. From
here trstctl tracks the certificate and alerts before expiry; renewal is a
manual, one-click action today.

!!! note "Measured issuance time"
    In the end-to-end integration test — assembled control plane,
    out-of-process signer — the transition to *issued* drives the outbox
    handler to mint and record the certificate in tens of milliseconds
    (`TestAssembledServerIssuesCertIntoInventory`, ~20 ms). The running
    server's outbox dispatcher polls about once a second, so the certificate
    appears within roughly a second of clicking **Issue**.

### Prove served integrations

This optional screen demonstrates that integration packages are reachable
from the shipped control plane, not merely present in the source tree.
Against systems an operator has already configured, it: reads the served
connector catalog, creates a [deployment target](glossary.md#destination-deployment-target), and deploys the newly issued identity via
`POST /api/v1/connectors/targets/{id}/deploy`; submits an operator-supplied
CSR to `POST /api/v1/external-cas/{id}/issue`; and opens a 15-minute
dynamic-secret lease through `POST /api/v1/secrets/leases`. The wizard
retains only lease metadata — it never renders or stores the returned
one-time credential in browser state. A core-only install can choose
**Skip integration proof for now**; skipping does not claim an integration
was proven.

### Connect an agent (optional)

This optional step connects a
[trstctl Edge runtime](glossary.md#agent-trstctl-edge-runtime). The shipped wizard,
binary, and API still use **agent** for compatibility; the glossary separates this
execution runtime from a customer AI agent.

Certificate operations are already usable at this point. Choose **Skip agent
for now** if this evaluation should not inspect or deploy to a host; the review
screen records that the optional step was deferred rather than claiming an
agent exists.

To add discovery and deployment now, mint a one-time bootstrap token. Save it
to a file readable only
by the installing user, then build the local evaluation CA bundle the agent
pins — the HTTPS self-signed eval certificate (used for `/enroll/bootstrap`)
plus the signer-custodied agent-channel CA (mTLS on `localhost:19443`):

```bash
umask 077
read -rsp 'Bootstrap token: ' BOOTSTRAP_TOKEN
printf '\n'
printf '%s' "$BOOTSTRAP_TOKEN" > ./trstctl-bootstrap-token
unset BOOTSTRAP_TOKEN

docker compose -f deploy/docker/docker-compose.yml cp trstctl:/public-trust/control-plane.crt ./trstctl-https-ca.pem
docker compose -f deploy/docker/docker-compose.yml cp trstctl:/data/ca/agent-ca.crt ./trstctl-agent-ca.pem
cat ./trstctl-https-ca.pem ./trstctl-agent-ca.pem > ./trstctl-ca.pem

trstctl-agent --enroll-url https://localhost:8443 \
  --bootstrap-token-file ./trstctl-bootstrap-token \
  --server localhost:19443 \
  --server-name localhost \
  --name edge-agent-1 \
  --ca-bundle ./trstctl-ca.pem \
  --inventory-cert-roots /etc/ssl,/etc/pki/tls/certs \
  --inventory-os-trust-roots /etc/ssl/certs \
  --inventory-private-key-roots /etc/ssl/private,/etc/ssh
```

When you intentionally replace the control-plane container, use the Compose
project so its network-namespace companions are replaced with it:

```bash
docker compose -f deploy/docker/docker-compose.yml up --detach --force-recreate trstctl
```

Do not replace only the container with `docker rm` plus `docker run`; that
bypasses Compose's dependency restart wiring and can leave the local login
bridge in the retired network namespace. Recreating through Compose with the
same `trstctldata` volume keeps both CA pins valid. Capture the HTTPS certificate
again and rebuild `./trstctl-ca.pem` only after you replace/delete that volume
or intentionally rotate the internal TLS identity. A missing volume is a new
identity and must not inherit trust from the old one.

The agent generates its key locally and enrolls with the token; **private
keys never leave the host**. The three `--inventory-*` flags report,
respectively: public certificate metadata from those directories, the CA
trust anchors the host trusts, and private-key locations as metadata plus
public-key-derived fingerprints only. Findings appear in discovery inventory
and the credential graph. The wizard polls and advances once the agent
registers (typically well under five minutes). See [Install](install.md) for
getting the `trstctl-agent` binary on Linux, macOS, and Windows.

### Complete setup

Review the proved signer/issuer state, protocol profile, issued certificate,
integration-proof status, and either the enrolled agent or the explicit
optional-step deferral. **Complete setup** latches the wizard closed in this
browser and leaves a clear **Track and renew certificates** link. It does not
redirect without warning; use that link to open certificate operations.

## Get your first API token

The product default fails closed: protected API routes return `401` until you
present a credential. The blank **evaluation Compose profile** is the explicit
local-only exception described above; it wires one loopback OIDC operator so the
browser journey is executable. Production and custom deployments serve OIDC,
SAML, or LDAP / Active Directory only after their `auth.*.enabled` blocks are
configured. SCIM 2.0 can then provision users with a tenant-bound SCIM token.

For automation or recovery, the network-independent first credential is the
host-local bootstrap verb. It talks straight to the deployment datastore (no
existing HTTP token required) and prints a tenant-scoped token once:

```bash
# Pick any UUID as your tenant id (a single-tenant deployment uses one well-known id).
# Run the server binary inside the Compose custody boundary: its PostgreSQL service
# is deliberately not exposed to the host.
umask 077
docker compose -f deploy/docker/docker-compose.yml exec -T trstctl \
  /usr/local/bin/trstctl token create \
  --tenant 11111111-1111-1111-1111-111111111111 \
  --subject ci-bot > ./trstctl-api-token
export TRSTCTL_BOOTSTRAP_TOKEN="$(cat ./trstctl-api-token)"
# The trst_... token is printed once and the file is mode 0600 because of umask.
```

For a non-Compose deployment, run `trstctl token create` on the control-plane
host with the same PostgreSQL, signer, event-log, and audit configuration as the
running service. Do not run an unconfigured local binary: it would bootstrap a
different datastore.

The token carries a full set of operator scopes deliberately excluding
certificate issuance (`certs:issue`): a bootstrap credential can administer
the platform but cannot self-issue a certificate. Use it as
`Authorization: Bearer <token>`; shell examples keep it in
`TRSTCTL_BOOTSTRAP_TOKEN`.

## Prefer the command line?

Everything the wizard does is scriptable with `trstctl-cli` (see the
[CLI reference](cli.md)). Install a release binary or run `make build` and use
`./bin/trstctl-cli`; Compose does not install it on the host. The bootstrap token creates the owner and identity;
the served issue transition requires a distinct issuer/approver credential
with `certs:issue` — not the bootstrap token. This registration-authority
split is described in [Policy & governance](features/policy-and-governance.md).

```bash
export TRSTCTL_SERVER=https://localhost:8443
export TRSTCTL_TOKEN="$TRSTCTL_BOOTSTRAP_TOKEN"

# Copy the same certificate-only file you deliberately trusted for the browser.
# The pin survives a normal restart with the same trstctldata volume; inspect a
# new pin after replacing the volume or intentionally rotating TLS.
docker compose -f deploy/docker/docker-compose.yml cp \
  trstctl:/public-trust/control-plane.crt ./trstctl-eval-ca.pem
openssl x509 -in trstctl-eval-ca.pem -noout -fingerprint -sha256
export TRSTCTL_CA_FILE="$PWD/trstctl-eval-ca.pem"

# The blank Compose stack selects PROFILE=eval. Activate the assembled responders
# for this authenticated tenant before using their public protocol endpoints.
curl -fsS --cacert "$TRSTCTL_CA_FILE" \
  -X POST "$TRSTCTL_SERVER/api/v1/setup/protocols/activate" \
  -H "Authorization: Bearer $TRSTCTL_TOKEN" \
  -H "Idempotency-Key: first-run-eval-protocols"

# Create an owner and an identity; each command returns JSON with an id.
# This creates the request-side records; nothing is issued yet.
owner=$(echo '{"kind":"workload","name":"payments"}' | trstctl-cli owners create -f - | jq -r .id)
ident=$(echo "{\"kind\":\"x509_certificate\",\"name\":\"payments.svc\",\"owner_id\":\"$owner\"}" \
          | trstctl-cli identities create -f - | jq -r .id)

# Mint or provide a separate issuer credential. A real SSO operator/approver
# session works too; this local-eval example uses the served access-admin route.
cat > issuer-token.json <<'JSON'
{"subject":"first-cert-issuer","scopes":["identities:read","identities:write","certs:read","certs:issue"]}
JSON
trstctl-cli --idempotency-key first-cert-issuer-token access tokens create -f issuer-token.json > issuer-token-response.json
export TRSTCTL_ISSUER_TOKEN="$(jq -r .token issuer-token-response.json)"
rm -f issuer-token.json issuer-token-response.json

# Transition to "issued" with the issuer token: the running outbox dispatcher
# mints the certificate through the internal signer-backed CA.
echo '{"to":"issued"}' | TRSTCTL_TOKEN="$TRSTCTL_ISSUER_TOKEN" trstctl-cli identities transition "$ident" -f -
sleep 2

# The newly minted certificate is now in inventory: your first certificate,
# discovered, owned, and tracked.
TRSTCTL_TOKEN="$TRSTCTL_ISSUER_TOKEN" trstctl-cli certificates list
```

How the API, CLI, and UI fit together is described in
[Platform & API](features/platform-and-api.md); the single issuance path and
its guarantees in [Issuance & CAs](features/issuance-and-cas.md).

## Next steps

- [Automate TLS across your fleet](journeys/automate-fleet-tls.md) or
  [give Kubernetes workloads an identity](journeys/kubernetes-workload-identity.md).
- Harden the deployment: [Configuration](configuration.md).
- Done evaluating? [Uninstall](uninstall.md) cleanly. Hit a snag?
  [Troubleshooting](troubleshooting.md).
