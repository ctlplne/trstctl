# Getting started

This walkthrough takes a fresh machine to its first issued certificate. The
control plane is serving about two minutes after `compose up`; issuance itself
is sub-second (measured figure under [Issue your first cert](#issue-your-first-cert)).
Most of the wall-clock is the single agent-install step. You bring up a blank
control plane with one command, then the in-product wizard connects a CA,
issues a certificate, and enrolls an agent.

If you want a pre-populated sales/demo environment instead of a blank
first-run, use the demo stack: `docker compose -f deploy/demo/docker-compose.yml up --build`
serves a seeded UI (owners, certificates, secrets, transit keys, managed keys)
with local SSO at <https://localhost:9443>. Everything below uses the blank
stack at <https://localhost:8443>; the two can run side by side. The demo seed
stores a terminal version checkpoint and reads lifecycle state before acting,
so repeating `up --build` with the same volumes preserves the exact seeded
inventory. `scripts/ci/demo-seed-convergence.sh` waits for the first seed and
proves a second pass changes neither logical inventory nor event/outbox counts.
For a read-only, click-by-click product tour, open the
**[beginner demo walkthrough](demo-click-through.html)** beside the seeded UI.

## Prerequisites

- Docker with the Compose plugin (`docker compose version` works), or a Go
  1.26.6+ toolchain to run from source.
- About 1 GB of free disk for the PostgreSQL and NATS volumes.

## 1. Bring up the control plane (about 2 minutes)

```bash
docker compose -f deploy/docker/docker-compose.yml up --build
```

Compose starts PostgreSQL and NATS JetStream, waits for both to report
healthy, then starts the control plane wired to them through its external
datastore configuration. The process brings up the event log, projections,
orchestrator, and API in order, and supervises the signing service as a child
process — it answers real API requests end to end. TLS is on by default with
a self-signed internal certificate, so health-check with `-k`:

```bash
curl -fksS https://localhost:8443/healthz   # {"status":"ok"}
```

The web UI is served by the same binary at <https://localhost:8443>. The
blank stack also enables the agent mTLS gRPC channel for the wizard at
`localhost:19443` (container `:9443`; the demo stack's UI keeps
`localhost:9443`, so both projects coexist).

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

## 2. Open the UI and sign in

Visit <https://localhost:8443> (accept the self-signed evaluation
certificate) and sign in. A fresh install lands on a **Get started** prompt
that launches the setup wizard. The wizard has six screens: use the internal
CA, activate the evaluation enrollment profile, issue the first certificate,
prove configured integrations, enroll an agent, and complete setup.

## 3. Run the wizard (about 10 minutes)

### Use the internal CA

Continue with the signer-backed X.509 CA the server provisioned at boot. The
first-certificate flow does not create an external issuer.
External X.509 issuers require a certificate chain and are added after setup
from the issuers/API surface.

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
trstctl creates the owner and identity and issues the certificate through the
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
connector catalog, creates a target, and deploys the identity just issued via
`POST /api/v1/connectors/targets/{id}/deploy`; submits an operator-supplied
CSR to `POST /api/v1/external-cas/{id}/issue`; and opens a 15-minute
dynamic-secret lease through `POST /api/v1/secrets/leases`. The wizard
retains only lease metadata — it never renders or stores the returned
one-time credential in browser state. A core-only install can choose
**Skip integration proof for now**; skipping does not claim an integration
was proven.

### Install an agent

The wizard mints a one-time bootstrap token. Save it to a file readable only
by the installing user, then build the local evaluation CA bundle the agent
pins — the HTTPS self-signed eval certificate (used for `/enroll/bootstrap`)
plus the signer-custodied agent-channel CA (mTLS on `localhost:19443`):

```bash
umask 077
read -rsp 'Bootstrap token: ' BOOTSTRAP_TOKEN
printf '\n'
printf '%s' "$BOOTSTRAP_TOKEN" > ./trstctl-bootstrap-token
unset BOOTSTRAP_TOKEN

openssl s_client -connect localhost:8443 -servername localhost -showcerts </dev/null 2>/dev/null \
  | awk '/BEGIN CERTIFICATE/,/END CERTIFICATE/' > ./trstctl-https-ca.pem
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

Recreating or restarting the Compose control-plane container with the same
`trstctldata` volume keeps both CA pins valid. Capture the HTTPS certificate
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

Confirm the internal CA, protocol profile, issued certificate,
integration-proof status, and enrolled agent. The wizard latches closed in
this browser and sends you to the certificate operations view.

## Get your first API token

A freshly booted control plane fails closed: every API route returns `401`
until you present a credential. OIDC, SAML, and LDAP / Active Directory login
are served once their `auth.*.enabled` blocks are configured, and SCIM 2.0
can provision users after you configure a tenant-bound SCIM token — but the
zero-dependency first credential is the host-local bootstrap verb. It talks
straight to the datastore (no existing token required) and prints a
tenant-scoped token once:

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
[CLI reference](cli.md)). The bootstrap token creates the owner and identity;
the served issue transition requires a distinct issuer/approver credential
with `certs:issue` — not the bootstrap token. This registration-authority
split is described in [Policy & governance](features/policy-and-governance.md).

```bash
export TRSTCTL_SERVER=https://localhost:8443
export TRSTCTL_TOKEN="$TRSTCTL_BOOTSTRAP_TOKEN"

# The evaluation certificate is self-signed. Capture its public certificate,
# compare this fingerprint with the one your browser accepted, then let the CLI
# trust only that certificate. The pin survives a normal restart with the same
# trstctldata volume; inspect a new pin after replacing the volume or rotating TLS.
openssl s_client -connect localhost:8443 -servername localhost </dev/null 2>/dev/null \
  | openssl x509 -out trstctl-eval-ca.pem
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
