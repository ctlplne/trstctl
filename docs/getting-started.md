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
6. Confirm the issued certificate appears in **Certificates** and its
   creation appears in change history.

The detailed commands and recovery notes follow in the same order.

## 1. Bring up the control plane (about 2 minutes)

```bash
export TRSTCTL_BUILD_COMMIT="$(git rev-parse HEAD)"
if test -n "$(git status --porcelain --untracked-files=normal)"; then
  export TRSTCTL_BUILD_COMMIT="${TRSTCTL_BUILD_COMMIT}-dirty"
fi
export TRSTCTL_BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
docker compose -f deploy/docker/docker-compose.yml up --build --detach --wait --wait-timeout 180
```

These build arguments stamp the control plane and separate signer from the same
checkout. A `-dirty` suffix means tracked or untracked work was present; it does
not identify those extra bytes. Recompute the values before each source build.
Check the running image with
`docker compose -f deploy/docker/docker-compose.yml exec trstctl /usr/local/bin/trstctl --version`.
Direct builds without these arguments retain the explicit unknown-source defaults;
release artifacts use their release pipeline's source identity.

Compose starts PostgreSQL and NATS JetStream, generates a stable local OIDC
keypair, starts the signing service in its own container, and then starts the
control plane through the external-datastore path. A loopback-only local identity provider (IdP)
gives this disposable blank evaluation one first operator. The evaluation profile
registers its configured tenant in the event history at startup, so the first
certificate has the tenant lifecycle needed for later revocation. Restart preserves
that registration; erasing a tenant does not cause startup to recreate it. The signer remains a
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

The wizard needs an accountable [owner](glossary.md#owner) and a public certificate signing request
(CSR). The CSR contains the workload's public key and requested DNS name; the
matching private key stays on that workload. The form never creates or accepts a
private key.

For this disposable evaluation, use `payments.svc` as the service name and DNS
name. On the machine that will hold its private key, run these commands with
OpenSSL 1.1.1 or newer (use a new directory so an existing key is not overwritten):

```bash
(
set -eu
umask 077
mkdir trstctl-first-certificate
cd trstctl-first-certificate
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout payments.key -out payments.csr \
  -subj '/CN=payments.svc' -addext 'subjectAltName=DNS:payments.svc'
openssl req -in payments.csr -noout -verify -subject
cat payments.csr
)
```

The subshell stops if the directory already exists and leaves your terminal in
the repository root. Files are under `trstctl-first-certificate/`.
`payments.key` is the private key; `umask 077` makes new files readable only by
your user. Keep that key on this machine. `payments.csr` is public and is the only
file to paste into the wizard. A real deployment must request the DNS name its
clients actually use; this example does not configure DNS or install a certificate
on a service.

Fill in every field:

| Field | Disposable evaluation value |
|---|---|
| Service name | `payments.svc` |
| Application ID | `payments` |
| Environment | `evaluation` |
| Alert contact | `eval-admin@trstctl.local` |
| Ownership confirmation | Confirm that this application owns the test certificate |
| Public certificate request (CSR) | The complete `payments.csr`, including its BEGIN/END lines |

The evaluation email is a local fixture, not an alert destination. Production
ownership must name an accountable application and a monitored contact.

Click **Issue certificate** using the signed-in operator, who has issuance
authority. Setup bootstrap tokens and agent enrollment tokens cannot issue. The
wizard creates and attests the owner, creates its identity, and submits issuance
to the separate signer. Keep the page open until it shows the recorded issuer,
certificate fingerprint, and **Download leaf certificate**. In this fresh-stack
walk, the result appeared after approximately four seconds; accepting the request
is not yet proof that a certificate exists.

Download the public leaf and, if needed, the returned public chain. The private
key remains `payments.key`; downloading a chain does not install trust or deploy
the certificate. Use **Open certificate inventory** to confirm the subject, owner,
and expiry, then **Operations → Change history** to inspect the recorded changes.
From here trstctl tracks the certificate. Configuring alert delivery, deployment,
and renewal is separate work; the wizard does not prove those paths.

If automatic delivery retries are exhausted, the wizard shows the retained
recovery evidence. When the original certificate or signing operation is
recoverable, correct the reported failure, enter a reason, and choose
**Request one recovery attempt**. This grants one additional attempt for the
same issuer and certificate request. If its response is lost, repeating the
same recovery request returns the original receipt. Requests without enough
retained evidence require reconciliation with the issuer before new issuance.

If a response is interrupted, keep the page open and use its retained retry.
After a reload or sign-out, inspect identity inventory and change history before
starting another request; an empty form does not prove the previous request failed.
See [First-certificate recovery](journeys/first-certificate.md).

!!! note "Measured issuance and visible completion"
    `TestAssembledServerIssuesCertIntoInventory` measures the assembled issuance
    path in milliseconds, with a separate signer process. A running deployment
    also waits for the outbox worker and the browser's result polling. The local
    walk above measured about four seconds to a visible result; the integration
    test timing is not a promise about browser latency.

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
project and explicitly include the login bridge. Both containers must be
replaced together because the bridge shares the control plane's network namespace:

```bash
docker compose -f deploy/docker/docker-compose.yml up --detach --force-recreate trstctl oidc-loopback
```

Selecting only `trstctl`, or using `docker rm` plus `docker run`, can leave the
local login bridge in the retired network namespace. Existing sessions may still
work while a new login fails with `token exchange failed`. Run the command above
to replace both services, then verify a fresh SSO login. Recreating through Compose with the
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
# Use the tenant selected by the blank evaluation profile. If you set
# COMPOSE_E2E_TENANT before startup, use that same UUID here.
# Run the server binary inside the Compose custody boundary: its PostgreSQL service
# is deliberately not exposed to the host.
umask 077
docker compose -f deploy/docker/docker-compose.yml exec -T trstctl \
  /usr/local/bin/trstctl token create \
  --tenant 11111111-1111-4111-8111-111111111111 \
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

The CLI uses the same tenant, owner, CSR, and separate signer as the wizard (see
the [CLI reference](cli.md)). Install a release binary or run `make build`; the
commands below use `./bin/trstctl-cli`. For an installed release, set
`TRSTCTL_CLI=trstctl-cli` first.

First obtain **two distinct credentials**. Keep the bootstrap token from the
previous section for owner and identity registration. It cannot issue or mint a
token with issuance authority: delegation cannot grant a permission the caller
does not hold. In the browser, sign in as the evaluation operator and open
**Operations → People and roles → Sessions and access keys → Create access key**.
Use subject `first-cert-issuer` and these comma-separated scopes:
`identities:read,identities:write,certs:read,certs:issue`. Choose **Create access key**
and copy the reveal-once value. In production, an authorized administrator must
delegate these scopes according to your approval policy.

Read that value without placing it in shell history or echoing it:

```bash
printf 'Paste the issuer access key: ' >&2
IFS= read -r -s TRSTCTL_ISSUER_TOKEN
printf '\n'
export TRSTCTL_ISSUER_TOKEN
```

Create the private key and public CSR under `trstctl-first-certificate/` using
[Issue your first cert](#issue-your-first-cert) if you have not already done so.
Reuse that CSR here; never upload `payments.key`. Then, from the repository root:

```bash
(
set -euo pipefail
umask 077
TRSTCTL_CLI="${TRSTCTL_CLI:-./bin/trstctl-cli}"
export TRSTCTL_SERVER=https://localhost:8443
export TRSTCTL_TOKEN="${TRSTCTL_BOOTSTRAP_TOKEN:?Create the bootstrap token first}"
: "${TRSTCTL_ISSUER_TOKEN:?Obtain an issuer key from the signed-in administrator}"
certdir=trstctl-first-certificate
test -s "$certdir/payments.csr"

# Trust the same inspected public certificate used by the browser.
docker compose -f deploy/docker/docker-compose.yml cp \
  trstctl:/public-trust/control-plane.crt ./trstctl-eval-ca.pem
openssl x509 -in trstctl-eval-ca.pem -noout -fingerprint -sha256
export TRSTCTL_CA_FILE="$PWD/trstctl-eval-ca.pem"

"$TRSTCTL_CLI" --idempotency-key first-run-eval-protocols setup protocols activate

# Stable keys recover the same first request when these exact commands are retried.
owner=$(printf '%s' '{"kind":"workload","name":"payments","application_id":"payments","environment":"evaluation","email":"eval-admin@trstctl.local"}' \
  | "$TRSTCTL_CLI" --idempotency-key first-cli-owner owners create -f - | jq -er .id)
"$TRSTCTL_CLI" --idempotency-key first-cli-attestation owners attest "$owner"
ident=$(jq -n --arg owner "$owner" \
  '{kind:"x509_certificate",name:"payments.svc",owner_id:$owner}' \
  | "$TRSTCTL_CLI" --idempotency-key first-cli-identity identities create -f - | jq -er .id)
printf '%s\n' "$ident" > "$certdir/identity-id"

# This body contains only the public CSR. Keep it unchanged for recovery.
jq -n --rawfile csr "$certdir/payments.csr" \
  '{to:"issued",subject_csr_pem:$csr}' > "$certdir/issue-request.json"
request_key=first-cli-certificate-issue
printf '%s\n' "$request_key" > "$certdir/issuance-request-key"
export TRSTCTL_TOKEN="$TRSTCTL_ISSUER_TOKEN"
"$TRSTCTL_CLI" --idempotency-key "$request_key" identities transition "$ident" \
  -f "$certdir/issue-request.json"

# Acceptance is asynchronous. Read the result for this exact request.
"$TRSTCTL_CLI" identities issuance-result "$ident" --request_key "$request_key" \
  > "$certdir/issuance-result.json"
jq '{identity_id,request_key,state,delivery,certificate}' "$certdir/issuance-result.json"
)
```

If the result says `pending`, repeat the read below to check progress.
`failed` means the original delivery exhausted its automatic retries; it does
not prove the CA never signed a certificate. `unavailable` means neither a
delivery record nor its exact public certificate is retained. In either case,
preserve the identity, request key, and original CSR. When a failed result
includes `retry.allowed=true`, correct the failure and request bounded recovery
as described below. Otherwise reconcile the original request with its issuer
before new issuance. A new request could mint a duplicate. Reading this endpoint
never retries delivery.

Recovery uses `POST /api/v1/identities/{id}/issuance-retry`, with a separate
`Idempotency-Key` and JSON containing the original `request_key` and a required
`reason` (at most 1,024 UTF-8 bytes). The operator needs `certs:issue` permission
in the identity's tenant. A `202` receipt means one attempt was granted; read the
original issuance result to observe completion. Reuse the same recovery key and
body after a lost response. A `409` means recovery cannot proceed under that
request; refresh the original result and follow its explanation.

The grant is an immutable `issuance.retry_requested` event. It preserves the
original outbox payload, CA command key, and cumulative attempt count; neither
receipt replay nor projection rebuild refunds a consumed attempt. Recovery
requires a retained usable certificate, a prepared signing operation with the
original subject key or CSR, or an exact retained external-CA result. Historical
requests without this evidence are refused. A new grant does not bypass current
policy, key custody, issuer binding, or lifecycle state checks.
The certificate audit history includes the grant; API readers can select it
with `feature_id=F4&action=retry_issuance` on `/api/v1/audit/events`.

`delivery.status` and `delivery.attempts` describe the original CA command,
when retained. An exact recorded public certificate takes precedence and returns
`issued` even if later delivery bookkeeping failed. That result alone does not
prove deployment to a listener. Keep the identity and request key; do not create
another identity to poll:

```bash
TRSTCTL_TOKEN="$TRSTCTL_ISSUER_TOKEN" "${TRSTCTL_CLI:-./bin/trstctl-cli}" \
  --server https://localhost:8443 --ca-file "$PWD/trstctl-eval-ca.pem" \
  identities issuance-result "$(cat trstctl-first-certificate/identity-id)" \
  --request_key "$(cat trstctl-first-certificate/issuance-request-key)" \
  > trstctl-first-certificate/issuance-result.json
jq '{identity_id,request_key,state,delivery,certificate}' trstctl-first-certificate/issuance-result.json
```

Once `issued`, save the returned public chain and inspect its first certificate:

```bash
jq -er 'select(.state == "issued") | .certificate_pem' \
  trstctl-first-certificate/issuance-result.json \
  > trstctl-first-certificate/returned-chain.pem
openssl x509 -in trstctl-first-certificate/returned-chain.pem \
  -noout -subject -issuer -dates -fingerprint -sha256
```

The matching private key remains `trstctl-first-certificate/payments.key`.
The returned chain is public data; it does not install trust or deploy to a
listener. Confirm the certificate and its owner in inventory and change history.
The example contact is a local evaluation fixture, not a working alert route.

If a mutation response is lost, retry the same body with the same idempotency key.
After a terminal error, inspect the saved identity and change history before
starting again. These fixed keys name one first CLI request in this disposable
tenant; use new keys for a deliberately different request. Never change the CSR
under an existing issuance key. See [First-certificate recovery](journeys/first-certificate.md).

How the API, CLI, and UI fit together is described in
[Platform & API](features/platform-and-api.md); the single issuance path and
its guarantees in [Issuance & CAs](features/issuance-and-cas.md).

## Next steps

- [Automate TLS across your fleet](journeys/automate-fleet-tls.md) or
  [give Kubernetes workloads an identity](journeys/kubernetes-workload-identity.md).
- Harden the deployment: [Configuration](configuration.md).
- Done evaluating? [Uninstall](uninstall.md) cleanly. Hit a snag?
  [Troubleshooting](troubleshooting.md).
