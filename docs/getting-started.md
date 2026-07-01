# Getting started

This walkthrough takes a fresh machine to its **first issued certificate in a few
minutes** — and most of those minutes are the single agent-install step, not
waiting on trstctl. The control plane is serving about two minutes after
`compose up`, and issuance itself is a sub-second operation (see the measured
figure under [Issue your first cert](#issue-your-first-cert)). You will bring up
the blank control plane with one command, then follow the in-product wizard to
connect a CA, install an agent, and issue a certificate.

If you want a pre-populated sales/demo environment instead of a blank first-run
workflow, use the dedicated demo stack:

```bash
docker compose -f deploy/demo/docker-compose.yml up --build
```

It serves the UI at <https://localhost:9443>, includes local SSO, and seeds demo
owners, certificates, secrets, transit keys, and managed keys. The walkthrough
below uses the blank operational/eval stack at <https://localhost:8443>.

## Prerequisites

- Docker with the Compose plugin (`docker compose version` works), **or** a Go
  1.26.4+ toolchain if you prefer to run from source.
- About 1 GB of free disk for the Postgres and NATS volumes.

## 1. Bring up the control plane (about 2 minutes)

trstctl ships a one-command blank evaluation stack — the control plane plus
PostgreSQL and NATS JetStream:

```bash
docker compose -f deploy/docker/docker-compose.yml up --build
```

Compose starts Postgres and NATS, waits for both to report healthy, and then
starts the control plane wired to them through its **external** datastore
configuration. The control-plane process starts the event log, projections,
orchestrator, and API in order and supervises the signing service as a child
process, so it answers real API requests end to end. The control plane serves
over **TLS by default** with a self-signed internal certificate, so confirm it is
up with `-k` (the eval certificate is not from a public CA):

```bash
curl -fksS https://localhost:8443/healthz   # {"status":"ok"}
```

The web UI is served by the same binary at <https://localhost:8443>.
The blank Compose stack also enables the served agent mTLS gRPC channel for the
wizard and publishes it as `localhost:19443` (container `:9443`). The dedicated
demo stack keeps `localhost:9443` for its UI, so the two Compose projects can
still run side by side.

!!! tip "Transport encryption"
    TLS is on out of the box (`server.tls.mode=internal`). For production, set
    `server.tls.mode=file` with your own certificate (`TRSTCTL_SERVER_TLS_CERT_FILE`
    / `TRSTCTL_SERVER_TLS_KEY_FILE`). Plaintext mode is local-dev only and requires
    both `server.tls.mode=disabled`, `TRSTCTL_DEV_ALLOW_PLAINTEXT=true`, and a
    loopback `server.addr`; it serves plaintext and logs a loud warning. See
    [Configuration](configuration.md#transport-encryption-tls).

!!! tip
    Want to point at your own managed Postgres/NATS instead of the
    Compose-provided ones? See [Configuration](configuration.md#external-datastores).
    The same env vars the Compose file sets are all you need.

!!! note "Two ways to evaluate: the single binary, or Compose"
    Compose is the recommended eval path because it runs explicit PostgreSQL and
    NATS service containers while exercising the same external-datastore wiring as
    production. The `trstctl` binary can also run a single-node eval stack —
    bundled PostgreSQL (`TRSTCTL_POSTGRES_MODE=bundled`, the default) plus embedded
    NATS (`TRSTCTL_NATS_MODE=embedded`, the default) — on host archives with
    committed provenance pins in `deploy/supply-chain/embedded-postgres.json`
    (summarized in [Supply chain](supply-chain.md)).
    Those pins currently cover `linux-amd64`, `linux-arm64v8`, and
    `darwin-arm64v8`. Bundled PostgreSQL downloads its pinned runtime once on first
    use and fails closed if the host archive is unsupported, unpinned, or hash-
    mismatched; in that case use Compose or set
    `TRSTCTL_POSTGRES_MODE=external` / `TRSTCTL_POSTGRES_DSN`. For **production**,
    use external PostgreSQL and NATS (`TRSTCTL_NATS_MODE=external` /
    `TRSTCTL_NATS_URL`) exactly as the Compose stack and Helm chart wire up. See
    [Configuration](configuration.md#datastores).

## 2. Open the UI and sign in

Visit <https://localhost:8443> (accept the self-signed evaluation certificate) and
sign in. On a fresh install you land on a
**Get started** prompt that launches the setup wizard. The wizard has three
steps, each a single screen.

## 3. Run the wizard (about 10 minutes)

### Use the internal CA

In **Use the internal CA**, continue with the signer-backed X.509 CA that the
server provisioned at boot. This first certificate flow does not create an
external issuer. External X.509 issuers require a certificate chain and are added
after setup from the issuers/API surface.

### Install an agent

In **Install an agent**, trstctl mints a one-time bootstrap token. Save that
token to a local file readable only by the installing user. Then build the local
evaluation CA bundle the agent pins. It contains the HTTPS self-signed eval
certificate used for `/enroll/bootstrap` and the signer-custodied agent-channel
CA used for mTLS on `localhost:19443`:

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

If you recreate or restart the Compose control-plane container before enrolling,
capture the HTTPS eval certificate again and rebuild `./trstctl-ca.pem`; the
internal eval HTTPS certificate is self-signed at boot. The agent CA file
persists in the `trstctldata` volume.

The agent generates its key locally and enrolls with the token — **private keys
never leave the host**. With `--inventory-cert-roots`, it also reports public
certificate metadata from those directories over the mTLS agent channel; with
`--inventory-os-trust-roots`, it reports public CA trust anchors the host trusts; with
`--inventory-private-key-roots`, it locates private-key files but sends only
metadata and public-key-derived fingerprints. Findings then show up in discovery inventory and the credential graph. The wizard polls and
advances automatically once the agent registers (typically well under five minutes). See [Install](install.md)
for how to get the `trstctl-agent` binary on Linux, macOS, and Windows.

### Issue your first cert

In **Issue your first cert**, name the service the certificate belongs to and
click **Issue**. trstctl creates the owner and identity and issues the
certificate through the internal signer-backed CA. You will see a confirmation
and a link to the certificate inventory.

That is your first certificate — discovered, owned, and tracked. trstctl will now
track it and alert before expiry. Renewal is a manual, one-click action today.

!!! note "Measured issuance time"
    Issuance is fast. In trstctl's end-to-end integration test — the assembled
    control plane with the out-of-process signer — a lifecycle transition to
    *issued* drives the outbox handler to mint the certificate and record it in
    inventory in **tens of milliseconds** (`TestAssembledServerIssuesCertIntoInventory`
    measured ~20 ms). In the running server the outbox dispatcher polls about once
    a second, so the certificate appears within roughly a second of clicking
    **Issue**. The wall-clock for the whole walkthrough is dominated by installing
    the agent, not by trstctl.

## Get your first API token

A freshly booted control plane **fails closed**: every API route returns `401`
until you present a credential. Interactive OIDC, SAML, and LDAP / Active Directory
login are served when their `auth.*.enabled` blocks are configured, and SCIM 2.0 can
provision users after you configure a tenant-bound SCIM token, but the
zero-dependency first credential is still the host-local bootstrap token. Run the network-trust-free bootstrap verb on the
host (it talks straight to the datastore — no existing token required) and it
prints a tenant-scoped token **once**:

```bash
# Pick any UUID as your tenant id (a single-tenant deployment uses one well-known id):
trstctl token create --tenant 11111111-1111-1111-1111-111111111111 --subject ci-bot
# -> prints a trst_... token on stdout. Store it now; it is shown only once.
```

The token carries its tenant and a full set of operator scopes — deliberately
**excluding** certificate issuance (`certs:issue`), so a bootstrap credential can
administer the platform but cannot self-issue a certificate. Use it as
`Authorization: Bearer <token>` (or `TRSTCTL_TOKEN` for the CLI).

## Prefer the command line?

Everything the wizard does is also scriptable with `trstctl-cli`. With the API
token you minted above (see the [CLI reference](cli.md)):

```bash
export TRSTCTL_SERVER=https://localhost:8443
export TRSTCTL_TOKEN=trst_...

# Create an owner and an identity; the id of each is in its JSON.
owner=$(echo '{"kind":"workload","name":"payments"}' | trstctl-cli owners create -f - | jq -r .id)
ident=$(echo "{\"kind\":\"x509_certificate\",\"name\":\"payments.svc\",\"owner_id\":\"$owner\"}" \
          | trstctl-cli identities create -f - | jq -r .id)

# Transition it to "issued": the running outbox dispatcher mints the certificate
# through the internal signer-backed CA.
echo '{"to":"issued"}' | trstctl-cli identities transition "$ident" -f -
sleep 2

# The newly minted certificate is now in inventory.
trstctl-cli certificates list
```

## Next steps

- Harden the deployment: [Configuration](configuration.md).
- Learn the lifecycle and inventory views in the UI.
- When you are done evaluating, [Uninstall](uninstall.md) cleanly.
- Hit a snag? [Troubleshooting](troubleshooting.md).
