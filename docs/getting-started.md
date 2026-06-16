# Getting started

This walkthrough takes a fresh machine to its **first issued certificate in a few
minutes** — and most of those minutes are the single agent-install step, not
waiting on trstctl. The control plane is serving about two minutes after
`compose up`, and issuance itself is a sub-second operation (see the measured
figure under [Issue your first cert](#issue-your-first-cert)). You will bring up
the control plane with one command, then follow the in-product wizard to connect
a CA, install an agent, and issue a certificate.

## Prerequisites

- Docker with the Compose plugin (`docker compose version` works), **or** a Go
  1.25+ toolchain if you prefer to run from source.
- About 1 GB of free disk for the Postgres and NATS volumes.

## 1. Bring up the control plane (about 2 minutes)

trstctl ships a one-command evaluation stack — the control plane plus PostgreSQL
and NATS JetStream:

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

!!! tip "Transport encryption"
    TLS is on out of the box (`server.tls.mode=internal`). For production, set
    `server.tls.mode=file` with your own certificate (`TRSTCTL_SERVER_TLS_CERT_FILE`
    / `TRSTCTL_SERVER_TLS_KEY_FILE`). Only set `server.tls.mode=disabled` for local
    development — it serves plaintext and logs a loud warning. See
    [Configuration](configuration.md#transport-encryption-tls).

!!! tip
    Want to point at your own managed Postgres/NATS instead of the
    Compose-provided ones? See [Configuration](configuration.md#external-datastores).
    The same env vars the Compose file sets are all you need.

!!! note "Two ways to evaluate: the single binary, or Compose"
    The `trstctl` binary runs a **complete single-node evaluation stack out of the
    box** — bundled single-node PostgreSQL (`TRSTCTL_POSTGRES_MODE=bundled`, the
    default) and embedded NATS (`TRSTCTL_NATS_MODE=embedded`, the default), no
    external services required. For **production**, point it at managed datastores:
    `TRSTCTL_POSTGRES_MODE=external` / `TRSTCTL_POSTGRES_DSN` and
    `TRSTCTL_NATS_MODE=external` / `TRSTCTL_NATS_URL` — exactly what the Compose
    stack and Helm chart wire up. See [Configuration](configuration.md#datastores).

## 2. Open the UI and sign in

Visit <https://localhost:8443> (accept the self-signed evaluation certificate) and
sign in. On a fresh install you land on a
**Get started** prompt that launches the setup wizard. The wizard has three
steps, each a single screen.

## 3. Run the wizard (about 10 minutes)

### Connect a CA

In **Connect a CA**, give your issuer a name and continue. trstctl brokers
issuance to the CA you connect; this first issuer is all you need to proceed.

### Install an agent

In **Install an agent**, trstctl mints a one-time bootstrap token and shows the
exact command to run on a host inside your network:

```bash
trstctl-agent enroll --server https://localhost:8443 --token <BOOTSTRAP_TOKEN>
```

The agent generates its key locally and enrolls with the token — **private keys
never leave the host**. The wizard polls and advances automatically once the
agent registers (typically well under five minutes). See [Install](install.md)
for how to get the `trstctl-agent` binary on Linux, macOS, and Windows.

### Issue your first cert

In **Issue your first cert**, name the service the certificate belongs to and
click **Issue**. trstctl creates the owner and identity and issues the
certificate through the CA you connected. You will see a confirmation and a link
to the certificate inventory.

That is your first certificate — discovered, owned, and tracked. trstctl will now
rotate and renew it automatically.

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
until you present a credential, and interactive OIDC login is not wired in this
build. To get the first credential, run the network-trust-free bootstrap verb on
the host (it talks straight to the datastore — no existing token required) and it
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

# Create an owner, an issuer, and an identity; the *id of each is in its JSON.
owner=$(echo '{"kind":"workload","name":"payments"}' | trstctl-cli owners create -f - | jq -r .id)
issuer=$(echo '{"kind":"x509_ca","name":"Primary CA"}' | trstctl-cli issuers create -f - | jq -r .id)
ident=$(echo "{\"kind\":\"x509_certificate\",\"name\":\"payments.svc\",\"owner_id\":\"$owner\",\"issuer_id\":\"$issuer\"}" \
          | trstctl-cli identities create -f - | jq -r .id)

# Transition it to "issued": the running outbox dispatcher mints the certificate.
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
