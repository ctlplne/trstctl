# Getting started

This walkthrough takes a fresh machine to its **first issued certificate in under
15 minutes**. You will bring up the control plane with one command, then follow
the in-product wizard to connect a CA, install an agent, and issue a certificate.

## Prerequisites

- Docker with the Compose plugin (`docker compose version` works), **or** a Go
  1.25+ toolchain if you prefer to run from source.
- About 1 GB of free disk for the Postgres and NATS volumes.

## 1. Bring up the control plane (about 2 minutes)

certctl ships a one-command evaluation stack — the control plane plus PostgreSQL
and NATS JetStream:

```bash
docker compose -f deploy/docker/docker-compose.yml up --build
```

Compose starts Postgres and NATS, waits for both to report healthy, and then
starts the control plane wired to them through its **external** datastore
configuration. The web UI is served by the control-plane binary at
<http://localhost:8443>.

!!! tip
    Want to point at your own managed Postgres/NATS instead of the bundled ones?
    See [Configuration](configuration.md#external-datastores). The same env vars
    the Compose file sets are all you need.

## 2. Open the UI and sign in

Visit <http://localhost:8443> and sign in. On a fresh install you land on a
**Get started** prompt that launches the setup wizard. The wizard has three
steps, each a single screen.

## 3. Run the wizard (about 10 minutes)

### Connect a CA

In **Connect a CA**, give your issuer a name and continue. certctl brokers
issuance to the CA you connect; this first issuer is all you need to proceed.

### Install an agent

In **Install an agent**, certctl mints a one-time bootstrap token and shows the
exact command to run on a host inside your network:

```bash
certctl-agent enroll --server https://localhost:8443 --token <BOOTSTRAP_TOKEN>
```

The agent generates its key locally and enrolls with the token — **private keys
never leave the host**. The wizard polls and advances automatically once the
agent registers (typically well under five minutes). See [Install](install.md)
for how to get the `certctl-agent` binary on Linux, macOS, and Windows.

### Issue your first cert

In **Issue your first cert**, name the service the certificate belongs to and
click **Issue**. certctl creates the owner and identity and issues the
certificate through the CA you connected. You will see a confirmation and a link
to the certificate inventory.

That is your first certificate — discovered, owned, and tracked. certctl will now
rotate and renew it automatically.

## Prefer the command line?

Everything the wizard does is also scriptable with `certctl-cli`. With a CI token
(see the [CLI reference](cli.md)):

```bash
export CERTCTL_SERVER=https://localhost:8443
export CERTCTL_TOKEN=certctl_pat_...

# Create an owner and an issuer, then issue and inspect.
echo '{"kind":"workload","name":"payments"}' | certctl-cli owners create -f -
echo '{"kind":"x509_ca","name":"Primary CA"}' | certctl-cli issuers create -f -
certctl-cli certificates list
```

## Next steps

- Harden the deployment: [Configuration](configuration.md).
- Learn the lifecycle and inventory views in the UI.
- When you are done evaluating, [Uninstall](uninstall.md) cleanly.
- Hit a snag? [Troubleshooting](troubleshooting.md).
