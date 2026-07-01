# Issue your first certificate

## Goal

When you finish this journey you will have a running trstctl control plane and your
**first real certificate** minted by it, owned, and visible in inventory. It is for
anyone evaluating trstctl who wants the shortest path from "nothing installed" to
"a signed certificate I can list" — using only the built-in CA, no external issuer,
no cloud account. In plain terms: you start a control plane, get a credential to
talk to it, name the thing that needs a certificate, flip it to *issued*, and watch
the control plane sign it and record it.

## Before you start

- **Docker with the Compose plugin**, or a Go toolchain if you run from source. The
  exact prerequisites and the full first-run walkthrough live in
  [Getting started](../getting-started.md) — this journey lifts its concrete steps
  into one straight line.
- About 1 GB of free disk for the PostgreSQL and NATS volumes.
- A few minutes. Issuance itself is sub-second; most of the wall-clock is the
  one-time stack startup.

## Steps

1. **Bring up the control plane.** From the repo root, start the one-command
   evaluation stack (control plane plus its datastores):

   ```sh
   docker compose -f deploy/docker/docker-compose.yml up --build
   ```

   You should see Compose wait for PostgreSQL and NATS to report healthy, then the
   control plane start its event log, projections, orchestrator, and API in order.

2. **Confirm it is serving.** The control plane serves over TLS by default with a
   self-signed evaluation certificate, so check health with `-k`:

   ```sh
   curl -fksS https://localhost:8443/healthz   # {"status":"ok"}
   ```

   You should get `{"status":"ok"}`. The web UI is the same binary at
   <https://localhost:8443>. How the API, CLI, and UI fit together is described in
   [Platform & API](../features/platform-and-api.md).

3. **Mint your first API token.** A fresh control plane fails closed — every route
   returns `401` until you present a credential. Run the host-local bootstrap verb
   (pick any UUID as your tenant id; a single-tenant deployment uses one well-known
   id):

   ```sh
   trstctl token create --tenant 11111111-1111-1111-1111-111111111111 --subject ci-bot
   # -> prints a trst_... token on stdout. Store it now; it is shown only once.
   ```

   You should see a `trst_...` token printed once. It carries operator scopes but
   deliberately **excludes** certificate issuance, so a bootstrap credential can
   administer the platform but cannot self-issue — the registration-authority split
   described in [Policy & governance](../features/policy-and-governance.md).

4. **Point the CLI at the control plane.** Export the server URL and keep the
   bootstrap credential in its own variable:

   ```sh
   export TRSTCTL_SERVER=https://localhost:8443
   export TRSTCTL_BOOTSTRAP_TOKEN=trst_...
   export TRSTCTL_TOKEN="$TRSTCTL_BOOTSTRAP_TOKEN"
   ```

   You should now be able to run setup/request-side `trstctl-cli` commands
   without a `401`.

5. **Create an owner and identity with the bootstrap token.** The owner is the
   service the certificate belongs to; the identity is the certificate itself:

   ```sh
   owner=$(echo '{"kind":"workload","name":"payments"}' | trstctl-cli owners create -f - | jq -r .id)
   ident=$(echo "{\"kind\":\"x509_certificate\",\"name\":\"payments.svc\",\"owner_id\":\"$owner\"}" \
             | trstctl-cli identities create -f - | jq -r .id)
   ```

   You should see each command return JSON. This creates the request-side records;
   it does not issue yet.

6. **Switch to an issuer credential for the issue transition.** The served gate
   requires `certs:issue`, so use an operator/approver token — not the bootstrap
   token — for the privileged transition. A real SSO operator session works; for a
   local evaluation you can mint a distinct API token through the served
   access-admin route:

   ```sh
   cat > issuer-token.json <<'JSON'
   {"subject":"first-cert-issuer","scopes":["identities:read","identities:write","certs:read","certs:issue"]}
   JSON
   trstctl-cli --idempotency-key first-cert-issuer-token access tokens create -f issuer-token.json > issuer-token-response.json
   export TRSTCTL_ISSUER_TOKEN="$(jq -r .token issuer-token-response.json)"

   echo '{"to":"issued"}' | TRSTCTL_TOKEN="$TRSTCTL_ISSUER_TOKEN" trstctl-cli identities transition "$ident" -f -
   sleep 2
   ```

   The transition to `issued` makes the orchestrator mint a leaf certificate
   through the built-in signer-backed CA. The single issuance path and the
   guarantees around it are covered in
   [Issuance & certificate authorities](../features/issuance-and-cas.md).

7. **See it in inventory.** List the certificates the control plane now tracks:

   ```sh
   TRSTCTL_TOKEN="$TRSTCTL_ISSUER_TOKEN" trstctl-cli certificates list
   ```

   You should see your freshly minted certificate — discovered, owned, and tracked.
   That is your first certificate.

## Where next

- [Automate TLS across your fleet with ACME](automate-fleet-tls.md)
- [Give your Kubernetes workloads an identity](kubernetes-workload-identity.md)

**Journey:** J1
**Steps through:** F4, F10, F11, F12, F8, F14
