# Automate TLS across your fleet with ACME

<!-- trstctl:journey-census:start -->
!!! success "Served path — wiring census 81/81"

    The Definition-of-Done census reports **81/81 required capabilities served**: **12 of 81 census rows launch the shipped binary** and **69 of 81 are proved through the production-assembled handler**.
    Production-assembled means production `buildRunDeps` output driving the assembled `Server.Handler` in-process, with a hand-built `Deps` rejected; only the process launch differs.
    Independently proof-gated capability rows used by this journey (all `required`, all `served`): `connector.registry`, `connector_right_size.dispatch`, `protocol_ergonomics.eval_profile`.
    Core surfaces guarded by route and journey tests: `acme_protocol`, `lifecycle_endpoint_bindings`, `certificate_renewal`.
    This badge is generated from `wiring-census.json`; `make journey-census-check` fails closed if the census or this page drifts.
<!-- trstctl:journey-census:end -->

## Goal

When you finish this journey, machines across your fleet will get and renew their
own TLS certificates from trstctl automatically, with no human in the loop — proven
by a DNS record instead of an open port, so it works for wildcards and hosts without
a public web server. It is for platform and infrastructure teams who already run an
ACME client (certbot, acme.sh, Caddy, cert-manager) and want trstctl to be the CA
those clients enroll against. In plain terms: you turn on trstctl's ACME endpoint,
point a standard client at it, prove you control a name via DNS, and let renewal and
deployment happen on their own.

## Before you start

- A running, reachable trstctl control plane with a provisioned issuing CA. Bring
  one up via [Getting started](../getting-started.md).
- A standard ACME client. This journey uses **certbot**.
- Write access to a DNS zone you control — ideally a throwaway validation zone you
  delegate to (see step 4), so trstctl never holds your production DNS keys.
- An API token exported as `TRSTCTL_TOKEN` if you want to inspect results from the
  CLI (from the getting-started CLI path).

## Steps

1. Enable the ACME server. trstctl speaks the CA side of ACME. Turn it on and
   bind it to your tenant in configuration:

   ```yaml
   protocols:
     acme:
       enabled: true
       tenant_id: "11111111-1111-1111-1111-111111111111"
   ```

   You should see the control plane mount the directory at `/directory` and the
   order/challenge endpoints under `/acme/...` on startup. It activates only when an
   issuing CA is provisioned. The whole ACME and DNS-validation toolkit is described
   in [ACME & DNS](../features/acme-and-dns.md).

2. Point a client at the directory and prove control via DNS-01. With certbot,
   request a name (and a wildcard) using the DNS challenge:

   ```sh
   certbot certonly \
     --server https://trstctl.example.com/directory \
     --preferred-challenges dns \
     -d 'example.com' -d '*.example.com'
   ```

   You should see certbot publish a `_acme-challenge` TXT record, trstctl look it up
   and confirm it, and certbot report `Successfully received certificate`. The
   DNS-01 publish side and the propagation/preflight checks are detailed in
   [ACME & DNS](../features/acme-and-dns.md).

3. Let trstctl pick the challenge when you don't want to. It selects the method
   automatically (wildcards and unreachable port 80 use DNS-01, otherwise
   HTTP-01), records a human-readable rationale per order in the audit trail,
   and never silently degrades — the selection rules are detailed in
   [ACME & DNS](../features/acme-and-dns.md).

4. Keep production DNS untouched with CNAME delegation. For the recommended
   production setup, add a one-time CNAME so trstctl only ever writes in an isolated
   validation zone:

   ```text
   _acme-challenge.example.com.  CNAME  <random-subdomain>.auth.acme-dns.example.net.
   ```

   You should see validation succeed while trstctl holds no production DNS
   credentials. trstctl also checks CAA before signing, so only an authorized issuer
   can mint for the name — both covered in
   [ACME & DNS](../features/acme-and-dns.md).

5. Plan renewal so the fleet doesn't stampede. trstctl publishes ACME Renewal
   Information (ARI) per certificate — a suggested renewal window (the last third of
   the certificate's life) that each client picks a spread-out point inside, served
   at `GET /acme/renewal-info/{certid}`. You should see clients renew within their
   window rather than all at once. The renewal model is described in
   [Lifecycle & PQC](../features/lifecycle-and-pqc.md).

6. Deploy the renewed certificate onto the thing that uses it. Getting the cert
   is only half the job; it has to land on the server or appliance that serves it. A
   deployment connector installs the credential on one kind of target (write to
   nginx and reload, import into AWS Certificate Manager, update PostgreSQL/MySQL
   TLS files, rotate RabbitMQ, push to an F5/BIG-IP, Citrix ADC/NetScaler, A10,
   Kemp, or PAN-OS appliance) and verifies it. You should see the new certificate
   delivered and the target reloaded. The connector set and its capability-scoped
   sandbox are covered in
   [Deployment connectors](../features/deployment-connectors.md).

   Use the endpoint-binding lifecycle API to review one exact issuer, key-custody
   path, destination, and effect list before any write. Put this request in
   `endpoint-binding-plan.json`; replace the issuer with the exact configured
   external, private, or platform CA you intend to keep using:

   ```json
   {
       "owner_id": "<owner-id>",
       "identity_name": "payments.example.com",
       "reason": "automate the reviewed payments endpoint",
       "issuer": {
         "source": "external",
         "id": "corporate-digicert"
       },
       "target": {
         "name": "edge/prod/payments",
         "connector": "nginx",
         "config": {
           "credential_ref": "secret://connectors/nginx/edge",
           "host": "edge-1.internal"
         }
       }
   }
   ```

   Preview it. This POST is read-only: the returned `preview_writes` and
   `preview_external_effects` must both be empty.

   ```sh
   trstctl-cli lifecycle endpoint-bindings preview \
     -f endpoint-binding-plan.json > endpoint-binding-preview.json
   jq '{ready,effect_free,issuer,target,custody,changes,queued_lifecycle_intents,recovery_steps,verification_steps,preview_writes,preview_external_effects,request_fingerprint}' \
     endpoint-binding-preview.json
   ```

   After reviewing those exact values, copy the server fingerprint into the
   execution body and authorize the idempotent mutation:

   ```sh
   jq --arg fingerprint "$(jq -r .request_fingerprint endpoint-binding-preview.json)" \
     '. + {preview_fingerprint:$fingerprint}' \
     endpoint-binding-plan.json > endpoint-binding-execute.json
   trstctl-cli --idempotency-key fleet-edge-payments-1 \
     lifecycle endpoint-bindings create -f endpoint-binding-execute.json
   ```

   The same flow is served in the console under **Deployment connectors** and over
   REST at `/api/v1/lifecycle/endpoint-bindings/preview` and
   `/api/v1/lifecycle/endpoint-bindings`. The target stores non-secret metadata and
   credential references only. When a host target declares `verify_server_name`, the
   requested `identity_name` must be that exact DNS name. The console fills and locks
   it from the destination; the API preview rejects a mismatch before issuance or a
   target write. Initial issuance and renewal use the previewed issuer;
   an unavailable issuer fails closed instead of falling back. Actual target mutation
   still moves through `connector.deploy` outbox work; if no native registry or signed
   plugin owns the connector, the binary records a failed worker receipt and leaves
   the work pending. A queued receipt has zero attempts and is intent evidence only;
   it never claims that delivery happened.

## Where next

- [Give your Kubernetes workloads an identity](kubernetes-workload-identity.md)
- [Enroll devices and IoT fleets](enroll-devices.md)

**Journey:** J2
**Steps through:** F5, F69, F70, F71, F72, F73, F74, F6, F46, F7, F27
