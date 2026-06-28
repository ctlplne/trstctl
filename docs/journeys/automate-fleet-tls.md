# Automate TLS across your fleet with ACME

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
  one up via [Issue your first certificate](first-certificate.md) or
  [Getting started](../getting-started.md).
- A standard ACME client. This journey uses **certbot**.
- Write access to a DNS zone you control — ideally a throwaway validation zone you
  delegate to (see step 4), so trstctl never holds your production DNS keys.
- An API token exported as `TRSTCTL_TOKEN` if you want to inspect results from the
  CLI (from the first-certificate journey).

## Steps

1. **Enable the ACME server.** trstctl speaks the CA side of ACME. Turn it on and
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

2. **Point a client at the directory and prove control via DNS-01.** With certbot,
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

3. **Let trstctl pick the challenge when you don't want to.** Rather than choosing a
   method per name, trstctl can select one automatically: wildcards must use DNS-01,
   an unreachable port 80 falls to DNS-01, otherwise HTTP-01 — and it records a
   human-readable rationale in the tamper-evident audit trail and never silently
   degrades. You should see the chosen method and its rationale captured per order.

4. **Keep production DNS untouched with CNAME delegation.** For the recommended
   production setup, add a one-time CNAME so trstctl only ever writes in an isolated
   validation zone:

   ```text
   _acme-challenge.example.com.  CNAME  <random-subdomain>.auth.acme-dns.example.net.
   ```

   You should see validation succeed while trstctl holds no production DNS
   credentials. trstctl also checks CAA before signing, so only an authorized issuer
   can mint for the name — both covered in
   [ACME & DNS](../features/acme-and-dns.md).

5. **Plan renewal so the fleet doesn't stampede.** trstctl publishes ACME Renewal
   Information (ARI) per certificate — a suggested renewal window (the last third of
   the certificate's life) that each client picks a spread-out point inside, served
   at `GET /acme/renewal-info/{certid}`. You should see clients renew within their
   window rather than all at once. The renewal model is described in
   [Lifecycle & PQC](../features/lifecycle-and-pqc.md).

6. **Deploy the renewed certificate onto the thing that uses it.** Getting the cert
   is only half the job; it has to land on the server or appliance that serves it. A
   deployment connector installs the credential on one kind of target (write to
   nginx and reload, import into AWS Certificate Manager, push to an F5, configure a
   NetScaler or PAN-OS appliance) and verifies it. You should see the new certificate
   delivered and the target reloaded. The connector set and its capability-scoped
   sandbox are covered in
   [Deployment connectors](../features/deployment-connectors.md).

   Create the tenant target first, bind the identity to it, then deploy through the
   normal lifecycle path:

   ```sh
   trstctl connector target create \
     --name edge/prod/payments \
     --connector nginx \
     --config-json '{"credential_ref":"secret://connectors/nginx/edge","host":"edge-1.internal"}'

   trstctl connector target bind --identity "$IDENTITY_ID" --target "$TARGET_ID"
   trstctl connector target deploy --identity "$IDENTITY_ID" --target "$TARGET_ID"
   ```

   The same flow is served in the console under **Deployment connectors** and over
   REST at `/api/v1/connectors/targets`. The target stores non-secret metadata and
   credential references only. Actual target mutation still moves through
   `connector.deploy` outbox work; if no native registry or signed plugin owns the
   connector, the binary records an `unrouted` receipt instead of pretending delivery
   happened.

## Where next

- [Give your Kubernetes workloads an identity](kubernetes-workload-identity.md)
- [Enroll devices and IoT fleets](enroll-devices.md)

**Journey:** J2
**Steps through:** F5, F69, F70, F71, F72, F73, F74, F6, F46, F7, F27
