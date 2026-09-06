# Start here: web servers (Apache, NGINX, IIS)

You run web servers whose certificates someone renews by hand, and you want the
renewal to happen on the host, on time, with proof — without changing the CA you
already trust. This page is the shortest path for that reader. It names the console
pages in the order you will use them and links the full journey for each step.

## What you will end up with

- One listener (start with a canary) whose certificate is issued by the CA you chose,
  installed by the trstctl agent on the host, verified on the wire, and renewed before
  expiry.
- An accountable owner, an alert route to your incident tool, and an exportable
  evidence bundle.

## Before you start

| Need | Where |
| --- | --- |
| A control plane you can open with validated TLS | [Local evaluation TLS](../local-evaluation-tls.md), including the isolated browser profile that changes nothing on your workstation |
| The agent on the web-server host | [Deployment connectors](../features/deployment-connectors.md#host-executed-keys) — host families (Apache, NGINX, IIS, HAProxy, Caddy, Traefik) run with `"executor": "agent"` so the private key never leaves the host |
| An owner with a current attestation | **Ownership → Add owner** attests on create; an owner without a current attestation is refused at the endpoint preview |
| Your CA registered (or the built-in evaluation CA) | [Keep your existing CA](../journeys/preserve-existing-ca.md#operator-prerequisites): for ACME CAs, a DNS-01 provider configuration that covers the listener's zone |

## The seven clicks

1. **Discover → Sources → Add source**: a network source for the host and port
   (`host:port` targets; loopback only with the local-test boundary switched on). Run it.
2. **Discover → Findings → Review finding → Claim**: create the identity from the
   finding and claim it as managed.
3. **Connectors → Destinations and safe actions → Add destination**: pick the web
   server family; the form seeds the host-executed template (certificate and key
   paths, `verify_address`, `verify_server_name`). Adjust the paths.
4. **Endpoint lifecycle** on the same page: destination, owner, identity name (pinned
   to `verify_server_name`), CA → **Build safe preview**. The preview refuses anything
   deployment would refuse later — control-plane custody with an asynchronous CA, an
   owner without a current attestation, a DNS-01 zone nobody can validate — and names
   the fix. Nothing is queued by a preview.
5. **Authorize issuance and deployment**: exactly one issuance; the host generates the
   key and sends a CSR; the agent installs and verifies the listener.
6. **Identities → View details → Renew** when you want to see a renewal happen now; the
   automatic renewal window is on **Identities → Lifecycle automation**.
7. **Notifications → Routing policies**: route the owner to your incident channel,
   **Review exact route**, save, then **Channels & test → Queue test**. Export the
   evidence bundle from **Audit → Signatures and evidence export**.

## IIS

IIS is a host family like the others: the agent runs on Windows, binds the certificate
through the certificate store, and verifies the listener. Current Windows coverage is
stated in [Current limitations](../limitations.md); a live IIS binding needs a real
Windows host and IIS, which the shipped labs do not include.

## When something is refused

Every refusal on this path is a named prerequisite with a next step: the preview's
detail text, the destination's connector test (`dry_run_blocked` names the exact
reachability error), and the owner's readiness on the Ownership page. Keep the
[troubleshooting guide](../troubleshooting.md) open; it starts with the safest
diagnostic.
