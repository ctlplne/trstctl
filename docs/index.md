# trstctl: machine trust without the maze

trstctl is a self-hosted control plane for every credential used by software and
machines instead of a person. It manages X.509 and SSH certificates, secrets, API
keys, tokens, and SPIFFE workload identities across hybrid infrastructure.

You do not need public-key infrastructure vocabulary to find the first action.
**Home** tells you what needs attention, what can break, when it is due, whether
automation is proven, who owns it, and what to do next. Six tools keep each kind
of daily work focused:

| Tool | Plain-language question |
| --- | --- |
| **Discover** | What machine credentials exist, where did we observe them, and what did we not scan? |
| **Certificate Lifecycle** | Which certificates could expire or fail renewal? |
| **Machine & Workload Trust** | Which machines can prove who they are? |
| **Secrets & Access** | Which secrets need rotation, delivery repair, or access review? |
| **Software Trust** | What was signed, who approved it, and was the signing key healthy? |
| **Trust Operations** | Which cross-product risk, incident, owner, alert, or system issue needs action? |

[Learn the product map](product-map.md) in five minutes. It explains non-human
identity (NHI), certificate lifecycle management (CLM), the six tools, shared
safety rails, status words, and the shortest path for each role.

## Choose your first outcome

### I want to evaluate the product

- **Blank installation:** [start the real stack and issue one certificate](getting-started.md).
- **Populated tour:** [follow the seeded demo browser walkthrough](demo-click-through.html).
- **Before relying on a capability:** read [Current limitations](limitations.md).

Success is concrete: verified HTTPS health, local single sign-on (SSO), one served
certificate, and visible event/audit readback. If any proof is missing, the
[troubleshooting guide](troubleshooting.md) starts with the safest diagnostic.

### I operate credentials every day

Start on Home, then follow the workspace named on the highest-priority item. For a
complete task, choose a journey:

- [Automate TLS across your fleet](journeys/automate-fleet-tls.md)
- [Give Kubernetes workloads an identity](journeys/kubernetes-workload-identity.md)
- [Manage application secrets](journeys/manage-secrets.md)
- [Issue and trust SSH at scale](journeys/ssh-at-scale.md)
- [Migrate from an existing certificate authority](journeys/migrate-from-existing-ca.md)

### I am responding to an incident

Open [Respond to a compromise](journeys/respond-to-compromise.md). It starts with
evidence preservation and blast-radius discovery, then replaces and revokes in an
order designed to avoid turning containment into an outage. Keep the
[incident-response runbook](runbooks/incident-response.md) open during the event.

### I need assurance evidence

Start with [Audit and compliance](compliance.md), then read the
[architecture invariants](design/architecture-invariants.md),
[key-custody boundary](custody.md), [threat model](security/threat-model.md), and
[privacy data catalog](privacy-data-catalog.md). These pages distinguish shipped
controls from external assessments that have not occurred.

### I am building automation

Follow [Build on the API, CLI, and SDKs](journeys/build-on-the-api.md). The running
control plane publishes its OpenAPI 3.1 contract. The CLI and generated clients use
that served contract, but each surface has its own documented coverage and edition
rules.

## What trstctl does

trstctl discovers, issues, deploys, rotates, revokes, and retires machine
credentials. It connects work that separate certificate, secrets, workload, and
software-signing products often hide from one another: ownership, dependency
blast radius, expiry alerts, delivery proof, policy, and audit history.

It is MPL-2.0 open core. Community code is open source under the repository
`LICENSE`. Proprietary Enterprise and Provider code lives under `ee/` and activates
with an offline Ed25519-signed license. Billing units are control-plane deployments,
never credential or rotation counts. trstctl is pre-1.0 and under active hardening;
[Current limitations](limitations.md) is the authority for what the running binary
serves today.

## How it protects the trust boundary

State changes enter an append-only event log. PostgreSQL enforces tenant isolation.
Private-key operations run in a separate signing process. External effects use a
transactional outbox, and bounded queues keep one slow subsystem from starving the
rest. [Architecture invariants](design/architecture-invariants.md) explains the
exact design and its test boundaries.

Everything runs on infrastructure you control. Telemetry is opt-in and off by
default. Exact license terms ship in the source checkout at `LICENSE` (MPL-2.0 core)
and `ee/LICENSE` (commercial code); [Editions](editions.md) explains the boundary.

Next: [understand the product map](product-map.md) or
[start a blank evaluation](getting-started.md).
