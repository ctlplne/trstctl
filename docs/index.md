# trstctl

trstctl is a Machine Identity Security Control Plane for every credential that
is not a human: X.509 certificates, SSH host and user certificates, secrets,
API keys, tokens, and SPIFFE workload identities. It discovers, issues,
deploys, rotates, revokes, and retires those credentials across hybrid
infrastructure.

trstctl is MPL-2.0 open core: the Free/Community core is open source under the
repository `LICENSE`; Enterprise and Provider features are proprietary, live
under `ee/`, and activate with an offline Ed25519-signed license. Billing
units are control-plane deployments — never credentials or rotations.
trstctl is pre-1.0 and under active hardening: **[Current
limitations](limitations.md)** states what the running binary serves today
versus what exists only as library code. Check it before relying on a
capability.

## Where to start

**[Getting started](getting-started.md)** brings up a control plane and
issues your first certificate — the wizard path and the CLI path. Then pick
the journey that matches your goal; each chains the features you need,
end to end:

- [Automate TLS across your fleet](journeys/automate-fleet-tls.md) — ACME, DNS-01, renewal, deploy.
- [Give Kubernetes workloads an identity](journeys/kubernetes-workload-identity.md) — SPIFFE, no static secrets.
- [Enroll devices & IoT fleets](journeys/enroll-devices.md) — EST, SCEP, CMP.
- [Migrate from your existing CA](journeys/migrate-from-existing-ca.md) — discover, stand up, cut over.
- [Onboard a team as a tenant](journeys/onboard-a-team.md) — SSO, RBAC, policy, audit.
- [Manage application secrets](journeys/manage-secrets.md) — rotation, dynamic secrets, sharing.
- [Issue & trust SSH at scale](journeys/ssh-at-scale.md) — SSH CA, deploy/trust, attested certs.
- [Respond to a compromise](journeys/respond-to-compromise.md) — revoke, re-issue, break-glass.
- [Run in production](journeys/run-in-production.md) — TLS, monitoring, backup/DR, compliance.
- [Build on the API, CLI & SDKs](journeys/build-on-the-api.md) — OpenAPI, Go/TS SDKs, the graph.
- [Stay crypto-agile & migrate to PQC](journeys/crypto-agility-pqc.md) — inventory, plan, migrate.

## Reference

- [All features](features.md) — the full capability catalog with a deep-dive
  page per domain; keep the [glossary](glossary.md) open if a term is new.
- [The web console](web-console.md) — every screen in the browser UI, mapped
  to the served endpoints behind it (same binary as the API).
- [Install](install.md) — Linux, macOS, Windows, Docker, Kubernetes; plus
  [air-gapped installs](airgap.md) with the no-phone-home guard.
- [Configuration](configuration.md) — datastore switches, server settings,
  lifecycle thresholds.
- [Performance SLOs](performance.md), [capacity planning](performance-capacity.md),
  and [usability outcome SLOs](usability.md).
- [Compliance](compliance.md), [category leadership](category-leadership.md),
  and the [product decision register](product-decision-register.md).
- [Pricing](pricing.md) and [editions](editions.md) — the
  Free/Enterprise/Provider matrix and billable units.
- [CLI](cli.md) — drive trstctl from scripts and CI with `trstctl-cli`.
- [Terraform provider](terraform-provider.md) — profiles, short-lived PKI
  credentials, and secrets from infrastructure-as-code.
- [Troubleshooting](troubleshooting.md) — fixes for the issues people hit first.

## Extend it

- [Authoring a connector](guides/connector-authoring.md) — deploy renewed
  credentials to a new target.
- [Authoring a plugin](guides/plugin-authoring.md) — add a CA or connector as
  a sandboxed WASM plugin.

## How it is built

Event-sourced and multi-tenant from the first commit; all cryptography routes
through a single boundary, with private-key operations isolated in their own
process — the [signing service design](design/signing-service.md) explains
that boundary. [Telemetry](telemetry.md) is opt-in and off by default. State
lives in PostgreSQL, the event log in NATS JetStream — bundled for
single-node evaluation, external for production. It runs entirely on
infrastructure you control; the licenses are in the repository:
[MPL-2.0 core](https://github.com/ctlplne/trstctl/blob/main/LICENSE) and
[ee/LICENSE](https://github.com/ctlplne/trstctl/blob/main/ee/LICENSE).
