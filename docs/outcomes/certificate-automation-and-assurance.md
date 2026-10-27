# Certificate automation and assurance

Find every certificate you have, give each one an owner, issue and deploy
replacements without anyone handling a private key, check what your endpoints
actually serve, renew and revoke on time, and show the evidence to the people
who rely on it.

In the console, start at **Certificates** (`/certificates`) or **Discovery**
(`/discovery`); the console home links here.

## How to read the proof column

Each step names the evidence it leaves behind and how strongly it is proved
today. The proof column names the test, so you can read it or run it yourself.

- **Proved end to end**: a test drives the step through the assembled control
  plane (the same handler the binary serves) and checks its effect.
- **Proved end to end, when enabled**: the same, for a step that needs a setting
  or a component turned on first.
- **Proved on the shipped binary**: a test builds and launches the binary.
- **What comes next**: not built yet; today's status is stated.

## The workflow

| Step | What happens | Evidence it leaves | Proof | Read more |
|---|---|---|---|---|
| Discover | Network, SSH and cloud discovery sources scan for certificates and record each one they find. | Discovery findings, each with the source and scan that found it | Proved end to end: `internal/server/discovery_served_test.go` | [Discovery source kinds](../features/discovery-and-inventory.md#discovery-source-kinds-one-shape) |
| Own | Owners are recorded and certificates assigned to them; a discovered certificate can be claimed for a managed identity. | Ownership assignment events naming who assigned what and why | Proved end to end: `internal/server/ownership_assignment_served_test.go` | [Ownership](../web-console.md#ownership-owners), [Discovery triage](../features/discovery-and-inventory.md#discovery-triage) |
| Issue | One issuance path for the platform CA, a CA hierarchy you run, external CAs and ACME. | The issued certificate, its issuance event and the key's recorded origin | Proved end to end: `internal/server/ca_hierarchy_served_test.go`, `internal/server/external_ca_served_test.go`; ACME when enabled: `internal/server/protocols_served_test.go` | [One issuance path, any CA](../features/issuance-and-cas.md#one-issuance-path-any-ca-f4) |
| Deploy | A connector or a host agent installs the certificate; for a target marked for agent execution, the key is generated on the host and never leaves it. | A delivery receipt per deployment, signed by the agent when an agent did the work | Proved end to end, when enabled (a host agent enrolled): `internal/server/journey_delivery_served_test.go`, `internal/server/host_agent_remote_served_test.go` | [Where credentials are installed](../features/deployment-connectors.md#console-journey-where-credentials-are-installed) |
| Verify | The host agent completes a TLS handshake with the endpoint after it deploys, a relay checks on a schedule, and external observers report what they see from outside. | Endpoint observations per listener and vantage, and observers' reports, kept apart from the product's own record | Proved end to end: `internal/server/external_observer_served_test.go` | [External observers](../features/deployment-connectors.md#confirm-deployments-from-an-external-observer-a180) |
| Renew | The lifecycle scheduler renews ahead of expiry, inside the CA's ACME renewal information window when it publishes one. | Renewal runs with predecessor and successor, and the redeployment receipts | Proved end to end: `internal/server/journey_delivery_served_test.go` | [Lifecycle automation](../features/lifecycle-and-pqc.md#lifecycle-automation-f6) |
| Revoke | A certificate is revoked and its status published over OCSP and in CRLs. | The revocation event, a signed OCSP answer and a signed CRL | Proved end to end: `internal/server/protocols_served_test.go`, `internal/server/broker_public_revoke_served_test.go` | [Revocation: OCSP and CRLs](../features/issuance-and-cas.md#revocation-ocsp-and-crls-f47) |
| Prove one credential | A signed record joins one certificate's discovery, owner, issuance, deployments, verifications, renewals and revocation, saying which were independently observed. | A signed, offline-verifiable assurance record | Proved end to end: `internal/server/assurance_served_test.go` | [Credential assurance records](../features/policy-and-governance.md#credential-assurance-records-a179) |
| Report to a customer | A plain-language report in the customer's brand covers inventory and ownership, expiry, renewals and failures, verification and incidents, compared with the previous period. | A signed scheduled report with its HTML rendering, verifiable offline | Proved end to end: `internal/server/customer_assurance_report_served_test.go`; for a Provider: `ee/provider/reports_test.go` | [Customer assurance report](../compliance.md#customer-assurance-report) |
| Evaluate on your endpoint | `trstctl evaluate` runs discovery through a signed audit export against an endpoint you choose. | A signed evidence pack with each step's outcome and its limits | Proved end to end (the journey in process; the command's flags in a unit test): `internal/server/evaluate_served_test.go` | [Evaluate on your endpoint](../operations/evaluate.md#running-it) |

## What comes next

- **Observers in the console.** External observers are served on the API and
  CLI; the console has no page for them yet.
- **Reports in the Provider console.** A Provider lists and downloads a
  customer's signed assurance reports on the Provider API; the Provider console
  does not show them yet.
- **A relay sweep in the evaluation.** The evaluation kit discovers the endpoint
  by the control plane's own handshake; a network relay's sweep for endpoints
  nobody listed is not part of the run.
