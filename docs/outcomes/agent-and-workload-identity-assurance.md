# Agent and workload identity assurance

Give every workload and AI agent an identity it has to prove before it gets one,
let agents act on behalf of people and other agents only as far as they were
delegated, keep every action an agent takes behind the same gates an operator
faces, and keep a signed record of what each one did.

In the console, start at **Workloads** (`/workloads`); the console home links
here.

## How to read the proof column

Each step names the evidence it leaves behind and how strongly it is proved
today. The proof column names the test, so you can read it or run it yourself.

- **Proved end to end**: a test drives the step through the assembled control
  plane (the same handler the binary serves) and checks its effect.
- **Proved end to end, when enabled**: the same, for a step that needs a setting
  or a component turned on first.
- **Proved on the shipped binary**: a test builds and launches the binary.
- **Proved against real services**: an integration test runs the step against
  the real signer and the services it talks to, outside the assembled control
  plane.
- **What comes next**: not built yet; today's status is stated.

## The workflow

| Step | What happens | Evidence it leaves | Proof | Read more |
|---|---|---|---|---|
| Issue workload identities | Workloads receive SPIFFE identities (X.509 and JWT SVIDs) through the standard Workload API, including in Kubernetes. | Issued SVIDs and their issuance events | Proved end to end: `internal/server/attested_issuance_served_test.go`; the Workload API itself when enabled | [The SPIFFE Workload API](../features/workload-identity.md#the-spiffe-workload-api-f24-the-standard-interface) |
| Attest before issuing | A workload proves where it runs (its platform and attester) before an identity is issued to it. | The attestation evidence each issuance was granted on | Proved end to end: `internal/server/workload_attester_trust_served_test.go` | [The attestation chain](../features/workload-identity.md#the-attestation-chain-f30-proof-before-trust) |
| Delegate to an agent | An agent receives a credential from its tenant's issuing CA that names whom it acts for and what it may do; relying services pin that CA and read the credential's status. | The delegation credential and its status | Proved against real services: `internal/agentid/intwire/relying_party_test.go` | [Relying services](../features/agent-delegation.md#relying-services) |
| Agents calling agents | One agent hands a task to another over A2A, each checking the other's identity. | Both agents' verified identities on the exchange | Proved against real services, with a reference pair of agents: `internal/agentid/intwire/a2a_test.go` | [Agents calling agents](../features/agent-delegation.md#agents-calling-agents-a2a) |
| Authorize MCP clients | An MCP client authorizes against your identity provider; trstctl publishes each agent's keys for it. | The agent's published key set and the provider's tokens | Proved end to end against Keycloak (needs Docker): `internal/server/mcp_authorization_keycloak_test.go` | [MCP authorization with Keycloak](../guides/mcp-authorization.md#keycloak) |
| Gate agents' writes | An agent's certificate write takes the same identity lifecycle gate as an operator's, dual control included: refused, proposed for approval, then run on the same call. | The lifecycle transition and the approval it ran under | Proved end to end, when enabled: `internal/server/mcp_write_gate_served_test.go` | [The trstctl MCP server](../features/graph-query-ai.md#the-trstctl-mcp-server-f78) |
| Answer with evidence | Agents' read tools answer posture and exposure questions with structured findings that cite their evidence. | Findings with evidence IDs, sources and confidence, under a published schema | Proved end to end, when enabled: `internal/server/mcp_evidence_tools_served_test.go` | [The trstctl MCP server](../features/graph-query-ai.md#the-trstctl-mcp-server-f78) |
| Keep the record | Every agent action is an audit event; the signed audit export verifies offline. | A signed, tamper-evident audit export | Proved on the shipped binary: `internal/server/audit_export_formats_served_test.go` | [The tamper-evidence trust model](../compliance.md#the-tamper-evidence-trust-model-read-this) |

## What comes next

- **Delegation in the console.** Agent delegation is served on the API and CLI;
  the console has no page for it yet.
- **Status pushed to relying services.** A relying service reads a delegation
  credential's status on request; a pushed revocation feed is what comes next.
- **Finding agents.** Agents calling agents is proved with a reference pair;
  discovering agents' A2A endpoints is what comes next.
