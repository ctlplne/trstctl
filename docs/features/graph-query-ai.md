# Graph, query & AI — see how everything connects, and ask in plain language

## What it is

trstctl builds a dependency graph instead of holding only a flat credential list.
The graph shows how credentials connect (who owns which key, who issued it, what it
can reach), exposes a unified query
layer to ask questions across all its data safely, and layers AI on top: a pluggable
model adapter, grounded root-cause analysis with natural-language questions, and an
[MCP](../glossary.md) server so external AI agents can query trstctl through a safe,
read-only interface.

The mental model: the graph maps roads between credential "buildings"; the query layer
is the one inspector's desk every question must pass through; and the AI layer is an
analyst who answers only from evidence pulled there, always citing sources.

## Why it exists

Security questions are rarely about one credential — they're about *relationships*: "if
this key leaks, what's exposed?", "what does this AI agent actually have access to?", "why
did this renewal fail?" Answering those needs a graph and a safe way to query it, through
one rigorously scoped path instead of each feature reinventing access control. The AI
layer then makes it approachable — ask in English, get a cited answer — without letting a
model invent facts or leak across tenants.

## How it works

### The credential graph (F21)

The graph models your inventory as nodes (workloads, credentials, issuers, resources,
crypto assets, attestations) and impact-oriented edges (`ISSUED`, `OWNS`, `DEPLOYED_TO`,
`GRANTS_ACCESS`, `CONNECTS_TO`, `EXHIBITS`), where edge `A→B` means "compromising A puts B
at risk." It's built on demand, and every read is isolated to the caller's tenant at the
database layer, so a traversal can never escape the tenant boundary. On top: `Reachable`
(breadth-first reach), `BlastRadius` (compromise impact by kind), and a minimal
Cypher-style `Query`.

`CONNECTS_TO` is not guessed from a test fixture. A host/network agent reports an exact
metadata-only `service_dependency` observation over its mTLS inventory channel. The
event-projected row binds the observing agent, an owner-model workload name, and one
target resource; `graph.Build` emits the edge only when that workload maps exactly inside
the same tenant. Credential owners are recovered by walking the incoming canonical
`workload → credential` `OWNS` edge. An unmapped workload or mismatched target makes the
graph unavailable instead of turning missing topology into a reassuring zero. This is
observed dependency truth, not passive traffic inference: unreported connections remain
unknown.

**Served** — `GET /api/v1/graph`, `/graph/reachable/{id}`, `/graph/blast-radius/{id}`,
`POST /api/v1/graph/query`, plus the `graph` CLI group.

### The unified semantic query layer (F75)

This is the one security boundary every advanced consumer (AI, MCP, compliance) routes
through, so scoping is never reinvented. Callers submit a typed `Spec` — allow-listed
surfaces (log, graph, inventory, owners, CBOM), fields, and operators, bound values, never
raw SQL or Cypher. The engine enforces tenant first (always the caller's, non-overridable,
database-layer-enforced), then RBAC (holding the permission for every selected surface, or
the query is denied before execution, not post-filtered). It runs in its own bounded lane
with a wall-clock deadline and row caps, pins results to a position in the immutable event
history, and returns deliberately coarse errors so a caller can't tell "out of scope" from
"not found."

**Served** through the read-only AI/RCA routes when `ai.enable_api` is on
(`POST /api/v1/ai/query`, `POST /api/v1/ai/rca`) and by `POST /api/v1/graph/query`, and
used by MCP tools; the standalone Go API stays available for embedded consumers. Saved
prompts and richer analysis workspaces remain roadmap residuals, not hidden GA scope.

### The pluggable AI model adapter (F76)

trstctl's AI features are model-agnostic: a thin adapter routes reasoning to a cloud LLM
gateway or a local Ollama/vLLM endpoint, for air-gapped deployments. `ai.model.mode` is
`off` (default), `local` (an operator-owned completion endpoint), or `cloud` (requires
explicit `allow_egress=true`); `GET /api/v1/ai/status` reports the live mode, endpoint,
egress class, and `pii_egress` posture. A secret redactor strips PEM blocks, secret/token
assignments, and long base64 runs before any prompt leaves the process, so key material
cannot reach a model or its logs; a residual-entropy gate blocks the send if any
high-entropy run survives.

The redactor deliberately preserves personal/identifying data (emails, certificate
subjects, graph node names, SPIFFE/OIDC subjects, IPs, hostnames) as useful in-house
context — personal-data egress is default-private. Since a configured cloud model is a
third party, a second PII-aware boundary runs after secret redaction:

- **`pii_egress: redact`** (the default): emails, IP addresses, OIDC/SPIFFE subjects,
  hostnames, and person names are stripped before egress.
- **`pii_egress: block`** (`ai.model.block_pii=true`): a prompt still carrying personal
  data after redaction is refused (strict fail-closed).
- **`pii_egress: allow`** (`ai.model.allow_pii=true`): an operator has explicitly
  consented to sending personal data to the model; PII is preserved.

Cloud egress needs two deliberate choices — `allow_egress=true` to reach a cloud model at
all, and `allow_pii=true` to include personal data. Provider data-retention/training-use
policies are outside trstctl's control in `cloud` mode; review them first, and keep
`allow_pii=false` (the default) unless permitted. **Served** as an optional adapter behind
`ai.enable_api`; no model is configured by default.

### Grounded RCA & natural-language query (F77)

You ask a question in plain language ("what's the blast radius of the payments cert?");
trstctl gathers evidence through the query layer (inheriting its tenant+RBAC scoping),
then answers using only that evidence — every claim carries a citation (`source#id`), and
with no evidence it says "insufficient evidence" rather than inventing one. Retrieved data
is treated as untrusted (a hostile string in a SAN can't become an instruction), the
pipeline is strictly read-only, and every gather is recorded as an immutable audit event.
**Served** at `POST /api/v1/ai/rca` when `ai.enable_api` is on.

### The trstctl MCP server (F78)

The [Model Context Protocol](../glossary.md) is how external AI agents call tools.
trstctl's MCP server exposes four read-only tools — `query_credentials`,
`get_blast_radius`, `explain_incident`, `compliance_status` — by default. Every call is
tenant-scoped (cross-tenant calls are refused before any query), per-caller
rate-limited, and audited; answers flow through the RCA pipeline, cited and redacted. The
server itself holds a [workload identity](workload-identity.md) from trstctl's own
broker. **Served** at `GET /api/v1/mcp/tools` and `POST /api/v1/mcp/tools/{tool}` when
`ai.enable_api` is on.

Write tools are a separate, explicit choice: with `TRSTCTL_AI_MCP_WRITE_TOOLS=true`, the
tool list also includes `issue_certificate` and `rotate_certificate`, each still hitting
the served CA hierarchy, requiring `certs:issue` and an `Idempotency-Key`, and recording
`mcp.tool.write`. Without the flag, write tools are not listed and calls fail closed.

Beyond that, route-backed REST MCP tools expand the surface further, named
`rest_<operationId>` (e.g. `rest_list_notifications` maps to the notifications list
route): read routes are exposed by default when RBAC permits, while REST-backed
mutations stay behind the same write-tool flag and idempotency checks. The MCP-vs-REST
parity CI guard fails when a served REST route has neither an MCP tool nor an allowlist
entry.

## Use it

In the web console, open **Product help** at `/assistant`. The calm overview performs
no AI-runtime or MCP-tool request. Select **Ask a question** to open the read-only
workspace, then ask in plain language. Open **Evidence and request details** only when
you need an exact subject or source scope. **Investigate a cause** uses the same
tenant-scoped evidence path for root-cause analysis. **Use read-only tools** and
**Runtime and privacy details** load their server-owned boundaries only when selected.
If `ai.enable_api` is off, these expert controls fail closed; the overview does not
pretend the feature is available.

The graph is served — explore relationships and blast radius:

```sh
trstctl-cli graph nodes
trstctl-cli graph blast-radius cert:payments-tls
trstctl-cli graph query 'MATCH (w:workload)-[:OWNS]->(c)-[:DEPLOYED_TO]->(r) WHERE w.name = "payments-svc" RETURN c, r.name'
```

Those map to the served `/api/v1/graph*` routes. When `ai.enable_api` is on, grounded
RCA (and `GET /api/v1/mcp/tools`) are served too:

```sh
curl -sS -H "Authorization: Bearer $TRSTCTL_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"question":"what is the blast radius of the payments cert?"}' \
  https://trstctl.example.com/api/v1/ai/rca
```

Enable guarded MCP issuance only for agents that should be allowed to act:

```sh
export TRSTCTL_AI_ENABLE_API=true
export TRSTCTL_AI_MCP_WRITE_TOOLS=true

curl -sS -X POST \
  -H "Authorization: Bearer $TRSTCTL_TOKEN" \
  -H "Content-Type: application/json" \
  -H "Idempotency-Key: mcp-issue-payments-2026-06-26" \
  -d '{"authority_id":"ca_123","csr_pem":"-----BEGIN CERTIFICATE REQUEST-----\n...\n-----END CERTIFICATE REQUEST-----\n","ttl_seconds":7200}' \
  https://trstctl.example.com/api/v1/mcp/tools/issue_certificate
```

## Pitfalls & limits

| Capability | Status today |
|---|---|
| Credential graph (F21) | **Served** — `/api/v1/graph*`, `graph` CLI |
| Semantic query layer (F75) | **Served** through `/api/v1/ai/query`, `/api/v1/ai/rca`, `/api/v1/graph/query`; saved prompts remain roadmap residuals |
| AI model adapter (F76) | **Served optional adapter**; no model configured by default, cloud/local egress opt-in; self-service model settings editor remains a roadmap residual |
| Grounded RCA / NL query (F77) | **Served** — `POST /api/v1/ai/rca`, read-only and cited |
| MCP server (F78) | **Served** — `GET /api/v1/mcp/tools`, `POST /api/v1/mcp/tools/{tool}`; investigation tools read-only by default, write tools require `TRSTCTL_AI_MCP_WRITE_TOOLS=true`, `certs:issue`, `Idempotency-Key` |

The graph and query layer build per request, so very large tenants pay a bounded build
cost. AI features are grounded and read-only by design: no actions, no answers beyond the
evidence; with no model configured, RCA returns the raw evidence listing, not a prose
answer. See [Current limitations](../limitations.md).

## Reference

- **Graph (served):** `GET /api/v1/graph`, `/graph/reachable/{id}`,
  `/graph/blast-radius/{id}`, `POST /api/v1/graph/query`; CLI `graph`.
- **Node kinds:** workload, credential, issuer, resource, crypto-asset, attestation.
- **Query surfaces:** log, graph, certificates, owners, CBOM (tenant-then-RBAC,
  allow-listed fields/operators, no raw SQL/Cypher).
- **AI:** model adapter (cloud or local Ollama/vLLM) with boundary redaction; RCA returns
  cited answers; MCP tools are read-only and rate-limited by default; write tools are
  explicit opt-in and audited; REST MCP tools use stable `rest_<operationId>` names under
  the MCP-vs-REST parity CI guard.

## See also

[Discovery & inventory](discovery-and-inventory.md) (populates the graph) ·
[Observability & risk](observability-and-risk.md) (exposure scoring) ·
[Incident response & JIT](incident-and-jit.md) (blast-radius remediation) ·
[Workload identity](workload-identity.md) (the MCP server's own identity) ·
glossary: [event sourcing](../glossary.md), [RLS](../glossary.md)

**Covers:** F21, F75, F76, F77, F78
