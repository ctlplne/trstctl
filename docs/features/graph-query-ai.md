# Graph, query & AI — see how everything connects, and ask in plain language

## What it is

trstctl doesn't just hold a flat list of credentials — it builds a **graph** of how they
connect (which workload owns which key, which key was issued by which CA, what each can
reach), exposes a **unified query layer** to ask questions across all its data safely,
and layers **AI** on top: a pluggable model adapter, grounded root-cause analysis with
natural-language questions, and an [MCP](../glossary.md) server so external AI agents can
query trstctl through a safe, read-only interface.

The mental model: the graph is a map of your credential city showing every road between
buildings; the query layer is the one inspector's desk every question must pass through
(so nobody peeks at another tenant's records); and the AI layer is an analyst who answers
your questions **only** from evidence pulled across that desk, always citing sources.

## Why it exists

Security questions are rarely about one credential — they're about *relationships*: "if
this key leaks, what's exposed?", "what does this AI agent actually have access to?", "why
did this renewal fail?". Answering those needs a graph and a way to query it. And because
those queries touch sensitive data across many subsystems, they need **one** rigorously
scoped path rather than each feature reinventing access control. The AI layer then makes
the whole thing approachable — ask in English, get a cited answer — without ever letting a
model invent facts or leak across tenants.

## How it works

### The credential graph (F21)

The graph models your inventory as **nodes** (workloads, credentials, issuers, resources,
crypto assets, attestations) and **impact-oriented edges** (`ISSUED`, `OWNS`,
`DEPLOYED_TO`, `GRANTS_ACCESS`, `CONNECTS_TO`, `EXHIBITS`) where an edge `A→B` means
"compromising A puts B at risk." It's built on demand from the store, every read scoped by
tenant (**AN-1**), so a traversal can never escape the tenant boundary. On top of it:
`Reachable` (breadth-first reach), `BlastRadius` (everything a compromise touches, grouped
by kind), and a deliberately minimal Cypher-style `Query`.

*Code:* `internal/graph` (`Build`, `Reachable`, `BlastRadius`, `Query`). **Served** —
`GET /api/v1/graph`, `/graph/reachable/{id}`, `/graph/blast-radius/{id}`,
`POST /api/v1/graph/query`, plus the `graph` CLI group.

### The unified semantic query layer (F75)

This is the **one security boundary** every advanced consumer (AI, MCP, compliance) routes
through, so scoping is never reinvented. Callers submit a *typed* `Spec` — allow-listed
surfaces (log, graph, inventory, owners, CBOM), allow-listed fields and operators, bound
values — and **never raw SQL or Cypher**. The engine enforces, *by construction*:
**tenant first** (the tenant is always the caller's, non-overridable, RLS underneath —
**AN-1**), then **RBAC** (you must hold the permission for *every* selected surface, or the
whole query is denied before execution — not post-filtered). It runs on a
[bulkhead](../glossary.md) with a wall-clock deadline and row caps (**AN-7**), pins results
to an event-log offset for consistency (**AN-2**), and returns deliberately coarse errors
so a caller can't tell "out of scope" from "not found."

*Code:* `internal/query` (`Engine`, `Spec`, `Surface`, `Predicate`),
`internal/api`, `internal/server`. **Served through the read-only AI/RCA routes when
`ai.enable_api` is on** (`POST /api/v1/ai/query`, `POST /api/v1/ai/rca`) and used by the
read-only MCP tools. The standalone Go API remains available for embedded consumers.

### The pluggable AI model adapter (F76)

trstctl's AI features are model-agnostic: a thin adapter routes reasoning to either a
cloud LLM gateway or a **local** Ollama/vLLM endpoint by config, for air-gapped or
data-sovereign deployments. The served binary validates `ai.model.mode` as `off`,
`local`, or `cloud`; `off` is the default, `local` uses an operator-owned completion
endpoint, and `cloud` requires an explicit `allow_egress=true`. `GET
/api/v1/ai/status` reports the live mode, endpoint host, egress class, the
secret-redaction/refusal posture, and the **`pii_egress`** posture (below).
Critically, a **secret redactor** runs before any prompt leaves the
process — stripping PEM blocks, secret/token assignments, and long base64 runs (**AN-8**)
— so key material cannot reach a model or its logs, and a residual-entropy gate refuses
the send if any high-entropy run survives.

**Personal-data egress is default-private (PRIVACY-005).** The secret redactor
deliberately preserves personal/identifying data (owner emails, certificate subjects,
graph node names, SPIFFE/OIDC subjects, IPs, hostnames) because it is useful in-house
context. Because a configured **cloud** model is a third party, a second **PII-aware
egress boundary** runs after secret redaction and before the model send:

- **`pii_egress: redact`** (the default): emails, IPv4/IPv6 addresses, OIDC/SPIFFE
  subjects, FQDN hostnames, and person names are stripped from the prompt before egress.
- **`pii_egress: block`** (`ai.model.block_pii=true`): a prompt that still carries
  personal data after secret redaction is refused entirely (strict fail-closed).
- **`pii_egress: allow`** (`ai.model.allow_pii=true`): an operator has **explicitly
  consented** to sending personal data to the configured model; PII is preserved.

Cloud prompt egress therefore requires two deliberate, inspectable choices —
`allow_egress=true` to reach a cloud model at all, and `allow_pii=true` to include
personal data in the prompt. **Provider data retention:** when `cloud` mode is used,
prompts are sent to a third-party model provider whose retention and training-use
policies are outside trstctl's control; review them before enabling cloud egress, and
keep `allow_pii=false` (the default) unless the provider's terms permit subject-data
processing. The default posture sends nothing to a cloud (model `off`), and even with a
model configured no personal data leaves the process unless `allow_pii=true`.

If no model is configured, the served AI surface still returns grounded
evidence/citations without model egress. *Code:* `internal/aimodel` (`Adapter`,
`DefaultRedactor`, `PIIRedactor`/`RedactPII`/`ContainsPII`, `CloudModel`, `LocalModel`)
plus `internal/server/aisurface.go` for served config construction. **Served as an
optional adapter behind `ai.enable_api`; no model is configured by default.**

### Grounded RCA & natural-language query (F77)

You ask a question in plain language ("what's the blast radius of the payments cert?");
trstctl **gathers real evidence** through the query layer (inheriting its tenant+RBAC
scoping), then a synthesizer answers using **only** that evidence — every claim carries a
**citation** (`source#id`), and with no evidence it says "insufficient evidence" rather
than inventing an answer. The prompt explicitly treats retrieved data as untrusted (so a
hostile string in a SAN can't become an instruction), the pipeline is strictly
**read-only**, and every gather is audited. *Code:* `internal/rca` (`Pipeline`,
`Synthesizer`). **Served** at `POST /api/v1/ai/rca` when `ai.enable_api` is on.

### The trstctl MCP server (F78)

The [Model Context Protocol](../glossary.md) is how external AI agents call tools.
trstctl's MCP server exposes four **read-only** tools — `query_credentials`,
`get_blast_radius`, `explain_incident`, `compliance_status` — and nothing that writes (it
has no remediation tools). Every call is scoped to one tenant (a cross-tenant call is
refused *before* any query), per-caller rate-limited to resist enumeration, and audited;
answers flow through the grounded RCA pipeline so they're cited and redacted. Fittingly,
the server holds a [workload identity](workload-identity.md) issued by trstctl's own
broker — it dogfoods the platform. *Code:* `internal/mcpserver` (`Server`, `Call`,
`Tools`). **Served** at `GET /api/v1/mcp/tools` and
`POST /api/v1/mcp/tools/{tool}` when `ai.enable_api` is on.

## Use it

The graph is served — explore relationships and blast radius:

```sh
trstctl-cli graph nodes
trstctl-cli graph blast-radius cert:payments-tls
trstctl-cli graph query 'MATCH (w:workload)-[:OWNS]->(c)-[:DEPLOYED_TO]->(r) WHERE w.name = "payments-svc" RETURN c, r.name'
```

Those map to the served `/api/v1/graph*` routes. When `ai.enable_api` is on, grounded
query/RCA and read-only MCP are served too:

```sh
curl -sS -H "Authorization: Bearer $TRSTCTL_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"question":"what is the blast radius of the payments cert?"}' \
  https://trstctl.example.com/api/v1/ai/rca

curl -sS -H "Authorization: Bearer $TRSTCTL_TOKEN" \
  https://trstctl.example.com/api/v1/mcp/tools
```

## Pitfalls & limits

| Capability | Status today |
|---|---|
| Credential graph (F21) | **Served** — `/api/v1/graph*`, `graph` CLI |
| Semantic query layer (F75) | **Served** through `/api/v1/ai/query` and `/api/v1/ai/rca` when `ai.enable_api` is on; Go API also available |
| AI model adapter (F76) | **Optional served adapter**; no model configured by default, cloud/local model egress only when an operator opts in |
| Grounded RCA / NL query (F77) | **Served** — `POST /api/v1/ai/rca`, read-only and cited |
| MCP server (F78) | **Served** — `GET /api/v1/mcp/tools`, `POST /api/v1/mcp/tools/{tool}`, read-only tools only |

Other notes: the graph and query layer are built per request from the store, so very large
tenants pay a build cost (bounded by caps). The AI features are **grounded and read-only by
design** — they won't take actions and won't answer beyond the evidence. With no model
configured, RCA returns the raw evidence listing rather than a prose answer. See
[Current limitations](../limitations.md).

## Reference

- **Graph (served):** `GET /api/v1/graph`, `/graph/reachable/{id}`,
  `/graph/blast-radius/{id}`, `POST /api/v1/graph/query`; CLI `graph`.
- **Node kinds:** workload, credential, issuer, resource, crypto-asset, attestation.
- **Query surfaces:** log, graph, certificates, owners, CBOM (tenant-then-RBAC,
  allow-listed fields/operators, no raw SQL/Cypher).
- **AI:** model adapter (cloud or local Ollama/vLLM) with boundary redaction; RCA returns
  cited answers; MCP tools are read-only and rate-limited.

## See also

[Discovery & inventory](discovery-and-inventory.md) (what populates the graph) ·
[Observability & risk](observability-and-risk.md) (exposure scoring uses the graph) ·
[Incident response & JIT](incident-and-jit.md) (blast-radius-driven remediation) ·
[Workload identity](workload-identity.md) (the MCP server's own identity) ·
[Semantic query layer design](../design/semantic-query-layer.md) ·
glossary: [event sourcing](../glossary.md), [RLS](../glossary.md)

**Covers:** F21, F75, F76, F77, F78
