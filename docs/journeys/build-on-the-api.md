# Build on the API, CLI, and SDKs

<!-- trstctl:journey-census:start -->

!!! success "Served path — wiring census 81/81"

    The Definition-of-Done census reports **81/81 required capabilities served**: **12 of 81 census rows launch the shipped binary** and **69 of 81 are proved through the production-assembled handler**.
    Production-assembled means production `buildRunDeps` output driving the assembled `Server.Handler` in-process, with a hand-built `Deps` rejected; only the process launch differs.
    This journey uses no separately proof-gated capability row; it stays on core served surfaces.
    Core surfaces guarded by route and journey tests: `openapi_contract`, `cli`, `generated_sdks`, `cursor_pagination`, `credential_graph`.
    This badge is generated from `wiring-census.json`; `make journey-census-check` fails closed if the census or this page drifts.

<!-- trstctl:journey-census:end -->

## Goal

When you finish this journey you will have driven trstctl programmatically: fetched
its API contract, scripted it from the CLI, called it from a typed SDK with retries
and idempotency handled for you, paged through a large result set with cursors, and
queried the credential graph. It is for an integrator or platform engineer wiring
trstctl into automation, CI, or another service. In plain terms: trstctl is
data-driven — one route registry generates the spec, the server, and the CLI — so you
can pick the surface that fits (raw HTTP, CLI, or a generated SDK) and they all stay
in lockstep.

## Before you start

- A running control plane and an API token, set up in
  [Getting started](../getting-started.md). Mutations and the graph need a token.
- The shape of the API, idempotency, and pagination are described in
  [Platform & API](../features/platform-and-api.md); the typed clients in
  [Client SDKs](../features/client-sdks.md); and the graph/query layer in
  [Graph, query & AI](../features/graph-query-ai.md).

## Steps

1. Start in **API playground** at `/integrate/api` if you want a guided first
   request. The overview runs nothing. Choose **Try request** to begin with a
   read-only operation, create a 15-minute key scoped only to that operation, review
   the exact request, and send it explicitly. The result is explained in plain
   language before status, problem details, and the raw response.

   Use **All contract operations** to search every served operation without loading
   hundreds of controls at once. **Headers, body, and exact request** contains the
   editable OpenAPI fields and idempotency key. Writes additionally require an exact
   mutation confirmation that is cleared whenever an input changes.

2. Fetch the OpenAPI 3.1 contract. Every route is declared once and published as a
   single spec — no auth needed to read it:

   ```sh
   export TRSTCTL_CA_FILE="$PWD/trstctl-eval-ca.pem" # captured and inspected in Getting started
   curl -fsS --cacert "$TRSTCTL_CA_FILE" https://localhost:8443/api/v1/openapi.json
   ```

   You should get the full OpenAPI 3.1 document. Point your code generator or API
   tooling at it; the spec, server, and CLI cannot drift apart.

3. Drive it from the CLI. `trstctl-cli` maps each command straight to an API
   route and auto-supplies an `Idempotency-Key` on mutations:

   ```sh
   export TRSTCTL_SERVER=https://localhost:8443
   export TRSTCTL_TOKEN=trst_...
   # For the self-signed evaluation server, also set TRSTCTL_CA_FILE as shown
   # in Getting started. Production uses your operator-managed CA bundle.
   trstctl-cli certificates list --limit 50
   ```

   You should see the certificate inventory as JSON on stdout (exit `0` on success).
   The CLI is provably at parity with the API — see
   [Platform & API](../features/platform-and-api.md).

4. Call a mutation with your own idempotency key. Every state-changing request
   takes an `Idempotency-Key`; a retry with the same key returns the original result
   instead of acting twice. The CLI exposes it as a flag:

   ```sh
   echo '{"kind":"workload","name":"payments"}' \
     | trstctl-cli --idempotency-key my-stable-key owners create -f -
   ```

   You should see the owner created once; re-running the exact command returns the
   same owner rather than creating a second.

5. Use a typed SDK instead of hand-rolling a client. trstctl ships supported Go
   and TypeScript SDKs pinned to the served contract, with auth, idempotency, retries
   (honoring `Retry-After`), problem+json errors, and cursor iterators built in:

   ```go
   import (
       "context"
       "log"

       trstctl "trstctl.com/sdk/go/trstctl"
   )

   func main() {
       client := trstctl.New("https://localhost:8443", "trst_...")
       ctx := context.Background()

       // Cursor pagination: the iterator follows next_cursor across pages.
       it := client.Certificates(trstctl.CertificateListOptions{ListOptions: trstctl.ListOptions{Limit: 50}})
       for it.Next(ctx) {
           cert := it.Value()
           log.Printf("certificate %s: %s", cert.ID, cert.Subject)
       }
       if err := it.Err(); err != nil {
           log.Fatal(err)
       }
   }
   ```

   You should see each certificate printed as the iterator transparently follows
   `next_cursor`. The Go and TypeScript surfaces and their behavior are in
   [Client SDKs](../features/client-sdks.md).

6. Page a large list over raw HTTP with cursors. List endpoints return
   `{ items, next_cursor }`. Pass the returned cursor back to get the next page:

   ```sh
   curl -fsS --cacert "$TRSTCTL_CA_FILE" \
     -H "Authorization: Bearer $TRSTCTL_TOKEN" \
     "https://localhost:8443/api/v1/certificates?limit=50&cursor=<next_cursor>"
   ```

   You should get the next page of `items` plus a fresh `next_cursor` (absent on the
   last page). Over-budget callers get `429` with `Retry-After`.

7. Query the credential graph. Ask how things connect through the served graph
   surface — a typed, allow-listed query, not raw SQL:

   ```sh
   trstctl-cli graph query 'MATCH (w:workload)-[:OWNS]->(c)-[:DEPLOYED_TO]->(r) WHERE w.name = "payments-svc" RETURN c, r.name'
   ```

   You should see the matching nodes, scoped to your tenant. The graph and the unified
   query layer behind it are in [Graph, query & AI](../features/graph-query-ai.md).

## Where next

- [Run trstctl in production](run-in-production.md)
- [Stay crypto-agile and migrate to post-quantum](crypto-agility-pqc.md)

**Journey:** J11
**Steps through:** F10, F11, F21, F75
