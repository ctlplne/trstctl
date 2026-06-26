# Architecture invariants

trstctl protects non-human identities by making a small set of architecture
rules impossible to bypass by accident. The rules are simple enough to audit in a
change review and strict enough that the build blocks common regressions before
they ship. This page is the handoff document for engineers and operators who need
to understand what the guard protects, what it intentionally does not protect,
and how to extend it when the product grows.

## The eight invariants

| Invariant | Plain-language contract | What to look for in a change |
| --- | --- | --- |
| **multi-tenant storage** | Every durable row belongs to a tenant, and PostgreSQL row-level security is the fence. Application code may add checks, but it is not the only fence. | New tables carry `tenant_id`; repository reads and writes constrain `tenant_id`; cross-tenant system scans have a narrow documented reason. |
| **event-sourced state** | State-changing business facts are appended as events, then projected into read models. A rebuild from the event log must recover the same user-visible state. | New lifecycle transitions emit events first; projection code rebuilds derived rows; direct updates are only projection or housekeeping work. |
| **single crypto boundary** | Cryptographic primitives and key handling stay behind one boundary so algorithms, HSMs, and policy can change without scattering crypto code through handlers. | New signing, parsing, sealing, hashing, and key-format work routes through the crypto package surfaces instead of importing primitives in feature code. |
| **separate signing service** | Private-key operations run in the signer process, not inside the HTTP control plane. The control plane asks for signatures over a narrow transport. | New issuance and CA-key flows call the signer client; the signer does not gain HTTP, SQL, or broad operational dependencies. |
| **idempotent mutations** | Retrying a state-changing request returns the original result instead of performing the action twice. | New mutating API paths accept an idempotency key and record operation ownership before side effects happen. |
| **outbox external calls** | Calls to external systems are written as durable intent first, in the same transaction as the state change. Workers deliver them later. | New webhooks, connector calls, CA calls, notifications, and publishing paths write outbox rows instead of calling remote services inline. |
| **bulkheads and backpressure** | Slow or noisy subsystems get bounded worker pools and queues. A full queue rejects fast instead of starving the whole control plane. | New background work chooses a subsystem pool, exposes rejection signals, and has a clear retry or operator response. |
| **memory-safe key material** | Secret key bytes are short-lived byte buffers, not immutable strings, and are wiped or held in locked memory when practical. | New key-handling structs use byte slices or locked-key wrappers; logs, errors, telemetry, and docs never require secret values. |

## How the guard works

The architecture guard is a custom `go/analysis` linter that runs under
`make lint`. It is deliberately source based: it looks for imports, handler
shapes, SQL strings, and key-material types that violate the contracts above.
That makes the guard easy to run in a local checkout and easy to reason about in
code review.

The guard is not the only proof. The product also relies on package tests,
integration tests, DR drills, and docs checks. Think of the guard as the smoke
detector: it catches the regressions that are cheap to detect statically, while
the integration suite proves the runtime path still works.

## What failure means

When the guard fails, treat it as a design review, not a formatting problem.

1. Read the diagnostic literally. It should name the invariant and the risky
   shape, such as a crypto import outside the boundary or a repository query
   without a tenant predicate.
2. Fix the production shape first. Move logic behind the proper boundary, add the
   tenant predicate, introduce an outbox row, or pass work through the right
   subsystem pool.
3. Add or update a test that would have failed before the fix. A green linter
   without a behavior test is only half of the proof.
4. Re-run `make lint` and the card gate.

If the diagnostic is genuinely wrong, fix the analyzer with a fixture that shows
the false positive and the intended allowed shape. Do not silence a whole class of
checks to get one change through.

## How to extend the guard

Use this checklist when a new capability creates a new invariant or expands an
existing one:

1. Name the property in plain language. Example: "every new deployment connector
   must run through an outbox worker."
2. Write a bad fixture that shows the unsafe shape and a good fixture that shows
   the allowed shape.
3. Add the analyzer rule and run its test package directly.
4. Add a product test for the served path. The analyzer proves the shape; the
   product test proves the behavior.
5. Document the operator impact in the relevant runbook or feature page.
6. Run the complete gate: build, lint, the linter test suite, product tests,
   vulnerability scan, and the docs harness.

## Operator audit checklist

Use this during readiness reviews and after major upgrades:

- `make lint` is a required check in branch protection.
- The linter test suite runs and includes both clean and intentionally bad
  fixtures.
- DR drills prove event-log restore and PostgreSQL independent-state restore.
- The signer process is deployed separately from the HTTP control plane and is
  healthy in `/readyz`.
- Metrics show bulkhead rejections, signer health, projection lag, outbox lag,
  and event-log durability.
- Runbooks for incident response, signer recovery, fleet rollout, upgrade
  rollback, and disaster recovery are linked from the documentation nav.
