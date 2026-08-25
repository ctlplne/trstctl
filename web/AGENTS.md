# AGENTS.md — trstctl web console

Read the repository-root `AGENTS.md` and this directory's `DESIGN.md` completely
before changing the console. The root architecture and security boundaries remain
authoritative; this file adds only web-specific execution rules.

## Product structure

The console is one control plane with six focused tools: Discover, Certificates,
Workloads & Machines, Secrets, Software Trust, and Operations. Home is the global
cockpit. Platform & Integrations and account/tenant administration are supporting
areas, not customer tools. `src/lib/navigation.ts` is the single route-ownership
registry. Update navigation, route guards, page H1/title parity, command search,
journeys, docs, and tests together for every IA change.

## Backend-to-console parity

An endpoint is not a complete product capability. Primary operator workflows must
support understand, configure/select, preview, execute, observe, recover, and prove
against durable served state. Consume generated API types and the server-owned
capability catalog. Unknown configuration fields and lifecycle states fail visibly;
never ignore them, submit empty objects, or calculate security-sensitive risk,
authorization, ownership, completion, or delivery truth in the browser.

Use tenant-scoped product read models for overview counts, priorities, effective
ownership/routing, freshness, and partial state. UI-only fixtures are useful for
component work but never qualify a served capability. A console control needs a
served endpoint, durable readback, field-level errors, permission/edition states,
accurate docs, and live browser proof.

## Implementation discipline

- Use the shared primitives, tokens, query layer, zod/react-hook-form patterns,
  i18n catalogs, and Answer → Operate → Prove hierarchy defined in `DESIGN.md`.
- New multi-input workflows use `StepShell`; raw JSON is advanced evidence/import,
  never the primary path.
- When materially editing Discovery, Secrets, CAHierarchy, or Incidents, extract
  the touched section before extending it. Do not add to a monolith.
- Never render secret values, full credential references in review evidence, or
  tenant authority selected by browser input. Keep exact non-secret evidence behind
  deliberate disclosure.
- Preserve deep links, query/filter context, keyboard behavior, supported locales,
  mobile layout, reduced motion, 200% zoom, and WCAG 2.2 AA behavior.

## Required proof

Run focused tests while iterating, then the full commands in `DESIGN.md`. Any API
or capability change also requires generated-contract drift checks, a negative
parity oracle, and a served browser journey. Rebuild the committed embedded web
artifact with `make web` when the console bundle changes.
