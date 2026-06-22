# Audit Finding Ownership

trustctl audits can observe the same defect from more than one angle. The
remediation backlog must still give engineers one owner for one root cause. A
second audit may point at the same problem, but it is a cross-reference, not a
second open work item.

The rule is simple:

- The canonical finding owns the fix, tests, gate evidence, and final closure.
- Cross-reference-only observations are recorded in `source_ids`,
  `also_observed_by`, or `linked`.
- A duplicate observation must not become a second open remediation ticket unless
  it has a separate fix with separate acceptance evidence.
- If two owners intentionally keep separate tickets for the same root cause, the
  ownership exception must name the owner, rationale, and verification split.

## Resolved Duplicate Roots

| Root cause | Canonical finding | Cross-reference-only observations | Why |
| --- | --- | --- | --- |
| Certificate profile event sourcing and projection correctness | event-spine finding | architecture finding | Event sourcing and projection correctness is owned by the event-spine track. The architecture review can cite the architectural impact, but the replayable profile-state fix, projector tests, and disaster-recovery classification close under the event-spine track. |
| Node/Vitest browser storage runtime reproducibility | test-infrastructure finding | code-quality finding | The test-infrastructure track owns CI and test-runtime health. The code-quality observation described the same `localStorage`/Vitest runtime root cause and did not require a separate maintainability fix once the deterministic storage setup and runtime declaration landed. |

## Closure Check

Before closing a duplicate-ownership finding, check the backlog like this:

1. The canonical item lists every duplicate observation in `source_ids`.
2. The duplicate observation appears in `also_observed_by` or `linked`.
3. Only the canonical item is open while the fix is pending.
4. Closure notes name the canonical commit and the gate that proves the root cause
   is fixed.
5. The duplicate observation is not left as a second independent ticket.

This is not score bookkeeping. It is control-plane engineering hygiene: one root
cause gets one fix path, and every audit lens still remains traceable.
