# Runbook: a historical event cannot be projected

New event appends reject NUL, invalid UTF-8, unpaired Unicode surrogate
escapes, and JSON numbers outside PostgreSQL `jsonb`'s range before publishing
to JetStream. The production ingress also checks known event schema versions
against the projector before publication. Workload identity source creation and
retargeting refuse an occupied provider/target before publishing. An older release may already have
stored either kind of event. The event is still the source of truth; the control
plane does not edit or discard it.

Ordinary orchestrator commands also preview the core SQL projection inside a
savepoint of their own tenant transaction before publishing. The savepoint is
rolled back, and the actual projection runs after the event append. Commands
preparing the same event type serialize across tenants, which closes same-type
races over shared read-model identities through that command path. Other event
types and direct producers can still change read state between the two steps.
Tenant lifecycle, certificate recording, key-state changes, direct log producers,
and nontransactional extension projections retain their own admission rules.

On catch-up, live tail, full replay, or atomic rebuild, the projector records the first
affected sequence in `projection_tenant_quarantines`. It advances the global
checkpoint so later events from other tenants continue. Ordinary events for
the affected tenant are skipped, and tenant service admission refuses that
tenant. Key custody events, including offboarding and erasure, still replay;
an unsafe key custody event stops replay instead of being silently skipped.

Use a PostgreSQL owner or an approved diagnostic role to identify the tenant
and the exact retained event. Do not copy secret event payloads into a ticket.

```sql
SELECT tenant_id, first_failed_seq, reason_code, recorded_at
  FROM projection_tenant_quarantines
 ORDER BY recorded_at, tenant_id;
```

`reason_code` identifies the validation family. `projection_rejected` means a
decoded event failed a PostgreSQL data or integrity constraint or a JSON decoder.
Transport, datastore availability, restore admission, and key custody failures are not
classified as tenant data errors and stop the worker. The sequence is an event-log
coordinate, not proof that the event was applied. A green global `/readyz` and
an advanced checkpoint mean the healthy tenants can progress; they do not mean
the quarantined tenant's inventory is complete.

Preserve both PostgreSQL and JetStream backups. Investigate the exact producer
and event schema, then deploy and test an explicit recovery that can project
the retained event safely and rebuild that tenant's view. Quarantine is durable
across restart and rebuild. Deleting the quarantine row alone is not recovery:
the same retained event is rediscovered on replay, and serving incomplete
read state would be unsafe. Keep the tenant unavailable until its recovered
view and key custody are verified against the immutable event history.
