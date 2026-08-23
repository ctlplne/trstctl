import type { OutboxReconciliationConflictList } from "@/lib/api";
import { formatDateTime } from "@/i18n/format";
import { translateNow } from "@/i18n/I18nProvider";
import { StatusBadge } from "@/components/StatusBadge";

export function OutboxRecoveryPanel({ conflicts }: { conflicts: OutboxReconciliationConflictList }) {
  if (!Array.isArray(conflicts.items) || conflicts.items.length === 0) {
    return null;
  }

  return (
    <section aria-labelledby="outbox-recovery-heading" className="grid gap-3 border-y border-border py-4">
      <div>
        <h2 id="outbox-recovery-heading" className="text-title font-semibold">
          {translateNow("platform.idempotency.recoveryHeading")}
        </h2>
        <p className="mt-1 max-w-4xl text-sm text-muted-foreground">{conflicts.guidance}</p>
      </div>

      <div className="grid gap-3">
        {conflicts.items.map((conflict) => (
          <article key={conflict.id} className="ui-panel grid gap-3 p-comfortable">
            <div className="flex flex-wrap items-start justify-between gap-2">
              <div>
                <h3 className="text-body font-semibold">
                  {translateNow("secrets.methods.source")} <code>{conflict.source_event_id}</code>
                </h3>
                <p className="text-xs text-muted-foreground">
                  {translateNow("source.sequence.0740f4bade")} {conflict.source_event_sequence} · {formatDateTime(conflict.detected_at)}
                </p>
              </div>
              <StatusBadge vocabulary="delivery" value={conflict.status} tone="warning" />
            </div>
            <dl className="grid gap-3 text-sm lg:grid-cols-2">
              <div>
                <dt className="font-medium text-muted-foreground">{translateNow("incidents.response.idempotency")}</dt>
                <dd className="break-all font-mono text-xs">{conflict.idempotency_key}</dd>
              </div>
              <div>
                <dt className="font-medium text-muted-foreground">{translateNow("incidents.response.outbox")}</dt>
                <dd className="font-mono text-xs">{conflict.existing_outbox_id}</dd>
              </div>
              <div>
                <dt className="font-medium text-muted-foreground">
                  {translateNow("platform.usageEvidence.digest")} · {translateNow("incidents.response.outbox")}
                </dt>
                <dd className="break-all font-mono text-xs">{conflict.existing_payload_sha256}</dd>
              </div>
              <div>
                <dt className="font-medium text-muted-foreground">
                  {translateNow("platform.usageEvidence.digest")} · {translateNow("secrets.methods.source")}
                </dt>
                <dd className="break-all font-mono text-xs">{conflict.candidate_payload_sha256}</dd>
              </div>
              <div>
                <dt className="font-medium text-muted-foreground">{translateNow("platform.scale.lane")}</dt>
                <dd className="break-all font-mono text-xs">
                  {conflict.existing_effect_lane} → {conflict.candidate_effect_lane}
                </dd>
              </div>
              <div>
                <dt className="font-medium text-muted-foreground">{translateNow("platform.ha.role")}</dt>
                <dd className="font-mono text-xs">
                  {conflict.existing_required_agent_role || translateNow("source.none.140bedbf9c")} →{" "}
                  {conflict.candidate_required_agent_role || translateNow("source.none.140bedbf9c")}
                </dd>
              </div>
            </dl>
            <p className="text-sm text-muted-foreground">{conflict.reason}</p>
          </article>
        ))}
      </div>
    </section>
  );
}
