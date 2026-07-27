import type { ConnectorDelivery, RotationRun } from "@/lib/api";
import { translateNow } from "@/i18n/I18nProvider";

function shortFingerprint(value?: string): string {
  if (!value) return "-";
  return value.length <= 16 ? value : `${value.slice(0, 12)}...${value.slice(-8)}`;
}

export function CredentialActivityTimeline({
  credentialLabel,
  deliveryReceipt,
  rotationRun,
}: {
  credentialLabel?: string;
  deliveryReceipt?: ConnectorDelivery;
  rotationRun?: RotationRun;
}) {
  const rows = [
    { label: translateNow("source.lifecycle.accepted.436d4137b8"), value: "state is projected from the event log" },
    {
      label: translateNow("source.connector.delivery.670c8c3d02"),
      value: deliveryReceipt
        ? `${deliveryReceipt.status} ${deliveryReceipt.connector}/${deliveryReceipt.target} after ${deliveryReceipt.attempts} attempt${deliveryReceipt.attempts === 1 ? "" : "s"}`
        : "no connector delivery receipt yet",
    },
    {
      label: translateNow("source.rotation.run.a813bc1537"),
      value: rotationRun
        ? `${rotationRun.status} via ${rotationRun.trigger}; successor ${shortFingerprint(rotationRun.successor_fingerprint)}`
        : "no lifecycle rotation run yet",
    },
    {
      label: translateNow("source.rollback.evidence.bf960c995c"),
      value: rotationRun?.rollback_ref || deliveryReceipt?.rollback_ref || "no rollback reference recorded yet",
    },
  ];

  return (
    <section aria-labelledby="credential-activity-timeline-heading" className="mt-5 border-t border-border pt-4">
      <h3 id="credential-activity-timeline-heading" className="font-semibold">
        {translateNow("source.credential.activity.timeline.e03f707dcc")}
      </h3>
      <p className="mt-1 text-sm text-muted-foreground">
        {credentialLabel ? translateNow("source.value1.has.b0d0cf279e", { value1: credentialLabel }) : translateNow("source.this.credential.has.c3e23e67fc")}{" "}
        {translateNow("source.lifecycle.state.plus.projected.connector.a.efb351b308")}
      </p>
      <ol className="mt-3 grid gap-2 text-sm sm:grid-cols-4">
        {rows.map((row) => (
          <li key={row.label} className="rounded-md border border-border p-2">
            <p className="font-medium">{row.label}</p>
            <p className="mt-1 text-xs text-muted-foreground">{row.value}</p>
          </li>
        ))}
      </ol>
    </section>
  );
}
