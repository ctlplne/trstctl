import type { PAMServiceDependentRotationIntent } from "@/lib/api-types.gen";
import { useTranslation } from "@/i18n/I18nProvider";
import { CredentialChip } from "@/components/CredentialChip";

export function PAMReconciliationIntent({ intent, digest }: { intent: PAMServiceDependentRotationIntent; digest: string }) {
  const { t } = useTranslation();
  return (
    <section className="grid gap-3 rounded-control border border-border p-3" aria-label={t("admin.access.rotation.reconcileManifest")}>
      <h3 className="font-semibold">{t("admin.access.rotation.reconcileManifest")}</h3>
      <p>{t("admin.access.rotation.reconcileHelp")}</p>
      <dl className="grid gap-2">
        <dt>{t("admin.access.rotation.targetIdentity")}</dt>
        <dd>
          {intent.plan.account.dn}
          <p>
            <CredentialChip value={intent.plan.account.sid} fullValue /> <CredentialChip value={intent.plan.account.guid} fullValue />
          </p>
        </dd>
        <dt>{t("admin.access.rotation.resetIdentity")}</dt>
        <dd>
          {intent.reconcile?.dn}
          <p>
            <CredentialChip value={intent.reconcile?.sid ?? ""} fullValue /> <CredentialChip value={intent.reconcile?.guid ?? ""} fullValue />
          </p>
        </dd>
        <dt>{t("admin.access.rotation.password")}</dt>
        <dd>{intent.plan.secret_name}</dd>
        <dt>{t("admin.access.rotation.review")}</dt>
        <dd>
          <CredentialChip value={digest} fullValue />
        </dd>
      </dl>
      <p>{t("admin.access.rotation.reviewVersion", { name: intent.plan.secret_name, version: intent.expected_version, expires: intent.plan.expires_at })}</p>
      <ol className="grid gap-1">
        {intent.plan.order.map((ref, index) => (
          <li key={JSON.stringify(ref)}>
            {index + 1}. {ref.family}: {ref.name} <CredentialChip value={ref.agent_id} />{" "}
            <span>{intent.probes.find((p) => JSON.stringify(p.ref) === JSON.stringify(ref))?.probe_id}</span>
          </li>
        ))}
      </ol>
      <details>
        <summary>{t("admin.access.rotation.exactReview")}</summary>
        <pre className="overflow-auto whitespace-pre-wrap text-xs">{JSON.stringify(intent, null, 2)}</pre>
      </details>
    </section>
  );
}
