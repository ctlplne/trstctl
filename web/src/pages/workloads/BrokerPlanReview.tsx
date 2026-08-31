import type { ReactNode } from "react";
import { CredentialChip } from "@/components/CredentialChip";
import { useTranslation } from "@/i18n/I18nProvider";
import type { BrokerAgentIdentityPreview } from "@/lib/api-types.gen";

export function BrokerPlanReview({ plan, ready }: { plan: BrokerAgentIdentityPreview; ready: boolean }) {
  const { t } = useTranslation();
  return (
    <section className="grid gap-4" aria-label={t("broker.reviewBody")}>
      <div>
        <h3 className="font-semibold">{t(ready ? "workloads.attested.ready" : "workloads.ephemeral.blockedTitle")}</h3>
        <p className="mt-1 text-sm text-muted-foreground">{t("broker.reviewBody")}</p>
      </div>
      <dl className="grid gap-3 sm:grid-cols-2">
        <BrokerFact label={t("source.agent.id.510bce732d")}>{plan.agent_id}</BrokerFact>
        <BrokerFact label={t("workloads.ephemeral.trustDomain")}>{plan.trust_domain}</BrokerFact>
        <BrokerFact label={t("source.broker.scopes.60ad7540e2")}>{plan.scopes.join(", ")}</BrokerFact>
        <BrokerFact label={t("workloads.ephemeral.effectiveTTL")}>{t("workloads.ephemeral.seconds", { count: plan.effective_ttl_seconds })}</BrokerFact>
        <BrokerFact label={t("source.broker.method.86e0708911")}>{plan.method}</BrokerFact>
        <BrokerFact label={t("broker.taskCheck")}>{plan.task_envelope_verification}</BrokerFact>
      </dl>
      {plan.ttl_defaulted || plan.ttl_clamped ? (
        <p className="border-s-2 border-status-warning ps-3 text-sm">
          {t(plan.ttl_defaulted ? "workloads.ephemeral.ttlDefaulted" : "workloads.ephemeral.ttlClamped", { count: plan.effective_ttl_seconds })}
        </p>
      ) : null}
      {plan.effect_free && !plan.preview_writes.length && !plan.preview_external_effects.length && !plan.preview_signer_calls.length ? (
        <p className="text-sm text-muted-foreground">{t("workloads.ephemeral.effectFree")}</p>
      ) : (
        <p role="alert">{t("workloads.attested.previewUnsafe")}</p>
      )}
      {plan.blockers.length ? <BrokerList title={t("workloads.ephemeral.blockers")} values={plan.blockers} /> : null}
      <BrokerList
        title={t("workloads.attested.effects")}
        values={[...plan.execution_writes, ...plan.execution_external_effects, ...plan.execution_signer_calls]}
      />
      <BrokerList title={t("workloads.ephemeral.recovery")} values={plan.recovery_steps} />
      <details className="border-t border-border pt-3">
        <summary className="cursor-pointer text-sm font-medium">{t("workloads.attested.exactEvidence")}</summary>
        <div className="mt-3 grid gap-4">
          <dl className="grid gap-3 sm:grid-cols-2">
            <BrokerFact label={t("workloads.ephemeral.proofDigest")}>
              <CredentialChip value={plan.payload_sha256} label={t("workloads.ephemeral.proofDigest")} />
            </BrokerFact>
            <BrokerFact label={t("workloads.ephemeral.keyDigest")}>
              <CredentialChip value={plan.public_key_sha256} label={t("workloads.ephemeral.keyDigest")} />
            </BrokerFact>
            <BrokerFact label={t("broker.taskDigest")}>
              {plan.task_envelope_sha256 ? <CredentialChip value={plan.task_envelope_sha256} label={t("broker.taskDigest")} /> : t("broker.noTask")}
            </BrokerFact>
            <BrokerFact label={t("workloads.attested.permission")}>{plan.required_permission}</BrokerFact>
          </dl>
          <BrokerList title={t("workloads.ephemeral.supportedMethods")} values={plan.supported_methods} />
          <BrokerList title={t("workloads.ephemeral.dataHandling")} values={plan.data_handling} />
        </div>
      </details>
    </section>
  );
}

export function BrokerFact({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="min-w-0">
      <dt className="text-caption text-muted-foreground">{label}</dt>
      <dd className="mt-1 break-words text-sm">{children}</dd>
    </div>
  );
}
function BrokerList({ title, values }: { title: string; values: string[] }) {
  return (
    <div>
      <h4 className="text-sm font-medium">{title}</h4>
      <ul className="mt-2 list-disc space-y-1 ps-5 text-sm text-muted-foreground">
        {values.map((value, index) => (
          <li key={index}>{value}</li>
        ))}
      </ul>
    </div>
  );
}
