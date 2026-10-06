import { useRef, useState } from "react";

import { Button } from "@/components/ui/button";
import { useTranslation } from "@/i18n/I18nProvider";
import { api, type ConnectorDelivery, type DeploymentTarget } from "@/lib/api";
import { newIdempotencyKey } from "@/lib/apiTransport";
import { useApiQuery } from "@/lib/query";
import { RecoveryResult } from "@/pages/connectors/RecoveryResult";

export function EndpointContainment({ target, reason }: { target: DeploymentTarget; reason: string }) {
  const { t } = useTranslation();
  const [reviewing, setReviewing] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [initialReceipt, setInitialReceipt] = useState<ConnectorDelivery | null>(null);
  const attempt = useRef<{ body: string; key: string } | null>(null);
  const preview = useApiQuery(["endpoint-containment-preview", target.id], () => api.previewEndpointContainment(target.id), {
    enabled: reviewing,
    retry: false,
  });

  async function submit() {
    const plan = preview.data;
    if (!plan?.ready || !plan.effect_free || plan.target_id !== target.id || !reason.trim() || submitting) return;
    const request = {
      target_revision: plan.target_revision,
      identity_id: plan.identity_id,
      expected_fingerprint: plan.expected_fingerprint,
      required_agent_id: plan.required_agent_id,
      preview_fingerprint: plan.preview_fingerprint,
      reason: reason.trim(),
    };
    const body = JSON.stringify(request);
    if (attempt.current?.body !== body) attempt.current = { body, key: newIdempotencyKey() };
    setSubmitting(true);
    setSubmitError(null);
    try {
      const receipt = await api.containEndpoint(target.id, request, attempt.current.key);
      if (
        receipt.destination !== "endpoint.contain" ||
        receipt.fingerprint !== plan.expected_fingerprint ||
        receipt.identity_id !== plan.identity_id ||
        !receipt.outbox_id
      ) {
        throw new Error(t("connectors.containment.readFailed"));
      }
      setInitialReceipt(receipt);
    } catch (error) {
      setSubmitError(error instanceof Error ? error.message : String(error));
    } finally {
      setSubmitting(false);
    }
  }

  const plan = preview.data;
  return (
    <section aria-labelledby="endpoint-containment-heading" className="grid gap-3 rounded-control border border-border bg-muted/20 p-3 md:col-span-3">
      <div>
        <h3 id="endpoint-containment-heading" className="font-semibold">
          {t("connectors.containment.heading")}
        </h3>
        <p className="text-sm text-muted-foreground">{t("connectors.containment.help")}</p>
      </div>
      <Button
        type="button"
        variant="outline"
        className="justify-self-start"
        onClick={() => {
          setReviewing(true);
          if (reviewing) preview.refetch();
        }}
        disabled={preview.fetching || submitting}
      >
        {preview.fetching ? t("connectors.containment.reviewing") : t("connectors.containment.review")}
      </Button>
      {reviewing && preview.error && (
        <p role="alert" className="text-sm text-status-warning">
          {preview.error}
        </p>
      )}
      {plan && reviewing && (
        <div className="grid gap-3 rounded-control border border-border bg-card p-3 text-sm" role="status">
          <p className="font-semibold">{t("connectors.containment.previewTitle")}</p>
          <dl className="grid gap-2 sm:grid-cols-2">
            {(
              [
                [t("connectors.containment.target"), plan.target_name],
                [t("connectors.containment.identity"), plan.identity_name],
                [t("connectors.containment.leaf"), plan.expected_fingerprint],
                [t("connectors.containment.agent"), plan.required_agent_id],
                [t("connectors.containment.revision"), plan.target_revision],
                [t("connectors.containment.certificateStatus"), plan.certificate_status],
              ] as const
            ).map(([label, value]) => (
              <div key={label}>
                <dt className="text-muted-foreground">{label}</dt>
                <dd className="break-all">{value}</dd>
              </div>
            ))}
          </dl>
          {plan.warnings.map((warning) => (
            <p key={warning} className="rounded-control border border-status-warning/40 bg-status-warning/10 p-2">
              {warning}
            </p>
          ))}
          <p>{t("connectors.containment.effectBoundary")}</p>
          {plan.ready && plan.effect_free && !initialReceipt && (
            <div className="grid gap-2">
              <p>
                {t("connectors.containment.reason")}: {reason.trim() || t("connectors.containment.reasonRequired")}
              </p>
              <Button type="button" className="justify-self-start" loading={submitting} disabled={submitting || !reason.trim()} onClick={() => void submit()}>
                {t("connectors.containment.submit")}
              </Button>
            </div>
          )}
          {submitError && (
            <p role="alert" className="text-status-warning">
              {submitError}
            </p>
          )}
        </div>
      )}
      {initialReceipt && (
        <RecoveryResult
          initial={initialReceipt}
          onRetry={() => {
            attempt.current = null;
            setInitialReceipt(null);
            setSubmitError(null);
            preview.refetch();
          }}
        />
      )}
    </section>
  );
}
