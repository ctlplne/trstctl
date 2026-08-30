import { useState } from "react";
import { ErrorState, LoadingState, UnavailableState } from "@/components/StatePrimitives";
import { StatusBadge } from "@/components/StatusBadge";
import { Eyebrow } from "@/components/typography";
import { useCan } from "@/components/rbac";
import { Button } from "@/components/ui/button";
import { useTranslation } from "@/i18n/I18nProvider";
import { api, type ACMEOperatorPlan } from "@/lib/api";
import { useCapabilityExecution } from "@/lib/capabilities";
import { useApiQuery } from "@/lib/query";

function directoryURL(path: string): string {
  if (typeof window === "undefined") return path;
  return new URL(path, window.location.origin).toString();
}

function clientCommand(plan: ACMEOperatorPlan): string {
  const eab = plan.eab_required ? " --eab-kid '<configured-key-id>' --eab-hmac-key '<retrieve-from-secret-manager>'" : "";
  return `certbot certonly --standalone --server '${directoryURL(plan.directory_path)}' --domain '<dns-name>'${eab}`;
}

function isACMEOperatorPlan(value: unknown): value is ACMEOperatorPlan {
  if (typeof value !== "object" || value === null) return false;
  const plan = value as Partial<ACMEOperatorPlan>;
  return (
    typeof plan.ready === "boolean" &&
    typeof plan.directory_path === "string" &&
    Array.isArray(plan.challenge_methods) &&
    Array.isArray(plan.blockers) &&
    Array.isArray(plan.warnings) &&
    Array.isArray(plan.recovery_steps) &&
    Array.isArray(plan.preview_writes) &&
    Array.isArray(plan.preview_external_effects) &&
    Array.isArray(plan.validation_activity) &&
    typeof plan.next_action === "object" &&
    plan.next_action !== null &&
    typeof plan.next_action.kind === "string"
  );
}

function displayMethod(method: string): string {
  return method.toUpperCase();
}

function displayMethodList(methods: string[], locale: string): string {
  const labels = methods.map(displayMethod);
  if (labels.length === 0) return "—";
  return new Intl.ListFormat(locale, { style: "long", type: "conjunction" }).format(labels);
}

export function ACMEOperatorPanel() {
  const { t, locale, formatDateTime } = useTranslation();
  const canRead = useCan("issuers:read");
  const canWrite = useCan("issuers:write");
  const activation = useCapabilityExecution("F5", "activateProtocolProfile");
  const available = typeof api.acmeOperatorPlan === "function";
  const query = useApiQuery(["acme", "operator-plan"], api.acmeOperatorPlan, { enabled: canRead && available });
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const plan = isACMEOperatorPlan(query.data) ? query.data : null;

  if (!canRead) return null;

  async function activateEvalProfile() {
    setBusy(true);
    setActionError(null);
    try {
      await api.activateProtocolProfile();
      query.refetch();
    } catch (error) {
      setActionError(error instanceof Error ? error.message : String(error));
    } finally {
      setBusy(false);
    }
  }

  async function copyCommand() {
    if (!plan) return;
    await navigator.clipboard?.writeText(clientCommand(plan));
    setCopied(true);
  }

  return (
    <section
      id="acme-operator-panel"
      aria-labelledby="acme-operator-plan-heading"
      aria-label={t("protocols.acmePlan.region")}
      className="ui-panel grid scroll-mt-24 gap-4 p-comfortable"
    >
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0 max-w-3xl">
          <h2 id="acme-operator-plan-heading" className="text-title font-semibold">
            {t("protocols.acmePlan.heading")}
          </h2>
          <p className="mt-1 text-body text-muted-foreground">{t("protocols.acmePlan.description")}</p>
        </div>
        {plan ? (
          <StatusBadge
            value={plan.ready ? "ready" : "blocked"}
            label={plan.ready ? t("protocols.acmePlan.ready") : t("protocols.acmePlan.blocked")}
            tone={plan.ready ? "success" : "warning"}
          />
        ) : null}
      </div>

      {!available ? (
        <UnavailableState title={t("protocols.acmePlan.unavailableTitle")}>{t("protocols.acmePlan.unavailableBody")}</UnavailableState>
      ) : query.loading ? (
        <LoadingState>{t("protocols.acmePlan.loading")}</LoadingState>
      ) : query.error || !plan ? (
        <ErrorState title={t("protocols.acmePlan.unavailableTitle")}>{t("protocols.acmePlan.unavailableBody")}</ErrorState>
      ) : (
        <>
          <dl className="grid gap-px overflow-hidden rounded-control border border-border bg-border sm:grid-cols-2 lg:grid-cols-5">
            <div className="bg-surface px-3 py-3">
              <dt className="text-caption text-muted-foreground">{t("protocols.acmePlan.directory")}</dt>
              <dd className="mt-1 break-all font-mono text-xs font-medium">{plan.directory_path}</dd>
            </div>
            <div className="bg-surface px-3 py-3">
              <dt className="text-caption text-muted-foreground">{t("protocols.acmePlan.challenges")}</dt>
              <dd className="mt-1 text-sm font-medium">{plan.challenge_methods.join(", ")}</dd>
            </div>
            <div className="bg-surface px-3 py-3">
              <dt className="text-caption text-muted-foreground">{t("protocols.acmePlan.profile")}</dt>
              <dd className="mt-1 text-sm font-medium">{plan.issuing_profile || t("protocols.acmePlan.profileDefault")}</dd>
            </div>
            <div className="bg-surface px-3 py-3">
              <dt className="text-caption text-muted-foreground">{t("protocols.acmePlan.eab")}</dt>
              <dd className="mt-1 text-sm font-medium">
                {plan.eab_required
                  ? t("protocols.acmePlan.eabSummary", { active: plan.eab_active, configured: plan.eab_configured })
                  : t("protocols.acmePlan.eabNotRequired")}
              </dd>
            </div>
            <div className="bg-surface px-3 py-3">
              <dt className="text-caption text-muted-foreground">{t("protocols.acmePlan.dns")}</dt>
              <dd className="mt-1 text-sm font-medium">{t("protocols.acmePlan.dnsSummary", { count: plan.dns01_provider_configs })}</dd>
            </div>
          </dl>

          {plan.preview_writes.length === 0 && plan.preview_external_effects.length === 0 ? (
            <p className="text-caption text-muted-foreground">{t("protocols.acmePlan.effectFree")}</p>
          ) : null}

          <div className="grid gap-3 border-t border-border pt-4 md:grid-cols-[minmax(0,1fr)_auto] md:items-end">
            <div>
              <Eyebrow as="p">{t("protocols.acmePlan.nextStep")}</Eyebrow>
              <p className="mt-1 text-body font-semibold">{plan.next_action.label}</p>
              <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{plan.next_action.detail}</p>
            </div>
            <div className="flex flex-wrap gap-2">
              {plan.next_action.kind === "activate_eval_profile" && plan.activation_available ? (
                <Button
                  type="button"
                  disabled={busy || !canWrite || !activation.runnable}
                  title={!canWrite ? t("protocols.acmePlan.permissionDenied") : activation.unavailable?.detail}
                  onClick={() => void activateEvalProfile()}
                >
                  {plan.next_action.label}
                </Button>
              ) : null}
              {plan.ready ? (
                <Button type="button" variant="outline" onClick={() => void copyCommand()}>
                  {t("protocols.acmePlan.copy")}
                </Button>
              ) : null}
            </div>
          </div>
          {copied ? <p className="text-caption text-status-success">{t("protocols.acmePlan.copied")}</p> : null}
          {actionError ? <ErrorState title={t("protocols.acmePlan.actionFailed")}>{actionError}</ErrorState> : null}

          {plan.blockers.length > 0 ? (
            <section aria-labelledby="acme-plan-blockers-heading" className="border-s-2 border-status-warning ps-3">
              <h3 id="acme-plan-blockers-heading" className="text-sm font-semibold">
                {t("protocols.acmePlan.blockers")}
              </h3>
              <ul className="mt-2 grid gap-1 text-sm text-muted-foreground">
                {plan.blockers.map((blocker) => (
                  <li key={blocker}>{blocker}</li>
                ))}
              </ul>
            </section>
          ) : null}
          {plan.warnings.length > 0 ? (
            <details className="text-sm">
              <summary className="cursor-pointer font-medium">{t("protocols.acmePlan.warnings")}</summary>
              <ul className="mt-2 grid gap-1 text-muted-foreground">
                {plan.warnings.map((warning) => (
                  <li key={warning}>{warning}</li>
                ))}
              </ul>
            </details>
          ) : null}
          <section aria-labelledby="acme-validation-activity-heading" className="border-t border-border pt-4">
            <div className="flex flex-wrap items-end justify-between gap-2">
              <div>
                <h3 id="acme-validation-activity-heading" className="text-sm font-semibold">
                  {t("protocols.acmePlan.activityHeading")}
                </h3>
                <p className="mt-1 max-w-3xl text-caption text-muted-foreground">{t("protocols.acmePlan.activityDescription")}</p>
              </div>
              <span className="text-caption text-muted-foreground">{t("protocols.acmePlan.activityCount", { count: plan.validation_activity.length })}</span>
            </div>
            {plan.validation_activity.length === 0 ? (
              <p className="mt-3 text-sm text-muted-foreground">{t("protocols.acmePlan.activityEmpty")}</p>
            ) : (
              <ul className="mt-3 divide-y divide-border border-y border-border">
                {plan.validation_activity.map((activity) => {
                  const result = activity.validation_skipped
                    ? t("protocols.acmePlan.activitySkipped")
                    : activity.validated_method
                      ? t("protocols.acmePlan.activityValidated", { method: displayMethod(activity.validated_method) })
                      : t("protocols.acmePlan.activityWaiting");
                  return (
                    <li key={`${activity.order_id}:${activity.domain}`} className="grid gap-2 py-3 sm:grid-cols-[minmax(0,1fr)_auto] sm:items-center">
                      <div className="min-w-0">
                        <p className="break-all text-sm font-semibold">{activity.domain}</p>
                        <p className="mt-1 text-caption text-muted-foreground">
                          {t("protocols.acmePlan.activityOffered", { methods: displayMethodList(activity.challenge_methods, locale) })}
                        </p>
                        <p className="mt-1 text-caption text-muted-foreground">
                          {t("protocols.acmePlan.activityStarted", { at: formatDateTime(activity.created_at) })}
                        </p>
                      </div>
                      <div className="grid justify-items-start gap-1 sm:justify-items-end">
                        <StatusBadge
                          value={activity.authorization_status}
                          tone={activity.authorization_status === "valid" ? "success" : "neutral"}
                          label={result}
                        />
                        <span className="text-caption text-muted-foreground">
                          {t("protocols.acmePlan.activityOrder", { status: activity.order_status })}
                        </span>
                      </div>
                    </li>
                  );
                })}
              </ul>
            )}
          </section>
          <section aria-labelledby="acme-plan-recovery-heading" className="border-t border-border pt-4">
            <h3 id="acme-plan-recovery-heading" className="text-sm font-semibold">
              {t("protocols.acmePlan.recovery")}
            </h3>
            <ol className="mt-2 grid list-decimal gap-1 ps-5 text-sm text-muted-foreground">
              {plan.recovery_steps.map((step) => (
                <li key={step}>{step}</li>
              ))}
            </ol>
          </section>
        </>
      )}
    </section>
  );
}
