import { useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { CredentialChip } from "@/components/CredentialChip";
import { StatusBadge } from "@/components/StatusBadge";
import { ErrorState } from "@/components/StatePrimitives";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { useTranslation } from "@/i18n/I18nProvider";
import { api, type IdentityApplicationView } from "@/lib/api";
import { endpointBindingDefaultsHref } from "@/lib/endpointBindingDefaults";
import { useApiQuery } from "@/lib/query";

const stateCopy = {
  requested: "identities.application.state.requested",
  issued: "identities.application.state.issued",
  delivered: "identities.application.state.delivered",
  served: "identities.application.state.served",
  revoked: "identities.application.state.revoked",
  retired: "identities.application.state.retired",
} as const;

const sourceCopy = {
  external: "connectors.binding.sourceExternal",
  private: "connectors.binding.sourcePrivate",
  platform: "connectors.binding.sourcePlatform",
} as const;

const vantageCopy = {
  connector: "identities.application.vantage.connector",
  local: "identities.application.vantage.local",
  relay: "identities.application.vantage.relay",
} as const;

const nextCopy = {
  "issue on request": "identities.application.next.issue",
  none: "identities.application.next.none",
  "renewal retry": "identities.application.next.retry",
  blocked: "identities.application.next.blocked",
  "renew now": "identities.application.next.renewNow",
  "renew before expiry": "identities.application.next.renewBeforeExpiry",
  "none scheduled": "identities.application.next.noneScheduled",
} as const;

const changeCopy = {
  profile: "identities.application.changed.profile",
  destination: "identities.application.changed.destination",
  issuer: "identities.application.changed.issuer",
  identity: "identities.application.changed.identity",
} as const;

const verifyCopy = {
  connector: "identities.application.plan.verify.connector",
  local: "identities.application.plan.verify.local",
  relay: "identities.application.plan.verify.relay",
} as const;

const previewStateCopy = {
  previewed: "identities.application.plan.state.previewed",
  accepted: "identities.application.plan.state.accepted",
  later: "identities.application.plan.state.later",
} as const;

const planStepCopy = {
  approve: "identities.application.plan.step.approve",
  issue: "identities.application.plan.step.issue",
  deploy: "identities.application.plan.step.deploy",
} as const;

const actionCopy = {
  recover: "identities.application.action.recover",
  revoke: "identities.application.action.revoke",
  retire: "identities.application.action.retire",
} as const;

/** One certificate's application view (A244): owner, profile, exact CA,
 * destination, what was seen at the endpoint and from where, approvals, the
 * next automated action and the recover, revoke and retire actions. */
export function IdentityApplicationPanel({ identityId }: { identityId: string }) {
  const { t, formatDateTime } = useTranslation();
  const result = useApiQuery(
    ["identity-application", identityId],
    async () => {
      const view = await api.identityApplication(identityId);
      if (view.identity.id !== identityId) throw new Error(t("identities.application.mismatch"));
      return view;
    },
    { retry: false, live: { intervalMs: 10_000 } },
  );
  const view = result.data;
  return (
    <section className="mt-4 border-t border-border pt-4" aria-labelledby="identity-application-heading">
      <h3 id="identity-application-heading" className="font-semibold">
        {t("identities.application.title")}
      </h3>
      <p className="mt-1 text-xs text-muted-foreground">{t("identities.application.scope")}</p>
      {result.error ? (
        <div className="mt-3 grid gap-2">
          <ErrorState title={t("identities.application.failed")}>{result.error}</ErrorState>
          <Button onClick={result.refetch}>{t("identities.application.retry")}</Button>
        </div>
      ) : !view ? (
        <div className="mt-3 grid grid-cols-2 gap-3" aria-busy="true">
          <Skeleton className="h-12" />
          <Skeleton className="h-12" />
        </div>
      ) : (
        <ApplicationDetails view={view} formatDateTime={formatDateTime} />
      )}
    </section>
  );
}

/** A244-L3: a list the view starts and "show more" continues from its cursor.
 * Pages append in order; an item a refreshed first page already holds is not
 * repeated. emptyStretch says the last page read found nothing there (a
 * bounded alerts read can stop with more to read). */
function useMore<T extends { id: string }>(
  first: T[],
  firstCursor: string | undefined,
  load: (cursor: string) => Promise<{ items: T[]; next_cursor?: string }>,
) {
  const [extra, setExtra] = useState<{ items: T[]; cursor?: string; emptyStretch: boolean } | null>(null);
  const [busy, setBusy] = useState(false);
  const [failed, setFailed] = useState(false);
  const seen = new Set<string>();
  const items = [...first, ...(extra?.items ?? [])].filter((item) => !seen.has(item.id) && seen.add(item.id) !== undefined);
  const cursor = extra ? extra.cursor : firstCursor;
  const more = async () => {
    if (!cursor) return;
    setBusy(true);
    setFailed(false);
    try {
      const page = await load(cursor);
      setExtra((prev) => ({ items: [...(prev?.items ?? []), ...page.items], cursor: page.next_cursor, emptyStretch: page.items.length === 0 }));
    } catch {
      setFailed(true);
    } finally {
      setBusy(false);
    }
  };
  return { items, cursor, more, busy, failed, emptyStretch: extra?.emptyStretch ?? false };
}

function ApplicationDetails({ view, formatDateTime }: { view: IdentityApplicationView; formatDateTime: (value?: string) => string }) {
  const { t } = useTranslation();
  const { owner, profile, issuer, certificate, destination, served, renewal } = view;
  const approvals = useMore(view.approvals, view.approvals_next_cursor, (cursor) => api.identityApplicationApprovals(view.identity.id, cursor));
  const alerts = useMore(view.alerts, view.alerts_next_cursor, (cursor) => api.identityApplicationAlerts(view.identity.id, cursor));
  const reuse = endpointBindingDefaultsHref(view.defaults);
  return (
    <div className="mt-3 grid gap-4">
      <p>
        <span className="me-2 font-medium text-muted-foreground">{t("identities.application.inventory")}</span>
        <StatusBadge vocabulary="inventory" value={view.inventory_state} />
        <span className="ms-2 text-muted-foreground">{t(stateCopy[view.inventory_state])}</span>
      </p>
      <dl className="grid gap-3 sm:grid-cols-2">
        <Fact label={t("identities.application.owner")}>
          {owner ? t("identities.application.ownerDetail", { name: owner.name, kind: owner.kind }) : t("identities.application.noOwner")}
        </Fact>
        <Fact label={t("identities.application.profile")}>
          {profile
            ? t("identities.application.profileVersion", { name: profile.name, version: String(profile.version) })
            : t("identities.application.noProfile")}
          {profile?.requires_approval && <span className="block text-xs text-muted-foreground">{t("identities.application.approvalRequired")}</span>}
          {profile && (
            <span className="block text-xs text-muted-foreground">
              {profile.enrollment_methods.length > 0
                ? t("identities.application.enrollment", { methods: profile.enrollment_methods.join(", ") })
                : t("identities.application.enrollmentAny")}
            </span>
          )}
        </Fact>
        <Fact label={t("identities.application.issuer")}>
          {t("identities.issuer.selection", { source: t(sourceCopy[issuer.source]), name: issuer.name || issuer.id || "-" })}
          {issuer.certificate_issuer && (
            <span className="block text-xs text-muted-foreground">
              {t("identities.application.certificateIssuer")}: <code className="break-all">{issuer.certificate_issuer}</code>
            </span>
          )}
        </Fact>
        <Fact label={t("identities.application.certificate")}>
          {certificate ? (
            <>
              <CredentialChip value={certificate.serial || "-"} label={t("source.serial.8ea0949377")} />
              <span className="block text-xs text-muted-foreground">
                {t("identities.certificate.expires")}: {formatDateTime(certificate.not_after)}
              </span>
              {view.enrollment?.current_method && (
                <span className="block text-xs text-muted-foreground">
                  {t("identities.application.enrolledBy", { method: view.enrollment.current_method })}
                </span>
              )}
            </>
          ) : (
            t("identities.application.noCertificate")
          )}
          {view.enrollment?.first_method && (
            <span className="block text-xs text-muted-foreground">{t("identities.application.firstEnrolledBy", { method: view.enrollment.first_method })}</span>
          )}
        </Fact>
        <Fact label={t("identities.application.destination")}>
          {destination ? (
            <>
              {t("identities.application.destinationDetail", { name: destination.name, connector: destination.connector })}
              {!destination.enabled && <span className="block text-xs text-muted-foreground">{t("identities.application.destinationDisabled")}</span>}
              <span className="block text-xs text-muted-foreground">
                {destination.verify_address
                  ? t("identities.application.checkedAt", { address: destination.verify_address })
                  : t("identities.application.unchecked")}
              </span>
              {destination.last_delivery_status && (
                <span className="block text-xs text-muted-foreground">
                  {t("identities.application.lastDelivery", { at: formatDateTime(destination.last_delivery_at) })}{" "}
                  <StatusBadge vocabulary="delivery" value={destination.last_delivery_status} />
                </span>
              )}
            </>
          ) : (
            t("identities.application.noDestination")
          )}
        </Fact>
        <Fact label={t("identities.application.seen")}>
          {served ? (
            <>
              {t("identities.application.seenBy", { vantage: t(vantageCopy[served.vantage]), at: formatDateTime(served.at) })}
              {!served.matches_current && <span className="block text-xs text-muted-foreground">{t("identities.application.seenEarlier")}</span>}
            </>
          ) : (
            t("identities.application.notSeen")
          )}
        </Fact>
        <Fact label={t("identities.application.next")}>
          {t(nextCopy[renewal.next_action as keyof typeof nextCopy] ?? "identities.application.next.noneScheduled")}
          {renewal.latest_run_status && (
            <span className="block text-xs text-muted-foreground">{t("identities.application.latestRun", { status: renewal.latest_run_status })}</span>
          )}
          {renewal.blockers.length > 0 && (
            <span className="block text-xs text-muted-foreground">
              {t("identities.application.blockers")}: {renewal.blockers.join("; ")}
            </span>
          )}
        </Fact>
      </dl>
      <div>
        <h4 className="font-medium">{t("identities.application.plan")}</h4>
        <p className="text-xs text-muted-foreground">{t("identities.application.planHelp")}</p>
        {view.review_plan.length === 0 ? (
          <p className="text-muted-foreground">{t("identities.application.planNone")}</p>
        ) : (
          <ol className="mt-1 grid list-decimal gap-1 ps-5">
            {view.review_plan.map((step) => (
              <li key={step.action}>
                {planStep(step, t)}
                <PlanStepPreview preview={step.preview} t={t} />
              </li>
            ))}
          </ol>
        )}
      </div>
      <div>
        <h4 className="font-medium">{t("identities.application.approvals")}</h4>
        {approvals.items.length === 0 ? (
          <p className="text-muted-foreground">{t("identities.application.noApprovals")}</p>
        ) : (
          <ul className="mt-1 grid gap-1">
            {approvals.items.map((approval) => (
              <li key={approval.id}>
                <StatusBadge value={approval.status} />{" "}
                {t("identities.application.approval", { action: approval.action, at: formatDateTime(approval.created_at) })}
                {approval.changed.length > 0 && (
                  <span className="block text-xs text-destructive">
                    {t("identities.application.changed", { changes: approval.changed.map((change) => t(changeCopy[change])).join(", ") })}
                  </span>
                )}
              </li>
            ))}
          </ul>
        )}
        <MoreButton list={approvals} label={t("identities.application.moreApprovals")} />
      </div>
      <div>
        <h4 className="font-medium">{t("identities.application.alerts")}</h4>
        {alerts.items.length === 0 ? (
          <p className="text-muted-foreground">{t("identities.application.noAlerts")}</p>
        ) : (
          <ul className="mt-1 grid gap-1">
            {alerts.items.map((alert) => (
              <li key={alert.id}>
                <StatusBadge vocabulary="delivery" value={alert.status} /> {alert.kind ?? alert.destination} · {formatDateTime(alert.created_at)}
              </li>
            ))}
          </ul>
        )}
        {alerts.emptyStretch && alerts.cursor && <p className="text-xs text-muted-foreground">{t("identities.application.moreAlertsEmptyStretch")}</p>}
        <MoreButton list={alerts} label={t("identities.application.moreAlerts")} />
      </div>
      <div>
        <h4 className="font-medium">{t("identities.application.actions")}</h4>
        <ul className="mt-1 grid gap-1">
          {view.actions.map((action) => (
            <li key={action.action}>
              <span className="font-medium">{t(actionCopy[action.action])}</span>:{" "}
              <span className="text-muted-foreground">{action.available ? t("identities.application.actionAvailable") : action.reason}</span>
            </li>
          ))}
        </ul>
      </div>
      {reuse && (
        <p>
          <Link className="text-primary underline" to={reuse}>
            {t("identities.application.reuse")}
          </Link>
          <span className="block text-xs text-muted-foreground">{t("identities.application.reuseHelp")}</span>
        </p>
      )}
    </div>
  );
}

function planStep(step: IdentityApplicationView["review_plan"][number], t: ReturnType<typeof useTranslation>["t"]): string {
  switch (step.action) {
    case "approve":
      return t("identities.application.plan.approve", { subject: step.subject });
    case "issue":
      return t("identities.application.plan.issue", { subject: step.subject });
    case "deploy":
      return t("identities.application.plan.deploy", { subject: step.subject });
    default:
      return step.subject in verifyCopy ? t(verifyCopy[step.subject as keyof typeof verifyCopy]) : t("identities.application.plan.verify.none");
  }
}

/** What the effect-free transition preview says about one plan step (A244-L2):
 * whether it was previewed now, what refuses it or which earlier step it waits
 * on, and what execution checks and how to confirm it. */
function PlanStepPreview({ preview, t }: { preview: IdentityApplicationView["review_plan"][number]["preview"]; t: ReturnType<typeof useTranslation>["t"] }) {
  return (
    <>
      <span className="block text-xs text-muted-foreground">
        {preview.from && preview.to
          ? t(previewStateCopy[preview.state], { from: preview.from, to: preview.to })
          : t("identities.application.plan.state.reading")}
      </span>
      {!preview.ready && (
        <span className="block text-xs text-destructive">
          {preview.waits_on
            ? t("identities.application.plan.waitsOn", { step: t(planStepCopy[preview.waits_on]) })
            : t("identities.application.plan.refused", { refusals: preview.refusals.join("; ") })}
        </span>
      )}
      {preview.warnings.length > 0 && (
        <span className="block text-xs text-muted-foreground">{t("identities.application.plan.warnings", { warnings: preview.warnings.join("; ") })}</span>
      )}
      {(preview.policy.length > 0 || preview.readback.length > 0) && (
        <details className="text-xs text-muted-foreground">
          <summary>{t("identities.application.plan.details")}</summary>
          {preview.policy.length > 0 && (
            <>
              <p className="font-medium">{t("identities.application.plan.policy")}</p>
              <ul className="list-disc ps-4">
                {preview.policy.map((line) => (
                  <li key={line}>{line}</li>
                ))}
              </ul>
            </>
          )}
          {preview.readback.length > 0 && (
            <>
              <p className="font-medium">{t("identities.application.plan.readback")}</p>
              <ul className="list-disc ps-4">
                {preview.readback.map((line) => (
                  <li key={line}>{line}</li>
                ))}
              </ul>
            </>
          )}
        </details>
      )}
    </>
  );
}

function MoreButton({ list, label }: { list: { cursor?: string; busy: boolean; failed: boolean; more: () => Promise<void> }; label: string }) {
  const { t } = useTranslation();
  if (!list.cursor) return null;
  return (
    <div className="mt-1">
      <Button type="button" size="sm" variant="outline" loading={list.busy} onClick={() => void list.more()}>
        {label}
      </Button>
      {list.failed && <p className="text-xs text-destructive">{t("identities.application.moreFailed")}</p>}
    </div>
  );
}

function Fact({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <dt className="font-medium text-muted-foreground">{label}</dt>
      <dd>{children}</dd>
    </div>
  );
}
