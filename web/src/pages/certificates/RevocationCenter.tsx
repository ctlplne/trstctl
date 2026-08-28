import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { ShieldAlert } from "lucide-react";
import {
  api,
  type BulkRevokeRequest,
  type CRLDistribution,
  type GraphImpact,
  type Identity,
  type IdentityTransitionPreview,
  type RevocationHealth,
} from "@/lib/api";
import { apiProblemContext } from "@/lib/apiProblem";
import { Button } from "@/components/ui/button";
import { StepShell, type CarouselStep } from "@/components/wizard/StepShell";
import { useTranslation } from "@/i18n/I18nProvider";
import type { MessageKey } from "@/i18n/messages";
import { graphNodeIdForIdentity, revocationReasons } from "@/lib/revocation";

type ReviewState = {
  impact: GraphImpact | null;
  impactError: string | null;
  key: string;
  plan: IdentityTransitionPreview;
};

export interface RevocationCenterProps {
  distributions: CRLDistribution[];
  health: RevocationHealth | null;
  identities: Identity[];
  onRevoked?: (identity: Identity) => void;
}

const revocableStates = new Set(["issued", "deployed", "renewing", "renewal_failed"]);

function reviewKey(identityID: string, reason: string): string {
  return `${identityID}\u0000${reason}`;
}

function affectedCopy(impact: GraphImpact | null, error: string | null, t: (key: MessageKey, values?: Record<string, number | string>) => string): string {
  if (error) return t("certificates.revocation.impactUnknown", { error });
  if (!impact) return t("certificates.revocation.impactLoading");
  const count = impact.affected.length;
  return t(count === 1 ? "certificates.revocation.impactOne" : "certificates.revocation.impactMany", { count });
}

export function RevocationCenter({ distributions, health, identities, onRevoked }: RevocationCenterProps) {
  const { t } = useTranslation();
  const eligible = useMemo(
    () =>
      identities
        .filter((identity) => identity.kind === "x509_certificate" && revocableStates.has(identity.status))
        .sort((left, right) => left.name.localeCompare(right.name)),
    [identities],
  );
  const [step, setStep] = useState(0);
  const [identityID, setIdentityID] = useState("");
  const [reason, setReason] = useState<BulkRevokeRequest["reason"]>("unspecified");
  const [review, setReview] = useState<ReviewState | null>(null);
  const [reviewLoading, setReviewLoading] = useState(false);
  const [reviewError, setReviewError] = useState<string | null>(null);
  const [confirmName, setConfirmName] = useState("");
  const [executeLoading, setExecuteLoading] = useState(false);
  const [executeError, setExecuteError] = useState<string | null>(null);
  const [completed, setCompleted] = useState<Identity | null>(null);

  const selected = eligible.find((identity) => identity.id === identityID) ?? null;
  const currentKey = reviewKey(identityID, reason);
  const reviewCurrent = review?.key === currentKey;
  const freshEndpoints = health?.summary.fresh ?? 0;
  const endpointCount = health?.summary.endpoints ?? 0;
  const propagationCopy =
    health?.observed && endpointCount > 0
      ? freshEndpoints === endpointCount
        ? t(freshEndpoints === 1 ? "certificates.revocation.propagationFreshOne" : "certificates.revocation.propagationFreshMany", {
            count: freshEndpoints,
          })
        : t("certificates.revocation.propagationAttention", {
            count: endpointCount,
            fresh: freshEndpoints,
            attention: endpointCount - freshEndpoints,
          })
      : t("certificates.revocation.propagationUnknown");
  const crlCopy =
    distributions.length > 0
      ? t(distributions.length === 1 ? "certificates.revocation.crlPublishedOne" : "certificates.revocation.crlPublishedMany", {
          count: distributions.length,
        })
      : t("certificates.revocation.crlUnknown");

  const steps = useMemo<CarouselStep[]>(
    () => [
      {
        id: "configure",
        label: t("certificates.revocation.configureTitle"),
        description: t("certificates.revocation.configureDescription"),
        progressState: reviewCurrent ? "done" : "pending",
      },
      {
        id: "review",
        label: t("certificates.revocation.reviewTitle"),
        description: t("certificates.revocation.reviewDescription"),
        progressState: reviewCurrent ? "done" : "pending",
      },
      {
        id: "confirm",
        label: t("certificates.revocation.confirmTitle"),
        description: t("certificates.revocation.confirmDescription"),
        progressState: completed ? "done" : "pending",
      },
    ],
    [completed, reviewCurrent, t],
  );

  function invalidateReview() {
    setReview(null);
    setReviewError(null);
    setConfirmName("");
    setExecuteError(null);
    setCompleted(null);
  }

  async function loadReview() {
    if (!selected) return;
    setReviewLoading(true);
    setReviewError(null);
    setExecuteError(null);
    try {
      const plan = await api.previewIdentityTransition(selected.id, "revoked", reason);
      const nodeID = graphNodeIdForIdentity(selected);
      let impact: GraphImpact | null = null;
      let impactError: string | null = null;
      if (!nodeID) {
        impactError = t("certificates.revocation.graphBindingMissing");
      } else {
        try {
          impact = await api.graphBlastRadius(nodeID);
        } catch (error) {
          impactError = apiProblemContext(error, t("certificates.revocation.graphFailed"));
        }
      }
      setReview({ key: currentKey, plan, impact, impactError });
      setStep(1);
    } catch (error) {
      setReview(null);
      setReviewError(apiProblemContext(error, t("certificates.revocation.previewFailed")));
    } finally {
      setReviewLoading(false);
    }
  }

  async function execute() {
    if (!selected || !reviewCurrent || !review?.plan.ready || confirmName.trim() !== selected.name) return;
    setExecuteLoading(true);
    setExecuteError(null);
    try {
      const updated = await api.transitionIdentity(selected.id, "revoked", reason, undefined, undefined, review.plan.expected_version);
      if (updated.status !== "revoked") {
        throw new Error(t("certificates.revocation.verifyFailed"));
      }
      setCompleted(updated);
      onRevoked?.(updated);
    } catch (error) {
      setExecuteError(apiProblemContext(error, t("certificates.revocation.executeFailed")));
    } finally {
      setExecuteLoading(false);
    }
  }

  return (
    <section aria-labelledby="revocation-center-heading" className="grid gap-4">
      <header className="max-w-3xl">
        <div className="flex items-center gap-2">
          <ShieldAlert className="h-4 w-4 text-status-warning" aria-hidden="true" />
          <h2 id="revocation-center-heading" className="text-base font-semibold">
            {t("certificates.revocation.heading")}
          </h2>
        </div>
        <p className="mt-1 text-sm text-muted-foreground">{t("certificates.revocation.description")}</p>
        <div className="mt-3 grid gap-2 text-sm sm:grid-cols-2">
          <p className="rounded-control border border-border bg-muted/30 px-3 py-2">{propagationCopy}</p>
          <p className="rounded-control border border-border bg-muted/30 px-3 py-2">{crlCopy}</p>
        </div>
      </header>

      <StepShell
        currentIndex={step}
        steps={steps}
        progressLabel={t("certificates.revocation.progress")}
        onPrevious={step > 0 && !executeLoading ? () => setStep((current) => Math.max(0, current - 1)) : undefined}
        onNext={
          step === 0
            ? () => void loadReview()
            : step === 1 && reviewCurrent
              ? () => {
                  setConfirmName("");
                  setStep(2);
                }
              : undefined
        }
        nextDisabled={(step === 0 && (!selected || reviewLoading)) || (step === 1 && (!reviewCurrent || !review?.plan.ready))}
        nextLabel={
          step === 0
            ? reviewLoading
              ? t("certificates.revocation.reviewLoading")
              : t("certificates.revocation.reviewAction")
            : t("certificates.revocation.continueAction")
        }
      >
        {step === 0 && (
          <div className="grid max-w-2xl gap-4">
            <label className="grid gap-1 text-sm font-medium" htmlFor="revocation-center-identity">
              {t("certificates.revocation.identityLabel")}
              <select
                id="revocation-center-identity"
                value={identityID}
                onChange={(event) => {
                  setIdentityID(event.target.value);
                  invalidateReview();
                }}
                className="min-h-10 rounded-control border border-border bg-background px-3 py-2 text-sm"
              >
                <option value="">{t("certificates.revocation.identityPlaceholder")}</option>
                {eligible.map((identity) => (
                  <option key={identity.id} value={identity.id}>
                    {identity.name} · {identity.status}
                  </option>
                ))}
              </select>
            </label>
            <label className="grid gap-1 text-sm font-medium" htmlFor="revocation-center-reason">
              {t("certificates.revocation.reasonLabel")}
              <select
                id="revocation-center-reason"
                aria-label={t("certificates.revocation.reasonLabel")}
                value={reason}
                onChange={(event) => {
                  setReason(event.target.value as BulkRevokeRequest["reason"]);
                  invalidateReview();
                }}
                className="min-h-10 rounded-control border border-border bg-background px-3 py-2 text-sm"
              >
                {revocationReasons.map((item) => (
                  <option key={item} value={item}>
                    {item}
                  </option>
                ))}
              </select>
              <span className="text-xs text-muted-foreground">{t("certificates.revocation.reasonHelp")}</span>
            </label>
            {eligible.length === 0 && (
              <p className="rounded-control border border-border bg-muted/30 p-3 text-sm text-muted-foreground">{t("certificates.revocation.empty")}</p>
            )}
            {reviewError && (
              <p role="alert" className="rounded-control border border-destructive/30 bg-destructive/5 p-3 text-sm text-destructive">
                {reviewError}
              </p>
            )}
          </div>
        )}

        {step === 1 && reviewCurrent && review && (
          <div className="grid gap-4 text-sm">
            <div className="rounded-control border border-status-success/30 bg-status-success/5 p-3">
              <p className="font-semibold text-status-success">{t("certificates.revocation.noChanges")}</p>
              <p className="mt-1 text-muted-foreground">{review.plan.guidance}</p>
            </div>
            <dl className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
              <div>
                <dt className="text-xs text-muted-foreground">{t("certificates.revocation.owner")}</dt>
                <dd className="font-medium">{review.plan.owner_name || review.plan.owner_id}</dd>
              </div>
              <div>
                <dt className="text-xs text-muted-foreground">{t("certificates.revocation.reasonLabel")}</dt>
                <dd className="font-mono text-xs">{reason}</dd>
              </div>
              <div>
                <dt className="text-xs text-muted-foreground">{t("certificates.revocation.version")}</dt>
                <dd className="font-mono text-xs">{review.plan.expected_version}</dd>
              </div>
              <div>
                <dt className="text-xs text-muted-foreground">{t("certificates.revocation.effect")}</dt>
                <dd className="font-mono text-xs">{review.plan.side_effect_destination || t("certificates.revocation.noExternalEffect")}</dd>
              </div>
            </dl>
            <div className="rounded-control border border-border p-3">
              <h3 className="font-semibold">{t("certificates.revocation.impactTitle")}</h3>
              <p className="mt-1 text-muted-foreground">{affectedCopy(review.impact, review.impactError, t)}</p>
              {review.impact && Object.keys(review.impact.by_kind ?? {}).length > 0 && (
                <ul className="mt-2 flex flex-wrap gap-2 text-xs">
                  {Object.entries(review.impact.by_kind).map(([kind, count]) => (
                    <li key={kind} className="rounded-full border border-border px-2 py-1">
                      {kind}: {String(count)}
                    </li>
                  ))}
                </ul>
              )}
            </div>
            <div className="grid gap-4 lg:grid-cols-3">
              <PlanList title={t("certificates.revocation.prerequisites")} items={review.plan.prerequisites} />
              <PlanList title={t("certificates.revocation.writes")} items={[...review.plan.execution_writes, ...review.plan.execution_external_effects]} />
              <PlanList title={t("certificates.revocation.proof")} items={review.plan.verification_steps} />
            </div>
            <div>
              <p className="text-xs text-muted-foreground">{t("certificates.revocation.fingerprint")}</p>
              <code className="mt-1 block break-all rounded-control bg-muted px-2 py-1 text-xs">{review.plan.request_fingerprint}</code>
            </div>
          </div>
        )}

        {step === 2 && selected && reviewCurrent && review && (
          <div role="region" aria-label={t("certificates.revocation.confirmRegion")} className="grid max-w-2xl gap-4">
            <div className="rounded-control border border-destructive/30 bg-destructive/5 p-3 text-sm text-destructive">
              <p className="font-semibold">{t("certificates.revocation.irreversibleTitle")}</p>
              <p className="mt-1">{t("certificates.revocation.irreversibleBody", { identity: selected.name, reason })}</p>
            </div>
            <label className="grid gap-1 text-sm font-medium" htmlFor="revocation-center-confirm-name">
              {t("certificates.revocation.confirmName")}
              <input
                id="revocation-center-confirm-name"
                value={confirmName}
                onChange={(event) => setConfirmName(event.target.value)}
                placeholder={selected.name}
                className="min-h-10 rounded-control border border-destructive/40 bg-background px-3 py-2 text-sm"
              />
            </label>
            {executeError && (
              <p role="alert" className="rounded-control border border-destructive/30 bg-destructive/5 p-3 text-sm text-destructive">
                {executeError}
              </p>
            )}
            {completed ? (
              <div className="rounded-control border border-status-success/30 bg-status-success/5 p-3 text-sm">
                <p role="status" className="font-semibold text-status-success">
                  {t("certificates.revocation.accepted")}
                </p>
                <div className="mt-2 flex flex-wrap gap-3">
                  <Link
                    className="text-primary underline"
                    to={`/audit?type=${encodeURIComponent(review.plan.event_type)}&q=${encodeURIComponent(completed.id)}`}
                  >
                    {t("certificates.revocation.auditLink")}
                  </Link>
                  {graphNodeIdForIdentity(completed) && (
                    <Link className="text-primary underline" to={`/graph?node=${encodeURIComponent(graphNodeIdForIdentity(completed) ?? "")}`}>
                      {t("certificates.revocation.graphLink")}
                    </Link>
                  )}
                </div>
              </div>
            ) : (
              <Button
                type="button"
                variant="destructive"
                loading={executeLoading}
                disabled={confirmName.trim() !== selected.name || executeLoading}
                onClick={() => void execute()}
              >
                {t("certificates.revocation.executeAction")}
              </Button>
            )}
          </div>
        )}
      </StepShell>
    </section>
  );
}

function PlanList({ items, title }: { items: string[]; title: string }) {
  return (
    <section className="rounded-control border border-border p-3">
      <h3 className="font-semibold">{title}</h3>
      <ul className="mt-2 list-disc space-y-1 ps-5 text-sm text-muted-foreground">
        {items.map((item) => (
          <li key={item}>{item}</li>
        ))}
      </ul>
    </section>
  );
}
