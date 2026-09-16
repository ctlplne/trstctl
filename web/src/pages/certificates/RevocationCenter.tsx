import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { ShieldAlert } from "lucide-react";
import { graphNodeKindLabel } from "@/components/GraphView";
import {
  api,
  type BulkRevokeRequest,
  type Certificate,
  type CRLDistribution,
  type GraphImpact,
  type Identity,
  type IdentityTransitionPreview,
  type RevocationHealth,
} from "@/lib/api";
import { apiProblemContext } from "@/lib/apiProblem";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { Field } from "@/components/ui/field";
import { QueuedCertificateRevocation } from "./QueuedCertificateRevocation";
import { StepShell, type CarouselStep } from "@/components/wizard/StepShell";
import { useTranslation } from "@/i18n/I18nProvider";
import type { MessageKey } from "@/i18n/messages";
import { graphNodeIdForIdentity, revocationReasons } from "@/lib/revocation";
import { LifecycleApprovalRecovery } from "@/components/LifecycleApprovalRecovery";
import { lifecycleApproval, lifecycleCommandKey, type LifecycleApproval } from "@/lib/lifecycleCommand";

type ReviewBase = {
  impact: GraphImpact | null;
  impactError: string | null;
  key: string;
};

type IdentityReview = ReviewBase & {
  kind: "identity";
  plan: IdentityTransitionPreview;
};

type CertificateReview = ReviewBase & {
  certificate: Certificate;
  kind: "certificate";
};

type ReviewState = CertificateReview | IdentityReview;
type CompletedState = { certificate: Certificate; kind: "certificate"; queued?: boolean } | { identity: Identity; kind: "identity" };
type RevocationTarget =
  | { identity: Identity; key: string; kind: "identity"; name: string }
  | { certificate: Certificate; key: string; kind: "certificate"; name: string };

export interface RevocationCenterProps {
  certificates?: Certificate[];
  distributions: CRLDistribution[];
  health: RevocationHealth | null;
  identities: Identity[];
  onCertificateRevoked?: (certificate: Certificate) => void;
  onRevoked?: (identity: Identity) => void;
  targetCertificateID?: string;
}

const revocableIdentityStates = new Set(["issued", "deployed", "renewing", "renewal_failed"]);
const revocableCertificateStates = new Set<Certificate["status"]>(["active", "superseded"]);

function certificateTargetKey(id: string): string {
  return `certificate:${id}`;
}

function certificateTargetName(certificate: Certificate): string {
  return certificate.subject.trim() || certificate.id;
}

function reviewKey(targetKey: string, reason: string): string {
  return `${targetKey}\u0000${reason}`;
}

function affectedCopy(impact: GraphImpact | null, error: string | null, t: (key: MessageKey, values?: Record<string, number | string>) => string): string {
  if (error) return t("certificates.revocation.impactUnknown", { error });
  if (!impact) return t("certificates.revocation.impactLoading");
  const count = impact.affected.filter((node) => node.kind === "resource").length;
  return t(count === 1 ? "certificates.revocation.impactOne" : "certificates.revocation.impactMany", { count });
}

async function readImpact(nodeID: string, t: (key: MessageKey, values?: Record<string, number | string>) => string) {
  try {
    return { impact: await api.graphBlastRadius(nodeID), impactError: null };
  } catch (error) {
    return { impact: null, impactError: apiProblemContext(error, t("certificates.revocation.graphFailed")) };
  }
}

export function RevocationCenter({
  certificates = [],
  distributions,
  health,
  identities,
  onCertificateRevoked,
  onRevoked,
  targetCertificateID,
}: RevocationCenterProps) {
  const { t } = useTranslation();
  const linkedFailedCopy = t("certificates.revocation.linkedFailed");
  const linkedMismatchCopy = t("certificates.revocation.linkedMismatch");
  const [linkedCertificate, setLinkedCertificate] = useState<Certificate | null>(null);
  const [linkedLoading, setLinkedLoading] = useState(Boolean(targetCertificateID));
  const [linkedError, setLinkedError] = useState<string | null>(null);
  const [step, setStep] = useState(0);
  const [targetKey, setTargetKey] = useState(() => (targetCertificateID ? certificateTargetKey(targetCertificateID) : ""));
  const [reason, setReason] = useState<BulkRevokeRequest["reason"]>("unspecified");
  const [review, setReview] = useState<ReviewState | null>(null);
  const [reviewLoading, setReviewLoading] = useState(false);
  const [reviewError, setReviewError] = useState<string | null>(null);
  const [confirmName, setConfirmName] = useState("");
  const [executeLoading, setExecuteLoading] = useState(false);
  const [executeError, setExecuteError] = useState<string | null>(null);
  const [approvalNotice, setApprovalNotice] = useState<LifecycleApproval | null>(null);
  const [approvalRestart, setApprovalRestart] = useState<{ fingerprint: string; requestId: string } | null>(null);
  const [completed, setCompleted] = useState<CompletedState | null>(null);

  useEffect(() => {
    setStep(0);
    setReview(null);
    setReviewError(null);
    setConfirmName("");
    setExecuteError(null);
    setApprovalNotice(null);
    setApprovalRestart(null);
    setCompleted(null);
    setLinkedCertificate(null);
    setLinkedError(null);
    if (!targetCertificateID) {
      setLinkedLoading(false);
      return;
    }
    setTargetKey(certificateTargetKey(targetCertificateID));
    setLinkedLoading(true);
    let cancelled = false;
    api
      .getCertificate(targetCertificateID)
      .then((certificate) => {
        if (cancelled) return;
        if (certificate.id !== targetCertificateID) {
          throw new Error(linkedMismatchCopy);
        }
        setLinkedCertificate(certificate);
      })
      .catch((error) => {
        if (!cancelled) setLinkedError(apiProblemContext(error, linkedFailedCopy));
      })
      .finally(() => {
        if (!cancelled) setLinkedLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [linkedFailedCopy, linkedMismatchCopy, targetCertificateID]);

  const eligibleIdentities = useMemo(
    () =>
      identities
        .filter((identity) => identity.kind === "x509_certificate" && revocableIdentityStates.has(identity.status))
        .sort((left, right) => left.name.localeCompare(right.name)),
    [identities],
  );
  const certificateRecords = useMemo(() => {
    const records = new Map(certificates.map((certificate) => [certificate.id, certificate]));
    if (linkedCertificate) records.set(linkedCertificate.id, linkedCertificate);
    return Array.from(records.values()).sort((left, right) => certificateTargetName(left).localeCompare(certificateTargetName(right)));
  }, [certificates, linkedCertificate]);
  const targets = useMemo<RevocationTarget[]>(
    () => [
      ...eligibleIdentities.map((identity) => ({ identity, key: identity.id, kind: "identity" as const, name: identity.name })),
      ...certificateRecords.map((certificate) => ({
        certificate,
        key: certificateTargetKey(certificate.id),
        kind: "certificate" as const,
        name: certificateTargetName(certificate),
      })),
    ],
    [certificateRecords, eligibleIdentities],
  );
  const selected = targets.find((target) => target.key === targetKey) ?? null;
  const selectedCanReview = selected?.kind === "identity" || (selected?.kind === "certificate" && revocableCertificateStates.has(selected.certificate.status));
  const currentKey = reviewKey(targetKey, reason);
  const reviewCurrent = review?.key === currentKey;
  const reviewReady = reviewCurrent && (review.kind === "certificate" || review.plan.ready);
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
        progressState: completed && !(completed.kind === "certificate" && completed.queued) ? "done" : "pending",
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
    if (!selected || !selectedCanReview) return;
    setReviewLoading(true);
    setReviewError(null);
    setExecuteError(null);
    setApprovalNotice(null);
    try {
      if (selected.kind === "identity") {
        const plan = await api.previewIdentityTransition(selected.identity.id, "revoked", reason);
        const nodeID = graphNodeIdForIdentity(selected.identity);
        const graph = nodeID ? await readImpact(nodeID, t) : { impact: null, impactError: t("certificates.revocation.graphBindingMissing") };
        setReview({ kind: "identity", key: currentKey, plan, ...graph });
      } else {
        const certificate = await api.getCertificate(selected.certificate.id);
        if (certificate.id !== selected.certificate.id) throw new Error(t("certificates.revocation.linkedMismatch"));
        if (!revocableCertificateStates.has(certificate.status)) throw new Error(t("certificates.revocation.alreadyRevoked"));
        const graph = await readImpact(`cert:${certificate.id}`, t);
        setLinkedCertificate(certificate);
        setReview({ kind: "certificate", key: currentKey, certificate, ...graph });
      }
      setStep(1);
    } catch (error) {
      setReview(null);
      setReviewError(apiProblemContext(error, t("certificates.revocation.previewFailed")));
    } finally {
      setReviewLoading(false);
    }
  }

  async function execute() {
    if (!selected || selected.name.length === 0 || !reviewCurrent || !reviewReady || confirmName.trim() !== selected.name) return;
    setExecuteLoading(true);
    setExecuteError(null);
    setApprovalNotice(null);
    try {
      if (selected.kind === "identity" && review.kind === "identity") {
        const closedRequestId = approvalRestart?.fingerprint === review.plan.request_fingerprint ? approvalRestart.requestId : undefined;
        const updated = await api.transitionIdentity(
          selected.identity.id,
          "revoked",
          reason,
          undefined,
          lifecycleCommandKey(review.plan, closedRequestId),
          review.plan.expected_version,
        );
        if (updated.status !== "revoked") throw new Error(t("certificates.revocation.verifyFailed"));
        setCompleted({ kind: "identity", identity: updated });
        onRevoked?.(updated);
      } else if (selected.kind === "certificate" && review.kind === "certificate") {
        const current = await api.getCertificate(selected.certificate.id);
        if (
          current.id !== review.certificate.id ||
          current.fingerprint !== review.certificate.fingerprint ||
          current.subject !== review.certificate.subject ||
          current.status !== review.certificate.status
        ) {
          throw new Error(t("certificates.revocation.reviewStale"));
        }
        const result = await api.bulkRevokeCertificates({ certificate_ids: [current.id], reason });
        const item = result.items.find((candidate) => candidate.id === current.id);
        if (item?.status === "queued") {
          setCompleted({ kind: "certificate", certificate: current, queued: true });
          return;
        }
        if (!item || (item.status !== "revoked" && !(item.status === "skipped" && item.error === "already revoked"))) {
          throw new Error(item?.error || t("certificates.revocation.certificateVerifyFailed"));
        }
        const verified = await api.getCertificate(current.id);
        if (verified.id !== current.id || verified.status !== "revoked") {
          throw new Error(t("certificates.revocation.certificateVerifyFailed"));
        }
        setLinkedCertificate(verified);
        setCompleted({ kind: "certificate", certificate: verified });
        onCertificateRevoked?.(verified);
      }
    } catch (error) {
      setApprovalNotice(lifecycleApproval(error));
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
        onPrevious={step > 0 && !executeLoading && !completed ? () => setStep((current) => Math.max(0, current - 1)) : undefined}
        onNext={
          step === 0
            ? () => void loadReview()
            : step === 1 && reviewReady
              ? () => {
                  setConfirmName("");
                  setStep(2);
                }
              : undefined
        }
        nextDisabled={(step === 0 && (!selectedCanReview || linkedLoading || reviewLoading)) || (step === 1 && !reviewReady)}
        nextLabel={
          step === 0
            ? reviewLoading || linkedLoading
              ? t("certificates.revocation.reviewLoading")
              : t("certificates.revocation.reviewAction")
            : t("certificates.revocation.continueAction")
        }
      >
        {step === 0 && (
          <div className="grid max-w-2xl gap-4">
            <Field label={t("certificates.revocation.identityLabel")} controlId="revocation-center-identity">
              {(control) => (
                <Select
                  {...control}
                  value={targetKey}
                  onChange={(event) => {
                    setTargetKey(event.target.value);
                    invalidateReview();
                  }}
                >
                  <option value="">{t("certificates.revocation.identityPlaceholder")}</option>
                  {linkedLoading && targetCertificateID ? (
                    <option value={certificateTargetKey(targetCertificateID)}>{t("certificates.revocation.linkedLoading")}</option>
                  ) : null}
                  {eligibleIdentities.length > 0 ? (
                    <optgroup label={t("certificates.revocation.lifecycleGroup")}>
                      {eligibleIdentities.map((identity) => (
                        <option key={identity.id} value={identity.id}>
                          {identity.name} · {identity.status}
                        </option>
                      ))}
                    </optgroup>
                  ) : null}
                  {certificateRecords.length > 0 ? (
                    <optgroup label={t("certificates.revocation.recordsGroup")}>
                      {certificateRecords.map((certificate) => (
                        <option key={certificate.id} value={certificateTargetKey(certificate.id)}>
                          {certificateTargetName(certificate)} · {certificate.status} · {t("certificates.revocation.recordOption")}
                        </option>
                      ))}
                    </optgroup>
                  ) : null}
                </Select>
              )}
            </Field>
            <Field label={t("certificates.revocation.reasonLabel")} description={t("certificates.revocation.reasonHelp")} controlId="revocation-center-reason">
              {(control) => (
                <Select
                  {...control}
                  value={reason}
                  onChange={(event) => {
                    setReason(event.target.value as BulkRevokeRequest["reason"]);
                    invalidateReview();
                  }}
                >
                  {revocationReasons.map((item) => (
                    <option key={item} value={item}>
                      {item}
                    </option>
                  ))}
                </Select>
              )}
            </Field>
            {!linkedLoading && targets.length === 0 && !linkedError ? (
              <p className="rounded-control border border-border bg-muted/30 p-3 text-sm text-muted-foreground">{t("certificates.revocation.empty")}</p>
            ) : null}
            {selected?.kind === "certificate" && selected.certificate.status === "revoked" ? (
              <p className="rounded-control border border-border bg-muted/30 p-3 text-sm text-muted-foreground">
                {t("certificates.revocation.alreadyRevoked")}
              </p>
            ) : null}
            {linkedError ? (
              <p role="alert" className="rounded-control border border-destructive/30 bg-destructive/5 p-3 text-sm text-destructive">
                {linkedError}
              </p>
            ) : null}
            {reviewError ? (
              <p role="alert" className="rounded-control border border-destructive/30 bg-destructive/5 p-3 text-sm text-destructive">
                {reviewError}
              </p>
            ) : null}
          </div>
        )}

        {step === 1 && reviewReady && review ? (
          <div className="grid gap-4 text-sm">
            <div className="rounded-control border border-status-success/30 bg-status-success/5 p-3">
              <p className="font-semibold text-status-success">{t("certificates.revocation.noChanges")}</p>
              <p className="mt-1 text-muted-foreground">
                {review.kind === "identity" ? review.plan.guidance : t("certificates.revocation.certificateReviewGuidance")}
              </p>
            </div>
            {review.kind === "identity" ? (
              <dl className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
                <Fact label={t("certificates.revocation.owner")}>{review.plan.owner_name || review.plan.owner_id}</Fact>
                <Fact label={t("certificates.revocation.reasonLabel")} mono>
                  {reason}
                </Fact>
                <Fact label={t("certificates.revocation.version")} mono>
                  {String(review.plan.expected_version)}
                </Fact>
                <Fact label={t("certificates.revocation.effect")} mono>
                  {review.plan.side_effect_destination || t("certificates.revocation.noExternalEffect")}
                </Fact>
              </dl>
            ) : (
              <>
                <p className="font-semibold">{t("certificates.revocation.recordTitle")}</p>
                <dl className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
                  <Fact label={t("certificates.revocation.recordID")} mono>
                    {review.certificate.id}
                  </Fact>
                  <Fact label={t("certificates.revocation.recordState")} mono>
                    {review.certificate.status}
                  </Fact>
                  <Fact label={t("certificates.revocation.reasonLabel")} mono>
                    {reason}
                  </Fact>
                  <Fact label={t("certificates.revocation.effect")} mono>
                    {t("certificates.revocation.certificateEffect")}
                  </Fact>
                </dl>
              </>
            )}
            <div className="rounded-control border border-border p-3">
              <h3 className="font-semibold">{t("certificates.revocation.impactTitle")}</h3>
              <p className="mt-1 text-muted-foreground">{affectedCopy(review.impact, review.impactError, t)}</p>
              {review.impact && review.impact.affected.length > 0 ? (
                <ul className="mt-2 flex flex-wrap gap-2 text-xs">
                  {review.impact.affected.map((node) => (
                    <li key={node.id} className="rounded-control border border-border px-2 py-1">
                      <span className="font-medium">{node.name || node.id}</span>
                      <span className="ml-2 text-muted-foreground">{graphNodeKindLabel(node.kind)}</span>
                    </li>
                  ))}
                </ul>
              ) : null}
            </div>
            <div className="grid gap-4 lg:grid-cols-3">
              {review.kind === "identity" ? (
                <>
                  <PlanList title={t("certificates.revocation.prerequisites")} items={review.plan.prerequisites} />
                  <PlanList title={t("certificates.revocation.writes")} items={[...review.plan.execution_writes, ...review.plan.execution_external_effects]} />
                  <PlanList title={t("certificates.revocation.proof")} items={review.plan.verification_steps} />
                </>
              ) : (
                <>
                  <PlanList
                    title={t("certificates.revocation.prerequisites")}
                    items={[t("certificates.revocation.certificateBefore", { status: review.certificate.status })]}
                  />
                  <PlanList
                    title={t("certificates.revocation.writes")}
                    items={[t("certificates.revocation.certificateWrite", { id: review.certificate.id }), t("certificates.revocation.certificatePublish")]}
                  />
                  <PlanList
                    title={t("certificates.revocation.proof")}
                    items={[t("certificates.revocation.certificateProof", { id: review.certificate.id }), t("certificates.revocation.certificateAudit")]}
                  />
                </>
              )}
            </div>
            <div>
              <p className="text-xs text-muted-foreground">
                {review.kind === "identity" ? t("certificates.revocation.fingerprint") : t("certificates.revocation.certificateFingerprint")}
              </p>
              <code className="mt-1 block break-all rounded-control bg-muted px-2 py-1 text-xs">
                {review.kind === "identity" ? review.plan.request_fingerprint : review.certificate.fingerprint}
              </code>
            </div>
          </div>
        ) : null}

        {step === 2 && completed ? (
          <div role="region" aria-label={t("certificates.revocation.confirmRegion")} className="grid max-w-2xl gap-4">
            <p className="font-medium break-all">{completed.kind === "identity" ? completed.identity.name : certificateTargetName(completed.certificate)}</p>
            <div className="rounded-control border border-border bg-muted/30 p-3 text-sm">
              {completed.kind === "certificate" && completed.queued ? (
                <QueuedCertificateRevocation
                  certificate={completed.certificate}
                  onConfirmed={(certificate) => {
                    setLinkedCertificate(certificate);
                    setCompleted({ kind: "certificate", certificate });
                    onCertificateRevoked?.(certificate);
                  }}
                />
              ) : (
                <p role="status" className="font-semibold text-status-success">
                  {t(completed.kind === "identity" ? "certificates.revocation.accepted" : "certificates.revocation.certificateAccepted")}
                </p>
              )}
              <div className="mt-2 flex flex-wrap gap-3">
                <Link
                  className="text-primary underline"
                  to={
                    completed.kind === "identity"
                      ? `/audit?type=${encodeURIComponent("identity.revoked")}&q=${encodeURIComponent(completed.identity.id)}`
                      : `/audit?type=certificate.revocation.batch.applied&q=${encodeURIComponent(completed.certificate.id)}`
                  }
                >
                  {t("certificates.revocation.auditLink")}
                </Link>
                {completed.kind === "identity" && graphNodeIdForIdentity(completed.identity) ? (
                  <Link className="text-primary underline" to={`/graph?node=${encodeURIComponent(graphNodeIdForIdentity(completed.identity) ?? "")}`}>
                    {t("certificates.revocation.graphLink")}
                  </Link>
                ) : null}
                {completed.kind === "certificate" ? (
                  <Link className="text-primary underline" to={`/graph?node=${encodeURIComponent(`cert:${completed.certificate.id}`)}`}>
                    {t("certificates.revocation.graphLink")}
                  </Link>
                ) : null}
              </div>
            </div>

            <Button
              type="button"
              variant="outline"
              onClick={() => {
                setTargetKey("");
                invalidateReview();
                setApprovalNotice(null);
                setApprovalRestart(null);
                setStep(0);
              }}
            >
              {t("certificates.revocation.configureTitle")}
            </Button>
          </div>
        ) : null}

        {step === 2 && !completed && selected && reviewReady && review ? (
          <div role="region" aria-label={t("certificates.revocation.confirmRegion")} className="grid max-w-2xl gap-4">
            <div className="rounded-control border border-destructive/30 bg-destructive/5 p-3 text-sm text-destructive">
              <p className="font-semibold">{t("certificates.revocation.irreversibleTitle")}</p>
              <p className="mt-1">{t("certificates.revocation.irreversibleBody", { identity: selected.name, reason })}</p>
            </div>
            <Field label={t("certificates.revocation.confirmName")} controlId="revocation-center-confirm-name">
              {(control) => <Input {...control} value={confirmName} onChange={(event) => setConfirmName(event.target.value)} placeholder={selected.name} />}
            </Field>
            {executeError ? (
              <p role="alert" className="rounded-control border border-destructive/30 bg-destructive/5 p-3 text-sm text-destructive">
                {executeError}
              </p>
            ) : null}
            <LifecycleApprovalRecovery
              approval={approvalNotice}
              onReviewNew={(requestId) => {
                if (review.kind !== "identity") return;
                setApprovalRestart({ fingerprint: review.plan.request_fingerprint, requestId });
                setApprovalNotice(null);
                setExecuteError(null);
                void loadReview();
              }}
            />
            <Button
              type="button"
              variant="destructive"
              loading={executeLoading}
              disabled={selected.name.length === 0 || confirmName.trim() !== selected.name || executeLoading}
              onClick={() => void execute()}
            >
              {t("certificates.revocation.executeAction")}
            </Button>
          </div>
        ) : null}
      </StepShell>
    </section>
  );
}

function Fact({ children, label, mono = false }: { children: string; label: string; mono?: boolean }) {
  return (
    <div>
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd className={mono ? "break-all font-mono text-xs" : "font-medium"}>{children}</dd>
    </div>
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
