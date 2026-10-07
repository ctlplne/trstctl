import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { ArrowUpRight, Check, Copy, RefreshCw } from "lucide-react";
import { PageHeader } from "@/components/PageHeader";
import { capabilityExecutionReason } from "@/components/CapabilityTruth";
import { ErrorState, UnavailableState } from "@/components/StatePrimitives";
import { StatusBadge } from "@/components/StatusBadge";
import { Button, buttonVariants } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { StepShell, type CarouselStep } from "@/components/wizard/StepShell";
import { api } from "@/lib/api";
import type { Certificate, IdentityIssuanceResult, IssuanceRequest } from "@/lib/api-types.gen";
import { useApiQuery } from "@/lib/query";
import { hasJourneyMark, readJourneyMarks, toggleJourneyMark } from "@/lib/journeyProgress";
import { journeyCensus } from "@/lib/journeyCensus.gen";
import { journeyById, journeyDocUrl, journeys, type Journey, type JourneyDetector, type JourneyStep } from "@/lib/journeys";
import { resolveCapabilityAction, useCapabilities } from "@/lib/capabilities";
import type { CanonicalCapabilityID } from "@/lib/feature-contracts.gen";
import { translateNow, useTranslation } from "@/i18n/I18nProvider";
import { cn } from "@/lib/utils";

interface DetectorDefinition {
  capabilityId: CanonicalCapabilityID;
  operationId: string;
  run: () => Promise<boolean>;
}

/** Each detector names the exact server operation that answers “has the tenant
 * already done this?”. The capability projection is checked before the read, so
 * an unavailable feed becomes a visible blocked step instead of a hidden 404 or
 * a false ordinary “Pending”. */
const detectorDefinitions: Record<JourneyDetector, DetectorDefinition> = {
  issuers: { capabilityId: "F4", operationId: "listIssuers", run: () => api.issuers().then((rows) => rows.length > 0) },
  requests: { capabilityId: "F59", operationId: "listIdentities", run: () => api.identities().then((rows) => rows.length > 0) },
  certificates: {
    capabilityId: "F1",
    operationId: "listCertificates",
    run: () => api.certificatePage({ limit: 1 }).then((page) => (page.items ?? []).length > 0),
  },
  sources: {
    capabilityId: "F2",
    operationId: "listDiscoverySources",
    run: () => api.discoverySources({ limit: 1 }).then((page) => (page.items ?? []).length > 0),
  },
  runs: {
    capabilityId: "F2",
    operationId: "listDiscoveryRuns",
    run: () => api.discoveryRuns({ limit: 1 }).then((page) => (page.items ?? []).length > 0),
  },
  findings: {
    capabilityId: "F2",
    operationId: "listDiscoveryFindings",
    run: () => api.discoveryFindings({ limit: 1 }).then((page) => (page.items ?? []).length > 0),
  },
  profiles: { capabilityId: "F53", operationId: "listProfiles", run: () => api.profiles().then((rows) => rows.length > 0) },
  incidents: {
    capabilityId: "F31",
    operationId: "listIncidentExecutions",
    run: () => api.incidentExecutions({ limit: 1 }).then((page) => (page.items ?? []).length > 0),
  },
  agents: { capabilityId: "F3", operationId: "listAgents", run: () => api.agents().then((rows) => rows.length > 0) },
  secrets: {
    capabilityId: "F63",
    operationId: "listSecrets",
    run: () => api.secretPage({ limit: 1 }).then((page) => (page.items ?? []).length > 0),
  },
  members: { capabilityId: "F8", operationId: "listMembers", run: () => api.members({ limit: 1 }).then((page) => (page.items ?? []).length > 0) },
  audit: { capabilityId: "F9", operationId: "searchAudit", run: () => api.auditEvents({ limit: 1 }).then((rows) => rows.length > 0) },
};

type DetectorResult = { state: "done" | "pending" | "blocked" | "error"; reason?: string };
type DetectorState = Partial<Record<JourneyDetector, DetectorResult>>;
type ExactProof = { request: IssuanceRequest | null; result: IdentityIssuanceResult | null; certificate: Certificate | null; inventoryError: boolean };
const emptyExactProof: ExactProof = { request: null, result: null, certificate: null, inventoryError: false };
const requestIDPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function independentDecision(request: IssuanceRequest | null): boolean {
  return Boolean(
    request &&
    (request.status === "approved" || request.status === "issued") &&
    request.decided_at &&
    request.decided_by &&
    request.decided_by !== request.requester,
  );
}

function exactStepDone(step: JourneyStep, proof: ExactProof): boolean {
  if (step.id === "request") return Boolean(proof.request);
  if (step.id === "approve") return independentDecision(proof.request);
  if (step.id === "inventory") {
    return Boolean(
      independentDecision(proof.request) &&
      proof.request?.status === "issued" &&
      proof.request.identity_id &&
      proof.result?.state === "issued" &&
      proof.result.identity_id === proof.request.identity_id &&
      proof.result.request_key === `issuance-request-issue:${proof.request.id}` &&
      proof.result.certificate?.id &&
      proof.certificate?.id === proof.result.certificate.id &&
      proof.certificate.identity_ids?.includes(proof.request.identity_id),
    );
  }
  return false;
}

/** The checklist separates exact first-certificate evidence, broad tenant
 * signals, and browser-local review marks. None of those is a substitute for
 * external endpoint verification. */
function stepDone(journey: Journey, step: JourneyStep, detected: DetectorState, marks: Set<string>, proof: ExactProof): boolean {
  if (journey.id === "first-certificate" && step.id !== "wizard") return exactStepDone(step, proof);
  if (step.detect) return detected[step.detect]?.state === "done";
  return hasJourneyMark(marks, journey.id, step.id);
}

function journeyProgress(journey: Journey, detected: DetectorState, marks: Set<string>, proof: ExactProof): { done: number; total: number } {
  const done = journey.steps.filter((step) => stepDone(journey, step, detected, marks, proof)).length;
  return { done, total: journey.steps.length };
}

export function Journeys() {
  const { t, formatMessage } = useTranslation();
  const capabilities = useCapabilities();
  const [searchParams, setSearchParams] = useSearchParams();
  const active = journeyById(searchParams.get("j"));
  const requestID = searchParams.get("request") ?? "";
  const [requestDraft, setRequestDraft] = useState(requestID);
  const exactQuery = useApiQuery(
    ["journeys", "issuance-request", requestID],
    async (): Promise<ExactProof> => {
      const request = await api.issuanceRequest(requestID);
      if (request.status !== "issued" || !request.identity_id) return { ...emptyExactProof, request };
      try {
        const result = await api.identityIssuanceResult(request.identity_id, `issuance-request-issue:${requestID}`);
        const certificate = result.state === "issued" && result.certificate?.id ? await api.getCertificate(result.certificate.id) : null;
        return { request, result, certificate, inventoryError: false };
      } catch {
        return { ...emptyExactProof, request, inventoryError: true };
      }
    },
    { enabled: requestIDPattern.test(requestID) },
  );
  const exactProof = exactQuery.data ?? emptyExactProof;
  const [detected, setDetected] = useState<DetectorState>({});
  const [marks, setMarks] = useState<Set<string>>(() => readJourneyMarks());
  const [checking, setChecking] = useState(false);
  const [step, setStep] = useState(0);
  const navigation = useRef({ journeyId: active.id, manual: false });

  const refreshStatus = useCallback(async () => {
    if (capabilities.enabled && capabilities.loading) return;
    setChecking(true);
    const ids = Array.from(new Set(journeys.flatMap((journey) => journey.steps.flatMap((s) => (s.detect ? [s.detect] : [])))));
    const next: DetectorState = {};
    const runnable: JourneyDetector[] = [];
    for (const id of ids) {
      const definition = detectorDefinitions[id];
      if (!capabilities.enabled) {
        runnable.push(id);
        continue;
      }
      const action = resolveCapabilityAction(capabilities.view, definition.capabilityId, definition.operationId);
      if (action.state === "allowed" || action.state === "scoped") {
        runnable.push(id);
      } else {
        next[id] = {
          state: "blocked",
          reason: capabilityExecutionReason({ ...action, enforced: true, checking: false, runnable: false }, translateNow),
        };
      }
    }
    const results = await Promise.allSettled(runnable.map((id) => detectorDefinitions[id].run()));
    runnable.forEach((id, index) => {
      const result = results[index];
      next[id] =
        result.status === "fulfilled"
          ? { state: result.value ? "done" : "pending" }
          : { state: "error", reason: translateNow("journeys.detector.checkFailed") };
    });
    setDetected(next);
    setChecking(false);
  }, [capabilities.enabled, capabilities.loading, capabilities.view]);

  useEffect(() => {
    void refreshStatus();
  }, [refreshStatus]);

  useEffect(() => setRequestDraft(requestID), [requestID]);

  // Initial detection can choose the first incomplete step. Once the operator
  // interacts, refreshed evidence updates progress without moving their place.
  useEffect(() => {
    if (navigation.current.journeyId !== active.id) {
      navigation.current = { journeyId: active.id, manual: false };
    }
    if (navigation.current.manual) return;
    const firstOpen = active.steps.findIndex((s) => !stepDone(active, s, detected, marks, exactProof));
    setStep(firstOpen === -1 ? 0 : firstOpen);
    // Manual marks intentionally omitted: toggling a step should not yank the
    // operator to a different step mid-read.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [active, detected, exactProof]);

  function selectStep(index: number) {
    navigation.current = { journeyId: active.id, manual: true };
    setStep(Math.max(0, Math.min(index, active.steps.length - 1)));
  }

  function selectJourney(id: string) {
    setSearchParams(
      (current) => {
        const next = new URLSearchParams(current);
        next.set("j", id);
        return next;
      },
      { replace: true },
    );
  }

  const shellSteps: CarouselStep[] = useMemo(
    () =>
      active.steps.map((s) => {
        const detector = s.detect ? detected[s.detect] : undefined;
        return {
          id: s.id,
          label: t(s.titleKey),
          description: t(s.bodyKey),
          progressState: stepDone(active, s, detected, marks, exactProof)
            ? "done"
            : detector?.state === "blocked" || detector?.state === "error"
              ? "blocked"
              : "pending",
        };
      }),
    [active, detected, marks, exactProof, t],
  );
  const current = active.steps[step];
  const currentDone = current ? stepDone(active, current, detected, marks, exactProof) : false;
  const exactError = active.id === "first-certificate" && Boolean(exactQuery.error || (current?.id === "inventory" && exactProof.inventoryError));
  const currentDetector = current?.detect
    ? detected[current.detect]
    : exactError && current?.id !== "wizard"
      ? { state: "error" as const, reason: t("journeys.detector.checkFailed") }
      : undefined;
  // Keep the active path visible for deep links, then add only two nearby
  // recommendations. The remaining valid paths stay one disclosure away.
  const recommendedJourneys = [active, ...journeys.filter((journey) => journey.id !== active.id).slice(0, 2)];
  const otherJourneys = journeys.filter((journey) => !recommendedJourneys.some((recommended) => recommended.id === journey.id));

  function renderJourneyChoice(journey: Journey) {
    const progress = journeyProgress(journey, detected, marks, exactProof);
    const selected = journey.id === active.id;
    return (
      <button
        key={journey.id}
        type="button"
        aria-pressed={selected}
        onClick={() => selectJourney(journey.id)}
        className={cn(
          "grid w-full gap-1 border-s-2 px-3 py-3 text-start transition-colors duration-fast",
          selected ? "border-primary bg-primary/10" : "border-transparent hover:bg-muted/60",
        )}
      >
        <span className="text-body font-semibold">{t(journey.titleKey)}</span>
        <span className="text-caption leading-snug text-muted-foreground">{t(journey.descriptionKey)}</span>
        <span className="text-caption font-medium tabular-nums text-brand-accent">
          {formatMessage("journeys.progress", { done: progress.done, total: progress.total })}
        </span>
      </button>
    );
  }

  return (
    <section aria-labelledby="journeys-heading" className="grid gap-6">
      <PageHeader
        titleId="journeys-heading"
        title={t("nav.item.journeys")}
        eyebrow={t("journeys.eyebrow")}
        description={t("journeys.description")}
        technicalDetails={t("journeys.technicalDetails")}
        actions={
          <>
            <Button type="button" onClick={() => document.getElementById("journey-workspace")?.focus()}>
              {t("journeys.continue")}
            </Button>
            <Button
              type="button"
              variant="outline"
              loading={checking}
              onClick={() => {
                selectStep(step);
                void refreshStatus();
                if (requestIDPattern.test(requestID)) exactQuery.refetch();
              }}
            >
              <RefreshCw className="h-4 w-4" aria-hidden="true" />
              {t("journeys.refresh")}
            </Button>
          </>
        }
      />

      <div className="grid gap-6 lg:grid-cols-[minmax(15rem,19rem)_minmax(0,1fr)]">
        <nav aria-label={t("journeys.listLabel")} className="min-w-0 border-y border-border lg:border-e lg:border-y-0 lg:pe-5">
          <p className="px-3 pb-2 pt-3 text-caption font-semibold text-muted-foreground">{t("journeys.startHere")}</p>
          <div className="divide-y divide-border">{recommendedJourneys.map(renderJourneyChoice)}</div>
          <details className="group border-t border-border">
            <summary className="cursor-pointer list-none px-3 py-3 text-caption font-medium text-muted-foreground marker:hidden hover:text-foreground">
              {formatMessage("journeys.morePaths", { count: otherJourneys.length })}
            </summary>
            <div className="divide-y divide-border border-t border-border">{otherJourneys.map(renderJourneyChoice)}</div>
          </details>
        </nav>

        <div
          id="journey-workspace"
          tabIndex={-1}
          className="grid min-w-0 content-start gap-4 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus"
        >
          {active.id === "first-certificate" && (
            <form
              className="grid max-w-2xl gap-2 rounded-panel border border-border p-4"
              onSubmit={(event) => {
                event.preventDefault();
                if (!requestIDPattern.test(requestDraft.trim())) return;
                setSearchParams((current) => {
                  const next = new URLSearchParams(current);
                  next.set("request", requestDraft.trim());
                  return next;
                });
              }}
            >
              <label htmlFor="journey-request-id" className="text-body font-medium">
                {t("journeys.fc.exactRequest.label")}
              </label>
              <p className="text-caption text-muted-foreground">{t("journeys.fc.exactRequest.help")}</p>
              <div className="flex flex-wrap gap-2">
                <Input
                  id="journey-request-id"
                  className="min-w-0 flex-1 font-mono"
                  value={requestDraft}
                  onChange={(event) => setRequestDraft(event.target.value)}
                  autoComplete="off"
                  spellCheck={false}
                />
                <Button type="submit" disabled={!requestIDPattern.test(requestDraft.trim())}>
                  {t("journeys.fc.exactRequest.check")}
                </Button>
              </div>
              {requestID && exactQuery.error && (
                <p role="alert" className="text-caption text-status-danger">
                  {t("journeys.fc.exactRequest.unavailable")}
                </p>
              )}
            </form>
          )}
          <StepShell
            steps={shellSteps}
            currentIndex={step}
            progressLabel={t("journeys.progressLabel")}
            nextDisabled={step >= active.steps.length - 1}
            onNext={step < active.steps.length - 1 ? () => selectStep(step + 1) : undefined}
            onPrevious={() => selectStep(step - 1)}
          >
            {current && (
              <div className="grid max-w-2xl gap-4">
                <div className="flex flex-wrap items-center gap-3">
                  {currentDone ? (
                    <StatusBadge value="issued" label={t("journeys.status.done")} tone="success" />
                  ) : currentDetector?.state === "blocked" ? (
                    <StatusBadge value="unavailable" label={t("journeys.status.unavailable")} tone="warning" />
                  ) : currentDetector?.state === "error" ? (
                    <StatusBadge value="error" label={t("journeys.status.checkFailed")} tone="warning" />
                  ) : (
                    <StatusBadge value="requested" label={t("journeys.status.pending")} tone="neutral" />
                  )}
                  <p className="text-body text-muted-foreground">{t(current.bodyKey)}</p>
                </div>
                {currentDone && (
                  <p className="text-caption text-muted-foreground">
                    {active.id === "first-certificate" && current.id !== "wizard"
                      ? t("journeys.evidence.exact")
                      : current.detect
                        ? t("journeys.evidence.tenantSignal")
                        : t("journeys.evidence.local")}
                  </p>
                )}
                {currentDetector?.state === "blocked" ? (
                  <UnavailableState title={t("journeys.detector.unavailableTitle")}>{currentDetector.reason}</UnavailableState>
                ) : currentDetector?.state === "error" ? (
                  <ErrorState title={t("journeys.detector.checkFailedTitle")}>{currentDetector.reason}</ErrorState>
                ) : null}
                {current.command && (
                  <div className="grid gap-2 rounded-panel border border-border bg-muted/40 p-3">
                    <pre className="overflow-x-auto whitespace-pre font-mono text-caption leading-relaxed">{current.command}</pre>
                    <div>
                      <CopyCommand value={current.command} />
                    </div>
                  </div>
                )}
                <div className="flex flex-wrap items-center gap-3">
                  {current.to && (
                    <>
                      <Link to={current.to} className={buttonVariants()}>
                        {t("journeys.open")}
                        <ArrowUpRight className="h-4 w-4" aria-hidden="true" />
                      </Link>
                      <span className="font-mono text-caption text-muted-foreground">{current.to}</span>
                    </>
                  )}
                  {!current.detect && (active.id !== "first-certificate" || current.id === "wizard") && (
                    <Button
                      type="button"
                      variant={currentDone ? "outline" : "secondary"}
                      aria-pressed={currentDone}
                      onClick={() => {
                        selectStep(step);
                        setMarks((currentMarks) => toggleJourneyMark(currentMarks, active.id, current.id));
                      }}
                    >
                      <Check className="h-4 w-4" aria-hidden="true" />
                      {currentDone ? t("journeys.undoDone") : t("journeys.markDone")}
                    </Button>
                  )}
                </div>
              </div>
            )}
          </StepShell>

          <details className="border-t border-border pt-3">
            <summary className="cursor-pointer text-sm font-medium text-muted-foreground hover:text-foreground">{t("journeys.testingDetails")}</summary>
            <div className="mt-3 grid gap-2 text-caption text-muted-foreground">
              <StatusBadge
                value={journeyCensus.journeys[active.id].status}
                tone="success"
                label={formatMessage("journeys.census.verified", {
                  passed: journeyCensus.summary.served,
                  total: journeyCensus.summary.total,
                })}
                data-journey-census={active.id}
              />
              <p>{t("journeys.testingSummary")}</p>
            </div>
          </details>

          <p className="text-caption text-muted-foreground">
            {t("journeys.doc")}:{" "}
            <a
              href={journeyDocUrl(active)}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1 font-mono text-brand-accent underline underline-offset-2 hover:text-foreground"
            >
              {journeyDocUrl(active)}
              <ArrowUpRight className="h-3 w-3" aria-hidden="true" />
            </a>
          </p>
        </div>
      </div>
    </section>
  );
}

/** CopyCommand puts a journey step's verbatim command on the clipboard with a
 * polite announcement — the console-less steps stay one click, not one
 * retype. */
function CopyCommand({ value }: { value: string }) {
  const { t } = useTranslation();
  const [copied, setCopied] = useState(false);

  async function copy() {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1600);
    } catch {
      // Clipboard unavailable: the command stays selectable above.
    }
  }

  return (
    <>
      <Button type="button" size="sm" variant="secondary" onClick={() => void copy()}>
        {copied ? <Check className="h-3.5 w-3.5 text-status-success" aria-hidden="true" /> : <Copy className="h-3.5 w-3.5" aria-hidden="true" />}
        {copied ? t("journeys.copied") : t("journeys.copy")}
      </Button>
      <span role="status" className="sr-only">
        {copied ? t("journeys.copied") : ""}
      </span>
    </>
  );
}
