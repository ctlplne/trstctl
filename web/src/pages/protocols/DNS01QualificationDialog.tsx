import { useEffect, useRef, useState, type FormEvent } from "react";
import { CheckCircle2, ShieldCheck, TriangleAlert, X } from "lucide-react";
import { Dialog } from "@/components/Dialog";
import { ErrorState, LoadingState } from "@/components/StatePrimitives";
import { Button } from "@/components/ui/button";
import { useTranslation } from "@/i18n/I18nProvider";
import {
  api,
  ApiError,
  type ACMEDNS01ProviderCatalogItem,
  type ACMEDNS01ProviderConfig,
  type ACMEDNS01QualificationPreview,
  type ACMEDNS01QualificationRun,
} from "@/lib/api";
import { DNS01DelegationIsolationPanel } from "@/pages/protocols/DNS01DelegationIsolationPanel";
import { DNS01ProviderTrustPanel } from "@/pages/protocols/DNS01ProviderTrustPanel";

function qualificationError(err: unknown): string {
  if (err instanceof ApiError) return err.body || err.message;
  if (err instanceof Error) return err.message;
  return "The provider test could not be completed.";
}

function replaceRun(items: ACMEDNS01QualificationRun[], next: ACMEDNS01QualificationRun) {
  return [next, ...items.filter((item) => item.id !== next.id)];
}

/** A real provider test, deliberately separate from the evidence-only preflight.
 * The server generates and retains the TXT probe and recovery payload. */
export function DNS01QualificationDialog({
  config,
  provider,
  onClose,
}: {
  config: ACMEDNS01ProviderConfig;
  provider?: ACMEDNS01ProviderCatalogItem;
  onClose: () => void;
}) {
  const { t } = useTranslation();
  const [domain, setDomain] = useState("");
  const [preview, setPreview] = useState<ACMEDNS01QualificationPreview | null>(null);
  const [run, setRun] = useState<ACMEDNS01QualificationRun | null>(null);
  const [history, setHistory] = useState<ACMEDNS01QualificationRun[]>([]);
  const [historyLoading, setHistoryLoading] = useState(true);
  const [busy, setBusy] = useState<"review" | "run" | "cleanup" | null>(null);
  const [error, setError] = useState<string | null>(null);
  const domainRef = useRef<HTMLInputElement>(null);
  const titleId = "dns01-qualification-heading";

  useEffect(() => {
    let active = true;
    setHistoryLoading(true);
    api
      .acmeDNS01QualificationRuns(config.id)
      .then((result) => {
        if (active) setHistory(result.items ?? []);
      })
      .catch((cause: unknown) => {
        if (active) setError(qualificationError(cause));
      })
      .finally(() => {
        if (active) setHistoryLoading(false);
      });
    return () => {
      active = false;
    };
  }, [config.id]);

  async function review(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy("review");
    setError(null);
    setRun(null);
    try {
      setPreview(await api.previewACMEDNS01Qualification(config.id, { domain: domain.trim() }));
    } catch (cause) {
      setPreview(null);
      setError(qualificationError(cause));
    } finally {
      setBusy(null);
    }
  }

  async function execute() {
    if (!preview?.ready) return;
    setBusy("run");
    setError(null);
    try {
      const result = await api.runACMEDNS01Qualification(config.id, { domain: preview.domain });
      setRun(result);
      setHistory((current) => replaceRun(current, result));
    } catch (cause) {
      setError(qualificationError(cause));
    } finally {
      setBusy(null);
    }
  }

  async function retryCleanup() {
    if (!run) return;
    setBusy("cleanup");
    setError(null);
    try {
      const result = await api.retryACMEDNS01QualificationCleanup(run.id);
      setRun(result);
      setHistory((current) => replaceRun(current, result));
    } catch (cause) {
      setError(qualificationError(cause));
    } finally {
      setBusy(null);
    }
  }

  const priorHistory = history.filter((item) => item.id !== run?.id);

  return (
    <Dialog
      open
      onClose={onClose}
      titleId={titleId}
      initialFocusRef={domainRef}
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      overlayClassName="absolute inset-0 bg-black/55"
      panelClassName="relative max-h-[calc(100vh-2rem)] w-full max-w-3xl overflow-y-auto rounded-panel border border-border bg-card shadow-elevation2"
    >
      <header className="flex items-start justify-between gap-3 border-b border-border px-5 py-4">
        <div className="min-w-0">
          <h2 id={titleId} className="text-title font-semibold">
            {t("protocols.dns01.qualification.title", { name: config.name })}
          </h2>
          <p className="mt-1 max-w-2xl text-sm text-muted-foreground">{t("protocols.dns01.qualification.intro")}</p>
        </div>
        <Button type="button" variant="ghost" size="icon" onClick={onClose} aria-label={t("protocols.dns01.qualification.close")}>
          <X className="h-4 w-4" aria-hidden="true" />
        </Button>
      </header>

      <div className="grid gap-5 p-5">
        {error && <ErrorState title={t("protocols.dns01.qualification.errorTitle")}>{error}</ErrorState>}

        <DNS01ProviderTrustPanel provider={provider} />

        <form className="grid gap-3" onSubmit={(event) => void review(event)}>
          <label className="grid gap-1 text-body font-medium">
            {t("protocols.dns01.qualification.domain")}
            <input
              ref={domainRef}
              required
              value={domain}
              onChange={(event) => {
                setDomain(event.target.value);
                setPreview(null);
                setRun(null);
              }}
              placeholder={t("protocols.dns01.qualification.domainPlaceholder")}
              className="min-h-9 rounded-control border border-border bg-background px-3 py-2 text-body"
            />
          </label>
          <div>
            <Button type="submit" variant="outline" loading={busy === "review"} disabled={busy !== null || domain.trim() === ""}>
              {t("protocols.dns01.qualification.reviewAction")}
            </Button>
          </div>
        </form>

        {preview && (
          <section aria-label={t("protocols.dns01.qualification.planLabel")} className="grid gap-4 rounded-control border border-border bg-muted/20 p-4">
            <div className="flex items-start gap-3">
              {preview.ready ? (
                <ShieldCheck className="mt-0.5 h-5 w-5 shrink-0 text-status-success" aria-hidden="true" />
              ) : (
                <TriangleAlert className="mt-0.5 h-5 w-5 shrink-0 text-status-warning" aria-hidden="true" />
              )}
              <div>
                <h3 className="font-semibold">{preview.ready ? t("protocols.dns01.qualification.ready") : t("protocols.dns01.qualification.blocked")}</h3>
                <p className="mt-1 text-sm text-muted-foreground">{t("protocols.dns01.qualification.effectFree")}</p>
                <p className="mt-1 break-all font-mono text-xs text-muted-foreground">{preview.record_name}</p>
              </div>
            </div>

            <div className="grid gap-3 sm:grid-cols-2">
              <PlanList
                title={t("protocols.dns01.qualification.outsideEffects")}
                items={preview.execute_external_effects}
                empty={t("protocols.dns01.qualification.none")}
              />
              <PlanList
                title={t("protocols.dns01.qualification.serverEvidence")}
                items={preview.execute_writes}
                empty={t("protocols.dns01.qualification.none")}
              />
              <PlanList
                title={t("protocols.dns01.qualification.referenceFields")}
                items={preview.credential_reference_fields}
                empty={t("protocols.dns01.qualification.noReferenceFields")}
                mono
              />
              <PlanList
                title={t("protocols.dns01.qualification.leastPrivilege")}
                items={preview.least_privilege_checklist}
                empty={t("protocols.dns01.qualification.none")}
              />
            </div>

            {preview.checks.some((check) => !check.passed) && (
              <ul className="grid gap-2">
                {preview.checks
                  .filter((check) => !check.passed)
                  .map((check) => (
                    <li key={check.id} className="rounded-control border border-status-warning/30 bg-status-warning/10 p-3 text-sm">
                      <span className="font-semibold">{check.label}</span>
                      <span className="mt-1 block text-muted-foreground">{check.recovery}</span>
                    </li>
                  ))}
              </ul>
            )}
            <p className="text-caption text-muted-foreground">{preview.secret_data_handling}</p>
            <DNS01DelegationIsolationPanel config={config} recordName={preview.record_name} run={run} />
            <div>
              <Button type="button" loading={busy === "run"} disabled={!preview.ready || busy !== null} onClick={() => void execute()}>
                {t("protocols.dns01.qualification.executeAction")}
              </Button>
            </div>
          </section>
        )}

        {run && (
          <section
            aria-label={t("protocols.dns01.qualification.resultLabel")}
            className={`grid gap-3 rounded-control border p-4 ${run.status === "passed" ? "border-status-success/30 bg-status-success/10" : "border-status-warning/30 bg-status-warning/10"}`}
          >
            <div className="flex items-start gap-3">
              {run.status === "passed" ? (
                <CheckCircle2 className="mt-0.5 h-5 w-5 shrink-0 text-status-success" aria-hidden="true" />
              ) : (
                <TriangleAlert className="mt-0.5 h-5 w-5 shrink-0 text-status-warning" aria-hidden="true" />
              )}
              <div>
                <h3 className="font-semibold">
                  {run.status === "passed"
                    ? t("protocols.dns01.qualification.passed")
                    : run.status === "recovery_required"
                      ? t("protocols.dns01.qualification.cleanupAttention")
                      : t("protocols.dns01.qualification.failed")}
                </h3>
                <p className="mt-1 text-sm text-muted-foreground">
                  {t("protocols.dns01.qualification.resultSummary", {
                    propagation: run.propagation_status,
                    cleanup: run.cleanup_status,
                    attempts: run.attempts,
                  })}
                </p>
                {run.error_category && <p className="mt-1 font-mono text-xs">{run.error_category}</p>}
              </div>
            </div>
            <PlanList title={t("protocols.dns01.qualification.recovery")} items={run.recovery_steps} empty={t("protocols.dns01.qualification.none")} />
            <p className="text-caption text-muted-foreground">{run.secret_data_handling}</p>
            {run.cleanup_status === "failed" && (
              <div>
                <Button type="button" variant="outline" loading={busy === "cleanup"} disabled={busy !== null} onClick={() => void retryCleanup()}>
                  {t("protocols.dns01.qualification.retryCleanup")}
                </Button>
              </div>
            )}
          </section>
        )}

        <section aria-labelledby="dns01-qualification-history-heading" className="border-t border-border pt-4">
          <h3 id="dns01-qualification-history-heading" className="font-semibold">
            {t("protocols.dns01.qualification.history")}
          </h3>
          {historyLoading && <LoadingState>{t("protocols.dns01.qualification.historyLoading")}</LoadingState>}
          {!historyLoading && priorHistory.length === 0 && (
            <p className="mt-2 text-sm text-muted-foreground">{t("protocols.dns01.qualification.historyEmpty")}</p>
          )}
          {priorHistory.length > 0 && (
            <ul className="mt-3 grid gap-2">
              {priorHistory.map((item) => (
                <li key={item.id} className="grid gap-1 rounded-control border border-border px-3 py-2 text-sm sm:grid-cols-[minmax(0,1fr)_auto]">
                  <span>
                    <span className="font-medium">{item.domain}</span>
                    <span className="mt-0.5 block text-caption text-muted-foreground">
                      {t("protocols.dns01.qualification.historySummary", { propagation: item.propagation_status, cleanup: item.cleanup_status })}
                    </span>
                  </span>
                  <span className="font-medium">{item.status}</span>
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>
    </Dialog>
  );
}

function PlanList({ title, items, empty, mono = false }: { title: string; items: string[]; empty: string; mono?: boolean }) {
  return (
    <div>
      <h4 className="text-sm font-semibold">{title}</h4>
      {items.length === 0 ? (
        <p className="mt-1 text-sm text-muted-foreground">{empty}</p>
      ) : (
        <ul className={`mt-1 list-disc space-y-1 ps-5 text-sm text-muted-foreground ${mono ? "font-mono text-xs" : ""}`}>
          {items.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
      )}
    </div>
  );
}
