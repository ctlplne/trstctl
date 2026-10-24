import { useEffect, useRef, useState } from "react";
import { Bell, FileWarning, Radar, ShieldAlert } from "lucide-react";
import { Link } from "react-router-dom";
import { EmptyState } from "@/components/EmptyState";
import { PageHeader } from "@/components/PageHeader";
import { AuthorityAgreementPanel } from "@/components/AuthorityAgreementPanel";
import { ADCSTemplatePanel } from "@/components/posture/ADCSTemplatePanel";
import { ADCSDatabasePanel } from "@/components/posture/ADCSDatabasePanel";
import { useTranslation, translateNow } from "@/i18n/I18nProvider";
import { PQCReadinessSummary } from "@/components/pqc";
import { PQCMigrationWorkflow } from "@/components/PQCMigrationWorkflow";
import { StatusBadge } from "@/components/StatusBadge";
import { ErrorState, LoadingState } from "@/components/StatePrimitives";
import { Button } from "@/components/ui/button";
import { Num } from "@/components/typography";
import {
  api,
  type CBOMAsset,
  type CBOMInventory,
  type CBOMMigrationProgress,
  type CBOMScan,
  type CryptoReadiness,
  type CTMonitoring,
  type DriftRemediation,
  type DriftRemediationFinding,
  type DiscoveryRun,
  type DiscoverySource,
} from "@/lib/api";
import { useApiQuery } from "@/lib/query";
import { PQCCampaigns } from "@/pages/posture/PQCCampaigns";
import { PQCPilots } from "@/pages/posture/PQCPilots";
import { DriftRecoveryWorkflow } from "@/pages/posture/DriftRecoveryWorkflow";
import { loadLatestDriftRuns } from "@/pages/posture/DriftLatestRuns";
import { CBOMScanWorkflow } from "@/pages/posture/CBOMScanWorkflow";
import { PCASSuccessionWorkflow } from "@/pages/posture/PCASSuccessionWorkflow";
import { CTFindingsDashboard, DriftFindingsDashboard, type DashboardTriage, type DriftDecision } from "@/pages/posture/PostureFindingDashboards";
import { Metric, PreviewTable } from "@/pages/posture/PostureParts";

const emptyCBOMProgress: CBOMMigrationProgress = {
  total_assets: 0,
  out_of_policy_assets: 0,
  quantum_vulnerable_assets: 0,
  post_quantum_ready_assets: 0,
  percent_migrated: 0,
};

export function Posture() {
  const { t } = useTranslation();
  const cryptoReadiness = useApiQuery(["crypto-readiness"], api.cryptoReadiness);
  const [discoverySources, setDiscoverySources] = useState<DiscoverySource[]>([]);
  const [driftLatestRuns, setDriftLatestRuns] = useState<Record<string, DiscoveryRun | null>>({});
  const [discoveryLoading, setDiscoveryLoading] = useState(true);
  const [discoveryError, setDiscoveryError] = useState<string | null>(null);
  const [ctMonitoring, setCTMonitoring] = useState<CTMonitoring | null>(null);
  const [ctLoading, setCTLoading] = useState(true);
  const [ctError, setCTError] = useState<string | null>(null);
  const [ctFilter, setCTFilter] = useState<DashboardTriage>("");
  const [ctLoadingMore, setCTLoadingMore] = useState(false);
  const [driftRemediation, setDriftRemediation] = useState<DriftRemediation | null>(null);
  const [driftLoading, setDriftLoading] = useState(true);
  const [driftFilter, setDriftFilter] = useState<DashboardTriage>("");
  const [driftLoadingMore, setDriftLoadingMore] = useState(false);
  const [driftBusy, setDriftBusy] = useState<string | null>(null);
  const [driftResult, setDriftResult] = useState<string | null>(null);
  const [driftError, setDriftError] = useState<string | null>(null);
  const [cbomInventory, setCBOMInventory] = useState<CBOMInventory>({ items: [], migration_progress: emptyCBOMProgress });
  const [lastCBOMScan, setLastCBOMScan] = useState<CBOMScan | null>(null);
  const [cbomLoading, setCBOMLoading] = useState(true);
  const [cbomError, setCBOMError] = useState<string | null>(null);
  const [supportingOpen, setSupportingOpen] = useState(false);
  const [inventoryOpen, setInventoryOpen] = useState(false);
  const [planningOpen, setPlanningOpen] = useState(false);
  const planningDisclosureRef = useRef<HTMLDetailsElement>(null);

  useEffect(() => {
    let cancelled = false;

    async function loadDiscoveryPosture() {
      setDiscoveryLoading(true);
      setDiscoveryError(null);
      const [sourceResult, runResult, monitoringResult] = await Promise.allSettled([
        api.discoverySources({ limit: 50 }),
        api.discoveryRuns({ limit: 50 }),
        api.discoveryMonitoring(),
      ]);
      if (cancelled) return;

      if (sourceResult.status === "fulfilled") setDiscoverySources(sourceResult.value.items ?? []);
      else setDiscoverySources([]);
      const rejected = [sourceResult, runResult, monitoringResult].find((result) => result.status === "rejected");
      if (rejected?.status === "rejected") setDiscoveryError(rejected.reason instanceof Error ? rejected.reason.message : "Unable to load discovery findings");
      else if (sourceResult.status === "fulfilled" && runResult.status === "fulfilled" && monitoringResult.status === "fulfilled") {
        try {
          const latest = await loadLatestDriftRuns(sourceResult.value.items ?? [], runResult.value.items ?? [], monitoringResult.value, api.getDiscoveryRun);
          if (cancelled) return;
          setDriftLatestRuns(latest);
        } catch (error) {
          if (cancelled) return;
          setDriftLatestRuns({});
          setDiscoveryError(error instanceof Error ? error.message : "Unable to verify latest drift runs");
        }
      }
      setDiscoveryLoading(false);
    }

    void loadDiscoveryPosture();
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    let cancelled = false;

    async function loadCTMonitoring() {
      setCTLoading(true);
      setCTError(null);
      try {
        const state = await api.ctMonitoring({ triageStatus: ctFilter || undefined });
        if (cancelled) return;
        setCTMonitoring(state);
      } catch (error) {
        if (!cancelled) setCTError(error instanceof Error ? error.message : "Unable to load CT monitoring");
      } finally {
        if (!cancelled) setCTLoading(false);
      }
    }

    void loadCTMonitoring();
    return () => {
      cancelled = true;
    };
  }, [ctFilter]);

  useEffect(() => {
    let cancelled = false;

    async function loadDriftRemediation() {
      setDriftLoading(true);
      setDriftError(null);
      try {
        const state = await api.driftRemediation({ triageStatus: driftFilter || undefined });
        if (!cancelled) setDriftRemediation(state);
      } catch (error) {
        if (!cancelled) setDriftError(error instanceof Error ? error.message : "Unable to load drift remediation");
      } finally {
        if (!cancelled) setDriftLoading(false);
      }
    }

    void loadDriftRemediation();
    return () => {
      cancelled = true;
    };
  }, [driftFilter]);

  useEffect(() => {
    let cancelled = false;

    async function loadInventory() {
      setCBOMLoading(true);
      setCBOMError(null);
      try {
        const inventory = await api.listCBOMAssets();
        if (!cancelled) setCBOMInventory(inventory);
      } catch (error) {
        if (!cancelled) setCBOMError(error instanceof Error ? error.message : "Unable to load CBOM inventory");
      } finally {
        if (!cancelled) setCBOMLoading(false);
      }
    }

    void loadInventory();
    return () => {
      cancelled = true;
    };
  }, []);

  const cbomProgress = cbomInventory.migration_progress ?? lastCBOMScan?.migration_progress ?? emptyCBOMProgress;
  const upgradeAssets = cbomInventory.items.filter((asset) => asset.out_of_policy || asset.quantum_vulnerable);

  // A105: "load more" appends the next server page to what the dashboard shows.
  async function loadMoreCT() {
    const cursor = ctMonitoring?.next_cursor;
    if (!cursor) return;
    setCTLoadingMore(true);
    try {
      const page = await api.ctMonitoring({ triageStatus: ctFilter || undefined, cursor });
      setCTMonitoring((current) => (current ? { ...page, findings: [...current.findings, ...page.findings] } : page));
    } catch (error) {
      setCTError(error instanceof Error ? error.message : "Unable to load CT monitoring");
    } finally {
      setCTLoadingMore(false);
    }
  }

  async function loadMoreDrift() {
    const cursor = driftRemediation?.next_cursor;
    if (!cursor) return;
    setDriftLoadingMore(true);
    try {
      const page = await api.driftRemediation({ triageStatus: driftFilter || undefined, cursor });
      setDriftRemediation((current) => (current ? { ...page, findings: [...current.findings, ...page.findings] } : page));
    } catch (error) {
      setDriftError(error instanceof Error ? error.message : "Unable to load drift remediation");
    } finally {
      setDriftLoadingMore(false);
    }
  }

  function focusUpgradePlanning() {
    const disclosure = planningDisclosureRef.current;
    if (!disclosure) return;
    disclosure.open = true;
    setPlanningOpen(true);
    disclosure.querySelector("summary")?.focus();
  }

  async function recordDriftDecision(finding: DriftRemediationFinding, decision: DriftDecision) {
    const busyKey = `${finding.finding_id}:${decision}`;
    setDriftBusy(busyKey);
    setDriftError(null);
    setDriftResult(null);
    try {
      const response = await api.decideDriftRemediation(finding.finding_id, {
        decision,
        reason: driftDecisionReason(decision),
      });
      setDriftResult(`${driftDecisionLabel(decision)} recorded for ${finding.ref}`);
      // The decision moves the finding between statuses: re-read the first
      // page so the server's counts and the filtered list stay true. If that
      // read fails, the decided row still shows its new status.
      try {
        setDriftRemediation(await api.driftRemediation({ triageStatus: driftFilter || undefined }));
      } catch {
        setDriftRemediation((current) =>
          current
            ? { ...current, findings: current.findings.map((item) => (item.finding_id === response.finding.finding_id ? response.finding : item)) }
            : current,
        );
      }
    } catch (error) {
      setDriftError(error instanceof Error ? error.message : "Unable to record drift decision");
    } finally {
      setDriftBusy(null);
    }
  }

  return (
    <section aria-labelledby="posture-heading" className="grid gap-6">
      <PageHeader
        titleId="posture-heading"
        title={t("nav.item.posture")}
        description={t("posture.design.answer")}
        technicalDetails={t("posture.design.technicalDetails")}
        actions={
          <Button type="button" onClick={focusUpgradePlanning}>
            {t("posture.design.planUpgrade")}
          </Button>
        }
      />

      <CryptoUpgradeSummary assets={upgradeAssets} total={cbomProgress.total_assets} loading={cbomLoading} error={cbomError} />

      <details className="rounded-panel border border-border bg-card shadow-elevation1" onToggle={(event) => setSupportingOpen(event.currentTarget.open)}>
        <summary className="cursor-pointer px-4 py-3 font-semibold text-foreground">{t("posture.design.disclosure.supporting")}</summary>
        <div className="grid gap-6 border-t border-border p-4" hidden={!supportingOpen}>
          <section aria-labelledby="ct-heading" className="grid gap-3 border-y border-border py-4">
            <div className="flex items-start gap-3">
              <Radar className="mt-1 h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
              <div>
                <h2 id="ct-heading" className="text-title font-semibold">
                  {translateNow("source.certificate.transparency.monitoring.a0ad3241c4")}
                </h2>
                <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{translateNow("source.ct.monitoring.watches.public.logs.for.cert.3163770746")}</p>
              </div>
            </div>
            <CTFindingsDashboard
              state={ctMonitoring}
              loading={ctLoading}
              error={ctError}
              paging={{ filter: ctFilter, onFilter: setCTFilter, onLoadMore: () => void loadMoreCT(), loadingMore: ctLoadingMore }}
            />
            <div className="flex flex-wrap items-center justify-between gap-3 rounded-panel border border-border bg-background p-comfortable">
              <div>
                <p className="text-sm font-medium">{t("discovery.ct.postureReadOnly")}</p>
                <p className="mt-1 text-xs text-muted-foreground">{t("discovery.ct.postureReadOnlyDetail")}</p>
              </div>
              <Link className="rounded-control border border-border bg-card px-3 py-2 text-sm font-medium hover:bg-muted" to="/discovery">
                {t("discovery.ct.openInDiscovery")}
              </Link>
            </div>
            {ctMonitoring ? (
              <>
                <dl className="grid gap-3 md:grid-cols-5">
                  <Metric label="Watch domains" value={String(ctMonitoring.summary.watched_domain_count)} />
                  <Metric label="CT logs" value={String(ctMonitoring.summary.log_count)} />
                  <Metric label="Unexpected issuance" value={String(ctMonitoring.summary.unexpected_issuance_count)} />
                  <Metric label="Open findings" value={String(ctMonitoring.summary.open_finding_count)} />
                  <Metric label="Alert channels" value={String(ctMonitoring.summary.outbox_alert_channel_count)} />
                </dl>
                <PreviewTable title={translateNow("source.ct.log.checkpoints.4f19929a7b")} headers={["Log URL", "Next index"]}>
                  {(ctMonitoring.logs ?? []).map((log) => (
                    <tr key={log.url} className="align-top">
                      <td className="font-mono text-xs">{log.url}</td>
                      <td>{log.next_index}</td>
                    </tr>
                  ))}
                </PreviewTable>
              </>
            ) : null}
          </section>

          <ADCSTemplatePanel />
          <ADCSDatabasePanel />
          {/* C4: whether the authorities agree about what was issued. Sits beside
          the AD CS template posture because both answer "what does that
          authority actually say", one about policy and one about inventory. */}
          <AuthorityAgreementPanel />

          <section aria-labelledby="drift-heading" className="grid gap-3 border-y border-border py-4">
            <div className="flex items-start gap-3">
              <FileWarning className="mt-1 h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
              <div>
                <h2 id="drift-heading" className="text-title font-semibold">
                  {translateNow("source.drift.detection.93e554780a")}
                </h2>
                <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{translateNow("source.drift.detection.compares.what.trstctl.inte.95457304d6")}</p>
              </div>
            </div>
            <DriftRecoveryWorkflow sources={discoverySources} latestRuns={driftLatestRuns} loading={discoveryLoading} error={discoveryError} />
            <DriftFindingsDashboard
              state={driftRemediation}
              loading={driftLoading}
              error={driftError}
              busy={driftBusy}
              result={driftResult}
              onDecision={recordDriftDecision}
              paging={{ filter: driftFilter, onFilter: setDriftFilter, onLoadMore: () => void loadMoreDrift(), loadingMore: driftLoadingMore }}
            />
          </section>

          <section aria-labelledby="alert-heading" className="ui-panel flex items-start gap-3 p-comfortable text-sm">
            <Bell className="mt-1 h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
            <div>
              <h2 id="alert-heading" className="text-title font-semibold">
                {translateNow("source.alert.routing.is.managed.from.notification.f26eb33c8e")}
              </h2>
              <p className="mt-1 text-muted-foreground">{translateNow("source.ct.anomalies.and.drift.findings.can.be.rou.360679ac1d")}</p>
            </div>
          </section>
        </div>
      </details>

      <details className="rounded-panel border border-border bg-card shadow-elevation1" onToggle={(event) => setInventoryOpen(event.currentTarget.open)}>
        <summary className="cursor-pointer px-4 py-3 font-semibold text-foreground">{t("posture.design.disclosure.inventory")}</summary>
        <section aria-labelledby="cbom-heading" className="grid gap-3 border-t border-border p-4" hidden={!inventoryOpen}>
          <div className="flex items-start gap-3">
            <ShieldAlert className="mt-1 h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
            <div>
              <h2 id="cbom-heading" className="text-title font-semibold">
                {translateNow("source.cbom.and.cryptographic.observability.11b90cf944")}
              </h2>
              <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{translateNow("source.the.cbom.scanner.inventories.algorithms.ke.94de5272b7")}</p>
            </div>
          </div>
          <CBOMScanWorkflow
            onCompleted={(scan, inventory) => {
              setLastCBOMScan(scan);
              setCBOMInventory(inventory);
              setCBOMError(null);
            }}
          />
          {cbomError ? <ErrorState title={t("posture.cbom.inventoryLoadFailed")}>{cbomError}</ErrorState> : null}

          <dl className="grid gap-3 md:grid-cols-2">
            <Metric label="Total assets" value={String(cbomProgress.total_assets)} />
            <Metric label="Out of policy" value={`${cbomProgress.out_of_policy_assets} out of policy`} />
          </dl>
          <PQCReadinessSummary progress={cbomProgress} />
          <AlgorithmRollup assets={cbomInventory.items} loading={cbomLoading} />

          {lastCBOMScan ? (
            <dl className="grid gap-3 rounded-panel border border-border p-comfortable text-sm md:grid-cols-6">
              <Metric label="Sources scanned" value={String(lastCBOMScan.report.sources)} />
              <Metric label="Findings" value={String(lastCBOMScan.report.findings)} />
              <Metric label="Weak" value={String(lastCBOMScan.report.weak)} />
              <Metric label="Failed" value={String(lastCBOMScan.report.failed)} />
              <Metric label="Out of policy" value={String(lastCBOMScan.report.out_of_policy)} />
              <Metric label="Quantum vulnerable" value={String(lastCBOMScan.report.quantum_vulnerable)} />
            </dl>
          ) : null}

          <PreviewTable
            title={translateNow("source.cbom.asset.inventory.2ba70c3036")}
            headers={["Asset", "Crypto", "Transport", "Policy", "Recommended action", "Evidence"]}
          >
            {cbomInventory.items.map((asset) => (
              <tr key={asset.id} className="align-top">
                <td className="font-medium">
                  <span className="block">{asset.location}</span>
                  <span className="text-xs text-muted-foreground">{asset.kind}</span>
                </td>
                <td>{algorithmLabel(asset)}</td>
                <td>{transportLabel(asset)}</td>
                <td>
                  <StatusBadge
                    value={asset.out_of_policy ? "out_of_policy" : asset.quantum_vulnerable ? "quantum_vulnerable" : "allowed"}
                    label={asset.out_of_policy ? "Out of policy" : asset.quantum_vulnerable ? "Quantum vulnerable" : "Allowed"}
                    tone={asset.out_of_policy ? "critical" : asset.quantum_vulnerable ? "warning" : "success"}
                    vocabulary="risk"
                  />
                </td>
                <td>
                  <span className="block">{asset.migration_target}</span>
                  <span className="text-xs text-muted-foreground">
                    {asset.migration_standard} / {asset.migration_generation}
                  </span>
                </td>
                <td>{asset.reasons?.length ? asset.reasons.join("; ") : asset.strength}</td>
              </tr>
            ))}
          </PreviewTable>
          {!cbomLoading && cbomInventory.items.length === 0 ? (
            <EmptyState title={translateNow("source.no.cbom.assets.returned.yet.6164e1adf5")}>
              {translateNow("source.run.a.scan.against.tls.endpoints.or.host.c.e657e656ce")}
            </EmptyState>
          ) : null}
        </section>
      </details>

      <details
        ref={planningDisclosureRef}
        className="rounded-panel border border-border bg-card shadow-elevation1"
        onToggle={(event) => setPlanningOpen(event.currentTarget.open)}
      >
        <summary className="cursor-pointer px-4 py-3 font-semibold text-foreground">{t("posture.design.disclosure.compatibility")}</summary>
        <section aria-labelledby="crypto-agility-heading" className="grid gap-3 border-t border-border p-4" hidden={!planningOpen}>
          <div className="flex items-start gap-3">
            <ShieldAlert className="mt-1 h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
            <div>
              <h2 id="crypto-agility-heading" className="text-title font-semibold">
                {translateNow("source.crypto.agility.readiness.7bc9bc7019")}
              </h2>
              <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{translateNow("source.crypto.agility.means.the.system.can.see.we.6ff0a0d217")}</p>
            </div>
          </div>
          <CBOMReadinessTable
            assets={cbomInventory.items}
            loading={cbomLoading || cryptoReadiness.loading}
            readiness={cryptoReadiness.data}
            readinessError={cryptoReadiness.error}
          />
          <PQCCampaigns assets={cbomInventory.items} />
          <PQCPilots />
          <PQCMigrationWorkflow assets={cbomInventory.items} />
          <PCASSuccessionWorkflow />
        </section>
      </details>
    </section>
  );
}

function CryptoUpgradeSummary({ assets, total, loading, error }: { assets: CBOMAsset[]; total: number; loading: boolean; error: string | null }) {
  return (
    <section aria-labelledby="crypto-upgrade-status" className="ui-panel grid gap-4 p-comfortable">
      <div>
        <h2 id="crypto-upgrade-status" className="text-title font-semibold">
          {translateNow("posture.design.upgradeStatus")}
        </h2>
      </div>

      {loading ? <LoadingState>{translateNow("source.loading.cbom.readiness.0b111b06ca")}</LoadingState> : null}
      {!loading && error ? <ErrorState title={translateNow("dashboard.attention.unavailable")}>{error}</ErrorState> : null}
      {!loading && !error ? (
        <>
          <div className="grid gap-3 sm:grid-cols-2">
            <DecisionCount value={total} label={translateNow("source.checked.d2ver00006")} />
            <DecisionCount
              value={assets.length}
              label={translateNow(assets.length === 1 ? "dashboard.attention.needsAttentionOne" : "dashboard.attention.needsAttentionMany", {
                count: assets.length,
              })}
              tone={assets.length > 0 ? "critical" : "neutral"}
            />
          </div>

          {total === 0 ? (
            <EmptyState title={translateNow("source.no.cbom.assets.returned.yet.6164e1adf5")}>
              {translateNow("source.run.a.scan.against.tls.endpoints.or.host.c.e657e656ce")}
            </EmptyState>
          ) : assets.length === 0 ? (
            <EmptyState title={translateNow("dashboard.attention.healthy")} />
          ) : (
            <ul aria-labelledby="crypto-upgrade-status" className="grid gap-3">
              {assets.map((asset) => (
                <li key={asset.id} className="rounded-control border border-border bg-background p-4">
                  <div className="flex flex-wrap items-start justify-between gap-2">
                    <h3 className="font-semibold text-foreground">{asset.location}</h3>
                    <StatusBadge value="needs_upgrade" label={translateNow("operations.attention.heading")} tone="critical" vocabulary="risk" />
                  </div>
                  <ul className="mt-2 list-disc space-y-1 ps-5 text-sm text-foreground">
                    {asset.out_of_policy ? <li>{translateNow("risk.reason.weakCrypto")}</li> : null}
                    {asset.quantum_vulnerable ? <li>{translateNow("posture.design.reason.futureRisk")}</li> : null}
                  </ul>
                  <dl className="mt-3 grid gap-3 text-sm sm:grid-cols-2">
                    <div>
                      <dt className="text-caption text-muted-foreground">{translateNow("owners.readiness.currentNoDate")}</dt>
                      <dd className="mt-1 font-medium">
                        {translateNow("source.value1.value2.7c639bc99b", {
                          value1: algorithmLabel(asset),
                          value2: transportLabel(asset),
                        })}
                      </dd>
                    </div>
                    <div>
                      <dt className="text-caption text-muted-foreground">{translateNow("posture.algorithmRollup.target")}</dt>
                      <dd className="mt-1 font-medium">{asset.migration_target || translateNow("operations.detail.notRecorded")}</dd>
                    </div>
                  </dl>
                </li>
              ))}
            </ul>
          )}
        </>
      ) : null}
    </section>
  );
}

function DecisionCount({ value, label, tone = "neutral" }: { value: number; label: string; tone?: "neutral" | "critical" }) {
  const toneClass = tone === "critical" ? "border-destructive/30 bg-destructive/5" : "border-border";
  return (
    <div className={`rounded-control border p-3 ${toneClass}`}>
      <p className="text-display-sm font-semibold text-foreground">{value}</p>
      <p className="mt-1 text-sm text-muted-foreground">{label}</p>
    </div>
  );
}

function driftDecisionLabel(decision: DriftDecision): string {
  switch (decision) {
    case "mark_managed":
      return "Managed decision";
    case "dismiss":
      return "Dismiss decision";
    default:
      return "Investigation decision";
  }
}

function driftDecisionReason(decision: DriftDecision): string {
  switch (decision) {
    case "mark_managed":
      return "operator accepted drift remediation evidence";
    case "dismiss":
      return "operator dismissed drift finding after review";
    default:
      return "operator opened drift remediation investigation";
  }
}

function CBOMReadinessTable({
  assets,
  loading,
  readiness,
  readinessError,
}: {
  assets: CBOMAsset[];
  loading: boolean;
  readiness: CryptoReadiness | null;
  readinessError: string | null;
}) {
  if (loading) return <LoadingState>{translateNow("source.loading.cbom.readiness.0b111b06ca")}</LoadingState>;
  if (assets.length === 0) return <EmptyState title={translateNow("source.no.cbom.readiness.assets.returned.yet.e6abce03d0")} />;
  const readinessByAsset = new Map((readiness?.items ?? []).map((row) => [row.asset.id.replace(/^crypto:/, ""), row]));

  return (
    <>
      {readinessError ? <ErrorState title={translateNow("cryptoReadiness.unavailable")}>{readinessError}</ErrorState> : null}
      <PreviewTable
        title={translateNow("source.crypto.agility.readiness.7bc9bc7019")}
        headers={[
          translateNow("source.crypto.asset.m2seq00005"),
          translateNow("cryptoReadiness.header.inventory"),
          translateNow("cryptoReadiness.header.dependencies"),
          translateNow("cryptoReadiness.header.recommendation"),
          translateNow("cryptoReadiness.header.action"),
        ]}
      >
        {assets.map((asset) => {
          const row = readinessByAsset.get(asset.id);
          return (
            <tr key={asset.id} className="align-top">
              <td className="font-medium">
                <span className="block">{asset.location}</span>
                <span className="text-xs text-muted-foreground">{asset.kind}</span>
              </td>
              <td>
                {algorithmLabel(asset)}
                {transportLabel(asset) !== "not reported" ? translateNow("source.value1.550e636eaf", { value1: transportLabel(asset) }) : ""}
              </td>
              <td>
                {row ? (
                  <div className="grid gap-1 text-xs">
                    <span>
                      {(row.dependents ?? []).length > 0
                        ? (row.dependents ?? []).map((dependent, index) => (
                            <span key={`${dependent.node.id}:${dependent.via.id}`}>
                              {index > 0 ? ", " : ""}
                              <span>{dependent.node.name}</span>{" "}
                              <span>{translateNow("source.crypto.readiness.via.m2crp00001", { value1: dependent.via.name })}</span>
                            </span>
                          ))
                        : translateNow("cryptoReadiness.noDependents")}
                    </span>
                    <span className="text-muted-foreground">{(row.owners ?? []).join(", ") || translateNow("cryptoReadiness.ownerUnknown")}</span>
                  </div>
                ) : (
                  <span className="text-status-warning">{translateNow("cryptoReadiness.rowUnknown")}</span>
                )}
              </td>
              <td>{row?.recommendation ?? translateNow("cryptoReadiness.recommendationUnknown")}</td>
              <td>
                {(row?.actions ?? []).length > 0 ? (
                  <ul className="grid gap-1 text-xs">
                    {(row?.actions ?? []).map((action) => (
                      <li key={action.campaign_id}>
                        <span className="font-medium">{action.name}</span> — {action.owner} / {action.disposition}
                        {action.stale ? <span className="text-status-danger"> {translateNow("cryptoReadiness.stale")}</span> : null}
                        {action.evidence_refs.length > 0 ? <span className="block text-muted-foreground">{action.evidence_refs.join(", ")}</span> : null}
                      </li>
                    ))}
                  </ul>
                ) : (
                  <span className="text-muted-foreground">{translateNow("cryptoReadiness.actions.none")}</span>
                )}
              </td>
            </tr>
          );
        })}
      </PreviewTable>
      <p className="text-xs text-muted-foreground">{readiness?.coverage_guidance ?? translateNow("cryptoReadiness.coverageUnknown")}</p>
    </>
  );
}

// S-C14: the flat CBOM list answers "which asset", never "which algorithm is
// my problem". This rolls the same served inventory up by algorithm so the
// operator sees where the estate's exposure concentrates — the row that says
// "RSA-2048 x 412, all quantum-vulnerable, target ML-DSA-65" is the one that
// turns a scan into a migration plan.
type AlgorithmRollupRow = {
  algorithm: string;
  total: number;
  quantumVulnerable: number;
  outOfPolicy: number;
  migrationTarget: string;
  migrationStandard: string;
  futureReady: boolean;
};

export function rollupByAlgorithm(assets: CBOMAsset[]): AlgorithmRollupRow[] {
  const rows = new Map<string, AlgorithmRollupRow>();
  for (const asset of assets) {
    const algorithm = algorithmLabel(asset);
    const row = rows.get(algorithm) ?? {
      algorithm,
      total: 0,
      quantumVulnerable: 0,
      outOfPolicy: 0,
      // The served inventory carries the target per asset; assets sharing an
      // algorithm share it, so the first non-empty value describes the group.
      migrationTarget: asset.migration_target ?? "",
      migrationStandard: asset.migration_standard ?? "",
      futureReady: asset.migration_generation === "future-ready",
    };
    row.total += 1;
    if (asset.quantum_vulnerable) row.quantumVulnerable += 1;
    if (asset.out_of_policy) row.outOfPolicy += 1;
    if (!row.migrationTarget && asset.migration_target) {
      row.migrationTarget = asset.migration_target;
      row.migrationStandard = asset.migration_standard ?? "";
    }
    rows.set(algorithm, row);
  }
  // Biggest exposure first: most assets, then most quantum-vulnerable.
  return [...rows.values()].sort((a, b) => b.total - a.total || b.quantumVulnerable - a.quantumVulnerable);
}

function AlgorithmRollup({ assets, loading }: { assets: CBOMAsset[]; loading: boolean }) {
  if (loading) return <LoadingState>{translateNow("source.loading.cbom.readiness.0b111b06ca")}</LoadingState>;
  if (assets.length === 0) return null;
  const rows = rollupByAlgorithm(assets);

  return (
    <PreviewTable
      title={translateNow("posture.algorithmRollup.title")}
      headers={[
        translateNow("posture.algorithmRollup.algorithm"),
        translateNow("posture.algorithmRollup.assets"),
        translateNow("posture.algorithmRollup.exposure"),
        translateNow("posture.algorithmRollup.target"),
      ]}
    >
      {rows.map((row) => (
        <tr key={row.algorithm} className="align-top">
          <td className="font-medium">{row.algorithm}</td>
          <td>
            <Num>{String(row.total)}</Num>
          </td>
          <td>
            <StatusBadge
              value={row.outOfPolicy > 0 ? "out_of_policy" : row.quantumVulnerable > 0 ? "quantum_vulnerable" : "ready"}
              label={
                row.outOfPolicy > 0
                  ? translateNow("posture.algorithmRollup.outOfPolicyCount", { count: String(row.outOfPolicy) })
                  : row.quantumVulnerable > 0
                    ? translateNow("posture.algorithmRollup.quantumVulnerableCount", { count: String(row.quantumVulnerable) })
                    : translateNow("posture.algorithmRollup.noExposure")
              }
              tone={row.outOfPolicy > 0 ? "critical" : row.quantumVulnerable > 0 ? "warning" : "success"}
              vocabulary="risk"
            />
          </td>
          <td>
            {row.futureReady ? (
              <span className="text-sm">{translateNow("posture.algorithmRollup.futureReady")}</span>
            ) : (
              <>
                <span className="block">{row.migrationTarget}</span>
                {row.migrationStandard ? <span className="text-xs text-muted-foreground">{row.migrationStandard}</span> : null}
              </>
            )}
          </td>
        </tr>
      ))}
    </PreviewTable>
  );
}

function algorithmLabel(asset: CBOMAsset): string {
  if (!asset.algorithm && !asset.key_bits) return asset.library ?? "not reported";
  return `${asset.algorithm ?? "unknown"}${asset.key_bits ? `-${asset.key_bits}` : ""}`;
}

function transportLabel(asset: CBOMAsset): string {
  const parts = [asset.protocol, asset.cipher].filter(Boolean);
  return parts.length > 0 ? parts.join(" / ") : (asset.library ?? "not reported");
}
