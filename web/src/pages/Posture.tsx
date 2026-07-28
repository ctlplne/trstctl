import type { FormEvent, ReactNode } from "react";
import { useEffect, useMemo, useState } from "react";
import { Bell, CheckCircle2, FileWarning, Radar, SearchCheck, ShieldAlert, XCircle } from "lucide-react";
import { EmptyState } from "@/components/EmptyState";
import { PageHeader } from "@/components/PageHeader";
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
  type CTMonitoring,
  type DiscoveryFinding,
  type DriftRemediation,
  type DriftRemediationDecisionRequest,
  type DriftRemediationFinding,
  type DiscoveryRun,
  type DiscoverySource,
} from "@/lib/api";
import { formatDateTime as formatDateTimePolicy } from "@/i18n/format";
import { PQCCampaigns } from "@/pages/posture/PQCCampaigns";

const emptyCBOMProgress: CBOMMigrationProgress = {
  total_assets: 0,
  out_of_policy_assets: 0,
  quantum_vulnerable_assets: 0,
  post_quantum_ready_assets: 0,
  percent_migrated: 0,
};

export function Posture() {
  const { t } = useTranslation();
  const [discoverySources, setDiscoverySources] = useState<DiscoverySource[]>([]);
  const [discoveryRuns, setDiscoveryRuns] = useState<DiscoveryRun[]>([]);
  const [discoveryFindings, setDiscoveryFindings] = useState<DiscoveryFinding[]>([]);
  const [discoveryLoading, setDiscoveryLoading] = useState(true);
  const [discoveryError, setDiscoveryError] = useState<string | null>(null);
  const [ctMonitoring, setCTMonitoring] = useState<CTMonitoring | null>(null);
  const [ctForm, setCTForm] = useState({
    name: "Certificate Transparency monitor",
    watchedDomains: "",
    logs: "",
    maxBatch: "25",
  });
  const [ctSaving, setCTSaving] = useState(false);
  const [ctResult, setCTResult] = useState<string | null>(null);
  const [ctError, setCTError] = useState<string | null>(null);
  const [driftRemediation, setDriftRemediation] = useState<DriftRemediation | null>(null);
  const [driftLoading, setDriftLoading] = useState(true);
  const [driftBusy, setDriftBusy] = useState<string | null>(null);
  const [driftResult, setDriftResult] = useState<string | null>(null);
  const [driftError, setDriftError] = useState<string | null>(null);
  const [cbomInventory, setCBOMInventory] = useState<CBOMInventory>({ items: [], migration_progress: emptyCBOMProgress });
  const [lastCBOMScan, setLastCBOMScan] = useState<CBOMScan | null>(null);
  const [cbomLoading, setCBOMLoading] = useState(true);
  const [cbomScanning, setCBOMScanning] = useState(false);
  const [cbomError, setCBOMError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    async function loadDiscoveryPosture() {
      setDiscoveryLoading(true);
      setDiscoveryError(null);
      const [sourceResult, runResult, findingResult] = await Promise.allSettled([
        api.discoverySources({ limit: 50 }),
        api.discoveryRuns({ limit: 50 }),
        api.discoveryFindings({ limit: 50 }),
      ]);
      if (cancelled) return;

      if (sourceResult.status === "fulfilled") setDiscoverySources(sourceResult.value.items ?? []);
      else setDiscoverySources([]);
      if (runResult.status === "fulfilled") setDiscoveryRuns(runResult.value.items ?? []);
      else setDiscoveryRuns([]);
      if (findingResult.status === "fulfilled") setDiscoveryFindings(findingResult.value.items ?? []);
      else setDiscoveryFindings([]);

      const rejected = [sourceResult, runResult, findingResult].find((result) => result.status === "rejected");
      if (rejected?.status === "rejected") setDiscoveryError(rejected.reason instanceof Error ? rejected.reason.message : "Unable to load discovery findings");
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
      setCTError(null);
      try {
        const state = await api.ctMonitoring();
        if (cancelled) return;
        applyCTMonitoringState(state);
      } catch (error) {
        if (!cancelled) setCTError(error instanceof Error ? error.message : "Unable to load CT monitoring");
      }
    }

    void loadCTMonitoring();
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    let cancelled = false;

    async function loadDriftRemediation() {
      setDriftLoading(true);
      setDriftError(null);
      try {
        const state = await api.driftRemediation();
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
  }, []);

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

  async function handleCBOMScan(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const formData = new FormData(form);
    const tlsEndpoints = linesFromField(formData.get("tls_endpoints"));
    const hostConfigs = linesFromField(formData.get("host_configs"));

    setCBOMScanning(true);
    setCBOMError(null);
    try {
      const scan = await api.startCBOMScan({
        ...(tlsEndpoints.length > 0 ? { tls_endpoints: tlsEndpoints } : {}),
        ...(hostConfigs.length > 0 ? { host_configs: hostConfigs } : {}),
      });
      const inventory = await api.listCBOMAssets();
      setLastCBOMScan(scan);
      setCBOMInventory(inventory);
      form.reset();
    } catch (error) {
      setCBOMError(error instanceof Error ? error.message : "Unable to run CBOM scan");
    } finally {
      setCBOMScanning(false);
    }
  }

  function applyCTMonitoringState(state: CTMonitoring) {
    setCTMonitoring(state);
    setCTForm({
      name: state.source?.name ?? defaultCTMonitorName,
      watchedDomains: (state.watched_domains ?? []).join("\n"),
      logs: (state.logs ?? []).map((log) => log.url).join("\n"),
      maxBatch: String(sourceMaxBatch(state) || 25),
    });
  }

  async function handleCTMonitoringSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const watchedDomains = linesFromText(ctForm.watchedDomains);
    const logs = linesFromText(ctForm.logs);
    const maxBatch = Number.parseInt(ctForm.maxBatch, 10);
    setCTSaving(true);
    setCTError(null);
    setCTResult(null);
    try {
      const state = await api.updateCTMonitoring({
        name: ctForm.name.trim() || defaultCTMonitorName,
        logs,
        watched_domains: watchedDomains,
        max_batch: Number.isFinite(maxBatch) && maxBatch > 0 ? maxBatch : 25,
        run_now: true,
      });
      applyCTMonitoringState(state);
      setCTResult(state.run?.id ? `Run ${state.run.id} queued` : "CT watchlist saved");
    } catch (error) {
      setCTError(error instanceof Error ? error.message : "Unable to update CT monitoring");
    } finally {
      setCTSaving(false);
    }
  }

  const cbomProgress = cbomInventory.migration_progress ?? lastCBOMScan?.migration_progress ?? emptyCBOMProgress;
  const discoverySourceByID = useMemo(() => new Map(discoverySources.map((source) => [source.id, source])), [discoverySources]);
  const discoveryRunByID = useMemo(() => new Map(discoveryRuns.map((run) => [run.id, run])), [discoveryRuns]);
  const ctFindings = discoveryFindings.filter((finding) => findingSourceKind(finding, discoverySourceByID) === "ct_log");
  const driftFindings = discoveryFindings.filter((finding) => findingSourceKind(finding, discoverySourceByID) === "drift");

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
      setDriftRemediation((current) => {
        if (!current) return current;
        return {
          ...current,
          findings: current.findings.map((item) => (item.finding_id === response.finding.finding_id ? response.finding : item)),
        };
      });
      setDriftResult(`${driftDecisionLabel(decision)} recorded for ${finding.ref}`);
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
        description="Your fleet's cryptographic health: certificate-transparency findings, configuration drift, and a cryptographic bill of materials (which algorithms you run and how post-quantum-ready they are). For per-credential rotation urgency see Risk; for scan setup see Discovery."
      />

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
        <DiscoveryFindingTable
          title={translateNow("source.certificate.transparency.findings.55891f79b6")}
          findings={ctFindings}
          sourceByID={discoverySourceByID}
          runByID={discoveryRunByID}
          loading={discoveryLoading}
          error={discoveryError}
          emptyTitle="No CT findings returned yet"
        />
        <form className="grid gap-3 rounded-panel border border-border p-comfortable" onSubmit={handleCTMonitoringSubmit}>
          <div className="grid gap-3 md:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_10rem]">
            <label className="grid gap-1 text-sm font-medium" htmlFor="ct-watched-domains">
              {translateNow("source.watched.domains.0a60ff7e19")}
              <textarea
                id="ct-watched-domains"
                className="ui-input min-h-20 font-mono text-xs"
                value={ctForm.watchedDomains}
                onChange={(event) => setCTForm((current) => ({ ...current, watchedDomains: event.target.value }))}
                placeholder={translateNow("source.example.com.a379a6f6ee")}
              />
            </label>
            <label className="grid gap-1 text-sm font-medium" htmlFor="ct-log-urls">
              {translateNow("source.ct.log.urls.20c5c9807c")}
              <textarea
                id="ct-log-urls"
                className="ui-input min-h-20 font-mono text-xs"
                value={ctForm.logs}
                onChange={(event) => setCTForm((current) => ({ ...current, logs: event.target.value }))}
                placeholder={translateNow("source.https.ct.googleapis.com.logs.argon2026.109b891d19")}
              />
            </label>
            <label className="grid gap-1 text-sm font-medium" htmlFor="ct-max-batch">
              {translateNow("source.max.entries.per.poll.a77eca9293")}
              <input
                id="ct-max-batch"
                className="ui-input"
                type="number"
                min={1}
                value={ctForm.maxBatch}
                onChange={(event) => setCTForm((current) => ({ ...current, maxBatch: event.target.value }))}
              />
            </label>
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <Button type="submit" disabled={ctSaving || linesFromText(ctForm.watchedDomains).length === 0 || linesFromText(ctForm.logs).length === 0}>
              <Radar className="h-4 w-4" aria-hidden="true" />
              {ctSaving ? translateNow("source.saving.ct.c96661dcd1") : translateNow("source.save.and.poll.ct.609730cebd")}
            </Button>
            {ctResult ? <p className="text-sm font-medium text-status-success">{ctResult}</p> : null}
            {ctError ? <p className="text-sm font-medium text-destructive">{ctError}</p> : null}
          </div>
        </form>
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
              {ctMonitoring.logs.map((log) => (
                <tr key={log.url} className="align-top">
                  <td className="font-mono text-xs">{log.url}</td>
                  <td>{log.next_index}</td>
                </tr>
              ))}
            </PreviewTable>
          </>
        ) : null}
      </section>

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
        <DiscoveryFindingTable
          title={translateNow("source.drift.findings.cd56c69007")}
          findings={driftFindings}
          sourceByID={discoverySourceByID}
          runByID={discoveryRunByID}
          loading={discoveryLoading}
          error={discoveryError}
          emptyTitle="No drift findings returned yet"
        />
        <DriftRemediationWorkflow
          state={driftRemediation}
          loading={driftLoading}
          error={driftError}
          busy={driftBusy}
          result={driftResult}
          onDecision={recordDriftDecision}
        />
      </section>

      <section aria-labelledby="cbom-heading" className="grid gap-3 border-y border-border py-4">
        <div className="flex items-start gap-3">
          <ShieldAlert className="mt-1 h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
          <div>
            <h2 id="cbom-heading" className="text-title font-semibold">
              {translateNow("source.cbom.and.cryptographic.observability.11b90cf944")}
            </h2>
            <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{translateNow("source.the.cbom.scanner.inventories.algorithms.ke.94de5272b7")}</p>
          </div>
        </div>
        <form className="grid gap-3 rounded-panel border border-border p-comfortable" onSubmit={handleCBOMScan}>
          <div className="grid gap-3 md:grid-cols-2">
            <label className="grid gap-1 text-sm font-medium" htmlFor="cbom-tls-endpoints">
              {translateNow("source.tls.endpoints.c928457ec8")}
              <textarea
                id="cbom-tls-endpoints"
                className="ui-input min-h-20 font-mono text-xs"
                name="tls_endpoints"
                placeholder={translateNow("source.https.api.example.com.443.74d0333a40")}
              />
            </label>
            <label className="grid gap-1 text-sm font-medium" htmlFor="cbom-host-configs">
              {translateNow("source.host.config.paths.8b2c6c7bdd")}
              <textarea
                id="cbom-host-configs"
                className="ui-input min-h-20 font-mono text-xs"
                name="host_configs"
                placeholder={translateNow("source.etc.ssh.sshd.config.83ca950c7a")}
              />
            </label>
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <Button type="submit" disabled={cbomScanning}>
              {cbomScanning ? translateNow("source.running.scan.34932df63a") : translateNow("source.run.cbom.scan.ca786ed005")}
            </Button>
            <p className="text-sm text-muted-foreground">{translateNow("source.the.request.sends.endpoint.and.host.config.057e53f9e9")}</p>
          </div>
          {cbomError ? <p className="text-sm font-medium text-destructive">{cbomError}</p> : null}
        </form>

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

      <section aria-labelledby="crypto-agility-heading" className="grid gap-3 border-y border-border py-4">
        <div className="flex items-start gap-3">
          <ShieldAlert className="mt-1 h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
          <div>
            <h2 id="crypto-agility-heading" className="text-title font-semibold">
              {translateNow("source.crypto.agility.readiness.7bc9bc7019")}
            </h2>
            <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{translateNow("source.crypto.agility.means.the.system.can.see.we.6ff0a0d217")}</p>
          </div>
        </div>
        <CBOMReadinessTable assets={cbomInventory.items} loading={cbomLoading} />
        <PQCCampaigns assets={cbomInventory.items} />
        <PQCMigrationWorkflow assets={cbomInventory.items} />
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
    </section>
  );
}

function linesFromField(value: FormDataEntryValue | null): string[] {
  if (typeof value !== "string") return [];
  return linesFromText(value);
}

function linesFromText(value: string): string[] {
  return value
    .split(/[\n,]+/)
    .map((line) => line.trim())
    .filter(Boolean);
}

const defaultCTMonitorName = "Certificate Transparency monitor";
type DriftDecision = DriftRemediationDecisionRequest["decision"];

function sourceMaxBatch(state: CTMonitoring): number {
  const raw = state.source?.config;
  if (raw && typeof raw === "object" && !Array.isArray(raw) && "max_batch" in raw) {
    const value = raw.max_batch;
    if (typeof value === "number" && Number.isFinite(value)) return value;
  }
  return 0;
}

function DriftRemediationWorkflow({
  state,
  loading,
  error,
  busy,
  result,
  onDecision,
}: {
  state: DriftRemediation | null;
  loading: boolean;
  error: string | null;
  busy: string | null;
  result: string | null;
  onDecision: (finding: DriftRemediationFinding, decision: DriftDecision) => void;
}) {
  if (loading) return <LoadingState>{translateNow("source.loading.drift.remediation.c1b6240bc3")}</LoadingState>;

  const findings = state?.findings ?? [];
  return (
    <div className="grid gap-3 rounded-panel border border-border p-comfortable">
      <dl className="grid gap-3 md:grid-cols-5">
        <Metric label="Watched sources" value={String(state?.summary.source_count ?? 0)} />
        <Metric label="Open drift" value={String(state?.summary.open_finding_count ?? 0)} />
        <Metric label="Replaced" value={String(state?.summary.replaced_count ?? 0)} />
        <Metric label="Permissions" value={String(state?.summary.permission_changed_count ?? 0)} />
        <Metric label="Decisions" value={String(state?.summary.remediation_decision_count ?? 0)} />
      </dl>
      {error ? <ErrorState title={translateNow("source.drift.remediation.unavailable.2da12cc33d")}>{error}</ErrorState> : null}
      {result ? <p className="text-sm font-medium text-status-success">{result}</p> : null}
      {findings.length === 0 ? (
        <EmptyState title={translateNow("source.no.drift.remediation.findings.returned.yet.5034b41d52")} />
      ) : (
        <PreviewTable
          title={translateNow("source.drift.remediation.workflow.9456b591c4")}
          headers={["Credential", "Drift", "Risk", "Triage", "Recommended action", "Decision"]}
        >
          {findings.map((finding) => (
            <tr key={finding.finding_id} className="align-top">
              <td className="font-medium">
                <span className="block">{finding.ref}</span>
                <span className="text-xs text-muted-foreground">{finding.source_name}</span>
              </td>
              <td>
                <span className="block">{driftLabel(finding.drift_type)}</span>
                <span className="text-xs text-muted-foreground">{finding.credential_class}</span>
              </td>
              <td>{finding.risk_score}</td>
              <td>
                <StatusBadge value={finding.triage_status} label={triageLabel(finding.triage_status)} tone={triageTone(finding.triage_status)} />
              </td>
              <td>{finding.recommended_action}</td>
              <td>
                <div className="flex flex-wrap gap-2">
                  <Button
                    type="button"
                    variant="outline"
                    title={translateNow("source.investigate.e264109347")}
                    aria-label={translateNow("source.investigate.value1.39e7603180", { value1: finding.ref })}
                    disabled={!finding.available_decisions.includes("investigate") || busy === `${finding.finding_id}:investigate`}
                    onClick={() => onDecision(finding, "investigate")}
                  >
                    <SearchCheck className="h-4 w-4" aria-hidden="true" />
                    {translateNow("source.investigate.e264109347")}
                  </Button>
                  <Button
                    type="button"
                    variant="outline"
                    title={translateNow("source.mark.managed.61a3f9305a")}
                    aria-label={translateNow("source.mark.managed.value1.ba545156d1", { value1: finding.ref })}
                    disabled={!finding.available_decisions.includes("mark_managed") || busy === `${finding.finding_id}:mark_managed`}
                    onClick={() => onDecision(finding, "mark_managed")}
                  >
                    <CheckCircle2 className="h-4 w-4" aria-hidden="true" />
                    {translateNow("source.managed.8f2de600bf")}
                  </Button>
                  <Button
                    type="button"
                    variant="outline"
                    title={translateNow("source.dismiss.48845bff33")}
                    aria-label={translateNow("source.dismiss.value1.540d3af43e", { value1: finding.ref })}
                    disabled={!finding.available_decisions.includes("dismiss") || busy === `${finding.finding_id}:dismiss`}
                    onClick={() => onDecision(finding, "dismiss")}
                  >
                    <XCircle className="h-4 w-4" aria-hidden="true" />
                    {translateNow("source.dismiss.48845bff33")}
                  </Button>
                </div>
              </td>
            </tr>
          ))}
        </PreviewTable>
      )}
    </div>
  );
}

function DiscoveryFindingTable({
  title,
  findings,
  sourceByID,
  runByID,
  loading,
  error,
  emptyTitle,
}: {
  title: string;
  findings: DiscoveryFinding[];
  sourceByID: ReadonlyMap<string, DiscoverySource>;
  runByID: ReadonlyMap<string, DiscoveryRun>;
  loading: boolean;
  error: string | null;
  emptyTitle: string;
}) {
  if (loading) return <LoadingState>{translateNow("source.loading.discovery.findings.6d4fa8ee4b")}</LoadingState>;

  return (
    <>
      {error ? <ErrorState title={translateNow("source.discovery.findings.unavailable.8112281292")}>{error}</ErrorState> : null}
      {findings.length === 0 ? (
        <EmptyState title={emptyTitle} />
      ) : (
        <PreviewTable title={title} headers={["Reference", "Source", "Kind", "Risk", "Run state", "Alert state", "Discovered"]}>
          {findings.map((finding) => {
            const source = sourceByID.get(finding.source_id);
            const run = runByID.get(finding.run_id);
            const runStatus = run?.status ?? "not_reported";
            return (
              <tr key={finding.id} className="align-top">
                <td className="font-medium">{finding.ref}</td>
                <td>{source?.name ?? finding.source_id}</td>
                <td>{finding.kind}</td>
                <td>{finding.risk_score ?? 0}</td>
                <td>
                  <StatusBadge value={runStatus} label={runStatusLabel(runStatus)} tone={runStatusTone(runStatus)} />
                </td>
                <td>{safeFindingSummary(finding)}</td>
                <td>{formatDateTimePolicy(finding.discovered_at)}</td>
              </tr>
            );
          })}
        </PreviewTable>
      )}
    </>
  );
}

function driftLabel(value: DriftRemediationFinding["drift_type"]): string {
  switch (value) {
    case "deleted":
      return "Deleted";
    case "replaced":
      return "Replaced";
    case "relocated":
      return "Relocated";
    case "permission_changed":
      return "Permission changed";
    default:
      return "Unknown";
  }
}

function triageLabel(value: DriftRemediationFinding["triage_status"]): string {
  switch (value) {
    case "investigating":
      return "Investigating";
    case "managed":
      return "Managed";
    case "dismissed":
      return "Dismissed";
    default:
      return "Unmanaged";
  }
}

function triageTone(value: DriftRemediationFinding["triage_status"]) {
  switch (value) {
    case "managed":
      return "success";
    case "dismissed":
      return "neutral";
    case "investigating":
      return "warning";
    default:
      return "critical";
  }
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

function findingSourceKind(finding: DiscoveryFinding, sourceByID: ReadonlyMap<string, DiscoverySource>): DiscoverySource["kind"] | undefined {
  const kind = sourceByID.get(finding.source_id)?.kind;
  if (kind) return kind;
  const provenance = finding.provenance.toLowerCase();
  if (provenance.includes("ct_log") || provenance.includes("certificate transparency")) return "ct_log";
  if (provenance.includes("drift")) return "drift";
  return undefined;
}

function safeFindingSummary(finding: DiscoveryFinding): string {
  for (const key of ["alert", "evidence", "signal", "reason", "status", "summary"]) {
    const value = finding.metadata[key];
    if (typeof value === "string" && value.trim()) return value;
  }
  return finding.provenance;
}

function CBOMReadinessTable({ assets, loading }: { assets: CBOMAsset[]; loading: boolean }) {
  if (loading) return <LoadingState>{translateNow("source.loading.cbom.readiness.0b111b06ca")}</LoadingState>;
  if (assets.length === 0) return <EmptyState title={translateNow("source.no.cbom.readiness.assets.returned.yet.e6abce03d0")} />;

  return (
    <PreviewTable
      title={translateNow("source.crypto.agility.readiness.7bc9bc7019")}
      headers={["Asset", "Inventory", "Readiness", "Migration target", "Evidence"]}
    >
      {assets.map((asset) => (
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
            <StatusBadge value={readinessValue(asset)} label={readinessLabel(asset)} tone={readinessTone(asset)} vocabulary="risk" />
          </td>
          <td>{asset.migration_target}</td>
          <td>{asset.reasons?.length ? asset.reasons.join("; ") : asset.strength}</td>
        </tr>
      ))}
    </PreviewTable>
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

function readinessValue(asset: CBOMAsset): string {
  if (asset.out_of_policy) return "out_of_policy";
  if (asset.quantum_vulnerable) return "quantum_vulnerable";
  return "ready";
}

function readinessLabel(asset: CBOMAsset): string {
  if (asset.out_of_policy) return "Out of policy";
  if (asset.quantum_vulnerable) return "Quantum vulnerable";
  return "Ready";
}

function readinessTone(asset: CBOMAsset) {
  if (asset.out_of_policy) return "critical";
  if (asset.quantum_vulnerable) return "warning";
  return "success";
}

function runStatusLabel(value: string): string {
  return value.replace(/[_-]+/g, " ").replace(/\b\w/g, (char) => char.toUpperCase());
}

function runStatusTone(value: string) {
  const normalized = value.toLowerCase();
  if (normalized === "succeeded" || normalized === "success") return "success";
  if (normalized === "failed") return "critical";
  if (normalized === "queued" || normalized === "running") return "warning";
  return "neutral";
}

function algorithmLabel(asset: CBOMAsset): string {
  if (!asset.algorithm && !asset.key_bits) return asset.library ?? "not reported";
  return `${asset.algorithm ?? "unknown"}${asset.key_bits ? `-${asset.key_bits}` : ""}`;
}

function transportLabel(asset: CBOMAsset): string {
  const parts = [asset.protocol, asset.cipher].filter(Boolean);
  return parts.length > 0 ? parts.join(" / ") : (asset.library ?? "not reported");
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-panel border border-border bg-muted/20 px-3 py-2">
      <dt className="text-xs font-medium uppercase text-muted-foreground">{label}</dt>
      <dd className="mt-1 text-title font-semibold">{value}</dd>
    </div>
  );
}

function PreviewTable({ title, headers, children }: { title: string; headers: string[]; children: ReactNode }) {
  return (
    <div className="overflow-x-auto rounded-panel border border-border">
      <table className="ui-table min-w-[52rem]">
        <caption className="sr-only">{title}</caption>
        <thead>
          <tr>
            {headers.map((header) => (
              <th key={header} scope="col">
                {header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>{children}</tbody>
      </table>
    </div>
  );
}
