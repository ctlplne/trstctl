import type { FormEvent, ReactNode } from "react";
import { useEffect, useMemo, useState } from "react";
import { Bell, FileWarning, Radar, ShieldAlert } from "lucide-react";
import { EmptyState } from "@/components/EmptyState";
import { PageHeader } from "@/components/PageHeader";
import { StatusBadge } from "@/components/StatusBadge";
import { ErrorState, LoadingState } from "@/components/StatePrimitives";
import { PQCReadinessSummary } from "@/components/pqc";
import { Button } from "@/components/ui/button";
import {
  api,
  type CBOMAsset,
  type CBOMInventory,
  type CBOMMigrationProgress,
  type CBOMScan,
  type CTMonitoring,
  type DiscoveryFinding,
  type DiscoveryRun,
  type DiscoverySource,
  type PQCMigration,
  type PQCMigrationRollback,
} from "@/lib/api";
import { formatDateTime as formatDateTimePolicy } from "@/i18n/format";

const emptyCBOMProgress: CBOMMigrationProgress = {
  total_assets: 0,
  out_of_policy_assets: 0,
  quantum_vulnerable_assets: 0,
  post_quantum_ready_assets: 0,
  percent_migrated: 0,
};

export function Posture() {
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
  const [cbomInventory, setCBOMInventory] = useState<CBOMInventory>({ items: [], migration_progress: emptyCBOMProgress });
  const [lastCBOMScan, setLastCBOMScan] = useState<CBOMScan | null>(null);
  const [cbomLoading, setCBOMLoading] = useState(true);
  const [cbomScanning, setCBOMScanning] = useState(false);
  const [cbomError, setCBOMError] = useState<string | null>(null);
  const [lastPQCMigration, setLastPQCMigration] = useState<PQCMigration | null>(null);
  const [lastPQCRollback, setLastPQCRollback] = useState<PQCMigrationRollback | null>(null);
  const [pqcBusy, setPQCBusy] = useState<"start" | "rollback" | null>(null);
  const [pqcError, setPQCError] = useState<string | null>(null);

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
  const pqcCandidates = cbomInventory.items.filter(isPQCMigrationCandidate);
  const pqcCandidateIDs = pqcCandidates.map((asset) => asset.id);
  const pqcTargetAlgorithm = pqcCandidates[0]?.migration_target ?? "ML-KEM hybrid";
  const discoverySourceByID = useMemo(() => new Map(discoverySources.map((source) => [source.id, source])), [discoverySources]);
  const discoveryRunByID = useMemo(() => new Map(discoveryRuns.map((run) => [run.id, run])), [discoveryRuns]);
  const ctFindings = discoveryFindings.filter((finding) => findingSourceKind(finding, discoverySourceByID) === "ct_log");
  const driftFindings = discoveryFindings.filter((finding) => findingSourceKind(finding, discoverySourceByID) === "drift");

  async function queuePQCMigration() {
    if (pqcCandidateIDs.length === 0) return;
    setPQCBusy("start");
    setPQCError(null);
    try {
      const migration = await api.startPQCMigration({
        asset_ids: pqcCandidateIDs,
        target_algorithm: pqcTargetAlgorithm,
        protocol: "x509",
        rollback_on_failure: true,
      });
      setLastPQCMigration(migration);
      setLastPQCRollback(null);
    } catch (error) {
      setPQCError(error instanceof Error ? error.message : "Unable to queue PQC migration");
    } finally {
      setPQCBusy(null);
    }
  }

  async function rollbackPQCMigration() {
    if (!lastPQCMigration || pqcCandidateIDs.length === 0) return;
    setPQCBusy("rollback");
    setPQCError(null);
    try {
      const rollback = await api.rollbackPQCMigration(lastPQCMigration.run_id, {
        asset_ids: pqcCandidateIDs,
        reason: "operator requested rollback",
      });
      setLastPQCRollback(rollback);
    } catch (error) {
      setPQCError(error instanceof Error ? error.message : "Unable to queue PQC rollback");
    } finally {
      setPQCBusy(null);
    }
  }

  return (
    <section aria-labelledby="posture-heading" className="grid gap-6">
      <PageHeader
        titleId="posture-heading"
        title="Posture"
        description="Your fleet's cryptographic health: certificate-transparency findings, configuration drift, and a cryptographic bill of materials (which algorithms you run and how post-quantum-ready they are). For per-credential rotation urgency see Risk; for scan setup see Discovery."
      />

      <section aria-labelledby="ct-heading" className="grid gap-3 border-y border-border py-4">
        <div className="flex items-start gap-3">
          <Radar className="mt-1 h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
          <div>
            <h2 id="ct-heading" className="text-title font-semibold">
              Certificate Transparency monitoring
            </h2>
            <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
              CT monitoring watches public logs for certificates your tenant did not request. The discovery worker polls configured logs, records
              tenant-scoped findings, and dispatches unexpected-issuance alerts through the notification outbox.
            </p>
          </div>
        </div>
        <DiscoveryFindingTable
          title="Certificate Transparency findings"
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
              Watched domains
              <textarea
                id="ct-watched-domains"
                className="ui-input min-h-20 font-mono text-xs"
                value={ctForm.watchedDomains}
                onChange={(event) => setCTForm((current) => ({ ...current, watchedDomains: event.target.value }))}
                placeholder="example.com"
              />
            </label>
            <label className="grid gap-1 text-sm font-medium" htmlFor="ct-log-urls">
              CT log URLs
              <textarea
                id="ct-log-urls"
                className="ui-input min-h-20 font-mono text-xs"
                value={ctForm.logs}
                onChange={(event) => setCTForm((current) => ({ ...current, logs: event.target.value }))}
                placeholder="https://ct.googleapis.com/logs/argon2026/"
              />
            </label>
            <label className="grid gap-1 text-sm font-medium" htmlFor="ct-max-batch">
              Max entries per poll
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
              {ctSaving ? "Saving CT" : "Save and poll CT"}
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
            <PreviewTable title="CT log checkpoints" headers={["Log URL", "Next index"]}>
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
              Drift detection
            </h2>
            <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
              Drift detection compares what trstctl intended to deploy with what the worker can verify from a configured watched credential path.
              Deleted, replaced, relocated, and permission-changed credentials become tenant-scoped Discovery findings.
            </p>
          </div>
        </div>
        <DiscoveryFindingTable
          title="Drift findings"
          findings={driftFindings}
          sourceByID={discoverySourceByID}
          runByID={discoveryRunByID}
          loading={discoveryLoading}
          error={discoveryError}
          emptyTitle="No drift findings returned yet"
        />
      </section>

      <section aria-labelledby="cbom-heading" className="grid gap-3 border-y border-border py-4">
        <div className="flex items-start gap-3">
          <ShieldAlert className="mt-1 h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
          <div>
            <h2 id="cbom-heading" className="text-title font-semibold">
              CBOM and cryptographic observability
            </h2>
            <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
              The CBOM scanner inventories algorithms, key sizes, TLS versions, weak crypto, and PQC posture. The policy floor is RSA-2048, EC-256, and TLS 1.2,
              while 3DES/DES/RC4/NULL/EXPORT/MD5 are banned.
            </p>
          </div>
        </div>
        <form className="grid gap-3 rounded-panel border border-border p-comfortable" onSubmit={handleCBOMScan}>
          <div className="grid gap-3 md:grid-cols-2">
            <label className="grid gap-1 text-sm font-medium" htmlFor="cbom-tls-endpoints">
              TLS endpoints
              <textarea
                id="cbom-tls-endpoints"
                className="ui-input min-h-20 font-mono text-xs"
                name="tls_endpoints"
                placeholder="https://api.example.com:443"
              />
            </label>
            <label className="grid gap-1 text-sm font-medium" htmlFor="cbom-host-configs">
              Host config paths
              <textarea id="cbom-host-configs" className="ui-input min-h-20 font-mono text-xs" name="host_configs" placeholder="/etc/ssh/sshd_config" />
            </label>
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <Button type="submit" disabled={cbomScanning}>
              {cbomScanning ? "Running scan" : "Run CBOM scan"}
            </Button>
            <p className="text-sm text-muted-foreground">
              The request sends endpoint and host-config locators only. Inventory rows are loaded from the tenant-scoped CBOM asset endpoint after the scan.
            </p>
          </div>
          {cbomError ? <p className="text-sm font-medium text-destructive">{cbomError}</p> : null}
        </form>

        <dl className="grid gap-3 md:grid-cols-5">
          <Metric label="Total assets" value={String(cbomProgress.total_assets)} />
          <Metric label="Out of policy" value={`${cbomProgress.out_of_policy_assets} out of policy`} />
          <Metric label="Quantum vulnerable" value={String(cbomProgress.quantum_vulnerable_assets)} />
          <Metric label="PQC ready" value={String(cbomProgress.post_quantum_ready_assets)} />
          <Metric label="Migration" value={`${cbomProgress.percent_migrated}% migrated`} />
        </dl>

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

        <PreviewTable title="CBOM asset inventory" headers={["Asset", "Crypto", "Transport", "Policy", "Migration target", "Evidence"]}>
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
          <EmptyState title="No CBOM assets returned yet">
            Run a scan against TLS endpoints or host config paths. The inventory table stays empty until trstctl returns tenant-scoped assets.
          </EmptyState>
        ) : null}
      </section>

      <section aria-labelledby="crypto-agility-heading" className="grid gap-3 border-y border-border py-4">
        <div className="flex items-start gap-3">
          <ShieldAlert className="mt-1 h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
          <div>
            <h2 id="crypto-agility-heading" className="text-title font-semibold">
              Crypto-agility and PQC readiness
            </h2>
            <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
              Crypto-agility means the system can see weak algorithms, reject disallowed choices, and plan a move to PQC or hybrid algorithms without guessing
              from browser-only state.
            </p>
          </div>
        </div>
        <PQCReadinessSummary progress={cbomProgress} />
        <CBOMReadinessTable assets={cbomInventory.items} loading={cbomLoading} />
      </section>

      <section aria-labelledby="pqc-migration-heading" className="grid gap-3 border-y border-border py-4">
        <div className="flex items-start gap-3">
          <ShieldAlert className="mt-1 h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
          <div>
            <h2 id="pqc-migration-heading" className="text-title font-semibold">
              PQC migration orchestration
            </h2>
            <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
              PQC migration is a staged rollout: inventory first, hybrid canary second, workload rotation third, with rollback and resume points at every wave.
            </p>
          </div>
        </div>
        <div className="grid gap-3 rounded-panel border border-border p-comfortable">
          <dl className="grid gap-3 md:grid-cols-4">
            <Metric label="Candidate assets" value={String(pqcCandidateIDs.length)} />
            <Metric label="Target algorithm" value={pqcTargetAlgorithm} />
            <Metric label="Protocol" value="x509" />
            <Metric label="Rollback" value="enabled" />
          </dl>
          <div className="flex flex-wrap items-center gap-3">
            <Button type="button" onClick={() => void queuePQCMigration()} disabled={pqcBusy === "start" || pqcCandidateIDs.length === 0}>
              {pqcBusy === "start" ? "Queueing migration" : "Queue PQC migration"}
            </Button>
            {lastPQCMigration ? (
              <Button type="button" variant="outline" onClick={() => void rollbackPQCMigration()} disabled={pqcBusy === "rollback" || pqcCandidateIDs.length === 0}>
                {pqcBusy === "rollback" ? "Queueing rollback" : `Rollback migration ${lastPQCMigration.run_id}`}
              </Button>
            ) : null}
            <p className="text-sm text-muted-foreground">
              The queue uses CBOM asset IDs that are out of policy or quantum-vulnerable. Already-ready assets are not included.
            </p>
          </div>
          {pqcError ? <p className="text-sm font-medium text-destructive">{pqcError}</p> : null}
        </div>
        {lastPQCMigration ? (
          <PreviewTable title="PQC migration queue result" headers={["Run", "Queued", "Target", "Effective", "Protocol", "Rollback", "Queued at"]}>
            <tr className="align-top">
              <td className="font-medium">{lastPQCMigration.run_id}</td>
              <td>{lastPQCMigration.queued}</td>
              <td>{lastPQCMigration.target_algorithm}</td>
              <td>{lastPQCMigration.effective_algorithm}</td>
              <td>{lastPQCMigration.protocol}</td>
              <td>{lastPQCMigration.rollback_configured ? "configured" : "not configured"}</td>
              <td>{formatDateTimePolicy(lastPQCMigration.queued_at)}</td>
            </tr>
          </PreviewTable>
        ) : null}
        {lastPQCRollback ? (
          <div className="rounded-panel border border-border p-comfortable text-sm">
            <p className="font-medium">Rollback queued</p>
            <p className="mt-1 text-muted-foreground">
              {lastPQCRollback.queued} asset rollback queued for {lastPQCRollback.run_id}: {lastPQCRollback.reason}
            </p>
          </div>
        ) : null}
      </section>

      <section aria-labelledby="alert-heading" className="ui-panel flex items-start gap-3 p-comfortable text-sm">
        <Bell className="mt-1 h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
        <div>
          <h2 id="alert-heading" className="text-title font-semibold">
            Alert routing is managed from Notifications
          </h2>
          <p className="mt-1 text-muted-foreground">
            CT anomalies and drift findings can be routed through saved notification policies. Channel credentials stay in operator-managed configuration.
          </p>
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

function sourceMaxBatch(state: CTMonitoring): number {
  const raw = state.source?.config;
  if (raw && typeof raw === "object" && !Array.isArray(raw) && "max_batch" in raw) {
    const value = raw.max_batch;
    if (typeof value === "number" && Number.isFinite(value)) return value;
  }
  return 0;
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
  if (loading) return <LoadingState>Loading discovery findings...</LoadingState>;

  return (
    <>
      {error ? <ErrorState title="Discovery findings unavailable">{error}</ErrorState> : null}
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
  if (loading) return <LoadingState>Loading CBOM readiness...</LoadingState>;
  if (assets.length === 0) return <EmptyState title="No CBOM readiness assets returned yet" />;

  return (
    <PreviewTable title="Crypto-agility readiness" headers={["Asset", "Inventory", "Readiness", "Migration target", "Evidence"]}>
      {assets.map((asset) => (
        <tr key={asset.id} className="align-top">
          <td className="font-medium">
            <span className="block">{asset.location}</span>
            <span className="text-xs text-muted-foreground">{asset.kind}</span>
          </td>
          <td>
            {algorithmLabel(asset)}
            {transportLabel(asset) !== "not reported" ? ` / ${transportLabel(asset)}` : ""}
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

function isPQCMigrationCandidate(asset: CBOMAsset): boolean {
  return asset.out_of_policy || asset.quantum_vulnerable;
}

function readinessValue(asset: CBOMAsset): string {
  if (asset.out_of_policy) return "out_of_policy";
  if (asset.quantum_vulnerable) return "quantum_vulnerable";
  return "pqc_ready";
}

function readinessLabel(asset: CBOMAsset): string {
  if (asset.out_of_policy) return "Out of policy";
  if (asset.quantum_vulnerable) return "Quantum vulnerable";
  return "PQC ready";
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
