import { useEffect, useMemo, useRef, useState } from "react";
import type { FormEvent } from "react";
import { CheckCircle2, Activity, ClipboardList, Eye, Play, Plus, RefreshCw, Search, Tag, XCircle } from "lucide-react";
import { useSearchParams } from "react-router-dom";
import { EmptyState } from "@/components/EmptyState";
import { ErrorState, LoadingState, PermissionDeniedState } from "@/components/StatePrimitives";
import { StatusBadge } from "@/components/StatusBadge";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/PageHeader";
import { DiscoveryHero, CTDriftPanel } from "@/components/discovery";
import { useTranslation } from "@/i18n/I18nProvider";
import {
  api,
  ApiError,
  type DiscoveryFinding,
  type DiscoveryMonitoring,
  type DiscoveryRun,
  type DiscoverySchedule,
  type DiscoverySource,
  type DiscoverySourceRequest,
  type NHIDecommissionRequest,
  type NHIShadowPosture,
  type RemediationPlaybookRunRequest,
} from "@/lib/api";
import { formatDateTime as formatDateTimePolicy } from "@/i18n/format";
import type { MessageKey } from "@/i18n/messages";

type Notice = { kind: "permission" | "error" | "success"; message: string };
type SourceKind = DiscoverySourceRequest["kind"];
type FindingTriageStatus = NonNullable<DiscoveryFinding["triage_status"]>;
type FindingTriageFilter = "all" | FindingTriageStatus;
type FindingFacetFilter = string;
type FindingFilters = { triage: FindingTriageFilter; owner: FindingFacetFilter; team: FindingFacetFilter; tag: FindingFacetFilter };
type FindingLifecycleAction = "rotate" | "revoke" | "decommission" | "remediate";

const remediationPlaybookRevokeIdentity = "identity-revoke";
const remediationPlaybookRotateIdentity = "credential-rotate";

const sourceKinds: SourceKind[] = [
  "network",
  "ssh",
  "cloud_certificate",
  "cloud_secret",
  "ct_log",
  "drift",
  "secret_store",
  "api_key",
  "agent",
  "manual",
  "nhi_cross_surface",
  "oauth_grant",
  "service_account",
  "nhi_behavior",
  "credential_compromise",
  "k8s_ingress_gateway",
];
const sourceKindLabels: Record<SourceKind, string> = {
  network: "Network",
  ssh: "SSH",
  cloud_certificate: "Cloud certificates",
  cloud_secret: "Cloud secrets",
  ct_log: "Certificate Transparency",
  drift: "Drift",
  secret_store: "Secret stores",
  api_key: "API keys",
  agent: "Agent",
  manual: "Manual",
  nhi_cross_surface: "NHI surfaces",
  oauth_grant: "OAuth grants",
  service_account: "Service accounts",
  nhi_behavior: "NHI behavior",
  credential_compromise: "Compromised credentials",
  k8s_ingress_gateway: "Kubernetes TLS",
};
const triageFilterOptions = [
  { value: "all", labelKey: "discovery.findings.filterStatusAll" },
  { value: "unmanaged", labelKey: "discovery.findings.statusUnmanaged" },
  { value: "investigating", labelKey: "discovery.findings.statusInvestigating" },
  { value: "managed", labelKey: "discovery.findings.statusManaged" },
  { value: "dismissed", labelKey: "discovery.findings.statusDismissed" },
] as const;
const triageStatusLabelKeys: Record<FindingTriageStatus, MessageKey> = {
  unmanaged: "discovery.findings.statusUnmanaged",
  investigating: "discovery.findings.statusInvestigating",
  managed: "discovery.findings.statusManaged",
  dismissed: "discovery.findings.statusDismissed",
};

export function Discovery() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [sources, setSources] = useState<DiscoverySource[]>([]);
  const [schedules, setSchedules] = useState<DiscoverySchedule[]>([]);
  const [runs, setRuns] = useState<DiscoveryRun[]>([]);
  const [findings, setFindings] = useState<DiscoveryFinding[]>([]);
  const [monitoring, setMonitoring] = useState<DiscoveryMonitoring | null>(null);
  const [shadowPosture, setShadowPosture] = useState<NHIShadowPosture | null>(null);
  const [notice, setNotice] = useState<Notice | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState<string | null>(null);
  const [sourceName, setSourceName] = useState("");
  const [sourceKind, setSourceKind] = useState<SourceKind>("network");
  const [targets, setTargets] = useState("");
  const [tokenObservations, setTokenObservations] = useState("");
  const [nhiObservations, setNHIObservations] = useState("");
  const [oauthGrants, setOAuthGrants] = useState("");
  const [serviceAccounts, setServiceAccounts] = useState("");
  const [behaviorEvents, setBehaviorEvents] = useState("");
  const [compromiseSignals, setCompromiseSignals] = useState("");
  const [k8sResources, setK8sResources] = useState("");
  const [scheduleName, setScheduleName] = useState("");
  const [scheduleSourceID, setScheduleSourceID] = useState("");
  const [scheduleInterval, setScheduleInterval] = useState(3600);
  const sourceNameRef = useRef<HTMLInputElement>(null);
  const scheduleNameRef = useRef<HTMLInputElement>(null);

  async function load() {
    setLoading(true);
    setNotice(null);
    const [sourceResult, scheduleResult, runResult, monitoringResult, shadowPostureResult, findingResult] = await Promise.allSettled([
      api.discoverySources({ limit: 50 }),
      api.discoverySchedules({ limit: 50 }),
      api.discoveryRuns({ limit: 50 }),
      api.discoveryMonitoring(),
      api.nhiShadowPosture(),
      api.discoveryFindings({ limit: 50 }),
    ]);
    if (sourceResult.status === "fulfilled") setSources(sourceResult.value.items ?? []);
    else setSources([]);
    if (scheduleResult.status === "fulfilled") setSchedules(scheduleResult.value.items ?? []);
    else setSchedules([]);
    if (runResult.status === "fulfilled") setRuns(runResult.value.items ?? []);
    else setRuns([]);
    if (monitoringResult.status === "fulfilled") setMonitoring(monitoringResult.value);
    else setMonitoring(null);
    if (shadowPostureResult.status === "fulfilled") setShadowPosture(shadowPostureResult.value);
    else setShadowPosture(null);
    if (findingResult.status === "fulfilled") setFindings(findingResult.value.items ?? []);
    else setFindings([]);
    const rejected = [sourceResult, scheduleResult, runResult, monitoringResult, shadowPostureResult, findingResult].find((result) => result.status === "rejected");
    if (rejected?.status === "rejected") setNotice(noticeForError(rejected.reason, "Could not load discovery records"));
    setLoading(false);
  }

  useEffect(() => {
    void load();
  }, []);

  useEffect(() => {
    if (!scheduleSourceID && sources[0]) setScheduleSourceID(sources[0].id);
  }, [scheduleSourceID, sources]);

  const sourceByID = useMemo(() => new Map(sources.map((source) => [source.id, source])), [sources]);
  const findingFilters = useMemo<FindingFilters>(
    () => ({
      triage: triageFilterFromSearchParam(searchParams.get("triage")),
      owner: searchParams.get("owner") || "all",
      team: searchParams.get("team") || "all",
      tag: searchParams.get("tag") || "all",
    }),
    [searchParams],
  );
  const findingFacetOptions = useMemo(() => findingFacets(findings), [findings]);
  const filteredFindings = useMemo(() => applyFindingFilters(findings, findingFilters), [findings, findingFilters]);

  function setFindingFilter(key: keyof FindingFilters, value: string) {
    setSearchParams(
      (current) => {
        const next = new URLSearchParams(current);
        if (value === "all" || value === "") {
          next.delete(key);
        } else {
          next.set(key, value);
        }
        return next;
      },
      { replace: true },
    );
  }

  function replaceFinding(updated: DiscoveryFinding) {
    setFindings((current) => current.map((finding) => (finding.id === updated.id ? updated : finding)));
  }

  async function createSource(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy("source");
    setNotice(null);
    try {
      const config =
        sourceKind === "network"
          ? { targets: parseTargets(targets) }
          : sourceKind === "api_key"
          ? { observations: parseTokenObservations(tokenObservations) }
          : sourceKind === "nhi_cross_surface"
          ? { observations: parseNHIObservations(nhiObservations) }
          : sourceKind === "oauth_grant"
          ? { grants: parseOAuthGrants(oauthGrants) }
          : sourceKind === "service_account"
          ? { accounts: parseServiceAccounts(serviceAccounts) }
          : sourceKind === "nhi_behavior"
          ? { events: parseBehaviorEvents(behaviorEvents), business_hours: { start_hour: 8, end_hour: 18 } }
          : sourceKind === "credential_compromise"
          ? { signals: parseCompromiseSignals(compromiseSignals) }
          : sourceKind === "k8s_ingress_gateway"
          ? { resources: parseKubernetesTLSResources(k8sResources) }
          : {};
      const created = await api.createDiscoverySource({ name: sourceName.trim(), kind: sourceKind, config });
      setSourceName("");
      setTargets("");
      setTokenObservations("");
      setNHIObservations("");
      setOAuthGrants("");
      setServiceAccounts("");
      setBehaviorEvents("");
      setCompromiseSignals("");
      setK8sResources("");
      setScheduleSourceID(created.id);
      await load();
    } catch (err) {
      setNotice(noticeForError(err, "Could not create discovery source"));
    } finally {
      setBusy(null);
    }
  }

  async function createSchedule(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy("schedule");
    setNotice(null);
    try {
      await api.createDiscoverySchedule({
        source_id: scheduleSourceID,
        name: scheduleName.trim(),
        interval_seconds: scheduleInterval,
        enabled: true,
      });
      setScheduleName("");
      await load();
    } catch (err) {
      setNotice(noticeForError(err, "Could not create discovery schedule"));
    } finally {
      setBusy(null);
    }
  }

  async function startRun(sourceID: string, dryRun = false) {
    setBusy(`run:${sourceID}:${dryRun}`);
    setNotice(null);
    try {
      await api.startDiscoveryRun({ source_id: sourceID, dry_run: dryRun });
      await load();
    } catch (err) {
      setNotice(noticeForError(err, "Could not start discovery run"));
    } finally {
      setBusy(null);
    }
  }

  function focusSourceForm() {
    sourceNameRef.current?.scrollIntoView({ block: "center" });
    sourceNameRef.current?.focus();
  }

  function focusScheduleForm() {
    scheduleNameRef.current?.scrollIntoView({ block: "center" });
    scheduleNameRef.current?.focus();
  }

  return (
    <section aria-labelledby="discovery-heading" className="grid gap-6">
      <PageHeader
        titleId="discovery-heading"
        title="Discovery"
        description="Manage tenant discovery sources, schedules, runs, and findings."
        actions={
          <Button type="button" variant="outline" onClick={() => void load()} disabled={loading}>
            <RefreshCw className={loading ? "h-4 w-4 animate-spin" : "h-4 w-4"} aria-hidden="true" />
            Refresh
          </Button>
        }
      />

      <DiscoveryHero findings={findings} />
      <CTDriftPanel findings={findings} sources={sources} />
      <MonitoringPanel monitoring={monitoring} onCreateSource={focusSourceForm} />
      <ShadowPosturePanel posture={shadowPosture} />

      {notice && renderNotice(notice)}
      {loading && <LoadingState>Loading discovery records...</LoadingState>}

      <div className="grid gap-4 xl:grid-cols-[1.2fr_0.8fr]">
        <form aria-labelledby="source-form-heading" className="ui-panel grid gap-4 p-comfortable" onSubmit={createSource}>
          <div className="flex items-center gap-2">
            <Search className="h-4 w-4 text-muted-foreground" aria-hidden="true" />
            <h2 id="source-form-heading" className="text-title font-semibold">
              Source
            </h2>
          </div>
          <div className="grid gap-3 md:grid-cols-[1fr_14rem]">
            <label className="grid gap-1 text-sm font-medium">
              Name
              <input id="discovery-source-name" ref={sourceNameRef} className="ui-input" value={sourceName} onChange={(event) => setSourceName(event.target.value)} required />
            </label>
            <label className="grid gap-1 text-sm font-medium">
              Kind
              <select className="ui-input" value={sourceKind} onChange={(event) => setSourceKind(event.target.value as SourceKind)}>
                {sourceKinds.map((kind) => (
                  <option key={kind} value={kind}>
                    {sourceKindLabels[kind]}
                  </option>
                ))}
              </select>
            </label>
          </div>
          {sourceKind === "network" && (
            <label className="grid gap-1 text-sm font-medium">
              Targets
              <textarea
                className="ui-input min-h-24 font-mono text-xs"
                value={targets}
                onChange={(event) => setTargets(event.target.value)}
                placeholder="10.0.0.10:443"
                required
              />
            </label>
          )}
          {sourceKind === "nhi_cross_surface" && (
            <label className="grid gap-1 text-sm font-medium">
              Observations JSON
              <textarea
                className="ui-input min-h-40 font-mono text-xs"
                value={nhiObservations}
                onChange={(event) => setNHIObservations(event.target.value)}
                placeholder='[{"surface":"idp","system":"okta","external_id":"app/payments","principal":"payments-api","owner":"platform","credential_kind":"oauth_client"}]'
                required
              />
            </label>
          )}
          {sourceKind === "api_key" && (
            <label className="grid gap-1 text-sm font-medium">
              Observations JSON
              <textarea
                className="ui-input min-h-40 font-mono text-xs"
                value={tokenObservations}
                onChange={(event) => setTokenObservations(event.target.value)}
                placeholder='[{"surface":"saas","system":"github","external_id":"user/payments-ci/pat","principal":"payments-ci","credential_kind":"personal_access_token","credential_ref":"github:user/payments-ci/pat","masked_fingerprint":"sha256:github-pat-ref","evidence_refs":["github:audit/pat-1"]}]'
                required
              />
            </label>
          )}
          {sourceKind === "oauth_grant" && (
            <label className="grid gap-1 text-sm font-medium">
              OAuth grants JSON
              <textarea
                className="ui-input min-h-40 font-mono text-xs"
                value={oauthGrants}
                onChange={(event) => setOAuthGrants(event.target.value)}
                placeholder='[{"provider":"entra-id","app_id":"evil-consent-app","principal":"legacy-mail-archive","resource":"microsoft-graph","scopes":["offline_access","Directory.ReadWrite.All","*.default"],"consent_type":"admin","third_party":true,"publisher_verified":false,"threat_signals":["consent_phishing"],"evidence_refs":["entra:audit/consent-42"]}]'
                required
              />
            </label>
          )}
          {sourceKind === "service_account" && (
            <label className="grid gap-1 text-sm font-medium">
              Service accounts JSON
              <textarea
                className="ui-input min-h-40 font-mono text-xs"
                value={serviceAccounts}
                onChange={(event) => setServiceAccounts(event.target.value)}
                placeholder='[{"surface":"active_directory","provider":"ad","directory":"corp.example","account_id":"S-1-5-21-1000","principal":"svc-payments@corp.example","owner":"identity"},{"surface":"cloud","provider":"aws-iam","directory":"111111111111","account_id":"role/payments-prod","principal":"arn:aws:iam::111111111111:role/payments-prod","owner":"platform","privileged":true}]'
                required
              />
            </label>
          )}
          {sourceKind === "nhi_behavior" && (
            <label className="grid gap-1 text-sm font-medium">
              Behavior events JSON
              <textarea
                className="ui-input min-h-40 font-mono text-xs"
                value={behaviorEvents}
                onChange={(event) => setBehaviorEvents(event.target.value)}
                placeholder='[{"principal":"payments-api","occurred_at":"2026-06-01T10:00:00Z","ip":"198.51.100.10","geo":"US","user_agent":"payments-agent/1.0","usage_count":10,"baseline":true}]'
                required
              />
            </label>
          )}
          {sourceKind === "k8s_ingress_gateway" && (
            <label className="grid gap-1 text-sm font-medium">
              Kubernetes resources JSON
              <textarea
                className="ui-input min-h-40 font-mono text-xs"
                value={k8sResources}
                onChange={(event) => setK8sResources(event.target.value)}
                placeholder='[{"kind":"Ingress","namespace":"payments","name":"payments-web","tls_secret_name":"payments-web-tls","hosts":["payments.example.com"],"auto_issue":true}]'
                required
              />
            </label>
          )}
          {sourceKind === "credential_compromise" && (
            <label className="grid gap-1 text-sm font-medium">
              Compromise signals JSON
              <textarea
                className="ui-input min-h-40 font-mono text-xs"
                value={compromiseSignals}
                onChange={(event) => setCompromiseSignals(event.target.value)}
                placeholder='[{"principal":"payments-api","credential_ref":"api-token:payments-ci","credential_kind":"api_token","provider":"github-actions","detector":"honeytoken","observed_at":"2026-06-03T03:15:00Z","reason":"revoked token replayed from unfamiliar network","confidence":"critical","evidence_refs":["audit:api-token-use/evt-42"]}]'
                required
              />
            </label>
          )}
          <Button type="submit" className="justify-self-start" disabled={busy === "source"}>
            <Plus className="h-4 w-4" aria-hidden="true" />
            Create source
          </Button>
        </form>

        <form aria-labelledby="schedule-form-heading" className="ui-panel grid gap-4 p-comfortable" onSubmit={createSchedule}>
          <div className="flex items-center gap-2">
            <ClipboardList className="h-4 w-4 text-muted-foreground" aria-hidden="true" />
            <h2 id="schedule-form-heading" className="text-title font-semibold">
              Schedule
            </h2>
          </div>
          <label className="grid gap-1 text-sm font-medium">
            Source
            <select className="ui-input" value={scheduleSourceID} onChange={(event) => setScheduleSourceID(event.target.value)} required>
              {sources.length === 0 && <option value="">No source</option>}
              {sources.map((source) => (
                <option key={source.id} value={source.id}>
                  {source.name}
                </option>
              ))}
            </select>
          </label>
          <label className="grid gap-1 text-sm font-medium">
            Name
            <input id="discovery-schedule-name" ref={scheduleNameRef} className="ui-input" value={scheduleName} onChange={(event) => setScheduleName(event.target.value)} required />
          </label>
          <label className="grid gap-1 text-sm font-medium">
            Interval seconds
            <input
              className="ui-input"
              type="number"
              min={60}
              step={60}
              value={scheduleInterval}
              onChange={(event) => setScheduleInterval(Number(event.target.value))}
              required
            />
          </label>
          <Button type="submit" className="justify-self-start" disabled={busy === "schedule" || sources.length === 0}>
            <Plus className="h-4 w-4" aria-hidden="true" />
            Create schedule
          </Button>
        </form>
      </div>

      <section aria-labelledby="sources-heading" className="grid gap-3 border-y border-border py-4">
        <h2 id="sources-heading" className="text-title font-semibold">
          Sources
        </h2>
        {!loading && sources.length === 0 ? (
          <EmptyState
            icon={<Search className="h-5 w-5" aria-hidden="true" />}
            title="No discovery sources"
            primaryAction={{ label: "Create first source", onClick: focusSourceForm, icon: <Plus className="h-4 w-4" /> }}
            secondaryAction={{ label: "Enroll an agent", to: "/agents", icon: <Search className="h-4 w-4" /> }}
          >
            Add a network, cloud, CT log, NHI, OAuth, service-account, behavior, compromise, or agent source before discovery runs can be queued.
          </EmptyState>
        ) : (
          <SourceTable sources={sources} busy={busy} onStart={startRun} />
        )}
      </section>

      <section aria-labelledby="schedules-heading" className="grid gap-3 border-y border-border py-4">
        <h2 id="schedules-heading" className="text-title font-semibold">
          Schedules
        </h2>
        {!loading && schedules.length === 0 ? (
          <EmptyState
            icon={<ClipboardList className="h-5 w-5" aria-hidden="true" />}
            title="No discovery schedules"
            primaryAction={{ label: sources.length > 0 ? "Create schedule" : "Create source first", onClick: sources.length > 0 ? focusScheduleForm : focusSourceForm, icon: <Plus className="h-4 w-4" /> }}
            secondaryAction={{ label: "Refresh records", onClick: () => void load(), icon: <RefreshCw className="h-4 w-4" /> }}
          >
            Schedule a recurring scan once a source exists, or refresh to pick up work created by another operator.
          </EmptyState>
        ) : (
          <ScheduleTable schedules={schedules} sourceByID={sourceByID} />
        )}
      </section>

      <section aria-labelledby="runs-heading" className="grid gap-3 border-y border-border py-4">
        <h2 id="runs-heading" className="text-title font-semibold">
          Runs
        </h2>
        {!loading && runs.length === 0 ? (
          <EmptyState
            icon={<Play className="h-5 w-5" aria-hidden="true" />}
            title="No discovery runs"
            primaryAction={{ label: "Create source to run", onClick: focusSourceForm, icon: <Plus className="h-4 w-4" /> }}
            secondaryAction={{ label: "View certificates", to: "/certificates", icon: <Search className="h-4 w-4" /> }}
          >
            Runs appear here after a source is created and a tenant-scoped scan is queued.
          </EmptyState>
        ) : (
          <RunTable runs={runs} sourceByID={sourceByID} />
        )}
      </section>

      <section aria-labelledby="findings-heading" className="grid gap-3 border-y border-border py-4">
        <h2 id="findings-heading" className="text-title font-semibold">
          Findings
        </h2>
        {!loading && findings.length === 0 ? (
          <EmptyState
            icon={<Search className="h-5 w-5" aria-hidden="true" />}
            title="No discovery findings"
            primaryAction={{ label: "Create discovery source", onClick: focusSourceForm, icon: <Plus className="h-4 w-4" /> }}
            secondaryAction={{ label: "Open posture", to: "/posture", icon: <Search className="h-4 w-4" /> }}
          >
            Findings populate after discovery observes certificates, secrets, SSH trust, or drift.
          </EmptyState>
        ) : (
          <FindingTable
            findings={filteredFindings}
            allFindings={findings}
            sourceByID={sourceByID}
            filters={findingFilters}
            facetOptions={findingFacetOptions}
            onFilterChange={setFindingFilter}
            onFindingUpdated={replaceFinding}
            onNotice={setNotice}
          />
        )}
      </section>
    </section>
  );
}

function ShadowPosturePanel({ posture }: { posture: NHIShadowPosture | null }) {
  const { t } = useTranslation();
  if (!posture) return null;
  const kindCounts = topRecordEntries(posture.summary.kind_counts, 4);
  const surfaceCounts = topRecordEntries(posture.summary.surface_counts, 4);
  const findings = posture.findings.slice(0, 4);
  return (
    <section aria-labelledby="shadow-posture-heading" className="grid gap-3 border-y border-border py-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <Search className="h-4 w-4 text-muted-foreground" aria-hidden="true" />
          <h2 id="shadow-posture-heading" className="text-title font-semibold">
            {t("discovery.shadow.heading")}
          </h2>
        </div>
        <span className="rounded-full border border-border px-2 py-1 font-mono text-xs text-muted-foreground">{posture.capability}</span>
      </div>
      <div className="grid gap-3 md:grid-cols-3 xl:grid-cols-6">
        <ShadowMetric label={t("discovery.shadow.metricFindings")} value={posture.summary.findings} />
        <ShadowMetric label={t("discovery.shadow.metricUnmanaged")} value={posture.summary.unmanaged} />
        <ShadowMetric label={t("discovery.shadow.metricUnregistered")} value={posture.summary.unregistered} />
        <ShadowMetric label={t("discovery.shadow.metricOwnerless")} value={posture.summary.ownerless} />
        <ShadowMetric label={t("discovery.shadow.metricHigh")} value={posture.summary.high + posture.summary.critical} />
        <ShadowMetric label={t("discovery.shadow.metricAnalyzed")} value={posture.summary.total_analyzed} />
      </div>
      <div className="grid gap-4 xl:grid-cols-[0.7fr_1.3fr]">
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-1">
          <ShadowBreakdown title={t("discovery.shadow.kindBreakdown")} entries={kindCounts} />
          <ShadowBreakdown title={t("discovery.shadow.surfaceBreakdown")} entries={surfaceCounts} />
        </div>
        <div className="ui-panel overflow-x-auto">
          <table className="ui-table min-w-[54rem]">
            <caption className="sr-only">{t("discovery.shadow.caption")}</caption>
            <thead>
              <tr>
                <th scope="col">{t("discovery.findings.columnReference")}</th>
                <th scope="col">{t("discovery.findings.columnKind")}</th>
                <th scope="col">{t("discovery.shadow.columnSurface")}</th>
                <th scope="col">{t("discovery.shadow.columnSeverity")}</th>
                <th scope="col">{t("discovery.shadow.columnRecommendation")}</th>
              </tr>
            </thead>
            <tbody>
              {findings.length === 0 ? (
                <tr>
                  <td colSpan={5} className="py-8 text-center text-sm text-muted-foreground">
                    {t("discovery.shadow.empty")}
                  </td>
                </tr>
              ) : (
                findings.map((finding) => (
                  <tr key={finding.finding_id} className="align-top">
                    <td className="font-medium">{finding.ref}</td>
                    <td>{finding.kind}</td>
                    <td>{finding.surface || "-"}</td>
                    <td>
                      <span className={`inline-flex rounded-full border px-2 py-1 text-xs font-medium ${severityTone(finding.severity)}`}>{finding.severity}</span>
                    </td>
                    <td className="max-w-[26rem] text-sm">{finding.recommendation}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </section>
  );
}

function ShadowMetric({ label, value }: { label: string; value: number }) {
  return (
    <div className="ui-panel p-3">
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className="text-title font-semibold">{value}</div>
    </div>
  );
}

function ShadowBreakdown({ title, entries }: { title: string; entries: { key: string; value: number }[] }) {
  return (
    <div className="ui-panel grid gap-2 p-3">
      <h3 className="text-sm font-semibold">{title}</h3>
      {entries.length === 0 ? (
        <div className="text-sm text-muted-foreground">-</div>
      ) : (
        <dl className="grid gap-2">
          {entries.map((entry) => (
            <div key={entry.key} className="flex items-center justify-between gap-3 text-sm">
              <dt className="break-words text-muted-foreground">{entry.key}</dt>
              <dd className="font-semibold">{entry.value}</dd>
            </div>
          ))}
        </dl>
      )}
    </div>
  );
}

function topRecordEntries(value: unknown, limit: number): { key: string; value: number }[] {
  if (!value || typeof value !== "object" || Array.isArray(value)) return [];
  return Object.entries(value as Record<string, unknown>)
    .map(([key, raw]) => ({ key, value: typeof raw === "number" ? raw : Number(raw) }))
    .filter((entry) => entry.key && Number.isFinite(entry.value) && entry.value > 0)
    .sort((a, b) => b.value - a.value || a.key.localeCompare(b.key))
    .slice(0, limit);
}

function severityTone(severity: string): string {
  switch (severity) {
    case "critical":
      return "border-status-danger/60 bg-status-danger/15 text-status-danger";
    case "high":
      return "border-status-warning/60 bg-status-warning/15 text-status-warning";
    case "medium":
      return "border-accent/40 bg-accent/10 text-accent-foreground";
    default:
      return "border-muted-foreground/30 bg-muted text-muted-foreground";
  }
}

function MonitoringPanel({ monitoring, onCreateSource }: { monitoring: DiscoveryMonitoring | null; onCreateSource: () => void }) {
  const { t } = useTranslation();
  if (!monitoring) return null;
  return (
    <section aria-labelledby="monitoring-heading" className="grid gap-3 border-y border-border py-4">
      <div className="flex items-center gap-2">
        <Activity className="h-4 w-4 text-muted-foreground" aria-hidden="true" />
        <h2 id="monitoring-heading" className="text-title font-semibold">
          {t("discovery.monitoring.heading")}
        </h2>
      </div>
      <div className="grid gap-3 md:grid-cols-3 xl:grid-cols-6">
        <MonitoringMetric label={t("discovery.monitoring.metricSources")} value={monitoring.summary.source_count} />
        <MonitoringMetric label={t("discovery.monitoring.metricScheduled")} value={monitoring.summary.scheduled_source_count} />
        <MonitoringMetric label={t("discovery.monitoring.metricActive")} value={monitoring.summary.active_monitoring_count} />
        <MonitoringMetric label={t("discovery.monitoring.metricRuns")} value={monitoring.summary.completed_run_count} />
        <MonitoringMetric label={t("discovery.monitoring.metricFindings")} value={monitoring.summary.finding_count} />
        <MonitoringMetric label={t("discovery.monitoring.metricInventory")} value={monitoring.summary.certificate_inventory_count} />
      </div>
      {monitoring.sources.length === 0 ? (
        <EmptyState
          icon={<Activity className="h-5 w-5" aria-hidden="true" />}
          title={t("discovery.monitoring.emptyTitle")}
          primaryAction={{ label: t("discovery.monitoring.createSource"), onClick: onCreateSource, icon: <Plus className="h-4 w-4" /> }}
        >
          {t("discovery.monitoring.emptyBody")}
        </EmptyState>
      ) : (
        <div className="ui-panel overflow-x-auto">
          <table className="ui-table min-w-[68rem]">
            <caption className="sr-only">{t("discovery.monitoring.caption")}</caption>
            <thead>
              <tr>
                <th scope="col">{t("discovery.monitoring.columnSource")}</th>
                <th scope="col">{t("discovery.monitoring.columnSchedule")}</th>
                <th scope="col">{t("discovery.monitoring.columnLastRun")}</th>
                <th scope="col">{t("discovery.monitoring.columnFindings")}</th>
                <th scope="col">{t("discovery.monitoring.columnInventory")}</th>
                <th scope="col">{t("discovery.monitoring.columnRepository")}</th>
              </tr>
            </thead>
            <tbody>
              {monitoring.sources.map((source) => (
                <tr key={source.source_id} className="align-top">
                  <td>
                    <div className="font-medium">{source.name}</div>
                    <div className="text-xs text-muted-foreground">{sourceKindLabel(source.kind)}</div>
                  </td>
                  <td>
                    <StatusBadge vocabulary="lifecycle" value={source.scheduled ? "active" : "queued"} />
                    <div className="mt-1 text-xs text-muted-foreground">
                      {source.scheduled ? formatInterval(source.monitoring_interval_seconds, t("discovery.monitoring.unscheduled")) : t("discovery.monitoring.unscheduled")}
                    </div>
                  </td>
                  <td>
                    <StatusBadge vocabulary="lifecycle" value={source.last_run_status || "queued"} />
                    <div className="mt-1 text-xs text-muted-foreground">{formatDateTime(source.last_run_completed_at)}</div>
                  </td>
                  <td>{source.finding_count}</td>
                  <td>{source.certificate_inventory_count}</td>
                  <td className="font-mono text-xs">
                    <div>{source.repository_path}</div>
                    <div>{source.findings_path}</div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

function MonitoringMetric({ label, value }: { label: string; value: number }) {
  return (
    <div className="ui-panel p-3">
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className="text-title font-semibold">{value}</div>
    </div>
  );
}

function SourceTable({ sources, busy, onStart }: { sources: DiscoverySource[]; busy: string | null; onStart: (sourceID: string, dryRun?: boolean) => void }) {
  return (
    <div className="ui-panel overflow-x-auto">
      <table className="ui-table min-w-[56rem]">
        <caption className="sr-only">Discovery sources</caption>
        <thead>
          <tr>
            <th scope="col">Name</th>
            <th scope="col">Kind</th>
            <th scope="col">Targets</th>
            <th scope="col">Updated</th>
            <th scope="col">Actions</th>
          </tr>
        </thead>
        <tbody>
          {sources.map((source) => (
            <tr key={source.id} className="align-top">
              <td className="font-medium">{source.name}</td>
              <td>{sourceKindLabels[source.kind] ?? source.kind}</td>
              <td className="font-mono text-xs">{targetCount(source)}</td>
              <td>{formatDateTime(source.updated_at)}</td>
              <td>
                <div className="flex flex-wrap gap-2">
                  <Button type="button" size="sm" onClick={() => onStart(source.id, false)} disabled={busy?.startsWith(`run:${source.id}`)}>
                    <Play className="h-4 w-4" aria-hidden="true" />
                    Run
                  </Button>
                  <Button type="button" size="sm" variant="outline" onClick={() => onStart(source.id, true)} disabled={busy?.startsWith(`run:${source.id}`)}>
                    Dry run
                  </Button>
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function ScheduleTable({ schedules, sourceByID }: { schedules: DiscoverySchedule[]; sourceByID: Map<string, DiscoverySource> }) {
  return (
    <div className="ui-panel overflow-x-auto">
      <table className="ui-table min-w-[44rem]">
        <caption className="sr-only">Discovery schedules</caption>
        <thead>
          <tr>
            <th scope="col">Name</th>
            <th scope="col">Source</th>
            <th scope="col">Interval</th>
            <th scope="col">Enabled</th>
            <th scope="col">Updated</th>
          </tr>
        </thead>
        <tbody>
          {schedules.map((schedule) => (
            <tr key={schedule.id} className="align-top">
              <td className="font-medium">{schedule.name}</td>
              <td>{sourceByID.get(schedule.source_id)?.name ?? schedule.source_id}</td>
              <td>{schedule.interval_seconds}s</td>
              <td>{schedule.enabled ? "yes" : "no"}</td>
              <td>{formatDateTime(schedule.updated_at)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function RunTable({ runs, sourceByID }: { runs: DiscoveryRun[]; sourceByID: Map<string, DiscoverySource> }) {
  return (
    <div className="ui-panel overflow-x-auto">
      <table className="ui-table min-w-[58rem]">
        <caption className="sr-only">Discovery runs</caption>
        <thead>
          <tr>
            <th scope="col">Run</th>
            <th scope="col">Source</th>
            <th scope="col">Status</th>
            <th scope="col">Targets</th>
            <th scope="col">Discovered</th>
            <th scope="col">Failed</th>
            <th scope="col">Completed</th>
          </tr>
        </thead>
        <tbody>
          {runs.map((run) => (
            <tr key={run.id} className="align-top">
              <td className="font-mono text-xs">{shortID(run.id)}</td>
              <td>{sourceByID.get(run.source_id)?.name ?? run.source_id}</td>
              <td>
                <StatusBadge vocabulary="lifecycle" value={run.status} />
              </td>
              <td>{run.targets}</td>
              <td>{run.discovered}</td>
              <td>{run.failed + run.rejected}</td>
              <td>{formatDateTime(run.completed_at)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function FindingTable({
  findings,
  allFindings,
  sourceByID,
  filters,
  facetOptions,
  onFilterChange,
  onFindingUpdated,
  onNotice,
}: {
  findings: DiscoveryFinding[];
  allFindings: DiscoveryFinding[];
  sourceByID: Map<string, DiscoverySource>;
  filters: FindingFilters;
  facetOptions: { owners: string[]; teams: string[]; tags: string[] };
  onFilterChange: (key: keyof FindingFilters, value: string) => void;
  onFindingUpdated: (finding: DiscoveryFinding) => void;
  onNotice: (notice: Notice | null) => void;
}) {
  const { t } = useTranslation();
  const [selectedID, setSelectedID] = useState<string | null>(null);
  const [action, setAction] = useState<"claim" | "dismiss" | null>(null);
  const [reason, setReason] = useState("");
  const [managedIdentityID, setManagedIdentityID] = useState("");
  const [owner, setOwner] = useState("");
  const [team, setTeam] = useState("");
  const [tagText, setTagText] = useState("");
  const [actionBusy, setActionBusy] = useState(false);
  const selected = selectedID ? allFindings.find((finding) => finding.id === selectedID) ?? null : null;

  function populateFacetInputs(finding: DiscoveryFinding) {
    setOwner(findingOwner(finding));
    setTeam(findingTeam(finding));
    setTagText(findingTags(finding).join(", "));
  }

  function openDetail(finding: DiscoveryFinding) {
    setSelectedID(finding.id);
    setAction(null);
    setReason("");
    setManagedIdentityID(finding.managed_identity_id ?? "");
    populateFacetInputs(finding);
  }

  function openAction(finding: DiscoveryFinding, nextAction: "claim" | "dismiss") {
    setSelectedID(finding.id);
    setAction(nextAction);
    setReason(finding.triage_reason ?? "");
    setManagedIdentityID(finding.managed_identity_id ?? "");
    populateFacetInputs(finding);
  }

  async function submitAction(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selected || !action) return;
    setActionBusy(true);
    onNotice(null);
    try {
      const input = {
        managed_identity_id: action === "claim" ? managedIdentityID.trim() || undefined : undefined,
        reason: reason.trim() || undefined,
        owner: owner.trim(),
        team: team.trim(),
        tags: parseFindingTagInput(tagText),
      };
      const updated =
        action === "claim"
          ? await api.claimDiscoveryFinding(selected.id, input)
          : await api.dismissDiscoveryFinding(selected.id, { reason: input.reason, owner: input.owner, team: input.team, tags: input.tags });
      onFindingUpdated(updated);
      setSelectedID(updated.id);
      setAction(null);
      setReason("");
      setManagedIdentityID(updated.managed_identity_id ?? "");
      populateFacetInputs(updated);
    } catch (err) {
      onNotice(noticeForError(err, action === "claim" ? t("discovery.findings.claimError") : t("discovery.findings.dismissError")));
    } finally {
      setActionBusy(false);
    }
  }

  async function runFindingLifecycleAction(finding: DiscoveryFinding, nextAction: FindingLifecycleAction) {
    const identityID = findingActionIdentityID(finding);
    if (!identityID) {
      openAction(finding, "claim");
      onNotice({ kind: "error", message: t("discovery.findings.identityRequired") });
      return;
    }

    const reason = findingActionReason(finding);
    setActionBusy(true);
    onNotice(null);
    try {
      if (nextAction === "revoke") {
        await api.transitionIdentity(identityID, "revoked", reason);
        onNotice({ kind: "success", message: t("discovery.findings.revokeQueued", { ref: finding.ref }) });
        return;
      }

      if (nextAction === "decommission") {
        const request: NHIDecommissionRequest = {
          reason,
          revocation_reason: "keyCompromise",
          signals: [
            {
              type: "inactivity",
              identity_id: identityID,
              subject: finding.ref,
              evidence_refs: findingEvidenceRefs(finding),
            },
          ],
        };
        await api.decommissionNHI(request);
        onNotice({ kind: "success", message: t("discovery.findings.decommissionQueued", { ref: finding.ref }) });
        return;
      }

      const playbookInput: RemediationPlaybookRunRequest = {
        inventory_id: findingInventoryID(identityID),
        reason,
        target: finding.ref,
        target_identity_id: identityID,
      };
      if (nextAction === "rotate") {
        await api.runRemediationPlaybook(remediationPlaybookRotateIdentity, playbookInput);
        onNotice({ kind: "success", message: t("discovery.findings.rotateQueued", { ref: finding.ref }) });
        return;
      }

      await api.runRemediationPlaybook(remediationPlaybookRevokeIdentity, playbookInput);
      onNotice({ kind: "success", message: t("discovery.findings.remediationQueued", { ref: finding.ref }) });
    } catch (err) {
      onNotice(noticeForError(err, t("discovery.findings.actionError")));
    } finally {
      setActionBusy(false);
    }
  }

  return (
    <div className="grid gap-4">
      <div className="ui-panel grid gap-3 p-3 lg:grid-cols-4" aria-label={t("discovery.findings.filters")}>
        <label className="grid gap-1 text-sm font-medium">
          {t("discovery.findings.filterStatus")}
          <select className="ui-input" value={filters.triage} onChange={(event) => onFilterChange("triage", event.target.value)}>
            {triageFilterOptions.map((option) => (
              <option key={option.value} value={option.value}>
                {t(option.labelKey)}
              </option>
            ))}
          </select>
        </label>
        <label className="grid gap-1 text-sm font-medium">
          {t("discovery.findings.filterOwner")}
          <select className="ui-input" value={filters.owner} onChange={(event) => onFilterChange("owner", event.target.value)}>
            <option value="all">{t("discovery.findings.filterOwnerAll")}</option>
            {facetOptions.owners.map((owner) => (
              <option key={owner} value={owner}>
                {owner}
              </option>
            ))}
          </select>
        </label>
        <label className="grid gap-1 text-sm font-medium">
          {t("discovery.findings.filterTeam")}
          <select className="ui-input" value={filters.team} onChange={(event) => onFilterChange("team", event.target.value)}>
            <option value="all">{t("discovery.findings.filterTeamAll")}</option>
            {facetOptions.teams.map((team) => (
              <option key={team} value={team}>
                {team}
              </option>
            ))}
          </select>
        </label>
        <label className="grid gap-1 text-sm font-medium">
          {t("discovery.findings.filterTag")}
          <select className="ui-input" value={filters.tag} onChange={(event) => onFilterChange("tag", event.target.value)}>
            <option value="all">{t("discovery.findings.filterTagAll")}</option>
            {facetOptions.tags.map((tag) => (
              <option key={tag} value={tag}>
                {tag}
              </option>
            ))}
          </select>
        </label>
      </div>

      <div className="ui-panel overflow-x-auto">
        <table className="ui-table min-w-[104rem]">
          <caption className="sr-only">{t("discovery.findings.caption")}</caption>
          <thead>
            <tr>
              <th scope="col">{t("discovery.findings.columnStatus")}</th>
              <th scope="col">{t("discovery.findings.columnKind")}</th>
              <th scope="col">{t("discovery.findings.columnReference")}</th>
              <th scope="col">{t("discovery.findings.columnFingerprint")}</th>
              <th scope="col">{t("discovery.findings.columnOwner")}</th>
              <th scope="col">{t("discovery.findings.columnTeam")}</th>
              <th scope="col">{t("discovery.findings.columnTags")}</th>
              <th scope="col">{t("discovery.findings.columnSource")}</th>
              <th scope="col">{t("discovery.findings.columnRisk")}</th>
              <th scope="col">{t("discovery.findings.columnDiscovered")}</th>
              <th scope="col">{t("discovery.findings.columnActions")}</th>
            </tr>
          </thead>
          <tbody>
            {findings.length === 0 ? (
              <tr>
                <td colSpan={11} className="py-8 text-center text-sm text-muted-foreground">
                  {t("discovery.findings.noMatches")}
                </td>
              </tr>
            ) : (
              findings.map((finding) => {
                const hasIdentity = Boolean(findingActionIdentityID(finding));
                return (
                  <tr key={finding.id} className="align-top">
                    <td>
                      <TriagePill status={findingTriageStatus(finding)} />
                    </td>
                    <td>{finding.kind}</td>
                    <td className="font-medium">{finding.ref}</td>
                    <td className="font-mono text-xs">{maskFingerprint(finding.fingerprint)}</td>
                    <td>{findingOwner(finding) || "-"}</td>
                    <td>{findingTeam(finding) || "-"}</td>
                    <td>
                      <TagList tags={findingTags(finding)} />
                    </td>
                    <td>{sourceByID.get(finding.source_id)?.name ?? finding.source_id}</td>
                    <td>{finding.risk_score ?? 0}</td>
                    <td>{formatDateTime(finding.discovered_at)}</td>
                    <td>
                      <div className="flex flex-wrap gap-2">
                        <Button type="button" size="sm" variant="outline" onClick={() => openDetail(finding)}>
                          <Eye className="h-4 w-4" aria-hidden="true" />
                          {t("discovery.findings.details")}
                        </Button>
                        <Button type="button" size="sm" onClick={() => openAction(finding, "claim")} disabled={actionBusy}>
                          <CheckCircle2 className="h-4 w-4" aria-hidden="true" />
                          {t("discovery.findings.claim")}
                        </Button>
                        <Button
                          type="button"
                          size="sm"
                          variant="outline"
                          onClick={() => void runFindingLifecycleAction(finding, "rotate")}
                          disabled={actionBusy || !hasIdentity}
                        >
                          <RefreshCw className="h-4 w-4" aria-hidden="true" />
                          {t("discovery.findings.rotate")}
                        </Button>
                        <Button
                          type="button"
                          size="sm"
                          variant="outline"
                          onClick={() => void runFindingLifecycleAction(finding, "revoke")}
                          disabled={actionBusy || !hasIdentity}
                        >
                          <XCircle className="h-4 w-4" aria-hidden="true" />
                          {t("discovery.findings.revoke")}
                        </Button>
                        <Button
                          type="button"
                          size="sm"
                          variant="outline"
                          onClick={() => void runFindingLifecycleAction(finding, "decommission")}
                          disabled={actionBusy || !hasIdentity}
                        >
                          <Activity className="h-4 w-4" aria-hidden="true" />
                          {t("discovery.findings.decommission")}
                        </Button>
                        <Button
                          type="button"
                          size="sm"
                          variant="outline"
                          onClick={() => void runFindingLifecycleAction(finding, "remediate")}
                          disabled={actionBusy || !hasIdentity}
                        >
                          <ClipboardList className="h-4 w-4" aria-hidden="true" />
                          {t("discovery.findings.remediate")}
                        </Button>
                        <Button type="button" size="sm" variant="outline" onClick={() => openAction(finding, "dismiss")} disabled={actionBusy}>
                          <XCircle className="h-4 w-4" aria-hidden="true" />
                          {t("discovery.findings.dismiss")}
                        </Button>
                      </div>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {selected && (
        <aside className="ui-panel grid gap-4 p-comfortable" aria-labelledby="finding-detail-heading">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <h3 id="finding-detail-heading" className="text-title font-semibold">
                {t("discovery.findings.detailHeading")}
              </h3>
              <p className="font-mono text-xs text-muted-foreground">{selected.id}</p>
            </div>
            <Button type="button" variant="ghost" onClick={() => setSelectedID(null)}>
              {t("discovery.findings.close")}
            </Button>
          </div>

          <dl className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
            <FindingDetail label={t("discovery.findings.columnReference")} value={selected.ref} />
            <FindingDetail label={t("discovery.findings.columnStatus")} value={triageStatusLabel(t, findingTriageStatus(selected))} />
            <FindingDetail label={t("discovery.findings.columnOwner")} value={findingOwner(selected) || "-"} />
            <FindingDetail label={t("discovery.findings.columnTeam")} value={findingTeam(selected) || "-"} />
            <FindingDetail label={t("discovery.findings.columnSource")} value={sourceByID.get(selected.source_id)?.name ?? selected.source_id} />
            <FindingDetail label={t("discovery.findings.columnFingerprint")} value={maskFingerprint(selected.fingerprint)} />
            <FindingDetail label={t("discovery.findings.triageReason")} value={selected.triage_reason || "-"} />
            <FindingDetail label={t("discovery.findings.managedIdentity")} value={selected.managed_identity_id || "-"} />
          </dl>

          <div className="flex flex-wrap items-center gap-2">
            <Tag className="h-4 w-4 text-muted-foreground" aria-hidden="true" />
            <TagList tags={findingTags(selected)} />
          </div>

          {action && (
            <form className="grid gap-3 border-t border-border pt-4 md:grid-cols-2 xl:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_minmax(0,1fr)_minmax(0,1.5fr)_auto]" onSubmit={submitAction}>
              {action === "claim" ? (
                <label className="grid gap-1 text-sm font-medium">
                  {t("discovery.findings.managedIdentity")}
                  <input className="ui-input" value={managedIdentityID} onChange={(event) => setManagedIdentityID(event.target.value)} placeholder="identity-id" />
                </label>
              ) : (
                <div className="hidden md:block" aria-hidden="true" />
              )}
              <label className="grid gap-1 text-sm font-medium">
                {t("discovery.findings.triageReason")}
                <textarea className="ui-input min-h-20" value={reason} onChange={(event) => setReason(event.target.value)} required={action === "dismiss"} />
              </label>
              <label className="grid gap-1 text-sm font-medium">
                {t("discovery.findings.columnOwner")}
                <input className="ui-input" value={owner} onChange={(event) => setOwner(event.target.value)} />
              </label>
              <label className="grid gap-1 text-sm font-medium">
                {t("discovery.findings.columnTeam")}
                <input className="ui-input" value={team} onChange={(event) => setTeam(event.target.value)} />
              </label>
              <label className="grid gap-1 text-sm font-medium">
                {t("discovery.findings.columnTags")}
                <input className="ui-input" value={tagText} onChange={(event) => setTagText(event.target.value)} placeholder="internet, tls" />
              </label>
              <Button type="submit" className="self-end" disabled={actionBusy}>
                {action === "claim" ? <CheckCircle2 className="h-4 w-4" aria-hidden="true" /> : <XCircle className="h-4 w-4" aria-hidden="true" />}
                {action === "claim" ? t("discovery.findings.claimSubmit") : t("discovery.findings.dismissSubmit")}
              </Button>
            </form>
          )}
        </aside>
      )}
    </div>
  );
}

function FindingDetail({ label, value }: { label: string; value: string }) {
  return (
    <div className="grid gap-1">
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd className="break-words text-sm font-medium">{value}</dd>
    </div>
  );
}

function TriagePill({ status }: { status: FindingTriageStatus }) {
  const { t } = useTranslation();
  const tone =
    status === "managed"
      ? "border-status-success/40 bg-status-success/10 text-status-success"
      : status === "dismissed"
      ? "border-muted-foreground/30 bg-muted text-muted-foreground"
      : status === "investigating"
      ? "border-status-warning/40 bg-status-warning/10 text-status-warning"
      : "border-status-danger/40 bg-status-danger/10 text-status-danger";
  return <span className={`inline-flex rounded-full border px-2 py-1 text-xs font-medium ${tone}`}>{triageStatusLabel(t, status)}</span>;
}

function TagList({ tags }: { tags: string[] }) {
  if (tags.length === 0) return <span className="text-muted-foreground">-</span>;
  return (
    <div className="flex flex-wrap gap-1">
      {tags.map((tag) => (
        <span key={tag} className="rounded-full border border-border px-2 py-1 text-xs">
          {tag}
        </span>
      ))}
    </div>
  );
}

function findingTriageStatus(finding: DiscoveryFinding): FindingTriageStatus {
  return finding.triage_status ?? "unmanaged";
}

function triageFilterFromSearchParam(value: string | null): FindingTriageFilter {
  switch (value) {
    case "unmanaged":
    case "investigating":
    case "managed":
    case "dismissed":
      return value;
    default:
      return "all";
  }
}

function triageStatusLabel(t: (key: MessageKey) => string, status: FindingTriageStatus): string {
  return t(triageStatusLabelKeys[status]);
}

function applyFindingFilters(findings: DiscoveryFinding[], filters: FindingFilters): DiscoveryFinding[] {
  return findings.filter((finding) => {
    if (filters.triage !== "all" && findingTriageStatus(finding) !== filters.triage) return false;
    if (filters.owner !== "all" && findingOwner(finding) !== filters.owner) return false;
    if (filters.team !== "all" && findingTeam(finding) !== filters.team) return false;
    if (filters.tag !== "all" && !findingTags(finding).includes(filters.tag)) return false;
    return true;
  });
}

function findingFacets(findings: DiscoveryFinding[]): { owners: string[]; teams: string[]; tags: string[] } {
  const owners = new Set<string>();
  const teams = new Set<string>();
  const tags = new Set<string>();
  for (const finding of findings) {
    const owner = findingOwner(finding);
    const team = findingTeam(finding);
    if (owner) owners.add(owner);
    if (team) teams.add(team);
    for (const tag of findingTags(finding)) tags.add(tag);
  }
  return { owners: [...owners].sort(), teams: [...teams].sort(), tags: [...tags].sort() };
}

function findingOwner(finding: DiscoveryFinding): string {
  return metadataString(finding.metadata, ["owner", "owner_ref", "owner_id", "owner_email"]);
}

function findingTeam(finding: DiscoveryFinding): string {
  return metadataString(finding.metadata, ["team", "team_ref", "owner_team", "owner_group"]);
}

function findingTags(finding: DiscoveryFinding): string[] {
  const raw = finding.metadata.tags ?? finding.metadata.labels;
  if (Array.isArray(raw)) {
    return raw.map((value) => (typeof value === "string" ? value.trim() : "")).filter(Boolean).slice(0, 8);
  }
  if (raw && typeof raw === "object") {
    return Object.entries(raw)
      .flatMap(([key, value]) => (value === true ? [key] : typeof value === "string" ? [`${key}:${value}`] : []))
      .slice(0, 8);
  }
  return [];
}

function parseFindingTagInput(value: string): string[] {
  const tags: string[] = [];
  const seen = new Set<string>();
  for (const tag of value.split(",")) {
    const trimmed = tag.trim();
    if (!trimmed || seen.has(trimmed)) continue;
    seen.add(trimmed);
    tags.push(trimmed);
    if (tags.length === 16) break;
  }
  return tags;
}

function metadataString(metadata: Record<string, unknown>, keys: string[]): string {
  for (const key of keys) {
    const value = metadata[key];
    if (typeof value === "string" && value.trim() !== "") return value.trim();
  }
  return "";
}

function findingActionIdentityID(finding: DiscoveryFinding): string {
  return finding.managed_identity_id?.trim() || metadataString(finding.metadata, ["managed_identity_id", "identity_id", "nhi_identity_id"]);
}

function findingActionReason(finding: DiscoveryFinding): string {
  return `Discovery finding ${finding.id}: ${finding.ref}`;
}

function findingEvidenceRefs(finding: DiscoveryFinding): string[] {
  return [`discovery.finding:${finding.id}`, `discovery.run:${finding.run_id}`];
}

function findingInventoryID(identityID: string): string {
  return `identity/${identityID}`;
}

function sourceKindLabel(kind: string): string {
  return sourceKindLabels[kind as SourceKind] ?? kind;
}

function formatInterval(seconds: number, unscheduled: string): string {
  if (seconds <= 0) return unscheduled;
  if (seconds % 3600 === 0) return `${seconds / 3600}h`;
  if (seconds % 60 === 0) return `${seconds / 60}m`;
  return `${seconds}s`;
}

function parseTargets(value: string): string[] {
  return value
    .split(/[\n,]/)
    .map((target) => target.trim())
    .filter(Boolean);
}

function parseTokenObservations(value: string): unknown[] {
  const parsed = JSON.parse(value);
  if (!Array.isArray(parsed)) throw new Error("Token observations JSON must be an array.");
  return parsed;
}

function parseNHIObservations(value: string): unknown[] {
  const parsed = JSON.parse(value);
  if (!Array.isArray(parsed)) throw new Error("Observations JSON must be an array.");
  return parsed;
}

function parseOAuthGrants(value: string): unknown[] {
  const parsed = JSON.parse(value);
  if (!Array.isArray(parsed)) throw new Error("OAuth grants JSON must be an array.");
  return parsed;
}

function parseServiceAccounts(value: string): unknown[] {
  const parsed = JSON.parse(value);
  if (!Array.isArray(parsed)) throw new Error("Service accounts JSON must be an array.");
  return parsed;
}

function parseBehaviorEvents(value: string): unknown[] {
  const parsed = JSON.parse(value);
  if (!Array.isArray(parsed)) throw new Error("Behavior events JSON must be an array.");
  return parsed;
}

function parseCompromiseSignals(value: string): unknown[] {
  const parsed = JSON.parse(value);
  if (!Array.isArray(parsed)) throw new Error("Compromise signals JSON must be an array.");
  return parsed;
}

function parseKubernetesTLSResources(value: string): unknown[] {
  const parsed = JSON.parse(value);
  if (!Array.isArray(parsed)) throw new Error("Kubernetes resources JSON must be an array.");
  return parsed;
}

function targetCount(source: DiscoverySource): string {
  const targets = source.config.targets;
  if (Array.isArray(targets)) return String(targets.length);
  const observations = source.config.observations;
  if (Array.isArray(observations)) return source.kind === "api_key" ? `${observations.length} tokens` : `${observations.length} NHI`;
  const grants = source.config.grants;
  if (Array.isArray(grants)) return `${grants.length} grants`;
  const accounts = source.config.accounts;
  if (Array.isArray(accounts)) return `${accounts.length} accounts`;
  const events = source.config.events;
  if (Array.isArray(events)) return `${events.length} events`;
  const signals = source.config.signals;
  if (Array.isArray(signals)) return `${signals.length} signals`;
  const resources = source.config.resources;
  if (Array.isArray(resources)) return `${resources.length} k8s`;
  const cidrs = source.config.cidrs;
  if (Array.isArray(cidrs)) return `${cidrs.length} cidr`;
  return "-";
}

function renderNotice(notice: Notice) {
  if (notice.kind === "success") {
    return (
      <section role="status" className="rounded-control border border-status-success/40 bg-status-success/10 p-3 text-sm text-status-success">
        {notice.message}
      </section>
    );
  }
  if (notice.kind === "permission") return <PermissionDeniedState>{notice.message}</PermissionDeniedState>;
  return <ErrorState title="Discovery unavailable">{notice.message}</ErrorState>;
}

function noticeForError(err: unknown, fallback: string): Notice {
  if (err instanceof ApiError) {
    try {
      const problem = JSON.parse(err.body) as { detail?: string; title?: string };
      return {
        kind: err.status === 403 ? "permission" : "error",
        message: problem.detail || problem.title || fallback,
      };
    } catch {
      return { kind: err.status === 403 ? "permission" : "error", message: err.body || fallback };
    }
  }
  return { kind: "error", message: err instanceof Error ? err.message : fallback };
}

function shortID(id: string): string {
  return id.length <= 12 ? id : id.slice(0, 12);
}

function maskFingerprint(value: string): string {
  if (!value) return "-";
  if (value.length <= 16) return value;
  return `${value.slice(0, 10)}...${value.slice(-6)}`;
}

function formatDateTime(value?: string): string {
  return formatDateTimePolicy(value);
}
