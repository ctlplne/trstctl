import { useEffect, useMemo, useRef, useState } from "react";
import type { FormEvent } from "react";
import { ClipboardList, Play, Plus, RefreshCw, Search } from "lucide-react";
import { EmptyState } from "@/components/EmptyState";
import { ErrorState, LoadingState, PermissionDeniedState } from "@/components/StatePrimitives";
import { StatusBadge } from "@/components/StatusBadge";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/PageHeader";
import { DiscoveryHero, CTDriftPanel } from "@/components/discovery";
import { api, ApiError, type DiscoveryFinding, type DiscoveryRun, type DiscoverySchedule, type DiscoverySource, type DiscoverySourceRequest } from "@/lib/api";
import { formatDateTime as formatDateTimePolicy } from "@/i18n/format";

type Notice = { kind: "permission" | "error"; message: string };
type SourceKind = DiscoverySourceRequest["kind"];

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

export function Discovery() {
  const [sources, setSources] = useState<DiscoverySource[]>([]);
  const [schedules, setSchedules] = useState<DiscoverySchedule[]>([]);
  const [runs, setRuns] = useState<DiscoveryRun[]>([]);
  const [findings, setFindings] = useState<DiscoveryFinding[]>([]);
  const [notice, setNotice] = useState<Notice | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState<string | null>(null);
  const [sourceName, setSourceName] = useState("");
  const [sourceKind, setSourceKind] = useState<SourceKind>("network");
  const [targets, setTargets] = useState("");
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
    const [sourceResult, scheduleResult, runResult, findingResult] = await Promise.allSettled([
      api.discoverySources({ limit: 50 }),
      api.discoverySchedules({ limit: 50 }),
      api.discoveryRuns({ limit: 50 }),
      api.discoveryFindings({ limit: 50 }),
    ]);
    if (sourceResult.status === "fulfilled") setSources(sourceResult.value.items ?? []);
    else setSources([]);
    if (scheduleResult.status === "fulfilled") setSchedules(scheduleResult.value.items ?? []);
    else setSchedules([]);
    if (runResult.status === "fulfilled") setRuns(runResult.value.items ?? []);
    else setRuns([]);
    if (findingResult.status === "fulfilled") setFindings(findingResult.value.items ?? []);
    else setFindings([]);
    const rejected = [sourceResult, scheduleResult, runResult, findingResult].find((result) => result.status === "rejected");
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

  async function createSource(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy("source");
    setNotice(null);
    try {
      const config =
        sourceKind === "network"
          ? { targets: parseTargets(targets) }
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
          {sourceKind === "oauth_grant" && (
            <label className="grid gap-1 text-sm font-medium">
              OAuth grants JSON
              <textarea
                className="ui-input min-h-40 font-mono text-xs"
                value={oauthGrants}
                onChange={(event) => setOAuthGrants(event.target.value)}
                placeholder='[{"provider":"okta","app_id":"0oa-payments","principal":"payments-bi-export","resource":"google-workspace","scopes":["drive.readonly"],"third_party":true}]'
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
          <FindingTable findings={findings} sourceByID={sourceByID} />
        )}
      </section>
    </section>
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

function FindingTable({ findings, sourceByID }: { findings: DiscoveryFinding[]; sourceByID: Map<string, DiscoverySource> }) {
  return (
    <div className="ui-panel overflow-x-auto">
      <table className="ui-table min-w-[64rem]">
        <caption className="sr-only">Discovery findings</caption>
        <thead>
          <tr>
            <th scope="col">Kind</th>
            <th scope="col">Reference</th>
            <th scope="col">Source</th>
            <th scope="col">Fingerprint</th>
            <th scope="col">Risk</th>
            <th scope="col">Discovered</th>
          </tr>
        </thead>
        <tbody>
          {findings.map((finding) => (
            <tr key={finding.id} className="align-top">
              <td>{finding.kind}</td>
              <td className="font-medium">{finding.ref}</td>
              <td>{sourceByID.get(finding.source_id)?.name ?? finding.source_id}</td>
              <td className="font-mono text-xs">{maskFingerprint(finding.fingerprint)}</td>
              <td>{finding.risk_score ?? 0}</td>
              <td>{formatDateTime(finding.discovered_at)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function parseTargets(value: string): string[] {
  return value
    .split(/[\n,]/)
    .map((target) => target.trim())
    .filter(Boolean);
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
  if (Array.isArray(observations)) return `${observations.length} NHI`;
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
