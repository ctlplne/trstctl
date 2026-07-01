import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { BookOpen, Clipboard, Download, ShieldCheck } from "lucide-react";
import { PageHeader } from "@/components/PageHeader";
import { SectionCard } from "@/components/dashboard";
import { Button } from "@/components/ui/button";
import { useTranslation } from "@/i18n/I18nProvider";
import { api, ApiError, type DiscoverySource, type NotificationRoutingPolicy, type PolicyDryRun, type Profile } from "@/lib/api";

const protocols = [
  { name: "ACME", reference: "/acme/{profile}/directory", note: "RFC 8555 — cert-manager, Caddy, certbot, Traefik." },
  { name: "EST", reference: "/.well-known/est/{profile}/cacerts", note: "RFC 7030 — routers, switches, and embedded fleets." },
  { name: "SCEP", reference: "/scep/{profile}", note: "MDM enrollment for laptops and mobile devices." },
];

const sdks = [
  { name: "Python SDK", reference: "pip install trstctl-sdk" },
  { name: "Go SDK", reference: "go get trstctl.com/sdk/go" },
  { name: "TypeScript SDK", reference: "npm install ./clients/sdk/typescript" },
  { name: "Java SDK", reference: "com.trstctl:trstctl-sdk:0.1.0" },
];

const iac = [
  { name: "Terraform provider", reference: "terraform { required_providers { trstctl = { source = \"trstctl/trstctl\" } } }" },
  { name: "cert-manager issuer", reference: "kind: ClusterIssuer  # external-issuer: trstctl-acme" },
  { name: "SPIRE upstream authority", reference: "UpstreamAuthority \"trstctl\" { ... }" },
];

type ManifestType = "profile" | "discovery-source" | "routing-policy" | "install-values";

type DriftStatus = "In sync" | "Drift";

interface DriftRow {
  path: string;
  live: string;
  declared: string;
  status: DriftStatus;
}

const manifestTypes: Array<{ value: ManifestType; label: string }> = [
  { value: "profile", label: "Issuance profile" },
  { value: "discovery-source", label: "Discovery source" },
  { value: "routing-policy", label: "Notification routing policy" },
  { value: "install-values", label: "Install values" },
];

const gitOpsValidationModule = `package trstctl.gitops

default allow := false
default deny := false

allow if {
  input.action == "gitops.validate"
  input.declaration.apiVersion == "trstctl.com/v1"
  input.declaration_kind != ""
}

deny if {
  input.declaration_kind == ""
}
`;

function CopyRef({ value }: { value: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <span className="flex items-center gap-2">
      <code className="flex-1 truncate rounded bg-muted px-2 py-1 font-mono text-xs">{value}</code>
      <Button
        type="button"
        size="sm"
        variant="outline"
        aria-label={`Copy ${value}`}
        onClick={() => {
          void globalThis.navigator?.clipboard?.writeText(value);
          setCopied(true);
        }}
      >
        {copied ? "Copied" : "Copy"}
      </Button>
    </span>
  );
}

/** Integrate is the one place to wire trstctl into a stack: copy the served
 * ACME/EST/SCEP enrollment URLs, grab an SDK, or drop in the Terraform / cert-
 * manager / SPIRE integration. Every reference points at a served surface; no
 * internal-only endpoint is exposed here. */
export function Integrate() {
  const { t } = useTranslation();
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [sources, setSources] = useState<DiscoverySource[]>([]);
  const [policies, setPolicies] = useState<NotificationRoutingPolicy[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState("");
  const [manifestType, setManifestType] = useState<ManifestType>("profile");
  const [profileID, setProfileID] = useState("");
  const [sourceID, setSourceID] = useState("");
  const [policyID, setPolicyID] = useState("");
  const [manifestText, setManifestText] = useState("");
  const [validationBusy, setValidationBusy] = useState(false);
  const [validationError, setValidationError] = useState("");
  const [validationResult, setValidationResult] = useState<PolicyDryRun | null>(null);

  useEffect(() => {
    let active = true;
    setLoading(true);
    setLoadError("");
    Promise.all([api.profiles(), api.discoverySources({ limit: 50 }), api.notificationRoutingPolicies()])
      .then(([nextProfiles, nextSources, nextPolicies]) => {
        if (!active) return;
        setProfiles(nextProfiles);
        setSources(nextSources.items ?? []);
        setPolicies(nextPolicies.items ?? []);
      })
      .catch((err: unknown) => {
        if (active) setLoadError(describeIntegrateError(err, "GitOps live state unavailable"));
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    if (!profileID && profiles[0]) setProfileID(profiles[0].id);
  }, [profileID, profiles]);

  useEffect(() => {
    if (!sourceID && sources[0]) setSourceID(sources[0].id);
  }, [sourceID, sources]);

  useEffect(() => {
    if (!policyID && policies[0]) setPolicyID(policies[0].id);
  }, [policies, policyID]);

  const selectedProfile = profiles.find((profile) => profile.id === profileID) ?? profiles[0];
  const selectedSource = sources.find((source) => source.id === sourceID) ?? sources[0];
  const selectedPolicy = policies.find((policy) => policy.id === policyID) ?? policies[0];
  const liveManifest = useMemo(
    () => buildLiveManifest(manifestType, selectedProfile, selectedSource, selectedPolicy, profiles, sources, policies),
    [manifestType, policies, profiles, selectedPolicy, selectedProfile, selectedSource, sources],
  );
  const parsedManifest = useMemo(() => parseManifest(manifestText), [manifestText]);
  const driftRows = useMemo(() => (liveManifest && parsedManifest.value ? diffManifests(liveManifest, parsedManifest.value) : []), [liveManifest, parsedManifest.value]);
  const driftCount = driftRows.filter((row) => row.status === "Drift").length;
  const exportHref = useMemo(() => `data:application/json;charset=utf-8,${encodeURIComponent(manifestText)}`, [manifestText]);

  useEffect(() => {
    setManifestText(liveManifest ? JSON.stringify(liveManifest, null, 2) : "");
    setValidationError("");
    setValidationResult(null);
  }, [liveManifest]);

  async function validateDeclaration() {
    setValidationError("");
    setValidationResult(null);
    if (!parsedManifest.value) {
      setValidationError(parsedManifest.error || "Declaration must be valid JSON.");
      return;
    }
    setValidationBusy(true);
    try {
      const declarationKind = typeof parsedManifest.value.kind === "string" ? parsedManifest.value.kind : "";
      const subject = manifestName(parsedManifest.value) || manifestType;
      const result = await api.policyDryRun({
        kind: "abac",
        module: gitOpsValidationModule,
        input: {
          action: "gitops.validate",
          permission: "gitops:apply",
          subject,
          declaration_kind: declarationKind,
          declaration: parsedManifest.value,
          drift_count: driftCount,
          target_type: manifestType,
        },
        trace_limit: 20,
      });
      setValidationResult(result);
    } catch (err) {
      setValidationError(describeIntegrateError(err, "GitOps validation failed"));
    } finally {
      setValidationBusy(false);
    }
  }

  return (
    <section aria-labelledby="integrate-heading" className="grid gap-6">
      <PageHeader
        titleId="integrate-heading"
        title="Integrate"
        description="Wire trstctl into your stack: enrollment protocols, language SDKs, and infrastructure-as-code, each with a copyable reference."
        actions={
          <Link
            to="/integrate/api"
            className="inline-flex min-h-10 items-center justify-center gap-2 rounded-md border border-border bg-background px-3 py-2 text-sm font-medium hover:border-brand-accent/40 hover:bg-muted/60"
          >
            <BookOpen className="h-4 w-4" aria-hidden="true" />
            {t("nav.item.apiExplorer")}
          </Link>
        }
      />

      <SectionCard title="Enrollment protocols" description="Standards-based certificate enrollment endpoints (per issuance profile).">
        <ul className="grid gap-3">
          {protocols.map((protocol) => (
            <li key={protocol.name} className="grid gap-1">
              <span className="text-sm font-medium">{protocol.name}</span>
              <CopyRef value={protocol.reference} />
              <span className="text-caption text-muted-foreground">{protocol.note}</span>
            </li>
          ))}
        </ul>
      </SectionCard>

      <SectionCard title="SDKs" description="Generated client libraries for the trstctl API.">
        <ul className="grid gap-3 md:grid-cols-2">
          {sdks.map((sdk) => (
            <li key={sdk.name} className="grid gap-1">
              <span className="text-sm font-medium">{sdk.name}</span>
              <CopyRef value={sdk.reference} />
            </li>
          ))}
        </ul>
      </SectionCard>

      <SectionCard title="GitOps workflow" description="Generate declarations from live state, validate them through policy dry-run, and compare live versus declared fields.">
        <div className="grid gap-4">
          {loadError && (
            <div className="rounded-md border border-warning/40 bg-warning/10 px-3 py-2 text-sm text-warning-foreground" role="status">
              {loadError}
            </div>
          )}
          <div className="grid gap-3 lg:grid-cols-[minmax(11rem,14rem)_minmax(0,1fr)]">
            <label className="grid gap-1 text-sm">
              <span className="font-medium">Manifest type</span>
              <select
                className="ui-input"
                value={manifestType}
                onChange={(event) => {
                  setManifestType(event.target.value as ManifestType);
                  setValidationError("");
                  setValidationResult(null);
                }}
              >
                {manifestTypes.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
            </label>
            {manifestType !== "install-values" && (
              <label className="grid gap-1 text-sm">
                <span className="font-medium">Live object</span>
                <select className="ui-input" value={selectedObjectID(manifestType, profileID, sourceID, policyID)} onChange={(event) => updateSelectedObject(manifestType, event.target.value, setProfileID, setSourceID, setPolicyID)}>
                  {objectOptions(manifestType, profiles, sources, policies).map((option) => (
                    <option key={option.value} value={option.value}>
                      {option.label}
                    </option>
                  ))}
                </select>
              </label>
            )}
          </div>

          {loading && <p className="text-sm text-muted-foreground">Loading GitOps sources...</p>}

          <div className="grid gap-4 xl:grid-cols-[minmax(0,1.1fr)_minmax(22rem,0.9fr)]">
            <label className="grid gap-1 text-sm">
              <span className="font-medium">Declarative manifest</span>
              <textarea
                className="min-h-80 resize-y rounded-md border border-input bg-background px-3 py-2 font-mono text-xs"
                spellCheck={false}
                value={manifestText}
                onChange={(event) => {
                  setManifestText(event.target.value);
                  setValidationError("");
                  setValidationResult(null);
                }}
              />
            </label>

            <div className="grid content-start gap-3">
              <div className="flex flex-wrap items-center gap-2">
                <Button type="button" onClick={() => void validateDeclaration()} disabled={validationBusy || !manifestText.trim()}>
                  <ShieldCheck className="h-4 w-4" aria-hidden="true" />
                  {validationBusy ? "Validating" : "Validate declaration"}
                </Button>
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => {
                    void globalThis.navigator?.clipboard?.writeText(manifestText);
                  }}
                  disabled={!manifestText.trim()}
                >
                  <Clipboard className="h-4 w-4" aria-hidden="true" />
                  Copy declaration
                </Button>
                <a
                  className="inline-flex min-h-10 items-center justify-center gap-2 rounded-md border border-border bg-background px-3 py-2 text-sm font-medium hover:border-brand-accent/40 hover:bg-muted/60"
                  href={exportHref}
                  download={downloadName(manifestType)}
                >
                  <Download className="h-4 w-4" aria-hidden="true" />
                  Export declaration
                </a>
                <Link className="text-sm underline" to="/integrate/api?operation=dryRunPolicy">
                  Open in API explorer
                </Link>
              </div>

              {parsedManifest.error && <p className="text-sm text-destructive">{parsedManifest.error}</p>}
              {validationError && <p className="text-sm text-destructive">{validationError}</p>}
              {validationResult && (
                <section className="rounded-md border border-border p-3 text-sm" role="status" aria-label="GitOps validation result">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <p className="font-medium">{validationResult.valid ? "Valid" : "Invalid"}</p>
                    <span className="font-mono text-xs text-muted-foreground">{validationResult.audit_event}</span>
                  </div>
                  <dl className="mt-3 grid gap-2 sm:grid-cols-2">
                    <Metric label="Decision" value={validationResult.allow ? "allow" : validationResult.deny ? "deny" : "none"} />
                    <Metric label="Module digest" value={validationResult.module_sha256} mono />
                    <Metric label="Query" value={validationResult.query} mono />
                    <Metric label="Idempotency" value={validationResult.idempotency_key} mono />
                  </dl>
                </section>
              )}

              <div className="overflow-x-auto rounded-md border border-border">
                <table className="ui-table min-w-[40rem]">
                  <caption className="sr-only">GitOps drift comparison</caption>
                  <thead>
                    <tr>
                      <th scope="col">Path</th>
                      <th scope="col">Live</th>
                      <th scope="col">Declared</th>
                      <th scope="col">Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {driftRows.length > 0 ? (
                      driftRows.map((row) => (
                        <tr key={row.path} className="align-top">
                          <td className="font-mono text-xs">{row.path}</td>
                          <td className="font-mono text-xs">{row.live}</td>
                          <td className="font-mono text-xs">{row.declared}</td>
                          <td>{row.status}</td>
                        </tr>
                      ))
                    ) : (
                      <tr>
                        <td colSpan={4} className="text-muted-foreground">
                          No comparable declaration loaded.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
              <p className="text-caption text-muted-foreground">{driftCount} drift {driftCount === 1 ? "field" : "fields"}</p>
            </div>
          </div>
        </div>
      </SectionCard>

      <SectionCard title="Infrastructure as code" description="Declare trstctl trust the same way you declare the rest of your platform.">
        <ul className="grid gap-3">
          {iac.map((entry) => (
            <li key={entry.name} className="grid gap-1">
              <span className="text-sm font-medium">{entry.name}</span>
              <CopyRef value={entry.reference} />
            </li>
          ))}
        </ul>
      </SectionCard>
    </section>
  );
}

function Metric({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div>
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd className={mono ? "break-all font-mono text-xs" : "text-sm"}>{value || "-"}</dd>
    </div>
  );
}

function selectedObjectID(type: ManifestType, profileID: string, sourceID: string, policyID: string): string {
  if (type === "profile") return profileID;
  if (type === "discovery-source") return sourceID;
  if (type === "routing-policy") return policyID;
  return "";
}

function updateSelectedObject(
  type: ManifestType,
  id: string,
  setProfileID: (id: string) => void,
  setSourceID: (id: string) => void,
  setPolicyID: (id: string) => void,
) {
  if (type === "profile") setProfileID(id);
  if (type === "discovery-source") setSourceID(id);
  if (type === "routing-policy") setPolicyID(id);
}

function objectOptions(type: ManifestType, profiles: Profile[], sources: DiscoverySource[], policies: NotificationRoutingPolicy[]): Array<{ value: string; label: string }> {
  if (type === "profile") return profiles.map((profile) => ({ value: profile.id, label: `${profile.name} v${profile.version}` }));
  if (type === "discovery-source") return sources.map((source) => ({ value: source.id, label: `${source.name} (${source.kind})` }));
  if (type === "routing-policy") return policies.map((policy) => ({ value: policy.id, label: policy.name }));
  return [];
}

function buildLiveManifest(
  type: ManifestType,
  profile: Profile | undefined,
  source: DiscoverySource | undefined,
  policy: NotificationRoutingPolicy | undefined,
  profiles: Profile[],
  sources: DiscoverySource[],
  policies: NotificationRoutingPolicy[],
): Record<string, unknown> | null {
  if (type === "profile") {
    if (!profile) return null;
    return {
      apiVersion: "trstctl.com/v1",
      kind: "TrstctlProfile",
      metadata: { name: profile.name },
      spec: { version: profile.version, active: profile.active !== false, spec: profile.spec ?? {} },
    };
  }
  if (type === "discovery-source") {
    if (!source) return null;
    return {
      apiVersion: "trstctl.com/v1",
      kind: "TrstctlDiscoverySource",
      metadata: { name: source.name },
      spec: { kind: source.kind, config: source.config ?? {} },
    };
  }
  if (type === "routing-policy") {
    if (!policy) return null;
    return {
      apiVersion: "trstctl.com/v1",
      kind: "TrstctlNotificationRoutingPolicy",
      metadata: { name: policy.name },
      spec: {
        default_channels: policy.default_channels ?? [],
        channels_by_severity: policy.channels_by_severity ?? {},
        owner_ref: policy.owner_ref ?? "",
        owner_email: policy.owner_email ?? "",
        digest_interval_seconds: policy.digest_interval_seconds,
        digest_timezone: policy.digest_timezone,
      },
    };
  }
  return {
    apiVersion: "trstctl.com/v1",
    kind: "TrstctlInstallValues",
    metadata: { name: "trstctl-control-plane" },
    spec: {
      chart: "deploy/helm/trstctl",
      namespace: "trstctl",
      image: { digest: "sha256:<release-image-digest>" },
      postgres: { external: true, dsnSecretRef: "trstctl-postgres-dsn" },
      nats: { external: true, urlSecretRef: "trstctl-nats-url" },
      signer: { mode: "sidecar-uds" },
      profiles: profiles.map((item) => ({ name: item.name, version: item.version })),
      discovery_sources: sources.map((item) => ({ name: item.name, kind: item.kind })),
      notification_policies: policies.map((item) => ({ name: item.name, default_channels: item.default_channels ?? [] })),
    },
  };
}

function parseManifest(text: string): { value?: Record<string, unknown>; error?: string } {
  if (!text.trim()) return {};
  try {
    const value = JSON.parse(text) as unknown;
    if (!isRecord(value)) return { error: "Declaration must be a JSON object." };
    return { value };
  } catch (err) {
    return { error: err instanceof Error ? err.message : "Declaration must be valid JSON." };
  }
}

function diffManifests(live: Record<string, unknown>, declared: Record<string, unknown>): DriftRow[] {
  const liveValues = flattenManifest(live);
  const declaredValues = flattenManifest(declared);
  const keys = Array.from(new Set([...liveValues.keys(), ...declaredValues.keys()])).sort();
  return keys.map((path) => {
    const liveValue = liveValues.get(path) ?? "-";
    const declaredValue = declaredValues.get(path) ?? "-";
    return { path, live: liveValue, declared: declaredValue, status: liveValue === declaredValue ? "In sync" : "Drift" };
  });
}

function flattenManifest(value: unknown, prefix = "", out = new Map<string, string>()): Map<string, string> {
  if (Array.isArray(value)) {
    out.set(prefix, JSON.stringify(value));
    return out;
  }
  if (isRecord(value)) {
    const entries = Object.entries(value).sort(([a], [b]) => a.localeCompare(b));
    if (entries.length === 0 && prefix) out.set(prefix, "{}");
    for (const [key, child] of entries) {
      flattenManifest(child, prefix ? `${prefix}.${key}` : key, out);
    }
    return out;
  }
  if (prefix) out.set(prefix, formatManifestValue(value));
  return out;
}

function formatManifestValue(value: unknown): string {
  if (value == null) return "";
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  return JSON.stringify(value);
}

function manifestName(manifest: Record<string, unknown>): string {
  const metadata = manifest.metadata;
  if (!isRecord(metadata)) return "";
  return typeof metadata.name === "string" ? metadata.name : "";
}

function downloadName(type: ManifestType): string {
  return `trstctl-gitops-${type}.json`;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function describeIntegrateError(err: unknown, fallback: string): string {
  if (err instanceof ApiError) {
    try {
      const problem = JSON.parse(err.body) as { detail?: string; title?: string };
      return problem.detail || problem.title || err.message;
    } catch {
      return err.body || err.message;
    }
  }
  if (err instanceof Error) return err.message;
  return fallback;
}
