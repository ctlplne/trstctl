import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { ChangeEvent, FormEvent, RefObject } from "react";
import { CheckCircle2, Activity, ClipboardList, Code2, Play, Plus, RefreshCw, Search, ShieldCheck, Sparkles, Tag, Trash2, Upload, XCircle } from "lucide-react";
import { useSearchParams } from "react-router-dom";
import { EmptyState } from "@/components/EmptyState";
import { PageTabs, tabPanelProps } from "@/components/PageTabs";
import { ErrorState, LoadingState, PermissionDeniedState } from "@/components/StatePrimitives";
import { StatusBadge } from "@/components/StatusBadge";
import { SourceActivityCell, SourceFindingsCell, sourceActivityByID, type SourceActivity } from "./discovery/DiscoveryPageParts";
import { ADCSSourceFields, parseADCSEnrollmentEndpoints, parseADCSPrivateEgressCIDRs } from "./discovery/ADCSSourceFields";
import { DiscoveryRunScopeNotice } from "./discovery/DiscoveryRunScopeNotice";
import { SourceSetup } from "./discovery/SourceSetup";
import { Button } from "@/components/ui/button";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { PageHeader } from "@/components/PageHeader";
import { DataGrid, type DataGridColumn, type DataGridToolbarControls } from "@/components/DataGrid";
import { DataGridToolbar } from "@/components/DataGridToolbar";
import { DiscoveryHero, CTMonitoringPanel, DriftPanel } from "@/components/discovery";
import { useTranslation, translateNow } from "@/i18n/I18nProvider";
import {
  api,
  ApiError,
  type DiscoveryCoverage,
  type DiscoveryFinding,
  type DiscoveryMonitoring,
  type DiscoveryPlanPreview,
  type DiscoveryRun,
  type DiscoverySchedule,
  type DiscoverySource,
  type DiscoverySourceRequest,
  type Identity,
  type NHIDecommissionRequest,
  type NHIShadowPosture,
  type Owner,
  type RemediationPlaybookRunRequest,
} from "@/lib/api";
import { formatDateTime as formatDateTimePolicy } from "@/i18n/format";
import type { MessageKey } from "@/i18n/messages";
import type { GridViewPrimitive } from "@/lib/gridViews";
import { invalidateAppQueryKeys } from "@/lib/query";

type Notice = { kind: "permission" | "error" | "success"; message: string };
type SourceKind = DiscoverySourceRequest["kind"];
type FindingTriageStatus = NonNullable<DiscoveryFinding["triage_status"]>;
type FindingTriageFilter = "all" | FindingTriageStatus;
type FindingFacetFilter = string;
type FindingFilters = { triage: FindingTriageFilter; owner: FindingFacetFilter; team: FindingFacetFilter; tag: FindingFacetFilter };
type FindingLifecycleAction = "rotate" | "revoke" | "decommission" | "remediate";

const remediationPlaybookRevokeIdentity = "identity-revoke";
const remediationPlaybookRotateIdentity = "credential-rotate";
const identityKinds: Identity["kind"][] = ["x509_certificate", "ssh_certificate", "ssh_key", "secret", "api_key", "workload_identity"];

const sourceKinds: SourceKind[] = [
  "api_key",
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
  adcs: translateNow("source.adcs.heading.f1adcs0001"),
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
const structuredSourceKinds = [
  "nhi_cross_surface",
  "api_key",
  "oauth_grant",
  "service_account",
  "nhi_behavior",
  "credential_compromise",
  "k8s_ingress_gateway",
] as const;
type StructuredSourceKind = (typeof structuredSourceKinds)[number];
type StructuredFieldKind = "text" | "select" | "list" | "number" | "checkbox";
type StructuredField = {
  key: string;
  fieldName: string;
  inputKind?: StructuredFieldKind;
  required?: boolean;
  placeholder?: string;
  choices?: Array<{ value: string; displayName: string }>;
  defaultValue?: string | boolean;
};
type StructuredRow = Record<string, string | boolean>;
type SourceTemplate = {
  id: string;
  templateName: string;
  rows: Array<Record<string, string | boolean | number | string[]>>;
};
type StructuredSourceConfig = {
  payloadKey: "observations" | "grants" | "accounts" | "events" | "signals" | "resources";
  rowName: string;
  fields: StructuredField[];
  templates: SourceTemplate[];
  fixedConfig?: Record<string, unknown>;
};

const surfaceChoices = [
  { value: "idp", displayName: "IdP" },
  { value: "cloud", displayName: "Cloud" },
  { value: "saas", displayName: "SaaS" },
  { value: "on_prem", displayName: "On-prem" },
  { value: "code", displayName: "Code" },
  { value: "ci", displayName: "CI" },
];
const requiredNHISurfaces = surfaceChoices.map((surface) => surface.value);
const nhiSurfaceDisplayNames = Object.fromEntries(surfaceChoices.map((surface) => [surface.value, surface.displayName])) as Record<string, string>;
const structuredSourceConfigs: Record<StructuredSourceKind, StructuredSourceConfig> = {
  nhi_cross_surface: {
    payloadKey: "observations",
    rowName: "NHI observation",
    fields: [
      { key: "surface", fieldName: "Surface", inputKind: "select", required: true, choices: surfaceChoices },
      { key: "system", fieldName: "System", required: true, placeholder: "okta" },
      { key: "external_id", fieldName: "External ID", required: true, placeholder: "app/payments" },
      { key: "principal", fieldName: "Principal", required: true, placeholder: "payments-api" },
      { key: "owner", fieldName: "Owner", placeholder: "platform" },
      { key: "credential_kind", fieldName: "Credential kind", placeholder: "oauth_client" },
      { key: "credential_ref", fieldName: "Credential reference", placeholder: "okta:app/payments" },
      { key: "evidence_refs", fieldName: "Evidence refs", inputKind: "list", placeholder: "okta:audit/app-42" },
    ],
    templates: [
      {
        id: "complete-six-surface",
        templateName: "Complete six-surface sample",
        rows: [
          {
            surface: "idp",
            system: "okta",
            external_id: "app/payments",
            principal: "payments-api",
            owner: "platform",
            credential_kind: "oauth_client",
            evidence_refs: ["okta:audit/app-42"],
          },
          {
            surface: "cloud",
            system: "aws-iam",
            external_id: "role/payments-prod",
            principal: "payments-api",
            owner: "platform",
            credential_kind: "iam_role",
            evidence_refs: ["aws-iam:credential-report"],
          },
          {
            surface: "saas",
            system: "github",
            external_id: "app/installations/42",
            principal: "payments-api",
            owner: "platform",
            credential_kind: "github_app",
            evidence_refs: ["github:audit/app-42"],
          },
          {
            surface: "on_prem",
            system: "ldap",
            external_id: "svc-payments",
            principal: "payments-api",
            owner: "platform",
            credential_kind: "service_account",
            evidence_refs: ["ldap:audit/svc-payments"],
          },
          {
            surface: "code",
            system: "github-code-search",
            external_id: "repo/payments/path/deploy.yaml",
            principal: "payments-api",
            owner: "platform",
            credential_kind: "deploy_key",
            evidence_refs: ["github:code-search/deploy-key"],
          },
          {
            surface: "ci",
            system: "github-actions",
            external_id: "repo/payments/env/prod",
            principal: "payments-api",
            owner: "platform",
            credential_kind: "workflow_token",
            evidence_refs: ["github-actions:audit/workflow-token"],
          },
        ],
      },
    ],
  },
  api_key: {
    payloadKey: "observations",
    rowName: "API key observation",
    fields: [
      { key: "surface", fieldName: "Surface", inputKind: "select", required: true, choices: surfaceChoices },
      { key: "system", fieldName: "System", required: true, placeholder: "github" },
      { key: "external_id", fieldName: "External ID", required: true, placeholder: "user/payments-ci/pat" },
      { key: "principal", fieldName: "Principal", required: true, placeholder: "payments-ci" },
      {
        key: "credential_kind",
        fieldName: "Credential kind",
        inputKind: "select",
        required: true,
        choices: [
          { value: "personal_access_token", displayName: "Personal access token" },
          { value: "access_key", displayName: "Access key" },
          { value: "api_token", displayName: "API token" },
        ],
      },
      { key: "credential_ref", fieldName: "Credential reference", required: true, placeholder: "github:user/payments-ci/pat" },
      { key: "masked_fingerprint", fieldName: "Masked fingerprint", placeholder: "sha256:github-pat-ref" },
      { key: "evidence_refs", fieldName: "Evidence refs", inputKind: "list", placeholder: "github:audit/pat-1" },
    ],
    templates: [
      {
        id: "github-pat",
        templateName: "GitHub token",
        rows: [
          {
            surface: "saas",
            system: "github",
            external_id: "user/payments-ci/pat",
            principal: "payments-ci",
            credential_kind: "personal_access_token",
            credential_ref: "github:user/payments-ci/pat",
            masked_fingerprint: "sha256:github-pat-ref",
            evidence_refs: ["github:audit/pat-1"],
          },
        ],
      },
      {
        id: "aws-access-key",
        templateName: "AWS access key",
        rows: [
          {
            surface: "cloud",
            system: "aws-iam",
            external_id: "access-key/AKIAEXAMPLE",
            principal: "arn:aws:iam::111111111111:user/payments-deploy",
            credential_kind: "access_key",
            credential_ref: "aws-iam:111111111111:access-key/AKIAEXAMPLE",
            masked_fingerprint: "sha256:aws-access-key-ref",
            evidence_refs: ["aws-iam:credential-report"],
          },
        ],
      },
    ],
  },
  oauth_grant: {
    payloadKey: "grants",
    rowName: "OAuth grant",
    fields: [
      { key: "provider", fieldName: "Provider", required: true, placeholder: "okta" },
      { key: "app_id", fieldName: "App ID", required: true, placeholder: "0oa-payments" },
      { key: "app_name", fieldName: "App name", placeholder: "Payments BI Export" },
      { key: "principal", fieldName: "Principal", required: true, placeholder: "payments-bi-export" },
      { key: "resource", fieldName: "Resource", required: true, placeholder: "google-workspace" },
      { key: "scopes", fieldName: "Scopes", inputKind: "list", required: true, placeholder: "drive.readonly, admin.directory.user.readonly" },
      {
        key: "consent_type",
        fieldName: "Consent type",
        inputKind: "select",
        required: true,
        choices: [
          { value: "admin", displayName: "Admin" },
          { value: "user", displayName: "User" },
        ],
      },
      { key: "third_party", fieldName: "Third party", inputKind: "checkbox", defaultValue: true },
      { key: "owner", fieldName: "Owner", placeholder: "finance-platform" },
      { key: "publisher_verified", fieldName: "Publisher verified", inputKind: "checkbox" },
      { key: "threat_signals", fieldName: "Threat signals", inputKind: "list", placeholder: "consent_phishing" },
      { key: "evidence_refs", fieldName: "Evidence refs", inputKind: "list", placeholder: "okta:audit/consent-42" },
    ],
    templates: [
      {
        id: "admin-consent",
        templateName: "Admin consent app",
        rows: [
          {
            provider: "okta",
            app_id: "0oa-payments",
            app_name: "Payments BI Export",
            principal: "payments-bi-export",
            resource: "google-workspace",
            scopes: ["drive.readonly", "admin.directory.user.readonly"],
            consent_type: "admin",
            third_party: true,
            owner: "finance-platform",
            publisher_verified: false,
            threat_signals: ["consent_phishing"],
            evidence_refs: ["okta:audit/consent-42"],
          },
        ],
      },
      {
        id: "entra-third-party",
        templateName: "Entra third-party grant",
        rows: [
          {
            provider: "entra-id",
            app_id: "evil-consent-app",
            principal: "legacy-mail-archive",
            resource: "microsoft-graph",
            scopes: ["offline_access", "Directory.ReadWrite.All", "*.default"],
            consent_type: "admin",
            third_party: true,
            publisher_verified: false,
            threat_signals: ["consent_phishing"],
            evidence_refs: ["entra:audit/consent-42"],
          },
        ],
      },
    ],
  },
  service_account: {
    payloadKey: "accounts",
    rowName: "Service account",
    fields: [
      {
        key: "surface",
        fieldName: "Surface",
        inputKind: "select",
        required: true,
        choices: [
          { value: "active_directory", displayName: "Active Directory" },
          { value: "cloud", displayName: "Cloud" },
          { value: "saas", displayName: "SaaS" },
        ],
      },
      { key: "provider", fieldName: "Provider", required: true, placeholder: "ad" },
      { key: "directory", fieldName: "Directory", required: true, placeholder: "corp.example" },
      { key: "account_id", fieldName: "Account ID", required: true, placeholder: "S-1-5-21-1000" },
      { key: "principal", fieldName: "Principal", required: true, placeholder: "svc-payments@corp.example" },
      { key: "owner", fieldName: "Owner", placeholder: "identity" },
      { key: "privileged", fieldName: "Privileged", inputKind: "checkbox" },
      { key: "groups", fieldName: "Groups", inputKind: "list", placeholder: "CN=Payments,OU=Service Accounts,DC=corp,DC=example" },
      { key: "roles", fieldName: "Roles", inputKind: "list", placeholder: "AdministratorAccess" },
      { key: "credential_refs", fieldName: "Credential refs", inputKind: "list", placeholder: "ad:corp.example:svc-payments" },
    ],
    templates: [
      {
        id: "active-directory",
        templateName: "Active Directory account",
        rows: [
          {
            surface: "active_directory",
            provider: "ad",
            directory: "corp.example",
            account_id: "S-1-5-21-1000",
            principal: "svc-payments@corp.example",
            owner: "identity",
            groups: ["CN=Payments,OU=Service Accounts,DC=corp,DC=example"],
            credential_refs: ["ad:corp.example:svc-payments"],
          },
        ],
      },
      {
        id: "cloud-role",
        templateName: "Cloud privileged role",
        rows: [
          {
            surface: "cloud",
            provider: "aws-iam",
            directory: "111111111111",
            account_id: "role/payments-prod",
            principal: "arn:aws:iam::111111111111:role/payments-prod",
            owner: "platform",
            privileged: true,
            roles: ["AdministratorAccess"],
            credential_refs: ["aws:iam:role/payments-prod"],
          },
        ],
      },
    ],
  },
  nhi_behavior: {
    payloadKey: "events",
    rowName: "Behavior event",
    fixedConfig: { business_hours: { start_hour: 8, end_hour: 18 } },
    fields: [
      { key: "principal", fieldName: "Principal", required: true, placeholder: "payments-api" },
      { key: "occurred_at", fieldName: "Occurred at", required: true, placeholder: "2026-06-01T10:00:00Z" },
      { key: "ip", fieldName: "IP address", required: true, placeholder: "198.51.100.10" },
      { key: "geo", fieldName: "Geo", required: true, placeholder: "US" },
      { key: "user_agent", fieldName: "User agent", placeholder: "payments-agent/1.0" },
      { key: "usage_count", fieldName: "Usage count", inputKind: "number", required: true, placeholder: "10" },
      { key: "baseline", fieldName: "Baseline", inputKind: "checkbox" },
    ],
    templates: [
      {
        id: "baseline",
        templateName: "Baseline activity",
        rows: [
          {
            principal: "payments-api",
            occurred_at: "2026-06-01T10:00:00Z",
            ip: "198.51.100.10",
            geo: "US",
            user_agent: "payments-agent/1.0",
            usage_count: 10,
            baseline: true,
          },
        ],
      },
      {
        id: "anomalous",
        templateName: "Anomalous activity",
        rows: [
          {
            principal: "payments-api",
            occurred_at: "2026-06-02T02:15:00Z",
            ip: "203.0.113.9",
            geo: "DE",
            user_agent: "curl/8.7",
            usage_count: 90,
          },
        ],
      },
    ],
  },
  credential_compromise: {
    payloadKey: "signals",
    rowName: "Compromise signal",
    fields: [
      { key: "principal", fieldName: "Principal", required: true, placeholder: "payments-api" },
      { key: "credential_ref", fieldName: "Credential reference", required: true, placeholder: "api-token:payments-ci" },
      { key: "credential_kind", fieldName: "Credential kind", required: true, placeholder: "api_token" },
      { key: "provider", fieldName: "Provider", required: true, placeholder: "github-actions" },
      { key: "detector", fieldName: "Detector", required: true, placeholder: "honeytoken" },
      { key: "observed_at", fieldName: "Observed at", required: true, placeholder: "2026-06-03T03:15:00Z" },
      { key: "reason", fieldName: "Reason", required: true, placeholder: "revoked token replayed from unfamiliar network" },
      {
        key: "confidence",
        fieldName: "Confidence",
        inputKind: "select",
        required: true,
        choices: [
          { value: "low", displayName: "Low" },
          { value: "medium", displayName: "Medium" },
          { value: "high", displayName: "High" },
          { value: "critical", displayName: "Critical" },
        ],
      },
      { key: "evidence_refs", fieldName: "Evidence refs", inputKind: "list", placeholder: "audit:api-token-use/evt-42" },
    ],
    templates: [
      {
        id: "honeytoken",
        templateName: "Honeytoken replay",
        rows: [
          {
            principal: "payments-api",
            credential_ref: "api-token:payments-ci",
            credential_kind: "api_token",
            provider: "github-actions",
            detector: "honeytoken",
            observed_at: "2026-06-03T03:15:00Z",
            reason: "revoked token replayed from unfamiliar network",
            confidence: "critical",
            evidence_refs: ["audit:api-token-use/evt-42"],
          },
        ],
      },
    ],
  },
  k8s_ingress_gateway: {
    payloadKey: "resources",
    rowName: "Kubernetes TLS resource",
    fields: [
      {
        key: "kind",
        fieldName: "Kind",
        inputKind: "select",
        required: true,
        choices: [
          { value: "Ingress", displayName: "Ingress" },
          { value: "Gateway", displayName: "Gateway" },
        ],
      },
      { key: "namespace", fieldName: "Namespace", required: true, placeholder: "payments" },
      { key: "name", fieldName: "Name", required: true, placeholder: "payments-web" },
      { key: "tls_secret_name", fieldName: "TLS secret", required: true, placeholder: "payments-web-tls" },
      { key: "hosts", fieldName: "Hosts", inputKind: "list", required: true, placeholder: "payments.example.com" },
      { key: "auto_issue", fieldName: "Auto issue", inputKind: "checkbox", defaultValue: true },
    ],
    templates: [
      {
        id: "ingress",
        templateName: "Ingress TLS",
        rows: [
          {
            kind: "Ingress",
            namespace: "payments",
            name: "payments-web",
            tls_secret_name: "payments-web-tls",
            hosts: ["payments.example.com"],
            auto_issue: true,
          },
        ],
      },
      {
        id: "gateway",
        templateName: "Gateway TLS",
        rows: [
          {
            kind: "Gateway",
            namespace: "edge",
            name: "public",
            tls_secret_name: "edge-public-tls",
            hosts: ["edge.example.com", "api.example.com"],
            auto_issue: true,
          },
        ],
      },
    ],
  },
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

function gridControlsToolbar({ columnChooser, savedViews }: DataGridToolbarControls) {
  return <DataGridToolbar columnChooser={columnChooser} savedViews={savedViews} />;
}

function gridMetadataString(metadata: Record<string, GridViewPrimitive>, key: string, fallback = "all"): string {
  const value = metadata[key];
  return typeof value === "string" && value ? value : fallback;
}

function isStructuredSourceKind(kind: SourceKind): kind is StructuredSourceKind {
  return structuredSourceKinds.includes(kind as StructuredSourceKind);
}

function initialStructuredRows(): Record<StructuredSourceKind, StructuredRow[]> {
  return Object.fromEntries(structuredSourceKinds.map((kind) => [kind, [emptyStructuredRow(structuredSourceConfigs[kind])]])) as Record<
    StructuredSourceKind,
    StructuredRow[]
  >;
}

function initialStructuredTemplates(): Record<StructuredSourceKind, string> {
  return Object.fromEntries(structuredSourceKinds.map((kind) => [kind, structuredSourceConfigs[kind].templates[0]?.id ?? ""])) as Record<
    StructuredSourceKind,
    string
  >;
}

function initialStructuredJSONImports(): Record<StructuredSourceKind, string> {
  return Object.fromEntries(structuredSourceKinds.map((kind) => [kind, ""])) as Record<StructuredSourceKind, string>;
}

/** Findings render on the default tab; sources, schedules, and runs each get
 * their own workspace tab with the matching create form (audit P0: the page
 * previously stacked four KPI strips, two inline forms, and four tables). */
type DiscoveryTab = "findings" | "sources" | "schedules" | "runs";
const discoveryTabIds: readonly DiscoveryTab[] = ["findings", "sources", "schedules", "runs"];

function discoveryTabFromSearchParam(value: string | null): DiscoveryTab {
  return discoveryTabIds.includes(value as DiscoveryTab) ? (value as DiscoveryTab) : "findings";
}

export function Discovery() {
  const { formatDateTime, t } = useTranslation();
  const [searchParams, setSearchParams] = useSearchParams();
  const requestedRunID = searchParams.get("run_id")?.trim() ?? "";
  const [tab, setTab] = useState<DiscoveryTab>(() => discoveryTabFromSearchParam(searchParams.get("tab")));
  const [pendingFocus, setPendingFocus] = useState<"source" | "schedule" | "run" | null>(null);
  const [sources, setSources] = useState<DiscoverySource[]>([]);
  const [schedules, setSchedules] = useState<DiscoverySchedule[]>([]);
  const [runs, setRuns] = useState<DiscoveryRun[]>([]);
  const [findings, setFindings] = useState<DiscoveryFinding[]>([]);
  const [monitoring, setMonitoring] = useState<DiscoveryMonitoring | null>(null);
  const [coverageReport, setCoverageReport] = useState<DiscoveryCoverage | null>(null);
  const [shadowPosture, setShadowPosture] = useState<NHIShadowPosture | null>(null);
  const [notice, setNotice] = useState<Notice | null>(null);
  const [loading, setLoading] = useState(true);
  const [ctRefreshToken, setCTRefreshToken] = useState(0);
  const [busy, setBusy] = useState<string | null>(null);
  const [sourceName, setSourceName] = useState("");
  const [sourceKind, setSourceKind] = useState<SourceKind>("nhi_cross_surface");
  const [targets, setTargets] = useState("");
  const [segment, setSegment] = useState("");
  const [relayAgentID, setRelayAgentID] = useState("");
  const [adcsURL, setADCSURL] = useState("ldaps://");
  const [adcsConfigurationDN, setADCSConfigurationDN] = useState("");
  const [adcsBindDN, setADCSBindDN] = useState("");
  const [adcsPasswordRef, setADCSPasswordRef] = useState("");
  const [adcsEnrollmentEndpoints, setADCSEnrollmentEndpoints] = useState("");
  const [adcsAllowPrivateEndpoint, setADCSAllowPrivateEndpoint] = useState(false);
  const [adcsPrivateEgressCIDRs, setADCSPrivateEgressCIDRs] = useState("");
  const [structuredRows, setStructuredRows] = useState<Record<StructuredSourceKind, StructuredRow[]>>(() => initialStructuredRows());
  const [structuredTemplates, setStructuredTemplates] = useState<Record<StructuredSourceKind, string>>(() => initialStructuredTemplates());
  const [structuredJSONImports, setStructuredJSONImports] = useState<Record<StructuredSourceKind, string>>(() => initialStructuredJSONImports());
  const [openJSONImportKind, setOpenJSONImportKind] = useState<StructuredSourceKind | null>(null);
  const [apiKeyPlan, setAPIKeyPlan] = useState<{ requestKey: string; preview: DiscoveryPlanPreview } | null>(null);
  const [scheduleName, setScheduleName] = useState("");
  const [scheduleSourceID, setScheduleSourceID] = useState("");
  const [scheduleInterval, setScheduleInterval] = useState(3600);
  const sourceNameRef = useRef<HTMLInputElement>(null);
  const scheduleNameRef = useRef<HTMLInputElement>(null);
  const firstRunButtonRef = useRef<HTMLButtonElement>(null);

  const apiKeyDraft = useMemo(() => {
    if (sourceKind !== "api_key") return null;
    try {
      const request: DiscoverySourceRequest = {
        name: sourceName.trim(),
        kind: sourceKind,
        config: buildStructuredSourceConfig(sourceKind, structuredRows[sourceKind], structuredJSONImports[sourceKind]),
      };
      return { request, requestKey: JSON.stringify(request) };
    } catch {
      return null;
    }
  }, [sourceKind, sourceName, structuredRows, structuredJSONImports]);
  const apiKeyPlanIsCurrent = apiKeyDraft !== null && apiKeyPlan?.requestKey === apiKeyDraft.requestKey;
  const apiKeyPlanAllowsSave =
    apiKeyDraft !== null &&
    apiKeyPlan !== null &&
    apiKeyPlan.requestKey === apiKeyDraft.requestKey &&
    apiKeyPlan.preview.ready !== false &&
    apiKeyPlan.preview.side_effects === false &&
    apiKeyPlan.preview.blocked_reasons.length === 0;

  const load = useCallback(async () => {
    setLoading(true);
    setNotice(null);
    const [sourceResult, scheduleResult, runResult, monitoringResult, shadowPostureResult, findingResult, coverageResult] = await Promise.allSettled([
      api.discoverySources({ limit: 50 }),
      api.discoverySchedules({ limit: 50 }),
      api.discoveryRuns({ limit: 50 }),
      api.discoveryMonitoring(),
      api.nhiShadowPosture(),
      api.discoveryFindings({ limit: 50, ...(requestedRunID ? { runId: requestedRunID } : {}) }),
      api.discoveryCoverage(),
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
    if (findingResult.status === "fulfilled") {
      const items = findingResult.value.items ?? [];
      setFindings(requestedRunID ? items.filter((finding) => finding.run_id === requestedRunID) : items);
    } else setFindings([]);
    if (coverageResult.status === "fulfilled") setCoverageReport(coverageResult.value);
    else setCoverageReport(null);
    const rejected = [sourceResult, scheduleResult, runResult, monitoringResult, shadowPostureResult, findingResult].find(
      (result) => result.status === "rejected",
    );
    if (rejected?.status === "rejected") setNotice(noticeForError(rejected.reason, "Could not load discovery records"));
    setLoading(false);
  }, [requestedRunID]);

  useEffect(() => {
    void load();
  }, [load]);

  const refreshAll = useCallback(async () => {
    await load();
    setCTRefreshToken((current) => current + 1);
  }, [load]);

  useEffect(() => {
    if (!scheduleSourceID && sources[0]) setScheduleSourceID(sources[0].id);
  }, [scheduleSourceID, sources]);

  const sourceByID = useMemo(() => new Map(sources.map((source) => [source.id, source])), [sources]);
  // S-C15: join each source to its served monitoring row (last run,
  // findings, drift) so the table answers "did this actually run".
  const sourceActivity = useMemo(() => sourceActivityByID(monitoring?.sources ?? []), [monitoring]);
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

  function restoreFindingFilters(filters: FindingFilters) {
    setSearchParams(
      (current) => {
        const next = new URLSearchParams(current);
        for (const key of ["triage", "owner", "team", "tag"] as const) {
          const value = filters[key];
          if (value === "all" || value === "") {
            next.delete(key);
          } else {
            next.set(key, value);
          }
        }
        return next;
      },
      { replace: true },
    );
  }

  async function replaceFinding(updated: DiscoveryFinding) {
    setFindings((current) => current.map((finding) => (finding.id === updated.id ? updated : finding)));
    // Claim/dismiss changes the cross-domain posture that Home, Risk, NHI, and
    // Ownership cache independently. Refresh them immediately so navigating
    // away cannot show the pre-triage count for another 30 seconds.
    invalidateAppQueryKeys([["nhi-shadow-posture"], ["nhi-inventory"], ["risk"], ["contextual-priorities"], ["ownership-attribution"]]);
    // This page owns its shadow-posture state outside React Query. Re-read the
    // projection after triage so the open evidence panel cannot retain the old
    // unmanaged count. If that read fails, remove the stale number instead of
    // presenting it as current; the successful claim/dismiss remains intact.
    try {
      setShadowPosture(await api.nhiShadowPosture());
    } catch {
      setShadowPosture(null);
    }
  }

  async function createSource(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy("source");
    setNotice(null);
    try {
      const config =
        sourceKind === "adcs"
          ? {
              url: adcsURL.trim(),
              configuration_dn: adcsConfigurationDN.trim(),
              bind_dn: adcsBindDN.trim(),
              password_ref: adcsPasswordRef.trim(),
              ...(adcsEnrollmentEndpoints.trim() ? { enrollment_endpoints: parseADCSEnrollmentEndpoints(adcsEnrollmentEndpoints) } : {}),
              ...(adcsAllowPrivateEndpoint ? { allow_private_endpoint: true, private_egress_cidrs: parseADCSPrivateEgressCIDRs(adcsPrivateEgressCIDRs) } : {}),
              ...(relayAgentID.trim() ? { relay_agent_id: relayAgentID.trim() } : {}),
            }
          : sourceKind === "network" || sourceKind === "ssh"
            ? {
                targets: parseTargets(targets),
                segment: segment.trim(),
                ...(relayAgentID.trim() ? { relay_agent_id: relayAgentID.trim() } : {}),
              }
            : isStructuredSourceKind(sourceKind)
              ? buildStructuredSourceConfig(sourceKind, structuredRows[sourceKind], structuredJSONImports[sourceKind])
              : {};
      const request: DiscoverySourceRequest = { name: sourceName.trim(), kind: sourceKind, config };
      if (sourceKind === "api_key") {
        const requestKey = JSON.stringify(request);
        if (
          apiKeyPlan?.requestKey !== requestKey ||
          apiKeyPlan.preview.ready === false ||
          apiKeyPlan.preview.side_effects ||
          apiKeyPlan.preview.blocked_reasons.length > 0
        ) {
          // A failed or blocked re-preview must not leave an older approval
          // visible, even though the request-key check already keeps save
          // fail-closed.
          setAPIKeyPlan(null);
          const preview = await api.previewDiscoveryPlan(request);
          setAPIKeyPlan({ requestKey, preview });
          const blocked = preview.ready === false || preview.side_effects || preview.blocked_reasons.length > 0;
          setNotice({
            kind: blocked ? "error" : "success",
            message: blocked ? t("discovery.importPreview.blocked") : t("discovery.importPreview.reviewed"),
          });
          return;
        }
      }
      const created = await api.createDiscoverySource(request);
      setSourceName("");
      setTargets("");
      setSegment("");
      setRelayAgentID("");
      setADCSURL("ldaps://");
      setADCSConfigurationDN("");
      setADCSBindDN("");
      setADCSPasswordRef("");
      setADCSEnrollmentEndpoints("");
      setADCSAllowPrivateEndpoint(false);
      setADCSPrivateEgressCIDRs("");
      setStructuredRows(initialStructuredRows());
      setStructuredTemplates(initialStructuredTemplates());
      setStructuredJSONImports(initialStructuredJSONImports());
      setOpenJSONImportKind(null);
      setAPIKeyPlan(null);
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
      const preflight = await api.preflightDiscoverySource(sourceID);
      if (preflight.ready === false || preflight.blocked_reasons.length > 0) {
        const reason = preflight.blocked_reasons.join(" ") || t("discovery.run.blockedFallback");
        setNotice({ kind: "error", message: t("discovery.run.blocked", { reason }) });
        return;
      }
      await api.startDiscoveryRun({ source_id: sourceID, dry_run: dryRun });
      await load();
    } catch (err) {
      setNotice(noticeForError(err, "Could not start discovery run"));
    } finally {
      setBusy(null);
    }
  }

  async function retryRun(run: DiscoveryRun) {
    setBusy(`retry:${run.id}`);
    setNotice(null);
    try {
      const preflight = await api.preflightDiscoverySource(run.source_id);
      if (preflight.ready === false || preflight.blocked_reasons.length > 0) {
        const reason = preflight.blocked_reasons.join(" ") || t("discovery.run.blockedFallback");
        setNotice({ kind: "error", message: t("discovery.run.recoveryBlocked", { reason }) });
        return;
      }
      const replacement = await api.retryDiscoveryRun(run.id);
      await load();
      setNotice({
        kind: "success",
        message: t("discovery.run.recoveryQueued", { replacement: shortID(replacement.id), original: shortID(run.id) }),
      });
    } catch (err) {
      setNotice(noticeForError(err, t("discovery.run.retryFailed")));
    } finally {
      setBusy(null);
    }
  }

  function selectTab(next: string) {
    const value = discoveryTabFromSearchParam(next);
    setTab(value);
    setSearchParams(
      (current) => {
        const nextParams = new URLSearchParams(current);
        if (value === "findings") {
          nextParams.delete("tab");
        } else {
          nextParams.set("tab", value);
        }
        return nextParams;
      },
      { replace: true },
    );
  }

  // The create forms live behind their workspace tabs, so "create source" CTAs
  // first switch tabs and then focus once the form has mounted.
  useEffect(() => {
    if (!pendingFocus) return;
    const ref = pendingFocus === "source" ? sourceNameRef : pendingFocus === "schedule" ? scheduleNameRef : firstRunButtonRef;
    ref.current?.scrollIntoView?.({ block: "center" });
    ref.current?.focus();
    setPendingFocus(null);
  }, [pendingFocus, tab]);

  function focusSourceForm() {
    selectTab("sources");
    setPendingFocus("source");
  }

  function focusScheduleForm() {
    selectTab("schedules");
    setPendingFocus("schedule");
  }

  function focusRunAction() {
    selectTab("sources");
    setPendingFocus(sources.length === 0 ? "source" : "run");
  }

  return (
    <section aria-labelledby="discovery-heading" className="grid gap-6">
      <PageHeader
        titleId="discovery-heading"
        title={t("discovery.page.title")}
        description={t("discovery.page.answer")}
        technicalDetails={t("discovery.page.details")}
        actions={
          <>
            <Button type="button" onClick={focusRunAction}>
              <Play className="h-4 w-4" aria-hidden="true" />
              {t("discovery.action.runScan")}
            </Button>
            <Button type="button" variant="outline" onClick={() => void refreshAll()} disabled={loading}>
              <RefreshCw className={loading ? "h-4 w-4 animate-spin" : "h-4 w-4"} aria-hidden="true" />
              {translateNow("source.refresh.0e91610117")}
            </Button>
          </>
        }
      />

      <DiscoveryHero findings={findings} />

      {notice && renderNotice(notice)}
      {loading && <LoadingState>{translateNow("source.loading.discovery.records.da1c8fab87")}</LoadingState>}

      <PageTabs
        idPrefix="discovery"
        ariaLabel="Discovery workspaces"
        active={tab}
        onChange={selectTab}
        className="mb-0"
        tabs={[
          { id: "findings", label: t("discovery.tabs.findings") },
          { id: "sources", label: t("discovery.tabs.sources") },
          { id: "schedules", label: t("discovery.tabs.schedules") },
          { id: "runs", label: t("discovery.tabs.runs") },
        ]}
      />

      {tab === "findings" && (
        <>
          <section {...tabPanelProps("discovery", "findings")} aria-labelledby="findings-heading" className="grid gap-3 border-y border-border py-4">
            <h2 id="findings-heading" className="text-title font-semibold">
              {t("discovery.findings.heading")}
            </h2>
            {requestedRunID ? (
              <DiscoveryRunScopeNotice
                runId={requestedRunID}
                onClear={() => {
                  setSearchParams(
                    (current) => {
                      const next = new URLSearchParams(current);
                      next.delete("run_id");
                      return next;
                    },
                    { replace: true },
                  );
                }}
              />
            ) : null}
            {!loading && findings.length === 0 ? (
              <EmptyState
                icon={<Search className="h-5 w-5" aria-hidden="true" />}
                title={translateNow("source.no.discovery.findings.7c8b4f0e23")}
                primaryAction={{ label: t("discovery.action.runScan"), onClick: focusRunAction, icon: <Play className="h-4 w-4" /> }}
                secondaryAction={{ label: translateNow("source.open.posture.71199986c4"), to: "/posture", icon: <Search className="h-4 w-4" /> }}
              >
                {translateNow("source.findings.populate.after.discovery.observes.9d8596dcef")}
              </EmptyState>
            ) : (
              <FindingTable
                findings={filteredFindings}
                allFindings={findings}
                sourceByID={sourceByID}
                filters={findingFilters}
                facetOptions={findingFacetOptions}
                onFilterChange={setFindingFilter}
                onFiltersRestore={restoreFindingFilters}
                onFindingUpdated={replaceFinding}
                onNotice={setNotice}
              />
            )}
          </section>

          <details className="group overflow-hidden rounded-panel border border-border bg-card">
            <summary className="cursor-pointer list-none px-4 py-3 marker:hidden hover:bg-muted/40">
              <span className="block text-sm font-semibold">{t("discovery.evidence.title")}</span>
              <span className="mt-0.5 block text-caption text-muted-foreground">{t("discovery.evidence.description")}</span>
              <span className="mt-2 block text-xs text-muted-foreground group-open:hidden">{t("discovery.evidence.open")}</span>
              <span className="mt-2 hidden text-xs text-muted-foreground group-open:block">{t("discovery.evidence.close")}</span>
            </summary>
            <div className="grid gap-6 border-t border-border p-4">
              <CTMonitoringPanel refreshToken={ctRefreshToken} onRunTerminal={load} />
              <DriftPanel findings={findings} sources={sources} />
              <MonitoringPanel monitoring={monitoring} onCreateSource={focusSourceForm} />
              <ShadowPosturePanel posture={shadowPosture} />
            </div>
          </details>
        </>
      )}

      {tab === "sources" && (
        <div {...tabPanelProps("discovery", "sources")} className="grid gap-6">
          <SourceSetup
            onCreated={async (created) => {
              setScheduleSourceID(created.id);
              setNotice({ kind: "success", message: `Source ${created.name} was saved. No scan has run yet.` });
              await load();
            }}
          />
          <form aria-labelledby="source-form-heading" className="ui-panel grid gap-4 p-comfortable" onSubmit={createSource}>
            <div className="flex items-center gap-2">
              <Search className="h-4 w-4 text-muted-foreground" aria-hidden="true" />
              <h2 id="source-form-heading" className="text-title font-semibold">
                {t("discovery.sourceForm.importTitle")}
              </h2>
            </div>
            <div className="grid gap-3 md:grid-cols-[1fr_14rem]">
              <Field label={translateNow("source.name.dcd1d5223f")} required>
                {(control) => <Input {...control} ref={sourceNameRef} value={sourceName} onChange={(event) => setSourceName(event.target.value)} required />}
              </Field>
              <label className="grid gap-1 text-sm font-medium">
                {translateNow("source.kind.f5387f9bb6")}
                <select className="ui-input" value={sourceKind} onChange={(event) => setSourceKind(event.target.value as SourceKind)}>
                  {sourceKinds.map((kind) => (
                    <option key={kind} value={kind}>
                      {sourceKindLabels[kind]}
                    </option>
                  ))}
                </select>
              </label>
            </div>
            {(sourceKind === "network" || sourceKind === "ssh") && (
              <div className="grid gap-3">
                <label className="grid gap-1 text-sm font-medium">
                  {t("discovery.source.segment")}
                  <input
                    className="ui-input"
                    value={segment}
                    onChange={(event) => setSegment(event.target.value)}
                    placeholder={t("discovery.source.segmentPlaceholder")}
                    required
                  />
                </label>
                <label className="grid gap-1 text-sm font-medium">
                  {t("discovery.source.relayAgent")}
                  <input
                    className="ui-input font-mono text-xs"
                    value={relayAgentID}
                    onChange={(event) => setRelayAgentID(event.target.value)}
                    placeholder={t("discovery.source.relayAgentPlaceholder")}
                  />
                  <span className="text-xs font-normal text-muted-foreground">{t("discovery.source.relayHint")}</span>
                </label>
                <label className="grid gap-1 text-sm font-medium">
                  {translateNow("source.targets.27445f6ab6")}
                  <textarea
                    className="ui-input min-h-24 font-mono text-xs"
                    value={targets}
                    onChange={(event) => setTargets(event.target.value)}
                    placeholder={sourceKind === "ssh" ? "10.0.0.10:22" : "10.0.0.10:443"}
                    required
                  />
                </label>
              </div>
            )}
            {sourceKind === "adcs" && (
              <ADCSSourceFields
                url={adcsURL}
                configurationDN={adcsConfigurationDN}
                bindDN={adcsBindDN}
                passwordRef={adcsPasswordRef}
                relayAgentID={relayAgentID}
                enrollmentEndpoints={adcsEnrollmentEndpoints}
                allowPrivateEndpoint={adcsAllowPrivateEndpoint}
                privateEgressCIDRs={adcsPrivateEgressCIDRs}
                onURL={setADCSURL}
                onConfigurationDN={setADCSConfigurationDN}
                onBindDN={setADCSBindDN}
                onPasswordRef={setADCSPasswordRef}
                onRelayAgentID={setRelayAgentID}
                onEnrollmentEndpoints={setADCSEnrollmentEndpoints}
                onAllowPrivateEndpoint={setADCSAllowPrivateEndpoint}
                onPrivateEgressCIDRs={setADCSPrivateEgressCIDRs}
              />
            )}
            {isStructuredSourceKind(sourceKind) && (
              <StructuredSourceForm
                key={sourceKind}
                kind={sourceKind}
                rows={structuredRows[sourceKind]}
                selectedTemplate={structuredTemplates[sourceKind]}
                jsonImport={structuredJSONImports[sourceKind]}
                jsonImportOpen={openJSONImportKind === sourceKind}
                onRowsChange={(rows) => setStructuredRows((current) => ({ ...current, [sourceKind]: rows }))}
                onTemplateChange={(template) => setStructuredTemplates((current) => ({ ...current, [sourceKind]: template }))}
                onSampleLoaded={() => {
                  if (!sourceName.trim()) setSourceName(`${sourceKindLabels[sourceKind]} sample`);
                }}
                onJSONImportChange={(value) => setStructuredJSONImports((current) => ({ ...current, [sourceKind]: value }))}
                onToggleJSONImport={() => setOpenJSONImportKind((current) => (current === sourceKind ? null : sourceKind))}
              />
            )}
            {sourceKind === "api_key" && apiKeyPlanIsCurrent && apiKeyDraft && apiKeyPlan ? (
              <section aria-label={t("discovery.importPreview.label")} className="grid gap-4 rounded-panel border border-brand-accent/25 bg-brand-accent/5 p-4">
                <div className="flex items-start gap-3">
                  <ShieldCheck className="mt-0.5 h-5 w-5 text-brand-accent" aria-hidden="true" />
                  <div>
                    <h3 className="font-semibold">{t("discovery.importPreview.title")}</h3>
                    <p className="mt-1 text-sm text-muted-foreground">{t("discovery.importPreview.body")}</p>
                  </div>
                </div>
                <dl className="grid gap-3 text-sm sm:grid-cols-3">
                  <div className="border-s-2 border-border ps-3">
                    <dt className="text-caption text-muted-foreground">{t("discovery.importPreview.permission")}</dt>
                    <dd className="mt-0.5 font-medium">{apiKeyPlan.preview.permission}</dd>
                  </div>
                  <div className="border-s-2 border-border ps-3">
                    <dt className="text-caption text-muted-foreground">{t("discovery.importPreview.effect")}</dt>
                    <dd className="mt-0.5 font-medium">
                      {apiKeyPlan.preview.side_effects ? t("discovery.importPreview.effectBlocked") : t("discovery.importPreview.effectNone")}
                    </dd>
                  </div>
                  <div className="border-s-2 border-border ps-3">
                    <dt className="text-caption text-muted-foreground">{t("discovery.importPreview.dataHandling")}</dt>
                    <dd className="mt-0.5 font-medium">{apiKeyPlan.preview.data_handling}</dd>
                  </div>
                </dl>
                {!apiKeyPlanAllowsSave ? (
                  <div role="alert" className="rounded-control border border-risk-warning/40 bg-risk-warning/10 p-3 text-sm">
                    <p className="font-semibold">{t("discovery.importPreview.blocked")}</p>
                    {apiKeyPlan.preview.blocked_reasons.length > 0 ? (
                      <ul className="mt-1 list-disc space-y-1 ps-5 text-muted-foreground">
                        {apiKeyPlan.preview.blocked_reasons.map((reason) => (
                          <li key={reason}>{reason}</li>
                        ))}
                      </ul>
                    ) : null}
                  </div>
                ) : null}
                <details className="text-sm text-muted-foreground">
                  <summary className="cursor-pointer font-medium text-foreground">{t("discovery.importPreview.exactConfig")}</summary>
                  <pre className="mt-2 max-h-72 overflow-auto whitespace-pre-wrap rounded-control bg-background p-3 font-mono text-xs">
                    {JSON.stringify(apiKeyDraft.request.config, null, 2)}
                  </pre>
                </details>
              </section>
            ) : null}
            <Button type="submit" className="justify-self-start" disabled={busy === "source"}>
              <Plus className="h-4 w-4" aria-hidden="true" />
              {sourceKind === "api_key" && !apiKeyPlanAllowsSave ? t("discovery.importPreview.review") : translateNow("source.create.source.020457fb23")}
            </Button>
          </form>
        </div>
      )}

      {tab === "schedules" && (
        <div {...tabPanelProps("discovery", "schedules")} className="grid gap-6">
          <form aria-labelledby="schedule-form-heading" className="ui-panel grid gap-4 p-comfortable" onSubmit={createSchedule}>
            <div className="flex items-center gap-2">
              <ClipboardList className="h-4 w-4 text-muted-foreground" aria-hidden="true" />
              <h2 id="schedule-form-heading" className="text-title font-semibold">
                {translateNow("source.schedule.f4830a1dae")}
              </h2>
            </div>
            <label className="grid gap-1 text-sm font-medium">
              {translateNow("source.source.0e570ca6fa")}
              <select className="ui-input" value={scheduleSourceID} onChange={(event) => setScheduleSourceID(event.target.value)} required>
                {sources.length === 0 && <option value="">{translateNow("source.no.source.2eca7a588d")}</option>}
                {sources.map((source) => (
                  <option key={source.id} value={source.id}>
                    {source.name}
                  </option>
                ))}
              </select>
            </label>
            <label className="grid gap-1 text-sm font-medium">
              {translateNow("source.name.dcd1d5223f")}
              <input
                id="discovery-schedule-name"
                ref={scheduleNameRef}
                className="ui-input"
                value={scheduleName}
                onChange={(event) => setScheduleName(event.target.value)}
                required
              />
            </label>
            <label className="grid gap-1 text-sm font-medium">
              {translateNow("source.interval.seconds.5f0f5b832a")}
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
              {translateNow("source.create.schedule.5b08f3c719")}
            </Button>
          </form>
        </div>
      )}

      {tab === "sources" && (
        <section aria-labelledby="sources-heading" className="grid gap-3 border-y border-border py-4">
          <h2 id="sources-heading" className="text-title font-semibold">
            {translateNow("source.sources.caf85b0888")}
          </h2>
          {!loading && sources.length === 0 ? (
            <EmptyState
              icon={<Search className="h-5 w-5" aria-hidden="true" />}
              title={translateNow("source.no.discovery.sources.b70fd7af27")}
              primaryAction={{ label: translateNow("source.create.first.source.4d63a7434c"), onClick: focusSourceForm, icon: <Plus className="h-4 w-4" /> }}
              secondaryAction={{ label: translateNow("source.enroll.an.agent.43dbb20757"), to: "/agents", icon: <Search className="h-4 w-4" /> }}
            >
              {translateNow("source.add.a.network.cloud.ct.log.nhi.oauth.servi.1798feb274")}
            </EmptyState>
          ) : (
            <SourceTable sources={sources} busy={busy} onStart={startRun} activity={sourceActivity} firstRunButtonRef={firstRunButtonRef} />
          )}
          <section aria-labelledby="coverage-heading" className="grid gap-3">
            <h3 id="coverage-heading" className="text-title font-semibold">
              {t("discovery.coverage.heading")}
            </h3>
            {coverageReport ? (
              <>
                <p className="text-sm text-muted-foreground">
                  {t("discovery.coverage.summary", {
                    observed: coverageReport.observed,
                    unobserved: coverageReport.unobserved,
                    structural: coverageReport.structurally_unobservable,
                  })}
                </p>

                {/* C3: the headline is the honest number, not a total count.
                    A certificate count answers "how many did we find"; an
                    operator being audited is asked "how much did you look at",
                    and those are different questions with different answers. */}
                <dl className="grid gap-2 rounded-md border border-border p-3 text-sm sm:grid-cols-3">
                  <div>
                    <dt className="text-caption text-muted-foreground">{t("discovery.coverage.segmentPercent")}</dt>
                    <dd className={coverageReport.segment_coverage_percent >= 100 ? "font-medium" : "font-medium text-status-warning"}>
                      {(coverageReport.segments ?? []).length === 0
                        ? t("discovery.coverage.noSegments")
                        : t("discovery.coverage.percentValue", { percent: coverageReport.segment_coverage_percent })}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-caption text-muted-foreground">{t("discovery.coverage.provenance")}</dt>
                    <dd className={coverageReport.provenance?.never_observed ? "font-medium text-status-warning" : "font-medium"}>
                      {t("discovery.coverage.provenanceValue", {
                        observed: coverageReport.provenance?.observed ?? 0,
                        total: coverageReport.provenance?.total ?? 0,
                      })}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-caption text-muted-foreground">{t("discovery.coverage.unknowns")}</dt>
                    <dd className={(coverageReport.unknowns ?? []).length ? "font-medium text-status-warning" : "font-medium"}>
                      {(coverageReport.unknowns ?? []).length}
                    </dd>
                  </div>
                  <p className="text-caption text-muted-foreground sm:col-span-3">{t("discovery.coverage.help")}</p>
                </dl>

                {(coverageReport.segments ?? []).length > 0 && (
                  <div className="overflow-x-auto">
                    <table className="ui-table min-w-[48rem]">
                      <caption className="sr-only">{t("discovery.coverage.segmentsCaption")}</caption>
                      <thead>
                        <tr>
                          <th scope="col">{t("discovery.coverage.segment")}</th>
                          <th scope="col">{t("discovery.coverage.status")}</th>
                          <th scope="col">{t("discovery.coverage.lastSwept")}</th>
                          <th scope="col">{t("discovery.coverage.detail")}</th>
                        </tr>
                      </thead>
                      <tbody>
                        {(coverageReport.segments ?? []).map((seg) => (
                          <tr key={seg.name}>
                            <td className="font-mono text-xs">{seg.name}</td>
                            <td className={seg.status === "swept" ? undefined : "text-status-warning"}>{seg.status}</td>
                            <td className="text-sm">{seg.last_swept_at ? formatDateTime(seg.last_swept_at) : t("discovery.coverage.never")}</td>
                            <td className="max-w-[28rem] text-sm text-muted-foreground">
                              {seg.status === "excluded" ? seg.exclusion_reason : (seg.ranges ?? []).join(", ")}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}

                {(coverageReport.unknowns ?? []).length > 0 && (
                  <div className="rounded-md border border-status-warning/40 p-3">
                    <p className="text-sm font-medium">{t("discovery.coverage.unknownsHeading")}</p>
                    <ul className="mt-2 grid gap-1 text-sm text-muted-foreground">
                      {(coverageReport.unknowns ?? []).map((u, i) => (
                        <li key={`${u.kind}-${u.subject}-${i}`}>
                          <span className="font-mono text-xs">{u.subject}</span> — {u.detail}
                          {u.action ? <span className="block text-xs">{u.action}</span> : null}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
                <div className="overflow-x-auto">
                  <table className="ui-table min-w-[54rem]">
                    <caption className="sr-only">{t("discovery.coverage.caption")}</caption>
                    <thead>
                      <tr>
                        <th scope="col">{t("discovery.coverage.class")}</th>
                        <th scope="col">{t("discovery.coverage.status")}</th>
                        <th scope="col">{t("discovery.coverage.detail")}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(coverageReport.classes ?? []).map((row) => (
                        <tr key={row.class}>
                          <td className="font-mono text-xs">{row.class}</td>
                          <td>{row.status}</td>
                          <td className="max-w-[36rem] text-sm">
                            {row.status === "OBSERVED"
                              ? t("discovery.coverage.observedBy", { sources: (row.observed_by ?? []).join(", ") })
                              : [row.reason, row.action].filter(Boolean).join(" — ")}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </>
            ) : (
              !loading && <p className="text-sm text-muted-foreground">{t("discovery.coverage.unavailable")}</p>
            )}
          </section>
        </section>
      )}

      {tab === "schedules" && (
        <section aria-labelledby="schedules-heading" className="grid gap-3 border-y border-border py-4">
          <h2 id="schedules-heading" className="text-title font-semibold">
            {translateNow("source.schedules.221ff19c90")}
          </h2>
          {!loading && schedules.length === 0 ? (
            <EmptyState
              icon={<ClipboardList className="h-5 w-5" aria-hidden="true" />}
              title={translateNow("source.no.discovery.schedules.17183fb10e")}
              primaryAction={{
                label: sources.length > 0 ? "Create schedule" : "Create source first",
                onClick: sources.length > 0 ? focusScheduleForm : focusSourceForm,
                icon: <Plus className="h-4 w-4" />,
              }}
              secondaryAction={{
                label: translateNow("source.refresh.records.60bf2f8d78"),
                onClick: () => void load(),
                icon: <RefreshCw className="h-4 w-4" />,
              }}
            >
              {translateNow("source.schedule.a.recurring.scan.once.a.source.ex.e7c14af000")}
            </EmptyState>
          ) : (
            <ScheduleTable schedules={schedules} sourceByID={sourceByID} />
          )}
        </section>
      )}

      {tab === "runs" && (
        <section {...tabPanelProps("discovery", "runs")} aria-labelledby="runs-heading" className="grid gap-3 border-y border-border py-4">
          <h2 id="runs-heading" className="text-title font-semibold">
            {translateNow("source.runs.848f54e896")}
          </h2>
          {!loading && runs.length === 0 ? (
            <EmptyState
              icon={<Play className="h-5 w-5" aria-hidden="true" />}
              title={translateNow("source.no.discovery.runs.e3ba4972a6")}
              primaryAction={{ label: translateNow("source.create.source.to.run.8ef21d8f2a"), onClick: focusSourceForm, icon: <Plus className="h-4 w-4" /> }}
              secondaryAction={{ label: translateNow("source.view.certificates.dcc999606f"), to: "/certificates", icon: <Search className="h-4 w-4" /> }}
            >
              {translateNow("source.runs.appear.here.after.a.source.is.created.da81c4a3c9")}
            </EmptyState>
          ) : (
            <RunTable runs={runs} sourceByID={sourceByID} busy={busy} onRetry={retryRun} />
          )}
        </section>
      )}
    </section>
  );
}

function StructuredSourceForm({
  kind,
  rows,
  selectedTemplate,
  jsonImport,
  jsonImportOpen,
  onRowsChange,
  onTemplateChange,
  onSampleLoaded,
  onJSONImportChange,
  onToggleJSONImport,
}: {
  kind: StructuredSourceKind;
  rows: StructuredRow[];
  selectedTemplate: string;
  jsonImport: string;
  jsonImportOpen: boolean;
  onRowsChange: (rows: StructuredRow[]) => void;
  onTemplateChange: (template: string) => void;
  onSampleLoaded: () => void;
  onJSONImportChange: (value: string) => void;
  onToggleJSONImport: () => void;
}) {
  const config = structuredSourceConfigs[kind];
  const { t } = useTranslation();
  const [csvError, setCSVError] = useState<string | null>(null);
  const activeTemplate = config.templates.find((template) => template.id === selectedTemplate) ?? config.templates[0];
  const includedNHISurfaces = useMemo(() => {
    if (kind !== "nhi_cross_surface") return new Set<string>();
    try {
      const records = jsonImport.trim() ? parseStructuredJSONImport(kind, jsonImport) : structuredRowsToRecords(config, rows);
      return observedNHISurfaces(records);
    } catch {
      return new Set<string>();
    }
  }, [config, jsonImport, kind, rows]);

  function updateRow(index: number, key: string, value: string | boolean) {
    onRowsChange(rows.map((row, rowIndex) => (rowIndex === index ? { ...row, [key]: value } : row)));
  }

  function loadSampleRows() {
    if (!activeTemplate) return;
    setCSVError(null);
    onRowsChange(activeTemplate.rows.map((row) => rowFromTemplate(config, row)));
    onSampleLoaded();
  }

  async function handleCSVUpload(event: ChangeEvent<HTMLInputElement>) {
    const input = event.currentTarget;
    const file = input.files?.[0];
    if (!file) return;
    try {
      const text = await readFileText(file);
      onRowsChange(parseStructuredCSVRows(config, text));
      setCSVError(null);
    } catch (err) {
      setCSVError(err instanceof Error && err.message !== "csv-read-failed" ? err.message : t("discovery.sourceForm.csvReadFailed"));
    } finally {
      input.value = "";
    }
  }

  return (
    <div className="grid gap-3">
      {kind === "nhi_cross_surface" ? (
        <section aria-label={t("discovery.sourceForm.nhiRequirementLabel")} className="rounded-control border border-border bg-muted/30 p-3">
          <p className="text-sm font-medium text-foreground">{t("discovery.sourceForm.nhiRequirement")}</p>
          <div
            className="mt-2 flex flex-wrap gap-2"
            aria-label={t("discovery.sourceForm.nhiSurfaceProgress", { included: includedNHISurfaces.size, total: 6 })}
          >
            {surfaceChoices.map((surface) => {
              const included = includedNHISurfaces.has(surface.value);
              return (
                <span
                  key={surface.value}
                  className={`inline-flex items-center gap-1 rounded-full border px-2 py-1 text-xs ${
                    included ? "border-status-success/30 text-status-success" : "border-border text-muted-foreground"
                  }`}
                >
                  {included ? <CheckCircle2 className="h-3.5 w-3.5" aria-hidden="true" /> : <span aria-hidden="true">○</span>}
                  {surface.displayName}
                </span>
              );
            })}
          </div>
          <p className="mt-2 text-xs text-muted-foreground">{t("discovery.sourceForm.nhiSurfaceProgress", { included: includedNHISurfaces.size, total: 6 })}</p>
        </section>
      ) : null}
      <div className="grid gap-3 md:grid-cols-[1fr_auto] xl:grid-cols-[1fr_auto_12rem]">
        <label className="grid gap-1 text-sm font-medium">
          {translateNow("source.source.template.f2c4cfbcec")}
          <select className="ui-input" value={selectedTemplate} onChange={(event) => onTemplateChange(event.target.value)}>
            {config.templates.map((template) => (
              <option key={template.id} value={template.id}>
                {template.templateName}
              </option>
            ))}
          </select>
        </label>
        <Button type="button" variant="outline" className="self-end" onClick={loadSampleRows}>
          <Sparkles className="h-4 w-4" aria-hidden="true" />
          {kind === "nhi_cross_surface" ? t("discovery.sourceForm.loadCompleteSample") : translateNow("source.load.sample.ac404ab475")}
        </Button>
        <label className="grid gap-1 text-sm font-medium">
          {translateNow("source.csv.upload.1a9c1686fd")}
          <span className="relative">
            <Upload className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" aria-hidden="true" />
            <input
              type="file"
              accept=".csv,text/csv"
              className="ui-input file:mr-3 file:rounded-control file:border-0 file:bg-muted file:px-2 file:py-1 file:text-xs file:font-medium ps-9"
              onChange={handleCSVUpload}
            />
          </span>
        </label>
      </div>

      {csvError && (
        <p role="alert" className="text-sm text-destructive">
          {csvError}
        </p>
      )}

      <div className="grid gap-3">
        {rows.map((row, rowIndex) => (
          <fieldset key={rowIndex} className="grid gap-3 rounded-control border border-border p-3">
            <legend className="px-1 text-xs font-semibold text-muted-foreground">
              {config.rowName} {rowIndex + 1}
            </legend>
            <div className="grid gap-3 md:grid-cols-2">
              {config.fields.map((field) => (
                <StructuredSourceField
                  key={field.key}
                  kind={kind}
                  field={field}
                  rowIndex={rowIndex}
                  value={row[field.key]}
                  onChange={(value) => updateRow(rowIndex, field.key, value)}
                />
              ))}
            </div>
            {rows.length > 1 && (
              <Button
                type="button"
                variant="ghost"
                size="sm"
                className="justify-self-start"
                onClick={() => onRowsChange(rows.filter((_, index) => index !== rowIndex))}
              >
                <Trash2 className="h-4 w-4" aria-hidden="true" />
                {translateNow("source.remove.row.1810fddd9e")}
              </Button>
            )}
          </fieldset>
        ))}
      </div>

      <div className="flex flex-wrap gap-2">
        <Button type="button" variant="outline" onClick={() => onRowsChange([...rows, emptyStructuredRow(config)])}>
          <Plus className="h-4 w-4" aria-hidden="true" />
          {translateNow("source.add.row.1868a8dd78")}
        </Button>
        <Button type="button" variant="ghost" onClick={onToggleJSONImport}>
          <Code2 className="h-4 w-4" aria-hidden="true" />
          {translateNow("source.advanced.json.import.c72cfacdf6")}
        </Button>
      </div>

      {jsonImportOpen && (
        <label className="grid gap-1 text-sm font-medium">
          {sourceKindLabels[kind]} {translateNow("source.json.import.bc2fd1db82")}
          <textarea className="ui-input min-h-32 font-mono text-xs" value={jsonImport} onChange={(event) => onJSONImportChange(event.target.value)} />
        </label>
      )}
    </div>
  );
}

function StructuredSourceField({
  kind,
  field,
  rowIndex,
  value,
  onChange,
}: {
  kind: StructuredSourceKind;
  field: StructuredField;
  rowIndex: number;
  value: string | boolean | undefined;
  onChange: (value: string | boolean) => void;
}) {
  const id = `discovery-${kind}-${rowIndex}-${field.key}`;
  if (field.inputKind === "checkbox") {
    return (
      <label className="flex items-center gap-2 self-end text-sm font-medium" htmlFor={id}>
        <input
          id={id}
          type="checkbox"
          className="h-4 w-4 rounded border-border"
          checked={value === true}
          onChange={(event) => onChange(event.target.checked)}
        />
        {field.fieldName}
      </label>
    );
  }
  if (field.inputKind === "select") {
    return (
      <label className="grid gap-1 text-sm font-medium" htmlFor={id}>
        {field.fieldName}
        <select id={id} className="ui-input" value={typeof value === "string" ? value : ""} onChange={(event) => onChange(event.target.value)}>
          {(field.choices ?? []).map((choice) => (
            <option key={choice.value} value={choice.value}>
              {choice.displayName}
            </option>
          ))}
        </select>
      </label>
    );
  }
  return (
    <label className="grid gap-1 text-sm font-medium" htmlFor={id}>
      {field.fieldName}
      <input
        id={id}
        type={field.inputKind === "number" ? "number" : "text"}
        className="ui-input"
        value={typeof value === "string" ? value : ""}
        placeholder={field.placeholder}
        onChange={(event) => onChange(event.target.value)}
      />
    </label>
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
        <code className="text-xs text-muted-foreground">{posture.capability}</code>
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
                      <StatusBadge vocabulary="risk" value={finding.severity} />
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

function MonitoringPanel({ monitoring, onCreateSource }: { monitoring: DiscoveryMonitoring | null; onCreateSource: () => void }) {
  const { t } = useTranslation();
  if (!monitoring) return null;
  const columns: Array<DataGridColumn<DiscoveryMonitoring["sources"][number]>> = [
    {
      id: "source",
      header: t("discovery.monitoring.columnSource"),
      cell: (source) => (
        <div>
          <div className="font-medium">{source.name}</div>
          <div className="font-mono text-xs text-muted-foreground">{source.source_id}</div>
          <div className="text-xs text-muted-foreground">{sourceKindLabel(source.kind)}</div>
        </div>
      ),
    },
    {
      id: "schedule",
      header: t("discovery.monitoring.columnSchedule"),
      cell: (source) => (
        <div>
          <StatusBadge vocabulary="lifecycle" value={source.scheduled ? "active" : "queued"} />
          <div className="mt-1 text-xs text-muted-foreground">
            {source.scheduled
              ? formatInterval(source.monitoring_interval_seconds, t("discovery.monitoring.unscheduled"))
              : t("discovery.monitoring.unscheduled")}
          </div>
        </div>
      ),
    },
    {
      id: "last-run",
      header: t("discovery.monitoring.columnLastRun"),
      cell: (source) => (
        <div>
          <StatusBadge vocabulary="lifecycle" value={source.last_run_status || "queued"} />
          <div className="mt-1 text-xs text-muted-foreground">{formatDateTime(source.last_run_completed_at)}</div>
        </div>
      ),
    },
    {
      id: "findings",
      header: t("discovery.monitoring.columnFindings"),
      cell: (source) => source.finding_count,
    },
    {
      id: "inventory",
      header: t("discovery.monitoring.columnInventory"),
      cell: (source) => source.certificate_inventory_count,
    },
    {
      id: "repository",
      header: t("discovery.monitoring.columnRepository"),
      className: "font-mono text-xs",
      cell: (source) => (
        <div>
          <div>{source.repository_path}</div>
          <div>{source.findings_path}</div>
        </div>
      ),
    },
  ];
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
        <DataGrid
          ariaLabel={t("discovery.monitoring.caption")}
          rows={monitoring.sources}
          columns={columns}
          getRowId={(source) => source.source_id}
          showColumnChooser
          viewStorageKey="discovery-monitoring"
          toolbar={gridControlsToolbar}
        />
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

function SourceTable({
  sources,
  busy,
  onStart,
  activity,
  firstRunButtonRef,
}: {
  sources: DiscoverySource[];
  busy: string | null;
  onStart: (sourceID: string, dryRun?: boolean) => void;
  activity: Map<string, SourceActivity>;
  firstRunButtonRef?: RefObject<HTMLButtonElement>;
}) {
  const columns: Array<DataGridColumn<DiscoverySource>> = [
    {
      id: "name",
      header: "Name",
      cell: (source) => (
        <div>
          <div className="font-medium">{source.name}</div>
          <div className="font-mono text-xs text-muted-foreground">{source.id}</div>
        </div>
      ),
    },
    {
      id: "kind",
      header: "Kind",
      cell: (source) => sourceKindLabels[source.kind] ?? source.kind,
    },
    {
      id: "targets",
      header: "Targets",
      className: "font-mono text-xs",
      cell: (source) => targetCount(source),
    },
    {
      id: "relay-binding",
      header: translateNow("discovery.source.executionBinding"),
      cell: (source) => {
        const sourceReadiness = activity.get(source.id);
        return (
          <div className="grid gap-1">
            <span>{relayBinding(source)}</span>
            {sourceReadiness?.executionReady === false ? (
              <span className="text-caption text-status-critical">
                {translateNow("discovery.source.readinessBlocked")}: {sourceReadiness.blockedReasons.join(" ")}
              </span>
            ) : sourceReadiness?.executionReady === true ? (
              <span className="text-caption text-status-success">{translateNow("discovery.source.readinessReady")}</span>
            ) : null}
          </div>
        );
      },
    },
    {
      id: "last-run",
      header: "Last run",
      cell: (source) => <SourceActivityCell activity={activity.get(source.id)} formatDateTime={formatDateTime} />,
    },
    {
      id: "findings",
      header: "Findings",
      cell: (source) => <SourceFindingsCell activity={activity.get(source.id)} />,
    },
    {
      id: "updated",
      header: "Updated",
      cell: (source) => formatDateTime(source.updated_at),
    },
    {
      id: "actions",
      header: "Actions",
      cell: (source) => (
        <div className="flex flex-wrap gap-2">
          <Button
            ref={source.id === sources[0]?.id ? firstRunButtonRef : undefined}
            type="button"
            size="sm"
            onClick={() => onStart(source.id, false)}
            disabled={busy?.startsWith(`run:${source.id}`) || activity.get(source.id)?.executionReady === false}
            title={activity.get(source.id)?.executionReady === false ? activity.get(source.id)?.blockedReasons.join(" ") : undefined}
          >
            <Play className="h-4 w-4" aria-hidden="true" />
            {translateNow("source.run.00d60e31a4")}
          </Button>
          <Button
            type="button"
            size="sm"
            variant="outline"
            onClick={() => onStart(source.id, true)}
            disabled={busy?.startsWith(`run:${source.id}`) || activity.get(source.id)?.executionReady === false}
            title={activity.get(source.id)?.executionReady === false ? activity.get(source.id)?.blockedReasons.join(" ") : undefined}
          >
            {translateNow("source.dry.run.d5da154d9f")}
          </Button>
        </div>
      ),
    },
  ];
  return (
    <DataGrid
      ariaLabel="Discovery sources"
      rows={sources}
      columns={columns}
      getRowId={(source) => source.id}
      showColumnChooser
      viewStorageKey="discovery-sources"
      toolbar={gridControlsToolbar}
    />
  );
}

function ScheduleTable({ schedules, sourceByID }: { schedules: DiscoverySchedule[]; sourceByID: Map<string, DiscoverySource> }) {
  const columns: Array<DataGridColumn<DiscoverySchedule>> = [
    {
      id: "name",
      header: "Name",
      cell: (schedule) => (
        <div>
          <div className="font-medium">{schedule.name}</div>
          <div className="font-mono text-xs text-muted-foreground">{schedule.id}</div>
        </div>
      ),
    },
    {
      id: "source",
      header: "Source",
      cell: (schedule) => sourceByID.get(schedule.source_id)?.name ?? <span className="font-mono text-xs">{schedule.source_id}</span>,
    },
    {
      id: "interval",
      header: "Interval",
      cell: (schedule) => `${schedule.interval_seconds}s`,
    },
    {
      id: "enabled",
      header: "Enabled",
      cell: (schedule) => (schedule.enabled ? "yes" : "no"),
    },
    {
      id: "updated",
      header: "Updated",
      cell: (schedule) => formatDateTime(schedule.updated_at),
    },
  ];
  return (
    <DataGrid
      ariaLabel="Discovery schedules"
      rows={schedules}
      columns={columns}
      getRowId={(schedule) => schedule.id}
      showColumnChooser
      viewStorageKey="discovery-schedules"
      toolbar={gridControlsToolbar}
    />
  );
}

function RunTable({
  runs,
  sourceByID,
  busy,
  onRetry,
}: {
  runs: DiscoveryRun[];
  sourceByID: Map<string, DiscoverySource>;
  busy: string | null;
  onRetry: (run: DiscoveryRun) => void;
}) {
  const columns: Array<DataGridColumn<DiscoveryRun>> = [
    {
      id: "run",
      header: "Run",
      className: "font-mono text-xs",
      cell: (run) => shortID(run.id),
    },
    {
      id: "source",
      header: "Source",
      cell: (run) => sourceByID.get(run.source_id)?.name ?? <span className="font-mono text-xs">{run.source_id}</span>,
    },
    {
      id: "status",
      header: "Status",
      cell: (run) => <StatusBadge vocabulary="lifecycle" value={run.status} />,
    },
    {
      id: "targets",
      header: "Targets",
      cell: (run) => run.targets,
    },
    {
      id: "discovered",
      header: "Discovered",
      cell: (run) => run.discovered,
    },
    {
      id: "failed",
      header: "Failed",
      cell: (run) => run.failed + run.rejected + run.blocked,
    },
    {
      id: "failure-detail",
      header: "Failure detail",
      cell: (run) => {
        const unresolved = (run.target_results ?? []).filter((result) => result.status !== "succeeded");
        if (!run.error && unresolved.length === 0) {
          return <span className="text-muted-foreground">—</span>;
        }
        return (
          <div className="max-w-[28rem] space-y-1 text-xs">
            {run.error ? (
              <span className="block break-words text-risk-critical" title={run.error}>
                {run.error}
              </span>
            ) : null}
            {unresolved.length > 0 ? (
              <ul className="list-none space-y-0.5 pl-0 font-mono" aria-label={translateNow("discovery.run.targetOutcomes")}>
                {unresolved.map((result) => (
                  <li key={`${run.id}:${result.target}`} className="break-words">
                    <span className="text-foreground">{result.target}</span> <StatusBadge vocabulary="lifecycle" value={result.status} />
                    {result.error ? <span className="text-muted-foreground"> {result.error}</span> : null}
                  </li>
                ))}
              </ul>
            ) : null}
          </div>
        );
      },
    },
    {
      id: "executor",
      header: translateNow("discovery.run.executor"),
      cell: (run) => runExecution(run),
    },
    {
      id: "recovery",
      header: translateNow("discovery.run.recoveryColumn"),
      cell: (run) => {
        if (run.retry_of_run_id) {
          return <span className="text-xs text-muted-foreground">{translateNow("discovery.run.retries", { id: shortID(run.retry_of_run_id) })}</span>;
        }
        if (run.status !== "failed" && run.status !== "partial") {
          return <span className="text-muted-foreground">—</span>;
        }
        return (
          <Button
            type="button"
            variant="outline"
            size="sm"
            disabled={busy === `retry:${run.id}`}
            aria-label={translateNow("discovery.run.retryAria", { id: shortID(run.id) })}
            onClick={() => onRetry(run)}
          >
            <RefreshCw className="h-4 w-4" aria-hidden="true" />
            {busy === `retry:${run.id}` ? translateNow("discovery.run.retrying") : translateNow("discovery.run.retryAction")}
          </Button>
        );
      },
    },
    {
      id: "completed",
      header: "Completed",
      cell: (run) => formatDateTime(run.completed_at),
    },
  ];
  return (
    <DataGrid
      ariaLabel="Discovery runs"
      rows={runs}
      columns={columns}
      getRowId={(run) => run.id}
      showColumnChooser
      viewStorageKey="discovery-runs"
      toolbar={gridControlsToolbar}
    />
  );
}

function FindingTable({
  findings,
  allFindings,
  sourceByID,
  filters,
  facetOptions,
  onFilterChange,
  onFiltersRestore,
  onFindingUpdated,
  onNotice,
}: {
  findings: DiscoveryFinding[];
  allFindings: DiscoveryFinding[];
  sourceByID: Map<string, DiscoverySource>;
  filters: FindingFilters;
  facetOptions: { owners: string[]; teams: string[]; tags: string[] };
  onFilterChange: (key: keyof FindingFilters, value: string) => void;
  onFiltersRestore: (filters: FindingFilters) => void;
  onFindingUpdated: (finding: DiscoveryFinding) => Promise<void>;
  onNotice: (notice: Notice | null) => void;
}) {
  const { t } = useTranslation();
  const [selectedID, setSelectedID] = useState<string | null>(null);
  const [action, setAction] = useState<"claim" | "dismiss" | null>(null);
  const [reason, setReason] = useState("");
  const [managedIdentityID, setManagedIdentityID] = useState("");
  const [identitySearch, setIdentitySearch] = useState("");
  const [identityRoster, setIdentityRoster] = useState<Identity[]>([]);
  const [ownerRoster, setOwnerRoster] = useState<Owner[]>([]);
  const [identityRosterError, setIdentityRosterError] = useState(false);
  const [showIdentityCreate, setShowIdentityCreate] = useState(false);
  const [createIdentityName, setCreateIdentityName] = useState("");
  const [createIdentityKind, setCreateIdentityKind] = useState<Identity["kind"]>("x509_certificate");
  const [createIdentityOwnerID, setCreateIdentityOwnerID] = useState("");
  const [createIdentityBusy, setCreateIdentityBusy] = useState(false);
  const [owner, setOwner] = useState("");
  const [team, setTeam] = useState("");
  const [tagText, setTagText] = useState("");
  const [actionBusy, setActionBusy] = useState(false);
  const selected = selectedID ? (allFindings.find((finding) => finding.id === selectedID) ?? null) : null;
  const ownerByID = useMemo(() => new Map(ownerRoster.map((item) => [item.id, item])), [ownerRoster]);
  const selectedIdentity = identityRoster.find((identity) => identity.id === managedIdentityID) ?? null;
  const normalizedIdentitySearch = identitySearch.trim().toLowerCase();
  const filteredIdentities = identityRoster.filter((identity) => {
    if (identity.id === managedIdentityID || !normalizedIdentitySearch) return true;
    const identityOwner = ownerByID.get(identity.owner_id)?.name ?? "";
    return [identity.name, identity.kind, identity.status, identityOwner].some((value) => value.toLowerCase().includes(normalizedIdentitySearch));
  });

  useEffect(() => {
    let active = true;
    setIdentityRosterError(false);
    void api
      .identities()
      .then((items) => {
        if (active) setIdentityRoster(items);
      })
      .catch(() => {
        if (active) setIdentityRosterError(true);
      });
    void api
      .owners()
      .then((items) => {
        if (active) setOwnerRoster(items);
      })
      .catch(() => {
        if (active) setIdentityRosterError(true);
      });
    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    if (action !== "claim" || !selected || createIdentityOwnerID || ownerRoster.length === 0) return;
    const findingOwnerName = findingOwner(selected).trim().toLowerCase();
    const matchedOwner = ownerRoster.find((item) => item.name.trim().toLowerCase() === findingOwnerName);
    setCreateIdentityOwnerID(matchedOwner?.id ?? ownerRoster[0]?.id ?? "");
  }, [action, createIdentityOwnerID, ownerRoster, selected]);

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
    setIdentitySearch("");
    setShowIdentityCreate(false);
    populateFacetInputs(finding);
  }

  function openAction(finding: DiscoveryFinding, nextAction: "claim" | "dismiss") {
    setSelectedID(finding.id);
    setAction(nextAction);
    setReason(finding.triage_reason ?? "");
    setManagedIdentityID(finding.managed_identity_id ?? "");
    setIdentitySearch("");
    setShowIdentityCreate(false);
    setCreateIdentityName(suggestedIdentityName(finding));
    setCreateIdentityKind(identityKindForFinding(finding.kind));
    const findingOwnerName = findingOwner(finding).trim().toLowerCase();
    setCreateIdentityOwnerID(ownerRoster.find((item) => item.name.trim().toLowerCase() === findingOwnerName)?.id ?? ownerRoster[0]?.id ?? "");
    populateFacetInputs(finding);
  }

  async function createIdentityFromFinding() {
    if (!selected || !createIdentityName.trim() || !createIdentityOwnerID) return;
    setCreateIdentityBusy(true);
    onNotice(null);
    try {
      const created = await api.createIdentity({
        name: createIdentityName.trim(),
        kind: createIdentityKind,
        owner_id: createIdentityOwnerID,
        attributes: {
          discovery_finding_id: selected.id,
          discovery_ref: selected.ref,
          discovery_source_id: selected.source_id,
        },
      });
      setIdentityRoster((current) => [created, ...current.filter((item) => item.id !== created.id)]);
      setManagedIdentityID(created.id);
      setIdentitySearch("");
      setShowIdentityCreate(false);
      onNotice({ kind: "success", message: t("discovery.findings.identityCreated", { name: created.name }) });
    } catch (err) {
      onNotice(noticeForError(err, t("discovery.findings.identityCreateError")));
    } finally {
      setCreateIdentityBusy(false);
    }
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
      await onFindingUpdated(updated);
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

  function restoreGridView(metadata: Record<string, GridViewPrimitive>) {
    onFiltersRestore({
      triage: triageFilterFromSearchParam(gridMetadataString(metadata, "triage")),
      owner: gridMetadataString(metadata, "owner"),
      team: gridMetadataString(metadata, "team"),
      tag: gridMetadataString(metadata, "tag"),
    });
  }

  const filterControls = (
    <>
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
    </>
  );

  const columns: Array<DataGridColumn<DiscoveryFinding>> = [
    {
      id: "reference",
      header: translateNow("source.credential.b1c42b3ce1"),
      cell: (finding) => (
        <span className="grid gap-1">
          <span className="font-medium">{finding.ref}</span>
          <span className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
            <TriagePill status={findingTriageStatus(finding)} />
            <span>{discoveryFindingKindLabel(t, finding.kind)}</span>
          </span>
        </span>
      ),
    },
    {
      id: "fingerprint",
      header: t("discovery.findings.columnFingerprint"),
      className: "font-mono text-xs",
      cell: (finding) => maskFingerprint(finding.fingerprint),
      hiddenByDefault: true,
    },
    {
      id: "owner",
      header: t("discovery.findings.columnOwner"),
      cell: (finding) => findingOwner(finding) || "-",
    },
    {
      id: "team",
      header: t("discovery.findings.columnTeam"),
      cell: (finding) => findingTeam(finding) || "-",
      hiddenByDefault: true,
    },
    {
      id: "tags",
      header: t("discovery.findings.columnTags"),
      cell: (finding) => <TagList tags={findingTags(finding)} />,
      hiddenByDefault: true,
    },
    {
      id: "source",
      header: t("discovery.findings.columnSource"),
      cell: (finding) => (
        <span className="grid gap-0.5">
          <span>{sourceByID.get(finding.source_id)?.name ?? t("discovery.findings.unknownSource")}</span>
          <span className="text-xs text-muted-foreground">{formatDateTime(finding.discovered_at)}</span>
        </span>
      ),
    },
    {
      id: "risk",
      header: t("discovery.findings.columnRisk"),
      cell: (finding) => finding.risk_score ?? 0,
    },
  ];

  return (
    <div className="grid gap-4">
      <DataGrid
        ariaLabel={t("discovery.findings.caption")}
        rows={findings}
        columns={columns}
        getRowId={(finding) => finding.id}
        state={findings.length === 0 ? "empty" : "ready"}
        stateTitle={t("discovery.findings.noMatches")}
        showColumnChooser
        viewStorageKey="discovery-findings"
        viewMetadata={{ triage: filters.triage, owner: filters.owner, team: filters.team, tag: filters.tag }}
        onViewRestore={restoreGridView}
        onRowOpen={openDetail}
        rowActionLabel={() => t("discovery.findings.review")}
        toolbar={({ columnChooser, savedViews }) => <DataGridToolbar filters={filterControls} columnChooser={columnChooser} savedViews={savedViews} />}
      />

      {selected && (
        <aside className="ui-panel grid gap-4 p-comfortable" aria-labelledby="finding-detail-heading">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <h3 id="finding-detail-heading" className="text-title font-semibold">
                {t("discovery.findings.detailHeading")}
              </h3>
              <p className="text-sm text-muted-foreground">{discoveryFindingKindLabel(t, selected.kind)}</p>
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
            <FindingDetail
              label={t("discovery.findings.columnSource")}
              value={sourceByID.get(selected.source_id)?.name ?? t("discovery.findings.unknownSource")}
            />
            <FindingDetail label={t("discovery.findings.triageReason")} value={selected.triage_reason || "-"} />
            <FindingDetail label={t("discovery.findings.columnRisk")} value={String(selected.risk_score ?? 0)} />
          </dl>

          <div className="flex flex-wrap items-center gap-2">
            <Tag className="h-4 w-4 text-muted-foreground" aria-hidden="true" />
            <TagList tags={findingTags(selected)} />
          </div>

          {!action && (
            <div className="flex flex-wrap items-start gap-2 border-t border-border pt-4">
              <Button type="button" size="sm" onClick={() => openAction(selected, "claim")} disabled={actionBusy}>
                <CheckCircle2 className="h-4 w-4" aria-hidden="true" />
                {t("discovery.findings.claim")}
              </Button>
              <details className="group min-w-52">
                <summary className="inline-flex min-h-9 cursor-pointer list-none items-center rounded-control border border-border bg-background px-3 text-sm font-medium marker:hidden hover:bg-muted/60">
                  {t("discovery.findings.moreActions")}
                </summary>
                <div className="mt-2 flex flex-wrap gap-2 rounded-control border border-border bg-muted/20 p-3">
                  <Button
                    type="button"
                    size="sm"
                    variant="outline"
                    onClick={() => void runFindingLifecycleAction(selected, "rotate")}
                    disabled={actionBusy || !findingActionIdentityID(selected)}
                  >
                    <RefreshCw className="h-4 w-4" aria-hidden="true" />
                    {t("discovery.findings.rotate")}
                  </Button>
                  <Button
                    type="button"
                    size="sm"
                    variant="outline"
                    onClick={() => void runFindingLifecycleAction(selected, "revoke")}
                    disabled={actionBusy || !findingActionIdentityID(selected)}
                  >
                    <XCircle className="h-4 w-4" aria-hidden="true" />
                    {t("discovery.findings.revoke")}
                  </Button>
                  <Button
                    type="button"
                    size="sm"
                    variant="outline"
                    onClick={() => void runFindingLifecycleAction(selected, "decommission")}
                    disabled={actionBusy || !findingActionIdentityID(selected)}
                  >
                    <Activity className="h-4 w-4" aria-hidden="true" />
                    {t("discovery.findings.decommission")}
                  </Button>
                  <Button
                    type="button"
                    size="sm"
                    variant="outline"
                    onClick={() => void runFindingLifecycleAction(selected, "remediate")}
                    disabled={actionBusy || !findingActionIdentityID(selected)}
                  >
                    <ClipboardList className="h-4 w-4" aria-hidden="true" />
                    {t("discovery.findings.remediate")}
                  </Button>
                  <Button type="button" size="sm" variant="outline" onClick={() => openAction(selected, "dismiss")} disabled={actionBusy}>
                    <XCircle className="h-4 w-4" aria-hidden="true" />
                    {t("discovery.findings.dismiss")}
                  </Button>
                </div>
              </details>
            </div>
          )}

          {observedCertificateDetails(selected).length > 0 && (
            <div className="border-t border-border pt-4">
              <h3 className="text-sm font-medium">{t("discovery.findings.observedHeading")}</h3>
              <dl className="mt-3 grid gap-3 rounded-control bg-muted/30 p-3 md:grid-cols-2 xl:grid-cols-4">
                {observedCertificateDetails(selected).map((detail) => (
                  <FindingDetail key={detail.label} label={detail.label} value={detail.value} />
                ))}
              </dl>
            </div>
          )}

          <details className="group border-t border-border pt-4">
            <summary className="cursor-pointer text-sm font-medium">{t("discovery.findings.exactEvidence")}</summary>
            <dl className="mt-3 grid gap-3 rounded-control bg-muted/30 p-3 md:grid-cols-2 xl:grid-cols-4">
              <FindingDetail label={t("discovery.findings.exactId")} value={selected.id} />
              <FindingDetail label={t("discovery.findings.exactKind")} value={selected.kind} />
              <FindingDetail label={t("discovery.findings.columnFingerprint")} value={selected.fingerprint} />
              <FindingDetail label={t("discovery.findings.managedIdentity")} value={selected.managed_identity_id || "-"} />
              <FindingDetail label={t("discovery.findings.exactSourceId")} value={selected.source_id} />
              <FindingDetail label={t("discovery.findings.exactRunId")} value={selected.run_id} />
              <FindingDetail label={t("discovery.findings.exactProvenance")} value={selected.provenance} />
              <FindingDetail label={t("discovery.findings.exactEvidenceRefs")} value={findingEvidenceRefs(selected).join(", ") || "-"} />
            </dl>
          </details>

          {action && (
            <form className="grid gap-3 border-t border-border pt-4 md:grid-cols-2" onSubmit={submitAction}>
              {action === "claim" ? (
                <section className="grid gap-3 rounded-control border border-border bg-muted/20 p-3 md:col-span-2" aria-labelledby="finding-identity-heading">
                  <div>
                    <h3 id="finding-identity-heading" className="text-sm font-semibold">
                      {t("discovery.findings.identityStepHeading")}
                    </h3>
                    <p className="mt-1 text-xs text-muted-foreground">{t("discovery.findings.identityStepDescription")}</p>
                  </div>
                  <div className="grid gap-3 md:grid-cols-2">
                    <label className="grid gap-1 text-sm font-medium">
                      {t("discovery.findings.identitySearch")}
                      <input
                        type="search"
                        className="ui-input"
                        value={identitySearch}
                        onChange={(event) => setIdentitySearch(event.target.value)}
                        placeholder={t("discovery.findings.identitySearchPlaceholder")}
                      />
                    </label>
                    <label className="grid gap-1 text-sm font-medium">
                      {t("discovery.findings.managedIdentity")}
                      <select className="ui-input" value={managedIdentityID} onChange={(event) => setManagedIdentityID(event.target.value)} required>
                        <option value="">{t("discovery.findings.identityChoose")}</option>
                        {managedIdentityID && !selectedIdentity && <option value={managedIdentityID}>{t("discovery.findings.identityUnavailable")}</option>}
                        {filteredIdentities.map((identity) => (
                          <option key={identity.id} value={identity.id}>
                            {identityOptionLabel(t, identity, ownerByID.get(identity.owner_id))}
                          </option>
                        ))}
                      </select>
                    </label>
                  </div>
                  {selectedIdentity && (
                    <p className="text-sm text-muted-foreground" aria-live="polite">
                      {identitySelectionSummary(t, selectedIdentity, ownerByID.get(selectedIdentity.owner_id))}
                    </p>
                  )}
                  {identityRosterError && <p className="text-sm text-risk-critical">{t("discovery.findings.identityRosterError")}</p>}
                  <div>
                    <Button type="button" variant="outline" size="sm" onClick={() => setShowIdentityCreate((current) => !current)}>
                      <Plus className="h-4 w-4" aria-hidden="true" />
                      {t("discovery.findings.identityCreateAction")}
                    </Button>
                  </div>
                  {showIdentityCreate && (
                    <section className="grid gap-3 border-s-2 border-brand-accent/40 ps-3" aria-labelledby="finding-create-identity-heading">
                      <div>
                        <h3 id="finding-create-identity-heading" className="text-sm font-semibold">
                          {t("discovery.findings.identityCreateHeading")}
                        </h3>
                        <p className="mt-1 text-xs text-muted-foreground">{t("discovery.findings.identityCreateDescription")}</p>
                      </div>
                      <div className="grid gap-3 md:grid-cols-3">
                        <label className="grid gap-1 text-sm font-medium">
                          {t("discovery.findings.identityName")}
                          <input className="ui-input" value={createIdentityName} onChange={(event) => setCreateIdentityName(event.target.value)} required />
                        </label>
                        <label className="grid gap-1 text-sm font-medium">
                          {t("discovery.findings.identityKind")}
                          <select
                            className="ui-input"
                            value={createIdentityKind}
                            onChange={(event) => setCreateIdentityKind(event.target.value as Identity["kind"])}
                          >
                            {identityKinds.map((kind) => (
                              <option key={kind} value={kind}>
                                {identityKindLabel(t, kind)}
                              </option>
                            ))}
                          </select>
                        </label>
                        <label className="grid gap-1 text-sm font-medium">
                          {t("discovery.findings.identityOwner")}
                          <select
                            className="ui-input"
                            value={createIdentityOwnerID}
                            onChange={(event) => setCreateIdentityOwnerID(event.target.value)}
                            required
                          >
                            <option value="">{t("discovery.findings.identityOwnerChoose")}</option>
                            {ownerRoster.map((item) => (
                              <option key={item.id} value={item.id}>
                                {item.name} — {item.kind}
                              </option>
                            ))}
                          </select>
                        </label>
                      </div>
                      <div>
                        <Button
                          type="button"
                          size="sm"
                          onClick={() => void createIdentityFromFinding()}
                          disabled={createIdentityBusy || !createIdentityName.trim() || !createIdentityOwnerID}
                        >
                          {createIdentityBusy ? t("discovery.findings.identityCreating") : t("discovery.findings.identityCreateSubmit")}
                        </Button>
                      </div>
                    </section>
                  )}
                </section>
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
                <input
                  className="ui-input"
                  value={tagText}
                  onChange={(event) => setTagText(event.target.value)}
                  placeholder={translateNow("source.internet.tls.f6752ebc7d")}
                />
              </label>
              <Button type="submit" className="self-end md:justify-self-start" disabled={actionBusy || (action === "claim" && !managedIdentityID)}>
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

// observedCertificateDetails surfaces what a discovery finding actually observed
// — the certificate's subject, issuer, validity window, SANs and key — from the
// finding metadata, so the evidence panel answers "what is this?" and not only
// "which fingerprint/ids". Empty for findings that carry none.
function observedCertificateDetails(finding: DiscoveryFinding): Array<{ label: string; value: string }> {
  const metadata = (finding.metadata ?? {}) as Record<string, unknown>;
  const out: Array<{ label: string; value: string }> = [];
  const push = (label: string, keys: string[]) => {
    const value = metadataString(metadata, keys);
    if (value) out.push({ label, value });
  };
  push(translateNow("discovery.findings.observedSubject"), ["subject", "common_name", "cn"]);
  push(translateNow("discovery.findings.observedIssuer"), ["issuer", "issuer_cn"]);
  const notBefore = metadataString(metadata, ["not_before", "valid_from"]);
  const notAfter = metadataString(metadata, ["not_after", "valid_to", "expires_at"]);
  if (notBefore || notAfter) {
    out.push({ label: translateNow("discovery.findings.observedValidity"), value: `${notBefore || "?"} → ${notAfter || "?"}` });
  }
  const sans = metadata["sans"];
  if (Array.isArray(sans) && sans.length > 0) {
    out.push({ label: translateNow("discovery.findings.observedSans"), value: sans.map((san) => String(san)).join(", ") });
  }
  push(translateNow("discovery.findings.observedSerial"), ["serial", "serial_number"]);
  const keyAlg = metadataString(metadata, ["key_algorithm", "key_type"]);
  const keyBits = metadata["public_key_bits"];
  if (keyAlg || typeof keyBits === "number") {
    out.push({
      label: translateNow("discovery.findings.observedKey"),
      value: [keyAlg, typeof keyBits === "number" ? `${keyBits}-bit` : ""].filter(Boolean).join(" "),
    });
  }
  push(translateNow("discovery.findings.observedLocation"), ["location", "address", "endpoint"]);
  return out;
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
  return <StatusBadge vocabulary="discovery" value={status} />;
}

function TagList({ tags }: { tags: string[] }) {
  if (tags.length === 0) return <span className="text-muted-foreground">-</span>;
  return (
    <span className="text-xs">
      {tags.map((tag, index) => (
        <span key={tag}>
          {index > 0 && <span aria-hidden="true"> · </span>}
          {tag}
        </span>
      ))}
    </span>
  );
}

function findingTriageStatus(finding: DiscoveryFinding): FindingTriageStatus {
  return finding.triage_status ?? "unmanaged";
}

function discoveryFindingKindLabel(t: (key: MessageKey) => string, kind: string): string {
  switch (kind.toLowerCase().replaceAll("-", "_")) {
    case "certificate":
    case "tls_certificate":
    case "x509_certificate":
      return t("discovery.kind.tlsCertificate");
    case "api_key":
    case "api_token":
    case "personal_access_token":
      return t("discovery.kind.apiKey");
    case "secret":
      return t("discovery.kind.secret");
    case "ssh_certificate":
      return t("discovery.kind.sshCertificate");
    case "ssh_key":
      return t("discovery.kind.sshKey");
    case "oauth_grant":
      return t("discovery.kind.oauthGrant");
    case "service_account":
      return t("discovery.kind.serviceAccount");
    case "spiffe":
    case "spiffe_svid":
    case "workload_identity":
      return t("discovery.kind.workloadIdentity");
    default:
      return t("discovery.kind.unknown");
  }
}

function identityKindForFinding(kind: string): Identity["kind"] {
  switch (kind.toLowerCase().replaceAll("-", "_")) {
    case "certificate":
    case "tls_certificate":
    case "x509_certificate":
      return "x509_certificate";
    case "ssh_certificate":
      return "ssh_certificate";
    case "ssh_key":
      return "ssh_key";
    case "secret":
      return "secret";
    case "api_key":
    case "api_token":
    case "personal_access_token":
      return "api_key";
    default:
      return "workload_identity";
  }
}

function suggestedIdentityName(finding: DiscoveryFinding): string {
  return metadataString(finding.metadata, ["principal", "subject", "service", "name"]) || finding.ref;
}

function identityKindLabel(t: (key: MessageKey) => string, kind: Identity["kind"]): string {
  switch (kind) {
    case "x509_certificate":
      return t("discovery.findings.identityKindX509");
    case "ssh_certificate":
      return t("discovery.findings.identityKindSSHCertificate");
    case "ssh_key":
      return t("discovery.findings.identityKindSSHKey");
    case "secret":
      return t("discovery.findings.identityKindSecret");
    case "api_key":
      return t("discovery.findings.identityKindAPIKey");
    case "workload_identity":
      return t("discovery.findings.identityKindWorkload");
  }
}

function identityOptionLabel(t: (key: MessageKey) => string, identity: Identity, owner?: Owner): string {
  return `${identity.name} — ${identityKindLabel(t, identity.kind)} — ${identity.status} — ${owner?.name ?? t("discovery.findings.identityOwnerUnknown")}`;
}

function identitySelectionSummary(t: (key: MessageKey, values?: Record<string, string>) => string, identity: Identity, owner?: Owner): string {
  return t("discovery.findings.identitySelectionSummary", {
    name: identity.name,
    status: identity.status,
    kind: identityKindLabel(t, identity.kind),
    owner: owner?.name ?? t("discovery.findings.identityOwnerUnknown"),
  });
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
    return raw
      .map((value) => (typeof value === "string" ? value.trim() : ""))
      .filter(Boolean)
      .slice(0, 8);
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

function buildStructuredSourceConfig(kind: StructuredSourceKind, rows: StructuredRow[], jsonImport: string): Record<string, unknown> {
  const config = structuredSourceConfigs[kind];
  const records = jsonImport.trim() ? parseStructuredJSONImport(kind, jsonImport) : structuredRowsToRecords(config, rows);
  if (kind === "nhi_cross_surface") {
    const observed = observedNHISurfaces(records);
    const missing = requiredNHISurfaces.filter((surface) => !observed.has(surface));
    if (missing.length > 0) {
      throw new Error(
        translateNow("discovery.sourceForm.nhiMissingSurfaces", {
          surfaces: missing.map((surface) => nhiSurfaceDisplayNames[surface] ?? surface).join(", "),
        }),
      );
    }
  }
  return { ...(config.fixedConfig ?? {}), [config.payloadKey]: records };
}

function observedNHISurfaces(records: unknown[]): Set<string> {
  const observed = new Set<string>();
  for (const record of records) {
    if (!record || typeof record !== "object" || Array.isArray(record)) continue;
    const raw = (record as Record<string, unknown>).surface;
    if (typeof raw !== "string") continue;
    const normalized = raw.trim().toLowerCase().replaceAll("-", "_");
    if (requiredNHISurfaces.includes(normalized)) observed.add(normalized);
  }
  return observed;
}

function parseStructuredJSONImport(kind: StructuredSourceKind, value: string): unknown[] {
  const parsed = JSON.parse(value);
  if (!Array.isArray(parsed)) throw new Error(`${sourceKindLabels[kind]} JSON import must be an array.`);
  return parsed;
}

function structuredRowsToRecords(config: StructuredSourceConfig, rows: StructuredRow[]): Array<Record<string, unknown>> {
  const records = rows.map((row) => structuredRowToRecord(config, row));
  if (records.length === 0) throw new Error(`Add at least one ${config.rowName.toLowerCase()}.`);
  return records;
}

function structuredRowToRecord(config: StructuredSourceConfig, row: StructuredRow): Record<string, unknown> {
  const record: Record<string, unknown> = {};
  for (const field of config.fields) {
    const value = row[field.key];
    if (field.inputKind === "checkbox") {
      record[field.key] = value === true;
      continue;
    }
    const text = typeof value === "string" ? value.trim() : "";
    if (!text) {
      if (field.required) throw new Error(`${field.fieldName} is required.`);
      continue;
    }
    if (field.inputKind === "list") {
      const items = splitDelimitedList(text);
      if (items.length > 0) record[field.key] = items;
      continue;
    }
    if (field.inputKind === "number") {
      const parsed = Number(text);
      if (!Number.isFinite(parsed)) throw new Error(`${field.fieldName} must be a number.`);
      record[field.key] = parsed;
      continue;
    }
    record[field.key] = text;
  }
  return record;
}

function emptyStructuredRow(config: StructuredSourceConfig): StructuredRow {
  const row: StructuredRow = {};
  for (const field of config.fields) {
    if (field.inputKind === "checkbox") {
      row[field.key] = field.defaultValue === true;
    } else if (typeof field.defaultValue === "string") {
      row[field.key] = field.defaultValue;
    } else if (field.inputKind === "select") {
      row[field.key] = field.choices?.[0]?.value ?? "";
    } else {
      row[field.key] = "";
    }
  }
  return row;
}

function rowFromTemplate(config: StructuredSourceConfig, values: Record<string, string | boolean | number | string[]>): StructuredRow {
  const row = emptyStructuredRow(config);
  for (const field of config.fields) {
    if (!Object.prototype.hasOwnProperty.call(values, field.key)) continue;
    const value = values[field.key];
    if (field.inputKind === "checkbox") row[field.key] = value === true || value === "true";
    else if (Array.isArray(value)) row[field.key] = value.join(", ");
    else row[field.key] = String(value);
  }
  return row;
}

function parseStructuredCSVRows(config: StructuredSourceConfig, text: string): StructuredRow[] {
  const rows = parseCSV(text);
  if (rows.length < 2) throw new Error("Uploaded CSV must include a header row and at least one record.");
  const headers = rows[0].map((header) => csvFieldKey(config, header));
  const parsedRows = rows
    .slice(1)
    .filter((row) => row.some((cell) => cell.trim() !== ""))
    .map((row) => {
      const structured = emptyStructuredRow(config);
      row.forEach((cell, index) => {
        const key = headers[index];
        if (!key) return;
        const field = config.fields.find((candidate) => candidate.key === key);
        if (!field) return;
        structured[key] = field.inputKind === "checkbox" ? parseBooleanCell(cell) : cell.trim();
      });
      return structured;
    });
  if (parsedRows.length === 0) throw new Error("Uploaded CSV did not contain source records.");
  return parsedRows;
}

function readFileText(file: File): Promise<string> {
  if (typeof file.text === "function") return file.text();
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.addEventListener("load", () => resolve(typeof reader.result === "string" ? reader.result : ""));
    reader.addEventListener("error", () => reject(reader.error ?? new Error("csv-read-failed")));
    reader.readAsText(file);
  });
}

function parseCSV(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let cell = "";
  let quoted = false;
  for (let index = 0; index < text.length; index += 1) {
    const char = text[index];
    const next = text[index + 1];
    if (char === '"') {
      if (quoted && next === '"') {
        cell += '"';
        index += 1;
      } else {
        quoted = !quoted;
      }
      continue;
    }
    if (char === "," && !quoted) {
      row.push(cell);
      cell = "";
      continue;
    }
    if ((char === "\n" || char === "\r") && !quoted) {
      if (char === "\r" && next === "\n") index += 1;
      row.push(cell);
      rows.push(row);
      row = [];
      cell = "";
      continue;
    }
    cell += char;
  }
  row.push(cell);
  rows.push(row);
  return rows.filter((candidate) => candidate.some((value) => value.trim() !== ""));
}

function csvFieldKey(config: StructuredSourceConfig, header: string): string | null {
  const normalized = normalizeCSVHeader(header);
  const field = config.fields.find((candidate) => normalizeCSVHeader(candidate.key) === normalized || normalizeCSVHeader(candidate.fieldName) === normalized);
  return field?.key ?? null;
}

function normalizeCSVHeader(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, "");
}

function parseBooleanCell(value: string): boolean {
  return /^(1|true|yes|y|on)$/i.test(value.trim());
}

function splitDelimitedList(value: string): string[] {
  return value
    .split(/[\n,]/)
    .map((item) => item.trim())
    .filter(Boolean);
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

function relayBinding(source: DiscoverySource): string {
  if (source.kind !== "network" && source.kind !== "ssh") return translateNow("discovery.run.controlPlane");
  const segment = typeof source.config.segment === "string" ? source.config.segment : translateNow("discovery.run.unbound");
  const relay = typeof source.config.relay_agent_id === "string" ? ` · ${shortID(source.config.relay_agent_id)}` : "";
  return `${translateNow("discovery.run.relay")} · ${segment}${relay}`;
}

function runExecution(run: DiscoveryRun): string {
  if (run.execution !== "relay") return translateNow("discovery.run.controlPlane");
  const relay = run.executed_by_agent_id || run.required_agent_id;
  const suffix = relay ? ` · ${shortID(relay)}` : "";
  return `${translateNow("discovery.run.relay")} · ${run.segment || translateNow("discovery.run.unbound")}${suffix}`;
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
  return <ErrorState title={translateNow("source.discovery.unavailable.839198b6dc")}>{notice.message}</ErrorState>;
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
