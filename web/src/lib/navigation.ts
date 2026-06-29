import type { MessageKey } from "@/i18n/messages";

export type NavIcon =
  | "activity"
  | "audit"
  | "bot"
  | "certificate"
  | "connector"
  | "dashboard"
  | "graph"
  | "identity"
  | "incident"
  | "key"
  | "owner"
  | "platform"
  | "policy"
  | "profile"
  | "protocol"
  | "notification"
  | "risk"
  | "rocket"
  | "secret"
  | "signature"
  | "spiffe"
  | "ssh";

export interface NavItem {
  to: string;
  labelKey: MessageKey;
  icon: NavIcon;
  end?: boolean;
  mode: "real" | "disclosure";
  featureIds: string[];
}

export interface TaskNavItem {
  to: string;
  labelKey: MessageKey;
  descriptionKey: MessageKey;
  icon: NavIcon;
  featureIds: string[];
}

export interface NavGroup {
  labelKey: MessageKey;
  items: NavItem[];
}

export interface ContextualRouteItem {
  to: string;
  labelKey: MessageKey;
  groupKey: MessageKey;
  featureIds: string[];
}

export const appRoutePaths = [
  "/login",
  "/",
  "/certificates",
  "/identities",
  "/owners",
  "/agents",
  "/discovery",
  "/profiles",
  "/request",
  "/ca-hierarchy",
  "/workloads",
  "/protocols",
  "/ssh",
  "/codesign",
  "/secrets",
  "/connectors",
  "/policy",
  "/risk",
  "/incidents",
  "/approvals",
  "/operations",
  "/notifications",
  "/posture",
  "/graph",
  "/audit",
  "/privacy",
  "/integrate",
  "/integrate/api",
  "/assistant",
  "/wizard",
  "/platform",
] as const;

const routePermissionAny: Record<string, string[]> = {
  "/": ["certs:read", "identities:read", "risk:read"],
  "/agents": ["agents:read"],
  "/approvals": ["certs:issue"],
  "/assistant": ["graph:read"],
  "/audit": ["audit:read"],
  "/ca-hierarchy": ["issuers:read"],
  "/certificates": ["certs:read"],
  "/codesign": ["keys:write"],
  "/connectors": ["connectors:read"],
  "/discovery": ["discovery:read"],
  "/graph": ["graph:read"],
  "/identities": ["identities:read"],
  "/incidents": ["incidents:read"],
  "/integrate": ["issuers:read"],
  "/integrate/api": ["access:read"],
  "/notifications": ["notifications:read"],
  "/operations": ["lifecycle:read"],
  "/owners": ["owners:read"],
  "/platform": ["access:read"],
  "/policy": ["access:read"],
  "/posture": ["risk:read"],
  "/privacy": ["privacy:read"],
  "/profiles": ["profiles:read"],
  "/protocols": ["issuers:read"],
  "/request": ["certs:request"],
  "/risk": ["risk:read"],
  "/secrets": ["secrets:read"],
  "/ssh": ["certs:read"],
  "/wizard": ["agents:write"],
  "/workloads": ["certs:issue", "secrets:write"],
};

export function permissionAnyForPath(to: string): readonly string[] | undefined {
  const path = to.split("?")[0] || "/";
  return routePermissionAny[path];
}

export const taskNavItems: TaskNavItem[] = [
  {
    to: "/certificates?expiry=30d",
    labelKey: "nav.task.expiringSoon.label",
    descriptionKey: "nav.task.expiringSoon.description",
    icon: "certificate",
    featureIds: ["F1"],
  },
  {
    to: "/approvals?status=pending",
    labelKey: "nav.task.pendingApprovals.label",
    descriptionKey: "nav.task.pendingApprovals.description",
    icon: "policy",
    featureIds: ["F33"],
  },
  {
    to: "/risk?sort=score",
    labelKey: "nav.task.highestRisk.label",
    descriptionKey: "nav.task.highestRisk.description",
    icon: "risk",
    featureIds: ["F19"],
  },
];

export const navGroups: NavGroup[] = [
  {
    labelKey: "nav.group.issuanceCas",
    items: [
      { to: "/wizard", labelKey: "nav.item.setUp", icon: "rocket", mode: "real", featureIds: ["F3", "F4"] },
      { to: "/request", labelKey: "nav.item.requestCredential", icon: "key", mode: "real", featureIds: ["F4", "F33"] },
      { to: "/certificates", labelKey: "nav.item.certificates", icon: "certificate", mode: "real", featureIds: ["F1"] },
      { to: "/identities", labelKey: "nav.item.identities", icon: "identity", mode: "real", featureIds: ["F4", "F6", "F47", "F59"] },
      {
        to: "/protocols",
        labelKey: "nav.item.protocols",
        icon: "protocol",
        mode: "real",
        featureIds: ["F5", "F46", "F69", "F70", "F71", "F72", "F73", "F74"],
      },
      {
        to: "/secrets",
        labelKey: "nav.item.secrets",
        icon: "secret",
        mode: "real",
        featureIds: ["F37", "F38", "F39", "F63", "F64", "F65", "F66", "F68"],
      },
    ],
  },
  {
    labelKey: "nav.group.inventoryDiscovery",
    items: [
      { to: "/discovery", labelKey: "nav.item.discovery", icon: "activity", mode: "real", featureIds: ["F2", "F35", "F36", "F42", "F49"] },
      { to: "/agents", labelKey: "nav.item.agents", icon: "activity", mode: "real", featureIds: ["F3", "F54"] },
      { to: "/workloads", labelKey: "nav.item.workloads", icon: "spiffe", mode: "real", featureIds: ["F25", "F30", "F61"] },
      { to: "/owners", labelKey: "nav.item.owners", icon: "owner", mode: "real", featureIds: ["F59"] },
    ],
  },
  {
    labelKey: "nav.group.incidentsJit",
    items: [
      { to: "/incidents", labelKey: "nav.item.incidents", icon: "incident", mode: "real", featureIds: ["F31", "F32", "F34"] },
      { to: "/approvals", labelKey: "nav.item.approvals", icon: "policy", mode: "real", featureIds: ["F33"] },
    ],
  },
  {
    labelKey: "nav.group.riskInsight",
    items: [
      { to: "/", labelKey: "nav.item.dashboard", icon: "dashboard", end: true, mode: "real", featureIds: ["F1", "F19"] },
      { to: "/posture", labelKey: "nav.item.posture", icon: "risk", mode: "real", featureIds: ["F16", "F17", "F18", "F52", "F57"] },
      { to: "/risk", labelKey: "nav.item.risk", icon: "risk", mode: "real", featureIds: ["F19"] },
      { to: "/graph", labelKey: "nav.item.graph", icon: "graph", mode: "real", featureIds: ["F21"] },
      { to: "/assistant", labelKey: "nav.item.assistant", icon: "bot", mode: "real", featureIds: ["F75", "F76", "F77", "F78"] },
    ],
  },
  {
    labelKey: "nav.group.platform",
    items: [
      { to: "/audit", labelKey: "nav.item.audit", icon: "audit", mode: "real", featureIds: ["F9"] },
      { to: "/policy", labelKey: "nav.item.policy", icon: "policy", mode: "real", featureIds: ["F28", "F29", "F62"] },
      { to: "/connectors", labelKey: "nav.item.connectors", icon: "connector", mode: "real", featureIds: ["F7", "F27", "F20"] },
      { to: "/platform", labelKey: "nav.item.platform", icon: "platform", mode: "real", featureIds: ["F10", "F11", "F12", "F14", "F15", "F20", "F40", "F41"] },
    ],
  },
];

export const contextualRouteItems: ContextualRouteItem[] = [
  { to: "/profiles", labelKey: "nav.item.profiles", groupKey: "nav.group.issuanceCas", featureIds: ["F53"] },
  { to: "/ca-hierarchy", labelKey: "nav.item.caHierarchy", groupKey: "nav.group.issuanceCas", featureIds: ["F26", "F48"] },
  { to: "/ssh", labelKey: "nav.item.sshTrust", groupKey: "nav.group.issuanceCas", featureIds: ["F44", "F45"] },
  { to: "/codesign", labelKey: "nav.item.codeSigning", groupKey: "nav.group.issuanceCas", featureIds: ["F50"] },
  { to: "/operations", labelKey: "nav.item.operations", groupKey: "nav.group.incidentsJit", featureIds: ["F7"] },
  { to: "/notifications", labelKey: "nav.item.notifications", groupKey: "nav.group.incidentsJit", featureIds: ["F7"] },
  { to: "/privacy", labelKey: "nav.item.privacy", groupKey: "nav.group.platform", featureIds: ["F79"] },
  { to: "/integrate", labelKey: "nav.item.integrate", groupKey: "nav.group.platform", featureIds: ["F5", "F46"] },
  { to: "/integrate/api", labelKey: "nav.item.apiExplorer", groupKey: "nav.group.platform", featureIds: ["F10", "F46"] },
];

export interface RealGuiSurface {
  featureId: string;
  routes: string[];
  component: string;
  kind: "operate" | "observe";
  evidence: string;
}

export const realGuiSurfaces: RealGuiSurface[] = [
  { featureId: "F1", routes: ["/certificates"], component: "Certificates", kind: "operate", evidence: "certificatePage/getCertificate/ingestCertificate" },
  {
    featureId: "F2",
    routes: ["/discovery", "/certificates", "/agents"],
    component: "Discovery",
    kind: "observe",
    evidence: "network discovery sources, schedules, runs, findings, and certificate inventory",
  },
  { featureId: "F3", routes: ["/agents", "/wizard"], component: "Agents", kind: "operate", evidence: "agent fleet and enrollment token workflow" },
  {
    featureId: "F4",
    routes: ["/identities", "/wizard", "/request"],
    component: "Identities",
    kind: "operate",
    evidence: "identity issue/deploy/revoke transitions plus self-service request intake",
  },
  { featureId: "F5", routes: ["/protocols"], component: "Protocols", kind: "observe", evidence: "ACME endpoint setup and protocol-status unavailable state" },
  {
    featureId: "F6",
    routes: ["/identities"],
    component: "Identities",
    kind: "observe",
    evidence: "manual lifecycle transitions and automation unavailable state",
  },
  {
    featureId: "F7",
    routes: ["/connectors", "/operations", "/notifications"],
    component: "Connectors",
    kind: "observe",
    evidence: "native and plugin connector registry, capability grants, delivery receipts, operations queue, notification triage, reachability, and rollback posture",
  },
  {
    featureId: "F8",
    routes: ["/platform", "/identities", "/certificates"],
    component: "Platform access control",
    kind: "observe",
    evidence: "required-scope map and permission-denied states",
  },
  { featureId: "F9", routes: ["/audit"], component: "Audit", kind: "observe", evidence: "audit filters, event detail, and signed export" },
  { featureId: "F10", routes: ["/platform"], component: "Platform", kind: "observe", evidence: "static OpenAPI spec view" },
  {
    featureId: "F11",
    routes: ["/platform"],
    component: "Platform",
    kind: "observe",
    evidence: "token-safe CLI companion commands matching supported command groups",
  },
  {
    featureId: "F13",
    routes: ["/platform", "/login"],
    component: "Platform auth status",
    kind: "observe",
    evidence: "current /auth/me session and honest OIDC-status gap",
  },
  {
    featureId: "F14",
    routes: ["/platform"],
    component: "Platform",
    kind: "observe",
    evidence: "single-binary runtime, build, datastore, embedded UI, and signer-supervision disclosure blocked on platform status",
  },
  { featureId: "F15", routes: ["/platform"], component: "Platform", kind: "observe", evidence: "browser transport posture and platform-status gap" },
  {
    featureId: "F16",
    routes: ["/posture"],
    component: "Posture",
    kind: "observe",
    evidence: "crypto-agility and PQC readiness fixtures with CBOM backend gate",
  },
  {
    featureId: "F17",
    routes: ["/posture", "/discovery"],
    component: "Posture",
    kind: "observe",
    evidence: "certificate-transparency discovery, alert dispatch, and dedicated-dashboard gap",
  },
  {
    featureId: "F18",
    routes: ["/posture", "/discovery"],
    component: "Posture",
    kind: "observe",
    evidence: "drift discovery findings with disabled remediation preview",
  },
  { featureId: "F19", routes: ["/risk"], component: "Risk", kind: "observe", evidence: "credential risk list" },
  {
    featureId: "F20",
    routes: ["/platform", "/connectors"],
    component: "Platform",
    kind: "observe",
    evidence: "plugin provenance, digest pin, capability grant, conformance, runtime-status, and denial-reason disclosure without live activation",
  },
  { featureId: "F21", routes: ["/graph"], component: "Graph", kind: "observe", evidence: "graph and blast radius" },
  { featureId: "F22", routes: ["/protocols"], component: "Protocols", kind: "observe", evidence: "EST endpoint setup and protocol-status unavailable state" },
  { featureId: "F23", routes: ["/protocols"], component: "Protocols", kind: "observe", evidence: "SCEP endpoint setup and protocol-status unavailable state" },
  {
    featureId: "F24",
    routes: ["/protocols"],
    component: "Protocols",
    kind: "observe",
    evidence: "SPIFFE Workload API setup with X.509-SVID and JWT-SVID browser evidence",
  },
  {
    featureId: "F25",
    routes: ["/workloads"],
    component: "Workloads",
    kind: "observe",
    evidence: "ephemeral credential lease fixture plus JIT issuance disclosure",
  },
  {
    featureId: "F26",
    routes: ["/ca-hierarchy"],
    component: "CAHierarchy",
    kind: "observe",
    evidence: "served AWS KMS, Azure Key Vault HSM, GCP Cloud KMS, and PKCS#11 HSM custody metadata/actions without key bytes",
  },
  {
    featureId: "F27",
    routes: ["/connectors"],
    component: "Connectors",
    kind: "observe",
    evidence: "appliance connector reachability, masked target references, native/plugin delivery receipts, and rollback fixtures",
  },
  {
    featureId: "F28",
    routes: ["/policy", "/identities", "/audit"],
    component: "Policy",
    kind: "observe",
    evidence: "policy gate explanation plus dry-run status gap",
  },
  {
    featureId: "F29",
    routes: ["/policy"],
    component: "Policy",
    kind: "observe",
    evidence: "expiry-alert scheduling with masked notification-channel references and no live channel config",
  },
  {
    featureId: "F31",
    routes: ["/incidents"],
    component: "Incidents",
    kind: "observe",
    evidence: "compromised credential intake plus graph blast-radius preview without remediation execute",
  },
  {
    featureId: "F32",
    routes: ["/incidents"],
    component: "Incidents",
    kind: "observe",
    evidence: "fleet reissue wave, health, resume, rollback, failed target, and audit receipt fixture",
  },
  {
    featureId: "F34",
    routes: ["/incidents"],
    component: "Incidents",
    kind: "observe",
    evidence: "break-glass declaration, quorum, offline issue, reconciliation, expiry, and checklist fixture without bypass control",
  },
  {
    featureId: "F33",
    routes: ["/approvals", "/identities", "/request"],
    component: "Approvals",
    kind: "operate",
    evidence: "dedicated JIT request queue, self-service request intake, and dual-control approval mutation",
  },
  {
    featureId: "F35",
    routes: ["/discovery", "/secrets"],
    component: "Discovery",
    kind: "observe",
    evidence: "secret-store discovery schedules, runs, metadata-only findings, and native secret metadata",
  },
  {
    featureId: "F36",
    routes: ["/discovery"],
    component: "Discovery",
    kind: "observe",
    evidence: "API-key discovery schedules, runs, and metadata-only findings",
  },
  {
    featureId: "F37",
    routes: ["/secrets"],
    component: "Secrets",
    kind: "operate",
    evidence: "manual native-store rotate/delete plus rollback-safe static rotation",
  },
  {
    featureId: "F38",
    routes: ["/secrets"],
    component: "Secrets",
    kind: "observe",
    evidence: "ephemeral API-key issuance with reveal-once token handling",
  },
  {
    featureId: "F39",
    routes: ["/secrets"],
    component: "Secrets",
    kind: "observe",
    evidence: "secret scanning source/detector/fingerprint/owner/rotation disclosure with redacted snippets only",
  },
  { featureId: "F40", routes: ["/platform"], component: "Platform", kind: "observe", evidence: "active tenant from authenticated session" },
  {
    featureId: "F41",
    routes: ["/platform"],
    component: "Platform",
    kind: "observe",
    evidence: "passive cross-cluster federation imports peer event logs and projects replicated read state",
  },
  {
    featureId: "F42",
    routes: ["/discovery"],
    component: "Discovery",
    kind: "observe",
    evidence: "SSH discovery schedules, runs, and metadata-only findings",
  },
  {
    featureId: "F43",
    routes: ["/protocols", "/ssh"],
    component: "SSHTrust",
    kind: "operate",
    evidence: "SSH CA status, KRL version, and revocation workflow",
  },
  {
    featureId: "F44",
    routes: ["/ssh"],
    component: "SSHTrust",
    kind: "operate",
    evidence: "explicit-confirmation SSH trust rollout and host retirement handoff",
  },
  {
    featureId: "F45",
    routes: ["/ssh"],
    component: "SSHTrust",
    kind: "operate",
    evidence: "attestation-gated SSH user cert request and retrieval workflow",
  },
  {
    featureId: "F46",
    routes: ["/protocols"],
    component: "Protocols",
    kind: "observe",
    evidence: "ARI renewal-window disclosure plus durable-state caveat and protocol-status gate",
  },
  { featureId: "F47", routes: ["/identities", "/audit"], component: "Identities", kind: "operate", evidence: "revoke transition plus audit trail" },
  {
    featureId: "F48",
    routes: ["/ca-hierarchy", "/certificates"],
    component: "CAHierarchy",
    kind: "observe",
    evidence: "issuer table plus m-of-n hierarchy ceremony gap",
  },
  {
    featureId: "F49",
    routes: ["/discovery", "/secrets", "/certificates"],
    component: "Discovery",
    kind: "observe",
    evidence: "cloud-certificate discovery schedules, runs, metadata-only findings, and sealed credential references",
  },
  {
    featureId: "F50",
    routes: ["/codesign"],
    component: "CodeSigning",
    kind: "observe",
    evidence: "signing request ledger, key/keyless modes, approvals, policy decision, signature receipt, and audit disclosure without live signing",
  },
  { featureId: "F51", routes: ["/protocols"], component: "Protocols", kind: "observe", evidence: "TSA endpoint setup and protocol-status unavailable state" },
  {
    featureId: "F52",
    routes: ["/posture", "/risk"],
    component: "Posture",
    kind: "observe",
    evidence: "CBOM scan and inventory disclosure plus weak-crypto preview linked to risk",
  },
  { featureId: "F53", routes: ["/profiles"], component: "Profiles", kind: "operate", evidence: "profile creation" },
  {
    featureId: "F54",
    routes: ["/agents", "/wizard"],
    component: "Agents",
    kind: "operate",
    evidence: "bootstrap token install command plus renewal-status unavailable state",
  },
  { featureId: "F55", routes: ["/protocols"], component: "Protocols", kind: "observe", evidence: "CMP endpoint setup and protocol-status unavailable state" },
  {
    featureId: "F56",
    routes: ["/protocols"],
    component: "Protocols",
    kind: "observe",
    evidence: "MDM/Intune SCEP challenge fixtures plus backend-gap disclosure",
  },
  {
    featureId: "F57",
    routes: ["/posture"],
    component: "Posture",
    kind: "observe",
    evidence: "PQC migration wave preview plus orchestration gap",
  },
  { featureId: "F59", routes: ["/identities", "/owners"], component: "Identities", kind: "operate", evidence: "NHI lifecycle rows and owner link" },
  {
    featureId: "F30",
    routes: ["/workloads"],
    component: "Workloads",
    kind: "observe",
    evidence: "workload attestation accepted/rejected/expired/wrong-tenant fixtures without token leakage",
  },
  { featureId: "F58", routes: ["/secrets"], component: "Secrets", kind: "operate", evidence: "machine login exchange through secrets login" },
  { featureId: "F60", routes: ["/secrets"], component: "Secrets", kind: "operate", evidence: "one-time share create/redeem" },
  {
    featureId: "F61",
    routes: ["/workloads"],
    component: "Workloads",
    kind: "observe",
    evidence: "AI-agent broker identity, scope, expiry, and audit fixture",
  },
  {
    featureId: "F62",
    routes: ["/policy", "/audit"],
    component: "Policy",
    kind: "observe",
    evidence: "signed audit evidence export plus framework-mapped compliance posture disclosure",
  },
  { featureId: "F63", routes: ["/secrets"], component: "Secrets", kind: "operate", evidence: "native secret store metadata/create/reveal/rotate/delete" },
  { featureId: "F64", routes: ["/secrets"], component: "Secrets", kind: "observe", evidence: "developer snippets plus store access test" },
  {
    featureId: "F65",
    routes: ["/secrets"],
    component: "Secrets",
    kind: "observe",
    evidence: "dynamic lease disclosure with provider role, TTL, issue, renew, revoke, and expiry status",
  },
  {
    featureId: "F66",
    routes: ["/secrets"],
    component: "Secrets",
    kind: "observe",
    evidence: "transit/KMIP key, encrypt/decrypt, HMAC/sign/verify, versions, rewrap, audit, and local-only plaintext disclosure",
  },
  { featureId: "F67", routes: ["/secrets"], component: "Secrets", kind: "operate", evidence: "PKI secret issue with reveal-once bundle" },
  {
    featureId: "F68",
    routes: ["/secrets"],
    component: "Secrets",
    kind: "observe",
    evidence: "secret sync posture, masked target mappings, and outbox delivery disclosure",
  },
  {
    featureId: "F69",
    routes: ["/protocols"],
    component: "Protocols",
    kind: "observe",
    evidence: "DNS-01 secret-reference disclosure with no raw provider-token controls",
  },
  {
    featureId: "F70",
    routes: ["/protocols"],
    component: "Protocols",
    kind: "observe",
    evidence: "built-in/plugin DNS provider disclosure with conformance and provenance gate",
  },
  { featureId: "F71", routes: ["/protocols"], component: "Protocols", kind: "observe", evidence: "CNAME validation isolation fixture preview" },
  {
    featureId: "F72",
    routes: ["/protocols"],
    component: "Protocols",
    kind: "observe",
    evidence: "CAA no-record/allowed/denied/DNS-failure/wildcard fixture preview",
  },
  { featureId: "F73", routes: ["/protocols"], component: "Protocols", kind: "observe", evidence: "HTTP-01/DNS-01/TLS-ALPN-01 method policy preview" },
  {
    featureId: "F74",
    routes: ["/protocols"],
    component: "Protocols",
    kind: "observe",
    evidence: "wildcard DNS-01-only acknowledgement and blast-radius disclosure",
  },
  { featureId: "F75", routes: ["/assistant"], component: "Assistant", kind: "operate", evidence: "grounded query with citations and runtime status" },
  { featureId: "F76", routes: ["/assistant"], component: "Assistant", kind: "observe", evidence: "AI model runtime disclosure and redaction boundary" },
  { featureId: "F77", routes: ["/assistant"], component: "Assistant", kind: "operate", evidence: "grounded RCA with citations and runtime status" },
  { featureId: "F78", routes: ["/assistant"], component: "Assistant", kind: "operate", evidence: "read-only MCP tools and runtime status" },
];
