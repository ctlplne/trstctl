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
  | "risk"
  | "rocket"
  | "secret"
  | "spiffe"
  | "ssh";

export interface NavItem {
  to: string;
  label: string;
  icon: NavIcon;
  end?: boolean;
  mode: "real" | "disclosure";
  featureIds: string[];
}

export interface NavGroup {
  label: string;
  items: NavItem[];
}

export const appRoutePaths = [
  "/login",
  "/",
  "/certificates",
  "/coverage",
  "/identities",
  "/owners",
  "/agents",
  "/discovery",
  "/profiles",
  "/ca-hierarchy",
  "/workloads",
  "/protocols",
  "/ssh",
  "/secrets",
  "/policy",
  "/risk",
  "/posture",
  "/graph",
  "/audit",
  "/assistant",
  "/wizard",
  "/platform",
] as const;

export const navGroups: NavGroup[] = [
  {
    label: "Overview",
    items: [
      { to: "/", label: "Dashboard", icon: "dashboard", end: true, mode: "real", featureIds: ["F1", "F19"] },
      { to: "/coverage", label: "Coverage roadmap", icon: "graph", mode: "real", featureIds: ["F12"] },
      { to: "/wizard", label: "Set up", icon: "rocket", mode: "real", featureIds: ["F3", "F4"] },
    ],
  },
  {
    label: "Inventory & Discovery",
    items: [
      { to: "/certificates", label: "Certificates", icon: "certificate", mode: "real", featureIds: ["F1"] },
      { to: "/identities", label: "Identities", icon: "identity", mode: "real", featureIds: ["F4", "F6", "F47", "F59"] },
      { to: "/owners", label: "Owners", icon: "owner", mode: "real", featureIds: ["F59"] },
      { to: "/agents", label: "Agents", icon: "activity", mode: "real", featureIds: ["F3", "F54"] },
      { to: "/discovery", label: "Discovery", icon: "activity", mode: "real", featureIds: ["F2", "F35", "F36", "F42", "F49"] },
      { to: "/workloads", label: "Workloads", icon: "spiffe", mode: "real", featureIds: ["F25", "F30", "F61"] },
    ],
  },
  {
    label: "Issuance & CAs",
    items: [
      { to: "/profiles", label: "Profiles", icon: "profile", mode: "real", featureIds: ["F53"] },
      { to: "/identities", label: "Issuance", icon: "key", mode: "real", featureIds: ["F4", "F6", "F33"] },
      { to: "/ca-hierarchy", label: "CA hierarchy", icon: "certificate", mode: "real", featureIds: ["F26", "F48"] },
    ],
  },
  {
    label: "Protocols",
    items: [
      { to: "/protocols", label: "ACME and DNS", icon: "protocol", mode: "real", featureIds: ["F5", "F46", "F69", "F70", "F71", "F72", "F73", "F74"] },
      { to: "/protocols", label: "Enrollment protocols", icon: "protocol", mode: "real", featureIds: ["F22", "F23", "F55", "F56"] },
      { to: "/protocols", label: "SPIFFE", icon: "spiffe", mode: "real", featureIds: ["F24"] },
      { to: "/protocols", label: "SSH CA", icon: "ssh", mode: "real", featureIds: ["F43"] },
      { to: "/ssh", label: "SSH trust", icon: "ssh", mode: "real", featureIds: ["F44", "F45"] },
      { to: "/protocols", label: "TSA", icon: "protocol", mode: "real", featureIds: ["F51"] },
    ],
  },
  {
    label: "Secrets",
    items: [
      { to: "/secrets", label: "Native secrets", icon: "secret", mode: "real", featureIds: ["F37", "F63", "F64"] },
      { to: "/secrets", label: "PKI secrets", icon: "secret", mode: "real", featureIds: ["F67"] },
      { to: "/secrets", label: "Machine login", icon: "key", mode: "real", featureIds: ["F58"] },
      { to: "/secrets", label: "Secret sharing", icon: "secret", mode: "real", featureIds: ["F60"] },
    ],
  },
  {
    label: "Connectors & Plugins",
    items: [
      { to: "/coverage?domain=Deployment%20connectors", label: "Connectors", icon: "connector", mode: "disclosure", featureIds: ["F20"] },
      { to: "/coverage?domain=Extensibility%20and%20plugins", label: "Plugins", icon: "connector", mode: "disclosure", featureIds: ["F20"] },
    ],
  },
  {
    label: "Risk & Insight",
    items: [
      { to: "/risk", label: "Risk", icon: "risk", mode: "real", featureIds: ["F19"] },
      { to: "/posture", label: "Posture", icon: "risk", mode: "real", featureIds: ["F16", "F17", "F18", "F52", "F57"] },
      { to: "/graph", label: "Graph", icon: "graph", mode: "real", featureIds: ["F21"] },
      { to: "/assistant", label: "Assistant", icon: "bot", mode: "real", featureIds: ["F75", "F77", "F78"] },
    ],
  },
  {
    label: "Incidents & JIT",
    items: [
      { to: "/coverage?domain=Incident%20and%20JIT", label: "Incidents", icon: "incident", mode: "disclosure", featureIds: ["F33"] },
      { to: "/identities", label: "Approvals", icon: "policy", mode: "real", featureIds: ["F33"] },
    ],
  },
  {
    label: "Governance",
    items: [
      { to: "/audit", label: "Audit", icon: "audit", mode: "real", featureIds: ["F9"] },
      { to: "/owners", label: "Ownership", icon: "owner", mode: "real", featureIds: ["F59"] },
      { to: "/coverage?feature=F8", label: "RBAC", icon: "policy", mode: "disclosure", featureIds: ["F8"] },
      { to: "/policy", label: "Policy", icon: "policy", mode: "real", featureIds: ["F28"] },
    ],
  },
  {
    label: "Platform",
    items: [
      { to: "/platform", label: "Platform", icon: "platform", mode: "real", featureIds: ["F10", "F12", "F15", "F40"] },
      { to: "/login", label: "SSO", icon: "key", mode: "real", featureIds: ["F13"] },
      { to: "/coverage?domain=Platform%20and%20API", label: "API and distribution", icon: "platform", mode: "disclosure", featureIds: ["F10", "F11", "F14"] },
    ],
  },
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
  { featureId: "F2", routes: ["/discovery", "/certificates", "/agents"], component: "Discovery", kind: "observe", evidence: "network scan blocked disclosure plus links to served ingest and agent enrollment" },
  { featureId: "F3", routes: ["/agents", "/wizard"], component: "Agents", kind: "operate", evidence: "agent fleet and enrollment token workflow" },
  { featureId: "F4", routes: ["/identities", "/wizard"], component: "Identities", kind: "operate", evidence: "identity issue/deploy/revoke transitions" },
  { featureId: "F5", routes: ["/protocols"], component: "Protocols", kind: "observe", evidence: "ACME endpoint setup and protocol-status unavailable state" },
  { featureId: "F6", routes: ["/identities"], component: "Identities", kind: "observe", evidence: "manual lifecycle transitions and automation unavailable state" },
  { featureId: "F8", routes: ["/platform", "/identities", "/certificates"], component: "Platform access control", kind: "observe", evidence: "required-scope map and permission-denied states" },
  { featureId: "F9", routes: ["/audit"], component: "Audit", kind: "observe", evidence: "audit filters, event detail, and signed export" },
  { featureId: "F10", routes: ["/platform"], component: "Platform", kind: "observe", evidence: "static OpenAPI spec view" },
  { featureId: "F12", routes: ["/platform", "/coverage"], component: "AppShell", kind: "observe", evidence: "grouped navigation and coverage route" },
  { featureId: "F13", routes: ["/platform", "/login"], component: "Platform auth status", kind: "observe", evidence: "current /auth/me session and honest OIDC-status gap" },
  { featureId: "F15", routes: ["/platform"], component: "Platform", kind: "observe", evidence: "browser transport posture and platform-status gap" },
  { featureId: "F16", routes: ["/posture"], component: "Posture", kind: "observe", evidence: "crypto-agility and PQC readiness fixtures with CBOM backend gate" },
  { featureId: "F17", routes: ["/posture"], component: "Posture", kind: "observe", evidence: "CT monitor library-only disclosure plus non-interactive triage preview" },
  { featureId: "F18", routes: ["/posture"], component: "Posture", kind: "observe", evidence: "drift library-only disclosure plus disabled remediation preview" },
  { featureId: "F19", routes: ["/risk"], component: "Risk", kind: "observe", evidence: "credential risk list" },
  { featureId: "F21", routes: ["/graph"], component: "Graph", kind: "observe", evidence: "graph and blast radius" },
  { featureId: "F22", routes: ["/protocols"], component: "Protocols", kind: "observe", evidence: "EST endpoint setup and protocol-status unavailable state" },
  { featureId: "F23", routes: ["/protocols"], component: "Protocols", kind: "observe", evidence: "SCEP endpoint setup and protocol-status unavailable state" },
  { featureId: "F24", routes: ["/protocols"], component: "Protocols", kind: "observe", evidence: "SPIFFE Workload API socket setup and protocol-status unavailable state" },
  { featureId: "F25", routes: ["/workloads"], component: "Workloads", kind: "observe", evidence: "ephemeral credential lease fixture plus library-only disclosure" },
  { featureId: "F26", routes: ["/ca-hierarchy"], component: "CAHierarchy", kind: "observe", evidence: "HSM/KMS custody metadata preview plus library-tier disclosure without key bytes" },
  { featureId: "F28", routes: ["/policy", "/identities", "/audit"], component: "Policy", kind: "observe", evidence: "served policy gate explanation plus dry-run API unavailable state" },
  { featureId: "F33", routes: ["/identities"], component: "Identities", kind: "operate", evidence: "JIT request queue and dual-control approval mutation" },
  { featureId: "F35", routes: ["/discovery", "/secrets"], component: "Discovery", kind: "observe", evidence: "native secret metadata table plus external discovery blocked disclosure" },
  { featureId: "F36", routes: ["/discovery"], component: "Discovery", kind: "observe", evidence: "api_key identity table with masked fingerprints plus scanner blocked disclosure" },
  { featureId: "F37", routes: ["/secrets"], component: "Secrets", kind: "operate", evidence: "manual native-store rotate/delete through served secrets store" },
  { featureId: "F40", routes: ["/platform"], component: "Platform", kind: "observe", evidence: "active tenant from authenticated session" },
  { featureId: "F42", routes: ["/discovery"], component: "Discovery", kind: "observe", evidence: "ssh_key/ssh_certificate identity table plus SSH scan findings blocked disclosure" },
  { featureId: "F43", routes: ["/protocols"], component: "Protocols", kind: "observe", evidence: "SSH CA endpoint/KRL setup and protocol-status unavailable state" },
  { featureId: "F44", routes: ["/ssh"], component: "SSHTrust", kind: "observe", evidence: "SSH trust rollout and rollback fixtures without live mutation controls" },
  { featureId: "F45", routes: ["/ssh"], component: "SSHTrust", kind: "observe", evidence: "attestation-gated SSH user cert fixtures without live issue control" },
  { featureId: "F46", routes: ["/protocols"], component: "Protocols", kind: "observe", evidence: "ARI renewal-window disclosure plus durable-state caveat and protocol-status gate" },
  { featureId: "F47", routes: ["/identities", "/audit"], component: "Identities", kind: "operate", evidence: "revoke transition plus audit trail" },
  { featureId: "F48", routes: ["/ca-hierarchy", "/certificates"], component: "CAHierarchy", kind: "observe", evidence: "served issuer table plus m-of-n hierarchy ceremony blocked disclosure" },
  { featureId: "F49", routes: ["/discovery", "/secrets", "/certificates"], component: "Discovery", kind: "observe", evidence: "cloud discovery blocked disclosure with sealed-secret credential-reference guidance" },
  { featureId: "F51", routes: ["/protocols"], component: "Protocols", kind: "observe", evidence: "TSA endpoint setup and protocol-status unavailable state" },
  { featureId: "F52", routes: ["/posture", "/risk"], component: "Posture", kind: "observe", evidence: "CBOM library-only disclosure plus weak-crypto preview linked to risk" },
  { featureId: "F53", routes: ["/profiles"], component: "Profiles", kind: "operate", evidence: "profile creation" },
  { featureId: "F54", routes: ["/agents", "/wizard"], component: "Agents", kind: "operate", evidence: "bootstrap token install command plus renewal-status unavailable state" },
  { featureId: "F55", routes: ["/protocols"], component: "Protocols", kind: "observe", evidence: "CMP endpoint setup and protocol-status unavailable state" },
  { featureId: "F56", routes: ["/protocols"], component: "Protocols", kind: "observe", evidence: "MDM/Intune SCEP challenge fixtures plus backend-gap disclosure" },
  { featureId: "F57", routes: ["/posture"], component: "Posture", kind: "observe", evidence: "PQC migration wave fixture plus library-only orchestration disclosure" },
  { featureId: "F59", routes: ["/identities", "/owners"], component: "Identities", kind: "operate", evidence: "NHI lifecycle rows and owner link" },
  { featureId: "F30", routes: ["/workloads"], component: "Workloads", kind: "observe", evidence: "workload attestation accepted/rejected/expired/wrong-tenant fixtures without token leakage" },
  { featureId: "F58", routes: ["/secrets"], component: "Secrets", kind: "operate", evidence: "machine login exchange through served secrets login" },
  { featureId: "F60", routes: ["/secrets"], component: "Secrets", kind: "operate", evidence: "one-time share create/redeem" },
  { featureId: "F61", routes: ["/workloads"], component: "Workloads", kind: "observe", evidence: "AI-agent broker identity/scope/expiry/audit fixture plus library-only disclosure" },
  { featureId: "F63", routes: ["/secrets"], component: "Secrets", kind: "operate", evidence: "native secret store metadata/create/reveal/rotate/delete" },
  { featureId: "F64", routes: ["/secrets"], component: "Secrets", kind: "observe", evidence: "developer snippets plus access test against served store" },
  { featureId: "F67", routes: ["/secrets"], component: "Secrets", kind: "operate", evidence: "PKI secret issue with reveal-once bundle" },
  { featureId: "F69", routes: ["/protocols"], component: "Protocols", kind: "observe", evidence: "DNS-01 secret-reference disclosure with no raw provider-token controls" },
  { featureId: "F70", routes: ["/protocols"], component: "Protocols", kind: "observe", evidence: "built-in/plugin DNS provider disclosure with conformance and provenance gate" },
  { featureId: "F71", routes: ["/protocols"], component: "Protocols", kind: "observe", evidence: "CNAME validation isolation fixture preview" },
  { featureId: "F72", routes: ["/protocols"], component: "Protocols", kind: "observe", evidence: "CAA no-record/allowed/denied/DNS-failure/wildcard fixture preview" },
  { featureId: "F73", routes: ["/protocols"], component: "Protocols", kind: "observe", evidence: "HTTP-01/DNS-01/TLS-ALPN-01 method policy preview" },
  { featureId: "F74", routes: ["/protocols"], component: "Protocols", kind: "observe", evidence: "wildcard DNS-01-only acknowledgement and blast-radius disclosure" },
  { featureId: "F75", routes: ["/assistant"], component: "Assistant", kind: "operate", evidence: "grounded query with citations and platform-status unavailable state" },
  { featureId: "F76", routes: ["/assistant"], component: "Assistant", kind: "observe", evidence: "AI model runtime disclosure and redaction boundary" },
  { featureId: "F77", routes: ["/assistant"], component: "Assistant", kind: "operate", evidence: "grounded RCA with citations and platform-status unavailable state" },
  { featureId: "F78", routes: ["/assistant"], component: "Assistant", kind: "operate", evidence: "read-only MCP tools and runtime-status unavailable state" },
];
