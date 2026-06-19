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
  "/profiles",
  "/protocols",
  "/risk",
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
      { to: "/coverage?domain=SSH", label: "SSH inventory", icon: "ssh", mode: "disclosure", featureIds: ["F42"] },
    ],
  },
  {
    label: "Issuance & CAs",
    items: [
      { to: "/profiles", label: "Profiles", icon: "profile", mode: "real", featureIds: ["F53"] },
      { to: "/identities", label: "Issuance", icon: "key", mode: "real", featureIds: ["F4", "F6", "F33"] },
      { to: "/coverage?domain=Issuance%20and%20CAs", label: "CA ceremonies", icon: "certificate", mode: "disclosure", featureIds: ["F18"] },
    ],
  },
  {
    label: "Protocols",
    items: [
      { to: "/protocols", label: "ACME and DNS", icon: "protocol", mode: "real", featureIds: ["F5"] },
      { to: "/protocols", label: "Enrollment protocols", icon: "protocol", mode: "real", featureIds: ["F22", "F23", "F55"] },
      { to: "/protocols", label: "SPIFFE", icon: "spiffe", mode: "real", featureIds: ["F24"] },
      { to: "/protocols", label: "SSH CA", icon: "ssh", mode: "real", featureIds: ["F43"] },
      { to: "/protocols", label: "TSA", icon: "protocol", mode: "real", featureIds: ["F51"] },
    ],
  },
  {
    label: "Secrets",
    items: [
      { to: "/coverage?domain=Secrets", label: "Native secrets", icon: "secret", mode: "disclosure", featureIds: ["F63"] },
      { to: "/coverage?feature=F67", label: "PKI secrets", icon: "secret", mode: "disclosure", featureIds: ["F67"] },
      { to: "/coverage?feature=F60", label: "Secret sharing", icon: "secret", mode: "disclosure", featureIds: ["F60"] },
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
      { to: "/coverage?feature=F28", label: "Policy", icon: "policy", mode: "disclosure", featureIds: ["F28"] },
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
  { featureId: "F19", routes: ["/risk"], component: "Risk", kind: "observe", evidence: "credential risk list" },
  { featureId: "F21", routes: ["/graph"], component: "Graph", kind: "observe", evidence: "graph and blast radius" },
  { featureId: "F22", routes: ["/protocols"], component: "Protocols", kind: "observe", evidence: "EST endpoint setup and protocol-status unavailable state" },
  { featureId: "F23", routes: ["/protocols"], component: "Protocols", kind: "observe", evidence: "SCEP endpoint setup and protocol-status unavailable state" },
  { featureId: "F24", routes: ["/protocols"], component: "Protocols", kind: "observe", evidence: "SPIFFE Workload API socket setup and protocol-status unavailable state" },
  { featureId: "F33", routes: ["/identities"], component: "Identities", kind: "operate", evidence: "JIT request queue and dual-control approval mutation" },
  { featureId: "F40", routes: ["/platform"], component: "Platform", kind: "observe", evidence: "active tenant from authenticated session" },
  { featureId: "F43", routes: ["/protocols"], component: "Protocols", kind: "observe", evidence: "SSH CA endpoint/KRL setup and protocol-status unavailable state" },
  { featureId: "F47", routes: ["/identities", "/audit"], component: "Identities", kind: "operate", evidence: "revoke transition plus audit trail" },
  { featureId: "F51", routes: ["/protocols"], component: "Protocols", kind: "observe", evidence: "TSA endpoint setup and protocol-status unavailable state" },
  { featureId: "F53", routes: ["/profiles"], component: "Profiles", kind: "operate", evidence: "profile creation" },
  { featureId: "F54", routes: ["/agents", "/wizard"], component: "Agents", kind: "operate", evidence: "bootstrap token install command plus renewal-status unavailable state" },
  { featureId: "F55", routes: ["/protocols"], component: "Protocols", kind: "observe", evidence: "CMP endpoint setup and protocol-status unavailable state" },
  { featureId: "F59", routes: ["/identities", "/owners"], component: "Identities", kind: "operate", evidence: "NHI lifecycle rows and owner link" },
];
