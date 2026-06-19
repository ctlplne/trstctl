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
  "/profiles",
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
      { to: "/identities", label: "Identities", icon: "identity", mode: "real", featureIds: ["F4", "F47", "F59"] },
      { to: "/owners", label: "Owners", icon: "owner", mode: "real", featureIds: ["F59"] },
      { to: "/wizard", label: "Agents", icon: "activity", mode: "real", featureIds: ["F3"] },
      { to: "/coverage?domain=SSH", label: "SSH inventory", icon: "ssh", mode: "disclosure", featureIds: ["F42"] },
    ],
  },
  {
    label: "Issuance & CAs",
    items: [
      { to: "/profiles", label: "Profiles", icon: "profile", mode: "real", featureIds: ["F53"] },
      { to: "/identities", label: "Issuance", icon: "key", mode: "real", featureIds: ["F4", "F33"] },
      { to: "/coverage?domain=Issuance%20and%20CAs", label: "CA ceremonies", icon: "certificate", mode: "disclosure", featureIds: ["F18"] },
    ],
  },
  {
    label: "Protocols",
    items: [
      { to: "/coverage?domain=ACME%20and%20DNS", label: "ACME and DNS", icon: "protocol", mode: "disclosure", featureIds: ["F5"] },
      { to: "/coverage?domain=Enrollment%20protocols", label: "Enrollment protocols", icon: "protocol", mode: "disclosure", featureIds: ["F22", "F23", "F55"] },
      { to: "/coverage?feature=F24", label: "SPIFFE", icon: "spiffe", mode: "disclosure", featureIds: ["F24"] },
      { to: "/coverage?feature=F43", label: "SSH CA", icon: "ssh", mode: "disclosure", featureIds: ["F43"] },
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
  { featureId: "F3", routes: ["/wizard"], component: "Wizard", kind: "operate", evidence: "agents and enrollment token workflow" },
  { featureId: "F4", routes: ["/identities", "/wizard"], component: "Identities", kind: "operate", evidence: "identity issue/deploy/revoke transitions" },
  { featureId: "F8", routes: ["/identities", "/certificates"], component: "Resource state primitives", kind: "observe", evidence: "permission-denied states for auth-gated routes" },
  { featureId: "F9", routes: ["/audit"], component: "Audit", kind: "observe", evidence: "audit events and export" },
  { featureId: "F12", routes: ["/platform", "/coverage"], component: "AppShell", kind: "observe", evidence: "grouped navigation and coverage route" },
  { featureId: "F15", routes: ["/platform"], component: "Platform", kind: "observe", evidence: "browser transport posture" },
  { featureId: "F19", routes: ["/risk"], component: "Risk", kind: "observe", evidence: "credential risk list" },
  { featureId: "F21", routes: ["/graph"], component: "Graph", kind: "observe", evidence: "graph and blast radius" },
  { featureId: "F40", routes: ["/platform"], component: "Platform", kind: "observe", evidence: "active tenant from authenticated session" },
  { featureId: "F47", routes: ["/identities", "/audit"], component: "Identities", kind: "operate", evidence: "revoke transition plus audit trail" },
  { featureId: "F53", routes: ["/profiles"], component: "Profiles", kind: "operate", evidence: "profile creation" },
  { featureId: "F59", routes: ["/identities", "/owners"], component: "Identities", kind: "operate", evidence: "NHI lifecycle rows and owner link" },
];
