import type { MessageKey } from "@/i18n/messages";
import type { CanonicalCapabilityID } from "@/lib/feature-contracts.gen";

export type NavIcon =
  | "activity"
  | "agent"
  | "approval"
  | "audit"
  | "bot"
  | "certificate"
  | "connector"
  | "dashboard"
  | "graph"
  | "identity"
  | "incident"
  | "journey"
  | "key"
  | "owner"
  | "platform"
  | "policy"
  | "posture"
  | "profile"
  | "protocol"
  | "notification"
  | "risk"
  | "rocket"
  | "secret"
  | "signature"
  | "spiffe"
  | "ssh"
  | "vault";

export interface NavItem {
  to: string;
  labelKey: MessageKey;
  icon: NavIcon;
  end?: boolean;
  mode: "real" | "disclosure";
  featureIds: CanonicalCapabilityID[];
}

export interface TaskNavItem {
  to: string;
  labelKey: MessageKey;
  descriptionKey: MessageKey;
  icon: NavIcon;
  featureIds: CanonicalCapabilityID[];
}

export interface NavGroup {
  labelKey: MessageKey;
  items: NavItem[];
}

export interface ContextualRouteItem {
  to: string;
  labelKey: MessageKey;
  groupKey: MessageKey;
  featureIds: CanonicalCapabilityID[];
}

/* S-C1 (tools): the unified-shell registry. Six operator mental models own
 * every product surface, and only Home (Dashboard + Journeys + worklists)
 * is global. The ids deliberately retain their original internal values so
 * stored preferences and audit deep links survive the 2026-08 product carve:
 * `posture` now presents Software Trust, and `platform` presents Trust
 * Operations. `discovery` is new because Discover is now a first-class tool,
 * not an Operations menu item. Customer labels and canonical route ownership
 * —not an internal persistence key—define the product. Route URLs stay stable. */
export type SpaceId = "discovery" | "certificates" | "workload" | "secrets" | "posture" | "platform";
/** Back-compat alias: audit deep links and preferences persist these ids. */
export type ModuleId = SpaceId;

export interface NavSpace {
  id: SpaceId;
  labelKey: MessageKey;
  questionKey: MessageKey;
  icon: NavIcon;
  /** The space's scoped sidebar — grouped exactly like the old rail bands. */
  groups: NavGroup[];
}

export interface NavModule {
  id: ModuleId;
  labelKey: MessageKey;
  icon: NavIcon;
  /** Routes scoped to this module — its sidebar band when the space is active. */
  routes: string[];
  featureIds: CanonicalCapabilityID[];
}

/** navSpaces: the six focused tools of the unified shell. Every customer route lives
 * in exactly one space group (the module_map partition guard). The visible
 * vocabulary is task-first: Discover; Certificates; Workloads & Machines;
 * Secrets; Software Trust; and Operations.
 *
 * S-C7 — the workspaces-vs-lenses rule for in-page tabs. A tab becomes a
 * sidebar ROUTE only when it is a distinct served workspace: its own feature
 * evidence, its own workflows/mutations, its own name. A tab that is a LENS —
 * an alternate view over the same object domain — stays an in-page tab and
 * must be URL-addressable via ?tab=. Rulings under this rule:
 *   - Secrets: six workspaces → six routes (S-C2).
 *   - Certificates (inventory/health/crlct/renewal): four lenses over one
 *     certificate inventory → tabs stay (?tab= deep links, e.g. the
 *     Dashboard's /certificates?tab=renewal, remain first-class).
 *   - Discovery (findings/sources/schedules/runs): four stages of ONE
 *     discovery pipeline sharing feature evidence (F2/F35/F36/F42/F49) →
 *     tabs stay.
 * Splitting a lens into a route (or vice versa) is an IA change: update this
 * comment, the guards, and the docs in the same PR. */
export const navSpaces: NavSpace[] = [
  {
    id: "discovery",
    labelKey: "nav.space.discovery",
    questionKey: "nav.spaceQuestion.discovery",
    icon: "activity",
    groups: [
      {
        labelKey: "nav.group.overview",
        items: [{ to: "/discovery", labelKey: "nav.item.discovery", icon: "activity", mode: "real", featureIds: ["F2", "F17", "F35", "F36", "F42", "F49"] }],
      },
    ],
  },
  {
    id: "certificates",
    labelKey: "nav.module.certificates",
    questionKey: "nav.spaceQuestion.certificates",
    icon: "certificate",
    groups: [
      {
        labelKey: "nav.group.inventory",
        items: [{ to: "/certificates", labelKey: "nav.item.certificates", icon: "certificate", mode: "real", featureIds: ["F1"] }],
      },
      {
        labelKey: "nav.group.issueAutomate",
        items: [
          { to: "/request", labelKey: "nav.item.requestCredential", icon: "key", mode: "real", featureIds: ["F4", "F33"] },
          { to: "/profiles", labelKey: "nav.item.profiles", icon: "profile", mode: "real", featureIds: ["F53"] },
          { to: "/ca-hierarchy", labelKey: "nav.item.caHierarchy", icon: "certificate", mode: "real", featureIds: ["F26", "F48"] },
          {
            to: "/protocols",
            labelKey: "nav.item.protocols",
            icon: "protocol",
            mode: "real",
            featureIds: ["F5", "F46", "F69", "F70", "F71", "F72", "F73", "F74"],
          },
        ],
      },
    ],
  },
  {
    id: "workload",
    labelKey: "nav.space.workload",
    questionKey: "nav.spaceQuestion.workload",
    icon: "spiffe",
    groups: [
      {
        labelKey: "nav.group.workloadIdentity",
        items: [
          { to: "/workloads", labelKey: "nav.item.workloads", icon: "spiffe", mode: "real", featureIds: ["F25", "F30", "F61"] },
          { to: "/identities", labelKey: "nav.item.identities", icon: "identity", mode: "real", featureIds: ["F4", "F6", "F47", "F59"] },
        ],
      },
      {
        labelKey: "nav.group.sshTrust",
        items: [{ to: "/ssh", labelKey: "nav.item.sshTrust", icon: "ssh", mode: "real", featureIds: ["F44", "F45"] }],
      },
      {
        labelKey: "nav.group.infrastructure",
        items: [{ to: "/agents", labelKey: "nav.item.agents", icon: "agent", mode: "real", featureIds: ["F3", "F54"] }],
      },
    ],
  },
  {
    id: "secrets",
    labelKey: "nav.module.secrets",
    questionKey: "nav.spaceQuestion.secrets",
    icon: "vault",
    /* S-C2: the Secrets workspaces are sidebar rows, not in-page tabs — the
     * store keeps /secrets, and each other workspace owns a sub-route. */
    groups: [
      {
        labelKey: "nav.group.secretsEngines",
        items: [
          { to: "/secrets", labelKey: "nav.item.secrets", icon: "vault", mode: "real", featureIds: ["F37", "F63"] },
          { to: "/secrets/engines", labelKey: "secrets.route.engines", icon: "key", mode: "real", featureIds: ["F65", "F66", "F67"] },
        ],
      },
      {
        labelKey: "nav.group.secretsAccess",
        items: [
          { to: "/secrets/access", labelKey: "secrets.route.access", icon: "identity", mode: "real", featureIds: ["F58", "F64"] },
          { to: "/secrets/sharing", labelKey: "secrets.route.sharing", icon: "secret", mode: "real", featureIds: ["F38", "F60"] },
        ],
      },
      {
        labelKey: "nav.group.secretsDelivery",
        items: [
          { to: "/secrets/sync", labelKey: "secrets.route.sync", icon: "connector", mode: "real", featureIds: ["F68"] },
          { to: "/secrets/scanning", labelKey: "secrets.tabs.scanning", icon: "activity", mode: "real", featureIds: ["F39"] },
        ],
      },
    ],
  },
  {
    id: "posture",
    labelKey: "nav.space.posture",
    questionKey: "nav.spaceQuestion.posture",
    icon: "posture",
    groups: [
      {
        labelKey: "nav.group.overview",
        items: [{ to: "/codesign", labelKey: "nav.item.codeSigning", icon: "signature", mode: "real", featureIds: ["F50"] }],
      },
    ],
  },
  {
    id: "platform",
    labelKey: "nav.space.platform",
    questionKey: "nav.spaceQuestion.platform",
    icon: "platform",
    groups: [
      {
        labelKey: "nav.group.overview",
        items: [{ to: "/trust-operations", labelKey: "nav.item.trustOperations", icon: "platform", mode: "real", featureIds: ["F7", "F19", "F31", "F59"] }],
      },
      {
        labelKey: "nav.group.detectRespond",
        items: [
          { to: "/risk", labelKey: "nav.item.risk", icon: "risk", mode: "real", featureIds: ["F19"] },
          { to: "/graph", labelKey: "nav.item.graph", icon: "graph", mode: "real", featureIds: ["F21"] },
          { to: "/posture", labelKey: "nav.item.posture", icon: "posture", mode: "real", featureIds: ["F16", "F17", "F18", "F52", "F57"] },
          { to: "/migration", labelKey: "source.migration.h2mig00001", icon: "graph", mode: "real", featureIds: ["F48"] },
          { to: "/incidents", labelKey: "nav.item.incidents", icon: "incident", mode: "real", featureIds: ["F31", "F32", "F34"] },
          { to: "/operations", labelKey: "nav.item.operations", icon: "activity", mode: "real", featureIds: ["F7"] },
        ],
      },
      {
        labelKey: "nav.group.governAdminister",
        items: [
          { to: "/policy", labelKey: "nav.item.policy", icon: "policy", mode: "real", featureIds: ["F28", "F29", "F62"] },
          { to: "/approvals", labelKey: "nav.item.approvals", icon: "approval", mode: "real", featureIds: ["F33"] },
          { to: "/audit", labelKey: "nav.item.audit", icon: "audit", mode: "real", featureIds: ["F9"] },
          { to: "/owners", labelKey: "nav.item.ownership", icon: "owner", mode: "real", featureIds: ["F59"] },
          { to: "/notifications", labelKey: "nav.item.notifications", icon: "notification", mode: "real", featureIds: ["F7"] },
          { to: "/privacy", labelKey: "nav.item.privacy", icon: "policy", mode: "real", featureIds: ["F79"] },
        ],
      },
      {
        labelKey: "nav.group.infrastructure",
        items: [{ to: "/connectors", labelKey: "nav.item.connectors", icon: "connector", mode: "real", featureIds: ["F7", "F27", "F20"] }],
      },
      {
        labelKey: "nav.group.integrations",
        items: [
          { to: "/integrate", labelKey: "nav.item.integrate", icon: "protocol", mode: "real", featureIds: ["F5", "F46"] },
          { to: "/integrate/api", labelKey: "nav.item.apiExplorer", icon: "protocol", mode: "real", featureIds: ["F10", "F46"] },
        ],
      },
      {
        labelKey: "nav.group.adminConsole",
        items: [
          { to: "/admin/access", labelKey: "platform.tabs.access", icon: "platform", mode: "real", featureIds: ["F8", "F13"] },
          {
            to: "/admin/system",
            labelKey: "platform.tabs.posture",
            icon: "platform",
            mode: "real",
            featureIds: ["F10", "F11", "F12", "F14", "F15", "F20", "F40"],
          },
          { to: "/admin/editions", labelKey: "platform.tabs.editions", icon: "platform", mode: "real", featureIds: ["F41"] },
          { to: "/assistant", labelKey: "nav.item.assistant", icon: "bot", mode: "real", featureIds: ["F75", "F76", "F77", "F78"] },
        ],
      },
    ],
  },
];

/** navModules: derived module view of the spaces (routes + feature union), kept
 * so the S-B1 helpers (moduleForRoute, surfaceModule, audit lenses) and their
 * guards keep one source of truth. */
export const navModules: NavModule[] = navSpaces.map((space) => ({
  id: space.id,
  labelKey: space.labelKey,
  icon: space.icon,
  routes: space.groups.flatMap((group) => group.items.map((item) => item.to.split("?")[0] || "/")),
  featureIds: Array.from(new Set(space.groups.flatMap((group) => group.items.flatMap((item) => item.featureIds)))),
}));

/** globalBand: routes that belong to no space. After S-C1 this is only the
 * Home plane (Dashboard + Journeys) plus the API-free /platform doorway —
 * everything else lives in exactly one space. */
export const globalBandRoutes: string[] = ["/", "/journeys", "/platform"];

/** spaceForRoute: the space owning a pathname, "home" for the global Home
 * plane, or undefined for exempt routes (/login, /wizard, /styleguide). */
export function spaceForRoute(to: string): SpaceId | "home" | undefined {
  const path = to.split("?")[0] || "/";
  const owner = moduleForRoute(path);
  if (owner) return owner;
  if (path === "/" || path === "/journeys") return "home";
  return undefined;
}

/** moduleForRoute maps a route to its owning module, or undefined if the route
 * is a global plane (or exempt: /login, /wizard, /styleguide). */
export function moduleForRoute(to: string): ModuleId | undefined {
  const path = to.split("?")[0] || "/";
  return navModules.find((module) => module.routes.includes(path))?.id;
}

/** S-B4: dual-scope filters for the global planes. A module id maps to a free-
 * text term that scopes the (single, shared) audit stream and risk list to that
 * module's events/credentials — Infisical's dual-scope audit, adapted. There is
 * still ONE audit surface and one hash chain; these are lenses, not silos (the
 * DigiCert per-manager-audit anti-pattern, 03 §2). FE-only: the term is applied
 * as the existing `q` free-text filter. */
const moduleScopeTerms: Record<ModuleId, string> = {
  discovery: "discover",
  certificates: "cert",
  workload: "ssh",
  secrets: "secret",
  posture: "sign",
  platform: "incident",
};

export function moduleScopeTerm(moduleId: string): string | undefined {
  return (moduleScopeTerms as Record<string, string>)[moduleId];
}

export function moduleLabelKey(moduleId: string): MessageKey | undefined {
  return navModules.find((module) => module.id === moduleId)?.labelKey;
}

/** S-B5 (DA-26 point-of-use upsell): the commercial feature each module needs
 * to be fully usable, if any. trstctl's five modules are all MPL-core, so this
 * map is EMPTY today — no module ever renders as a whole locked upsell row.
 * Edition gating in trstctl is per-sub-feature, quarantined to Platform →
 * Editions (S-A3). The seam exists so a future fully-commercial module (e.g. a
 * Provider-only module) surfaces exactly one graceful upsell row rather than
 * scattered locked panels (the Infisical OSS-billing lesson, 03 §1). */
export const moduleRequiredFeature: Partial<Record<ModuleId, string>> = {};

/** lockedModuleIds returns the modules that should render as an upsell row: a
 * module is locked iff it declares a required commercial feature that is not in
 * the licensed-feature set. With the empty map above this is always empty. */
export function lockedModuleIds(licensedFeatures: ReadonlySet<string>): ModuleId[] {
  return navModules
    .filter((module) => {
      const required = moduleRequiredFeature[module.id];
      return Boolean(required) && !licensedFeatures.has(required as string);
    })
    .map((module) => module.id);
}

export const appRoutePaths = [
  "/login",
  "/",
  "/trust-operations",
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
  "/secrets/access",
  "/secrets/sharing",
  "/secrets/engines",
  "/secrets/scanning",
  "/secrets/sync",
  "/connectors",
  "/policy",
  "/risk",
  "/incidents",
  "/approvals",
  "/operations",
  "/notifications",
  "/posture",
  "/graph",
  "/migration",
  "/audit",
  "/privacy",
  "/integrate",
  "/integrate/api",
  "/assistant",
  "/wizard",
  "/admin/access",
  "/admin/system",
  "/admin/editions",
  // C-A1: /platform stays registered as a readiness doorway; historical
  // ?tab= links redirect to their split /admin/* destinations.
  "/platform",
  "/styleguide",
  "/journeys",
] as const;

const routePermissionAny: Record<string, string[]> = {
  "/": ["certs:read", "identities:read", "risk:read"],
  "/trust-operations": ["risk:read", "incidents:read", "owners:read", "notifications:read", "audit:read", "access:read"],
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
  "/admin/access": ["access:read"],
  "/admin/system": ["access:read"],
  "/admin/editions": ["access:read"],
  "/platform": ["access:read"],
  "/policy": ["policy:read", "access:read"],
  "/posture": ["risk:read"],
  "/privacy": ["privacy:read"],
  "/profiles": ["profiles:read"],
  "/protocols": ["issuers:read"],
  "/request": ["certs:request"],
  "/risk": ["risk:read"],
  "/secrets": ["secrets:read"],
  "/secrets/access": ["secrets:read"],
  "/secrets/sharing": ["secrets:read"],
  "/secrets/engines": ["secrets:read"],
  "/secrets/scanning": ["secrets:read"],
  "/secrets/sync": ["secrets:read"],
  "/ssh": ["certs:read"],
  "/wizard": ["agents:write"],
  "/workloads": ["certs:issue", "secrets:write"],
};

export function permissionAnyForPath(to: string): readonly string[] | undefined {
  const path = to.split("?")[0] || "/";
  return routePermissionAny[path];
}

/** primaryNavItems render above the grouped rail: the landing page and the
 * guided-journeys hub belong at the top of the sidebar, not filed 20 links
 * deep inside a band. */
export const primaryNavItems: NavItem[] = [
  { to: "/", labelKey: "nav.item.dashboard", icon: "dashboard", end: true, mode: "real", featureIds: ["F1", "F19"] },
  { to: "/journeys", labelKey: "nav.item.journeys", icon: "journey", mode: "real", featureIds: ["F1", "F2", "F31"] },
];

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
    icon: "approval",
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

/** featureIdsForPath returns the canonical capability rows a routed screen
 * promises to surface. It is intentionally derived from navigation truth so
 * shell availability explanations cannot drift into a second route map. */
export function featureIdsForPath(to: string): CanonicalCapabilityID[] {
  const path = to.split("?")[0] || "/";
  const ids = new Set<CanonicalCapabilityID>();
  const basePath = (candidate: string) => candidate.split("?")[0] || "/";
  for (const item of primaryNavItems) if (basePath(item.to) === path) item.featureIds.forEach((id) => ids.add(id));
  for (const item of taskNavItems) if (basePath(item.to) === path) item.featureIds.forEach((id) => ids.add(id));
  for (const space of navSpaces) {
    for (const group of space.groups) {
      for (const item of group.items) if (basePath(item.to) === path) item.featureIds.forEach((id) => ids.add(id));
    }
  }
  return Array.from(ids);
}

/* S-C1: the flat rail is gone — `navGroups` is now DERIVED from the space
 * registry (every space's groups, in space order). Consumers that need "every
 * grouped destination" (routeLabel, the command palette, the parity and
 * completeness guards) keep their one stable source; consumers that scope by
 * space read `navSpaces` directly. Route URLs are unchanged. */
export const navGroups: NavGroup[] = navSpaces.flatMap((space) => space.groups);

/* S-A1: every product surface now lives in the rail, so there are no
 * contextual-only routes. The export stays (as an empty list) so downstream
 * consumers — CommandPalette and i18n/route-parity tests — keep their stable
 * shape; AppShell falls back to a title-cased route segment for non-rail
 * routes, and the module switcher (S-B2) reads `navModules` instead. */
export const contextualRouteItems: ContextualRouteItem[] = [];

export interface RealGuiSurface {
  featureId: CanonicalCapabilityID;
  routes: string[];
  component: string;
  kind: "operate" | "observe";
  evidence: string;
  /** S-B1: owning module, or "global" for a cross-module plane. Optional and
   * normally derived from the surface's routes via `surfaceModule`; present on
   * the type so a surface can pin an explicit module if routes are ambiguous. */
  module?: ModuleId | "global";
}

/** surfaceModule resolves a surface to its module: an explicit `module` wins,
 * otherwise the first module-owned route decides, else "global". */
export function surfaceModule(surface: RealGuiSurface): ModuleId | "global" {
  if (surface.module) return surface.module;
  for (const route of surface.routes) {
    const owner = moduleForRoute(route);
    if (owner) return owner;
  }
  return "global";
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
  {
    featureId: "F5",
    routes: ["/protocols"],
    component: "Protocols",
    kind: "operate",
    evidence:
      "ACME directory/account/order/challenge register, tenant-binding and profile gates, DNS-01 provider/config tables, live responder status, and client setup snippets",
  },
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
    evidence:
      "native and plugin connector registry, capability grants, delivery receipts, jobs-and-queues health, notification triage, reachability, and rollback posture",
  },
  {
    featureId: "F8",
    routes: ["/admin/access", "/identities", "/certificates"],
    component: "Platform access control",
    kind: "observe",
    evidence: "required-scope map and permission-denied states",
  },
  { featureId: "F9", routes: ["/audit"], component: "Audit", kind: "observe", evidence: "audit filters, event detail, and signed export" },
  {
    featureId: "F10",
    routes: ["/integrate/api"],
    component: "ApiExplorer",
    kind: "operate",
    evidence:
      "served OpenAPI operation browser, exact request preview, least-privilege temporary key, guarded mutation confirmation, live response explanation, cancellation, and key revocation",
  },
  {
    featureId: "F11",
    routes: ["/admin/system"],
    component: "Platform",
    kind: "observe",
    evidence: "token-safe CLI companion commands matching supported command groups",
  },
  {
    featureId: "F13",
    routes: ["/admin/access", "/login"],
    component: "Platform auth status",
    kind: "operate",
    evidence: "OIDC sign-in, current session, CSRF diagnostics, OIDC mapping status, served sign-out, access membership, token, and offboarding workflows",
  },
  {
    featureId: "F14",
    routes: ["/admin/system"],
    component: "Platform",
    kind: "observe",
    evidence: "single-binary runtime, build, datastore, embedded UI, and signer-supervision disclosure blocked on platform status",
  },
  { featureId: "F15", routes: ["/admin/system"], component: "Platform", kind: "observe", evidence: "browser transport posture and platform-status gap" },
  {
    featureId: "F16",
    routes: ["/posture"],
    component: "Posture",
    kind: "observe",
    evidence: "crypto-agility and PQC readiness fixtures with CBOM backend gate",
  },
  {
    featureId: "F17",
    routes: ["/discovery", "/posture"],
    component: "Discovery",
    kind: "observe",
    // C5: CT monitoring is a discovery capability — "is someone issuing
    // certificates for my domains?" — so Discovery is its home and Posture keeps
    // the readiness view. It used to be one shared count tile on Discovery,
    // which is why nobody could find it.
    evidence: "certificate-transparency watchlist, per-log checkpoint state, unexpected-issuance findings, and remediation hand-off on the Discovery workspace",
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
    routes: ["/admin/system", "/connectors"],
    component: "Platform",
    kind: "observe",
    evidence: "plugin provenance, digest pin, capability grant, conformance, runtime-status, and denial-reason disclosure without live activation",
  },
  { featureId: "F21", routes: ["/graph"], component: "Graph", kind: "observe", evidence: "graph and blast radius" },
  {
    featureId: "F22",
    routes: ["/protocols"],
    component: "Protocols",
    kind: "operate",
    evidence:
      "EST CA-certs/simpleenroll register, tenant-binding and auth gates, profile guidance, live responder status, enrollment diagnostics, and client setup snippets",
  },
  {
    featureId: "F23",
    routes: ["/protocols"],
    component: "Protocols",
    kind: "operate",
    evidence:
      "SCEP CA-discovery/enrollment register, RA and challenge policy status, MDM policy telemetry, CMS diagnostics, live responder status, and client setup snippets",
  },
  {
    featureId: "F24",
    routes: ["/protocols"],
    component: "Protocols",
    kind: "operate",
    evidence:
      "SPIFFE Workload API trust-domain/socket requirements, selector guidance, X.509-SVID and JWT-SVID support, live responder status, and client snippets",
  },
  {
    featureId: "F25",
    routes: ["/workloads"],
    component: "Workloads",
    kind: "operate",
    evidence:
      "dynamic and ephemeral credential issuance with provider role, TTL policy, lease metadata, renew and revoke controls, expiry state, and copy-once credential handling",
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
    evidence: "policy gate explanation, tenant-scoped dry-run trace, and audit decision links",
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
    evidence: "manual native-store rotate/delete plus worker-queued connector rotation; static and dynamic provider rotation fails closed before effects",
  },
  {
    featureId: "F38",
    routes: ["/secrets/sharing"],
    component: "Secrets",
    kind: "operate",
    evidence:
      "scoped short-TTL API-key issuance, reveal-once handling, expiry evidence, and access-service availability independent of the optional native secret store",
  },
  {
    featureId: "F39",
    routes: ["/secrets/scanning"],
    component: "Secrets",
    kind: "observe",
    evidence: "secret scanning source/detector/fingerprint/owner/rotation disclosure with redacted snippets only",
  },
  {
    featureId: "F40",
    routes: ["/admin/system"],
    component: "Platform",
    kind: "operate",
    evidence: "active tenant plus tenant key-domain migration, confirmed seal, terminal-failure recovery, and unseal",
  },
  {
    featureId: "F41",
    routes: ["/admin/editions"],
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
    evidence: "SSH CA authority status, attested user-certificate issuance, KRL revocation, public authority and KRL readback, and the /protocols probe link",
  },
  {
    featureId: "F44",
    routes: ["/ssh"],
    component: "SSHTrust",
    kind: "operate",
    evidence:
      "explicit-confirmation SSH trust rollout with target hosts, validation command, reload health command, rollback plan, status recording, and host retirement controls",
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
  {
    featureId: "F51",
    routes: ["/protocols"],
    component: "Protocols",
    kind: "operate",
    evidence:
      "TSA timestamp workflow with endpoint and certificate requirements, live responder status, OpenSSL query and verification commands, tenant binding, and audit-ready client guidance",
  },
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
    evidence: "bootstrap token install command plus served renewal and endpoint-discovery evidence",
  },
  {
    featureId: "F55",
    routes: ["/protocols"],
    component: "Protocols",
    kind: "operate",
    evidence:
      "CMP enrollment register with tenant-binding requirements, RA transport and profile gates, live responder status, enrollment diagnostics, and OpenSSL client guidance",
  },
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
    evidence: "crypto posture inventory plus remediation handoff",
  },
  { featureId: "F59", routes: ["/identities", "/owners"], component: "Identities", kind: "operate", evidence: "NHI lifecycle rows and owner link" },
  {
    featureId: "F30",
    routes: ["/workloads"],
    component: "Workloads",
    kind: "operate",
    evidence:
      "attestation policy administration with TPM, AWS, GCP, Azure, Kubernetes, and GitHub methods, trust-source create/rotate/revoke/delete controls, evidence-safe SVID issuance, and rejection metadata",
  },
  { featureId: "F58", routes: ["/secrets/access"], component: "Secrets", kind: "operate", evidence: "machine login exchange through secrets login" },
  { featureId: "F60", routes: ["/secrets/sharing"], component: "Secrets", kind: "operate", evidence: "one-time share create/redeem" },
  {
    featureId: "F61",
    routes: ["/workloads"],
    component: "Workloads",
    kind: "operate",
    evidence:
      "AI-agent broker identity issuance with attestation payload, public key, allowed scopes, TTL, issued credential metadata, and audit-safe result handling",
  },
  {
    featureId: "F62",
    routes: ["/policy", "/audit"],
    component: "Policy",
    kind: "observe",
    evidence: "signed audit evidence export plus framework-mapped compliance posture disclosure",
  },
  { featureId: "F63", routes: ["/secrets"], component: "Secrets", kind: "operate", evidence: "native secret store metadata/create/reveal/rotate/delete" },
  { featureId: "F64", routes: ["/secrets/access"], component: "Secrets", kind: "observe", evidence: "developer snippets plus store access test" },
  {
    featureId: "F65",
    routes: ["/secrets/engines"],
    component: "Secrets",
    kind: "operate",
    evidence:
      "dynamic secret lease issue/renew/revoke controls with backend provider, role, TTL, lease status, backend error handling, and reveal-once generated credential panel",
  },
  {
    featureId: "F66",
    routes: ["/secrets/engines"],
    component: "Secrets",
    kind: "operate",
    evidence:
      "Transit safe key-metadata list, purpose-locked create/select/rotate, encrypt/decrypt, rewrap, HMAC, signing, local-only reveal-once plaintext, and encryption-service availability independent of the optional native secret store; verify, full version history, audit, and KMIP appliance posture remain parity debt",
  },
  { featureId: "F67", routes: ["/secrets/engines"], component: "Secrets", kind: "operate", evidence: "PKI secret issue with reveal-once bundle" },
  {
    featureId: "F68",
    routes: ["/secrets/sync"],
    component: "Secrets",
    kind: "operate",
    evidence:
      "secret sync target catalog, configured mapping form, cloud/Kubernetes/workload-injection posture, drift visibility, rollback-safe target metadata, and sealed outbox delivery receipts",
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
  {
    featureId: "F76",
    routes: ["/assistant"],
    component: "Assistant",
    kind: "operate",
    evidence:
      "AI model adapter runtime diagnostics with enabled state, model mode/name, endpoint host, egress mode, personal-data egress policy, redaction boundary, residual-secret refusal gate, and last load error",
  },
  { featureId: "F77", routes: ["/assistant"], component: "Assistant", kind: "operate", evidence: "grounded RCA with citations and runtime status" },
  { featureId: "F78", routes: ["/assistant"], component: "Assistant", kind: "operate", evidence: "read-only MCP tools and runtime status" },
  {
    featureId: "F79",
    routes: ["/privacy"],
    component: "Privacy",
    kind: "operate",
    evidence: "subject erasure, subject export, retention enforcement/history, personal-data catalog review, and served privacy evidence controls",
  },
];
