export const journeySmokeSteps = ["onboard", "discover", "issue", "rotate", "revoke", "offboard"] as const;

export type JourneySmokeStep = (typeof journeySmokeSteps)[number];

export const journeySmokePersonas = [
  { id: "platform_sre_operator", label: "Platform/SRE operator" },
  { id: "security_pki_admin", label: "Security/PKI administrator" },
  { id: "ra_officer_requester", label: "RA officer/requester" },
  { id: "workload_application_owner", label: "Workload/application owner" },
  { id: "auditor_compliance_reader", label: "Auditor/compliance reader" },
  { id: "agent_ci_principal", label: "Agent/CI principal" },
] as const;

export type JourneySmokePersona = (typeof journeySmokePersonas)[number]["id"];
export type JourneySmokeStatus = "functional" | "partial" | "not_applicable";
export type JourneySmokeAcceptance = "JOURNEY-001" | "JOURNEY-002" | "JOURNEY-003" | "JOURNEY-004";

export interface JourneySmokeRoute {
  path: string;
  heading: string;
}

export interface JourneySmokeCell {
  persona: JourneySmokePersona;
  step: JourneySmokeStep;
  status: JourneySmokeStatus;
  uiRoute: string;
  uiHeading: string;
  apiPaths: readonly string[];
  cliCommands: readonly string[];
  docs: readonly string[];
  acceptance: readonly JourneySmokeAcceptance[];
}

const routeCatalog = {
  agents: { path: "/agents", heading: "Agents" },
  approvals: { path: "/approvals", heading: "Requests waiting for approval" },
  audit: { path: "/audit", heading: "Change history" },
  caHierarchy: { path: "/ca-hierarchy", heading: "Certificate authorities" },
  certificates: { path: "/certificates", heading: "Certificates" },
  discovery: { path: "/discovery", heading: "Discover" },
  graph: { path: "/graph", heading: "What could be affected" },
  identities: { path: "/identities", heading: "Machine identities" },
  migration: { path: "/migration", heading: "Move to trstctl" },
  incidents: { path: "/incidents", heading: "Security incidents" },
  integrate: { path: "/integrate", heading: "Connect other tools" },
  operations: { path: "/operations", heading: "Jobs and queues" },
  platform: { path: "/platform", heading: "People and roles" },
  policy: { path: "/policy", heading: "Rules and approvals" },
  privacy: { path: "/privacy", heading: "Evidence privacy" },
  profiles: { path: "/profiles", heading: "Certificate rules" },
  request: { path: "/request", heading: "Request a certificate" },
  risk: { path: "/risk", heading: "What to fix first" },
  workloads: { path: "/workloads", heading: "Workloads & Machines" },
  wizard: { path: "/wizard", heading: "Set up trstctl" },
} as const satisfies Record<string, JourneySmokeRoute>;

type RouteKey = keyof typeof routeCatalog;

interface ServedCellInput {
  route: RouteKey;
  apiPaths: readonly string[];
  cliCommands: readonly string[];
  docs: readonly string[];
  acceptance?: readonly JourneySmokeAcceptance[];
  status?: Exclude<JourneySmokeStatus, "not_applicable">;
}

function served(persona: JourneySmokePersona, step: JourneySmokeStep, input: ServedCellInput): JourneySmokeCell {
  const route = routeCatalog[input.route];
  return {
    persona,
    step,
    status: input.status ?? "functional",
    uiRoute: route.path,
    uiHeading: route.heading,
    apiPaths: input.apiPaths,
    cliCommands: input.cliCommands,
    docs: input.docs,
    acceptance: input.acceptance ?? ["JOURNEY-004"],
  };
}

function notApplicable(persona: JourneySmokePersona, step: JourneySmokeStep, docs: readonly string[]): JourneySmokeCell {
  return {
    persona,
    step,
    status: "not_applicable",
    uiRoute: "/audit",
    uiHeading: "Change history",
    apiPaths: [],
    cliCommands: [],
    docs,
    acceptance: ["JOURNEY-004"],
  };
}

const docs = {
  agent: ["docs/web-console.md", "docs/journeys/run-in-production.md"],
  audit: ["docs/web-console.md", "docs/features/policy-and-governance.md"],
  ca: ["docs/web-console.md", "docs/features/issuance-and-cas.md"],
  discovery: ["docs/web-console.md", "docs/features/discovery-and-inventory.md"],
  firstCertificate: ["docs/web-console.md", "docs/journeys/first-certificate.md"],
  governance: ["docs/web-console.md", "docs/journeys/onboard-a-team.md"],
  incident: ["docs/web-console.md", "docs/journeys/respond-to-compromise.md"],
  integration: ["docs/web-console.md", "docs/journeys/build-on-the-api.md"],
  lifecycle: ["docs/web-console.md", "docs/features/lifecycle-and-pqc.md"],
  workload: ["docs/web-console.md", "docs/journeys/kubernetes-workload-identity.md"],
} as const;

export const journeySmokeMatrix: readonly JourneySmokeCell[] = [
  served("platform_sre_operator", "onboard", {
    route: "wizard",
    apiPaths: ["/api/v1/issuers", "/api/v1/agents/enrollment-tokens"],
    cliCommands: ["trstctl-cli issuers create", "trstctl-cli agents enrollment-token create"],
    docs: docs.firstCertificate,
  }),
  served("platform_sre_operator", "discover", {
    route: "discovery",
    apiPaths: ["/api/v1/discovery/sources", "/api/v1/discovery/runs", "/api/v1/discovery/findings"],
    cliCommands: ["trstctl-cli discovery sources list", "trstctl-cli discovery runs start"],
    docs: docs.discovery,
    acceptance: ["JOURNEY-002", "JOURNEY-004"],
  }),
  served("platform_sre_operator", "issue", {
    route: "identities",
    apiPaths: ["/api/v1/identities", "/api/v1/identities/{id}/transitions"],
    cliCommands: ["trstctl-cli identities create", "trstctl-cli identities transition issued"],
    docs: docs.firstCertificate,
  }),
  served("platform_sre_operator", "rotate", {
    route: "operations",
    apiPaths: ["/api/v1/lifecycle/rotation-runs", "/api/v1/connectors/deliveries"],
    cliCommands: ["trstctl-cli lifecycle rotation-runs list", "trstctl-cli identities transition renewing"],
    docs: docs.lifecycle,
  }),
  served("platform_sre_operator", "revoke", {
    route: "incidents",
    apiPaths: ["/api/v1/identities/{id}/transitions", "/api/v1/incidents/executions"],
    cliCommands: ["trstctl-cli identities transition revoked", "trstctl-cli incidents execute"],
    docs: docs.incident,
  }),
  served("platform_sre_operator", "offboard", {
    route: "agents",
    apiPaths: ["/api/v1/agents/{id}/offboard", "/api/v1/access/members/{subject}/offboard"],
    cliCommands: ["trstctl-cli agents offboard", "trstctl-cli access members offboard"],
    docs: docs.agent,
    acceptance: ["JOURNEY-003", "JOURNEY-004"],
  }),

  served("security_pki_admin", "onboard", {
    route: "caHierarchy",
    apiPaths: ["/api/v1/ca/ceremonies", "/api/v1/profiles"],
    cliCommands: ["trstctl-cli ca ceremony start", "trstctl-cli profiles create"],
    docs: docs.ca,
  }),
  served("security_pki_admin", "discover", {
    route: "risk",
    apiPaths: ["/api/v1/risk/credentials", "/api/v1/graph"],
    cliCommands: ["trstctl-cli risk credentials list", "trstctl-cli graph query"],
    docs: docs.discovery,
  }),
  served("security_pki_admin", "issue", {
    route: "certificates",
    apiPaths: ["/api/v1/certificates", "/api/v1/identities/{id}/transitions"],
    cliCommands: ["trstctl-cli certificates issue", "trstctl-cli identities transition issued"],
    docs: docs.firstCertificate,
  }),
  served("security_pki_admin", "rotate", {
    route: "caHierarchy",
    apiPaths: ["/api/v1/ca/authorities/{id}/rotate", "/api/v1/managed-keys/rotate"],
    cliCommands: ["trstctl-cli ca authorities rotate", "trstctl-cli managed-keys rotate"],
    docs: docs.lifecycle,
  }),
  served("security_pki_admin", "revoke", {
    route: "identities",
    apiPaths: ["/api/v1/identities/{id}/transitions", "/api/v1/ssh/certificates/revoke"],
    cliCommands: ["trstctl-cli identities transition revoked", "trstctl-cli ssh certificates revoke"],
    docs: docs.incident,
  }),
  served("security_pki_admin", "offboard", {
    route: "platform",
    apiPaths: ["/api/v1/access/members/{subject}/offboard", "/api/v1/access/api-tokens/{id}"],
    cliCommands: ["trstctl-cli access members offboard", "trstctl-cli access api-tokens revoke"],
    docs: docs.governance,
  }),

  served("ra_officer_requester", "onboard", {
    route: "request",
    apiPaths: ["/api/v1/profiles", "/api/v1/identities"],
    cliCommands: ["trstctl-cli profiles list", "trstctl-cli identities create --request"],
    docs: docs.governance,
  }),
  served("ra_officer_requester", "discover", {
    route: "approvals",
    apiPaths: ["/api/v1/identities", "/api/v1/audit/events"],
    cliCommands: ["trstctl-cli identities list --mine", "trstctl-cli audit events list"],
    docs: docs.governance,
  }),
  served("ra_officer_requester", "issue", {
    route: "approvals",
    apiPaths: ["/api/v1/identities/{id}/approvals", "/api/v1/identities/{id}/transitions"],
    cliCommands: ["trstctl-cli identities approve issue", "trstctl-cli identities transition issued"],
    docs: docs.governance,
  }),
  served("ra_officer_requester", "rotate", {
    route: "approvals",
    apiPaths: ["/api/v1/identities/{id}/approvals", "/api/v1/lifecycle/rotation-runs"],
    cliCommands: ["trstctl-cli identities approve rotate", "trstctl-cli lifecycle rotation-runs list"],
    docs: docs.governance,
  }),
  served("ra_officer_requester", "revoke", {
    route: "approvals",
    apiPaths: ["/api/v1/identities/{id}/approvals", "/api/v1/identities/{id}/transitions"],
    cliCommands: ["trstctl-cli identities approve revoke", "trstctl-cli identities transition revoked"],
    docs: docs.governance,
  }),
  served("ra_officer_requester", "offboard", {
    route: "platform",
    apiPaths: ["/api/v1/access/members/{subject}/offboard", "/api/v1/audit/events"],
    cliCommands: ["trstctl-cli access members offboard", "trstctl-cli audit events list"],
    docs: docs.governance,
  }),

  served("workload_application_owner", "onboard", {
    route: "workloads",
    apiPaths: ["/api/v1/workloads/attester-trust-sources", "/api/v1/workloads/attested-issuance"],
    cliCommands: ["trstctl-cli workloads trust-sources create", "trstctl-cli workloads svid issue"],
    docs: docs.workload,
    acceptance: ["JOURNEY-001", "JOURNEY-004"],
  }),
  served("workload_application_owner", "discover", {
    route: "graph",
    apiPaths: ["/api/v1/graph", "/api/v1/discovery/findings"],
    cliCommands: ["trstctl-cli graph query", "trstctl-cli discovery findings list"],
    docs: docs.workload,
    acceptance: ["JOURNEY-001", "JOURNEY-004"],
  }),
  served("workload_application_owner", "issue", {
    route: "workloads",
    apiPaths: ["/api/v1/workloads/attested-issuance", "/api/v1/secrets/dynamic-leases"],
    cliCommands: ["trstctl-cli workloads svid issue", "trstctl-cli secrets leases issue"],
    docs: docs.workload,
    acceptance: ["JOURNEY-001", "JOURNEY-004"],
  }),
  served("workload_application_owner", "rotate", {
    route: "workloads",
    apiPaths: ["/api/v1/workloads/attester-trust-sources/{id}/rotate", "/api/v1/secrets/dynamic-leases/{id}/renew"],
    cliCommands: ["trstctl-cli workloads trust-sources rotate", "trstctl-cli secrets leases renew"],
    docs: docs.workload,
    acceptance: ["JOURNEY-001", "JOURNEY-004"],
  }),
  served("workload_application_owner", "revoke", {
    route: "workloads",
    apiPaths: ["/api/v1/workloads/attester-trust-sources/{id}/revoke", "/api/v1/secrets/dynamic-leases/{id}/revoke"],
    cliCommands: ["trstctl-cli workloads trust-sources revoke", "trstctl-cli secrets leases revoke"],
    docs: docs.workload,
    acceptance: ["JOURNEY-001", "JOURNEY-004"],
  }),
  served("workload_application_owner", "offboard", {
    route: "workloads",
    apiPaths: ["/api/v1/workloads/attester-trust-sources/{id}", "/api/v1/nhi/decommission"],
    cliCommands: ["trstctl-cli workloads trust-sources delete", "trstctl-cli nhi decommission"],
    docs: docs.workload,
    acceptance: ["JOURNEY-001", "JOURNEY-004"],
  }),

  served("auditor_compliance_reader", "onboard", {
    route: "audit",
    apiPaths: ["/api/v1/audit/events", "/api/v1/compliance/inventory-report"],
    cliCommands: ["trstctl-cli audit events list", "trstctl-cli compliance inventory-report"],
    docs: docs.audit,
  }),
  served("auditor_compliance_reader", "discover", {
    route: "privacy",
    apiPaths: ["/api/v1/privacy/catalog", "/api/v1/risk/credentials"],
    cliCommands: ["trstctl-cli privacy catalog", "trstctl-cli risk credentials list"],
    docs: docs.audit,
  }),
  notApplicable("auditor_compliance_reader", "issue", docs.audit),
  notApplicable("auditor_compliance_reader", "rotate", docs.audit),
  notApplicable("auditor_compliance_reader", "revoke", docs.audit),
  served("auditor_compliance_reader", "offboard", {
    route: "audit",
    apiPaths: ["/api/v1/audit/export", "/api/v1/privacy/retention-runs"],
    cliCommands: ["trstctl-cli audit export", "trstctl-cli privacy retention run"],
    docs: docs.audit,
  }),

  served("agent_ci_principal", "onboard", {
    route: "integrate",
    apiPaths: ["/api/v1/access/api-tokens", "/api/v1/agents/enrollment-tokens"],
    cliCommands: ["trstctl-cli access api-tokens create", "trstctl-cli agents enrollment-token create"],
    docs: docs.integration,
  }),
  served("agent_ci_principal", "discover", {
    route: "discovery",
    apiPaths: ["/api/v1/discovery/runs", "/api/v1/nhi/inventory"],
    cliCommands: ["trstctl-cli discovery runs list", "trstctl-cli nhi inventory"],
    docs: docs.discovery,
    acceptance: ["JOURNEY-002", "JOURNEY-004"],
  }),
  served("agent_ci_principal", "issue", {
    route: "workloads",
    apiPaths: ["/api/v1/broker/agent-identities/preview", "/api/v1/broker/agent-identities", "/api/v1/broker/agent-identities/{id}"],
    cliCommands: [
      "trstctl-cli broker agent-identities preview",
      "trstctl-cli broker agent-identities issue",
      "trstctl-cli broker agent-identities list",
      "trstctl-cli broker agent-identities get",
    ],
    docs: ["docs/features/workload-identity.md", ...docs.integration],
    status: "partial",
  }),
  served("agent_ci_principal", "rotate", {
    route: "operations",
    apiPaths: ["/api/v1/lifecycle/rotation-runs", "/api/v1/secrets/dynamic-leases/{id}/renew"],
    cliCommands: ["trstctl-cli lifecycle rotation-runs list", "trstctl-cli secrets leases renew"],
    docs: docs.lifecycle,
  }),
  served("agent_ci_principal", "revoke", {
    route: "identities",
    apiPaths: ["/api/v1/identities/{id}/transitions", "/api/v1/secrets/dynamic-leases/{id}/revoke"],
    cliCommands: ["trstctl-cli identities transition revoked", "trstctl-cli secrets leases revoke"],
    docs: docs.lifecycle,
  }),
  served("agent_ci_principal", "offboard", {
    route: "agents",
    apiPaths: ["/api/v1/agents/{id}/offboard", "/api/v1/access/api-tokens/{id}"],
    cliCommands: ["trstctl-cli agents offboard", "trstctl-cli access api-tokens revoke"],
    docs: docs.agent,
    acceptance: ["JOURNEY-003", "JOURNEY-004"],
  }),
];

export const journeySmokeUiRoutes: readonly JourneySmokeRoute[] = Array.from(
  new Map(
    journeySmokeMatrix
      .filter((cell) => cell.status !== "not_applicable")
      .map((cell) => [cell.uiRoute, { path: cell.uiRoute, heading: cell.uiHeading } as JourneySmokeRoute]),
  ).values(),
);
