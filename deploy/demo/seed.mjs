import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";

const tenant = process.env.TRSTCTL_TENANT || "11111111-1111-4111-8111-111111111111";
const serverURL = new URL(process.env.TRSTCTL_SERVER || "https://trstctl:8443");
if (!["https:", "http:"].includes(serverURL.protocol) || serverURL.username || serverURL.password || serverURL.pathname !== "/" || serverURL.search || serverURL.hash) {
  throw new Error("TRSTCTL_SERVER must be an absolute HTTP(S) origin without credentials, path, query, or fragment");
}
const server = serverURL.origin;
const demoURL = process.env.TRSTCTL_DEMO_URL || "https://127.0.0.1:9443";
const bootstrapTokenFile = process.env.TRSTCTL_DEMO_BOOTSTRAP_TOKEN_FILE || "/seed-state/bootstrap.token";
const seedVersion = "demo-seed-v3";
const migratableSeedVersions = new Set(["demo-seed-v1", "demo-seed-v2"]);
const seedCheckpointSubject = "trstctl-demo-seed-checkpoint";
const seedDiagnosticFile = "/seed-state/last-error.txt";
const demoDiscoverySegment = {
  name: "demo-control-plane",
  // Segment declarations describe the approved host/address denominator; ports
  // belong to the source target. Keeping those concepts separate lets the
  // server prove that trstctl:8443 is inside this exact hostname boundary.
  ranges: ["trstctl"],
  staleness_hours: 24,
};
const checkMode = process.argv.includes("--check");
const DAY_MS = 24 * 60 * 60 * 1000;
const demoNow = new Date(process.env.TRSTCTL_DEMO_NOW || new Date().toISOString());

if (Number.isNaN(demoNow.getTime())) {
  throw new Error("TRSTCTL_DEMO_NOW must be an RFC3339 timestamp when set");
}

let bearer = "";

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function b64(text) {
  return Buffer.from(text).toString("base64");
}

function stableKey(name) {
  return `${seedVersion}:${name}`;
}

function daysAgo(days) {
  return new Date(demoNow.getTime() - days * DAY_MS).toISOString();
}

function stableDemoValue(label) {
  const digest = createHash("sha256")
    .update(`${seedVersion}\0${tenant}\0${label}`)
    .digest("hex");
  return `demo-${label}-${digest}`;
}

function buildDemoHistory() {
  const members = [
    { key: "demo-admin", subject: "demo-admin", body: { display_name: "Demo Admin", email: "demo-admin@trstctl.local", roles: ["admin"], source: "demo-seed" }, daysAgo: 180 },
    { key: "se-operator", subject: "se-demo-operator", body: { display_name: "Solutions Engineer", email: "se-demo-operator@trstctl.local", roles: ["operator", "auditor"], source: "demo-seed" }, daysAgo: 174 },
    { key: "payments-bot", subject: "payments-bot", body: { display_name: "Payments Deploy Bot", email: "payments-bot@trstctl.local", roles: ["ra-officer"], source: "demo-seed" }, daysAgo: 151 },
    { key: "secops-analyst", subject: "secops-analyst", body: { display_name: "SecOps Analyst", email: "secops-analyst@trstctl.local", roles: ["auditor"], source: "demo-seed" }, daysAgo: 83 },
  ];
  const owners = [
    { key: "platform", body: { kind: "team", name: "Platform SRE", email: "platform-sre@acme.example", application_id: "app-platform", service: "shared-platform", business_unit: "Engineering", environment: "production", escalation_chain: ["demo-admin", "secops-analyst"] }, daysAgo: 180 },
    { key: "payments", body: { kind: "workload", name: "Payments API", email: "payments-api@acme.example", application_id: "app-payments", service: "payments-api", business_unit: "Payments", environment: "production", escalation_chain: ["payments-bot", "demo-admin"] }, daysAgo: 168 },
    { key: "edge", body: { kind: "workload", name: "Edge Gateway", email: "edge-gateway@acme.example", application_id: "app-edge", service: "edge-gateway", business_unit: "Engineering", environment: "production", escalation_chain: ["se-demo-operator", "demo-admin"] }, daysAgo: 162 },
    { key: "release", body: { kind: "service", name: "CI Release Bot", email: "release-bot@acme.example", application_id: "app-release", service: "release-automation", business_unit: "Engineering", environment: "production", escalation_chain: ["se-demo-operator", "secops-analyst"] }, daysAgo: 143 },
    { key: "mobile", body: { kind: "workload", name: "Mobile MDM", email: "mobile-mdm@acme.example", application_id: "app-mobile", service: "mobile-device-management", business_unit: "IT", environment: "production", escalation_chain: ["demo-admin", "secops-analyst"] }, daysAgo: 121 },
    { key: "data", body: { kind: "workload", name: "Data Warehouse", email: "data-platform@acme.example", application_id: "app-warehouse", service: "data-warehouse", business_unit: "Data", environment: "production", escalation_chain: ["se-demo-operator", "demo-admin"] }, daysAgo: 96 },
    { key: "iot", body: { kind: "workload", name: "Factory IoT Gateways", email: "factory-iot@acme.example", application_id: "app-factory-iot", service: "iot-gateway", business_unit: "Manufacturing", environment: "production", escalation_chain: ["demo-admin", "secops-analyst"] }, daysAgo: 61 },
    { key: "security", body: { kind: "team", name: "Security Engineering", email: "security@acme.example", application_id: "app-security", service: "security-operations", business_unit: "Security", environment: "production", escalation_chain: ["secops-analyst", "demo-admin"] }, daysAgo: 38 },
  ];
  const profiles = [
    { key: "service-mtls-30d", name: "service-mtls-30d", spec: { max_validity: "720h", eku: ["serverAuth", "clientAuth"], san_policy: "internal-dns" }, daysAgo: 179 },
    { key: "humanless-api-key-1h", name: "humanless-api-key-1h", spec: { max_validity: "1h", rotation: "forced", audience: "automation" }, daysAgo: 172 },
    { key: "pqc-hybrid-lab", name: "pqc-hybrid-lab", spec: { algorithm: "Hybrid-ML-DSA-44-ECDSA-P256", status: "lab-only" }, daysAgo: 130 },
    { key: "acme-trust-authenticated-90d", name: "acme-trust-authenticated-90d", spec: { max_validity: "2160h", acme: { external_account_binding: true, trust_authenticated: true } }, daysAgo: 104 },
    { key: "est-serverkeygen-iot-24h", name: "est-serverkeygen-iot-24h", spec: { max_validity: "24h", est: { serverkeygen: true, tls_unique_binding: "tls-server-end-point" } }, daysAgo: 79 },
    { key: "scep-intune-mobile-7d", name: "scep-intune-mobile-7d", spec: { max_validity: "168h", scep: { challenge: "intune-jws", replay_cache: "required" } }, daysAgo: 52 },
    { key: "ssh-host-12h", name: "ssh-host-12h", spec: { max_validity: "12h", ssh: { principals: "hostnames", renewal: "agent" } }, daysAgo: 23 },
  ];
  // These are truthful, non-secret setup records for the presenter path. They
  // deliberately do not fabricate an agent, a contacted target, or a successful
  // delivery. A live pitch must replace the demo hostnames and credential
  // references with an operator-owned lab and retain independent readback.
  const connectorTargets = [
    {
      key: "apache-payments",
      name: "Apache payments web tier (prepared, not contacted)",
      connector: "apache",
      enabled: false,
      config: {
        proof_state: "prepared_not_contacted",
        required_agent_role: "host",
        target_host: "apache-payments.demo.trstctl.local",
        certificate_path: "/etc/apache2/tls/payments.crt",
        private_key_path: "/etc/apache2/tls/payments.key",
        reload_profile: "apachectl-graceful",
        credential_ref: "secret://connectors/demo/apache-payments",
        verification_address: "https://apache-payments.demo.trstctl.local:8443",
      },
      daysAgo: 44,
    },
    {
      key: "iis-portal",
      name: "IIS customer portal (prepared, not contacted)",
      connector: "iis",
      enabled: false,
      config: {
        proof_state: "prepared_not_contacted",
        required_agent_role: "host",
        target_host: "iis-portal.demo.trstctl.local",
        binding: "*:443:iis-portal.demo.trstctl.local",
        certificate_store: "WebHosting",
        application_id: "demo-iis-portal",
        credential_ref: "secret://connectors/demo/iis-portal",
        verification_address: "https://iis-portal.demo.trstctl.local",
      },
      daysAgo: 37,
    },
    {
      key: "f5-edge",
      name: "F5 edge HA pair (prepared, API-double proof only)",
      connector: "f5",
      enabled: false,
      config: {
        proof_state: "prepared_not_contacted",
        required_agent_role: "network",
        management_endpoint: "https://f5-edge-a.demo.trstctl.local",
        ha_peer_endpoint: "https://f5-edge-b.demo.trstctl.local",
        client_ssl_profile: "/Common/demo-edge-clientssl",
        virtual_server: "/Common/demo-edge-https",
        credential_ref: "secret://connectors/demo/f5-edge",
        verification_address: "https://edge.demo.trstctl.local",
      },
      daysAgo: 31,
    },
  ];
  const managedIdentities = [
    { key: "payments-api", ownerKey: "payments", name: "payments-api.demo.trstctl.local", targetState: "deployed", profile: "service-mtls-30d", protocol: "acme", deployment: "k8s/payments/deployment/payments-api", connector: "envoy", daysAgo: 168 },
    { key: "edge-gateway", ownerKey: "edge", name: "edge-gateway.demo.trstctl.local", targetState: "deployed", profile: "service-mtls-30d", protocol: "acme", deployment: "edge/traefik/gateway", connector: "traefik", daysAgo: 151 },
    { key: "release-bot", ownerKey: "release", name: "release-bot.demo.trstctl.local", targetState: "deployed", profile: "humanless-api-key-1h", protocol: "api", deployment: "github-actions/release", connector: "api-token", daysAgo: 132 },
    { key: "legacy-vpn", ownerKey: "platform", name: "legacy-vpn.demo.trstctl.local", targetState: "revoked", profile: "service-mtls-30d", protocol: "manual", deployment: "vpn-appliance-02:/etc/ssl/vpn.crt", connector: "manual", daysAgo: 118, revocationReason: "cessationOfOperation" },
    { key: "mobile-mdm", ownerKey: "mobile", name: "mdm-scep.demo.trstctl.local", targetState: "deployed", profile: "scep-intune-mobile-7d", protocol: "scep", deployment: "intune/profile/mobile-mdm", connector: "intune", daysAgo: 84 },
    { key: "iot-est-gateway", ownerKey: "iot", name: "iot-est-gateway.demo.trstctl.local", targetState: "deployed", profile: "est-serverkeygen-iot-24h", protocol: "est", deployment: "factory-floor/gateway-17", connector: "caddy", daysAgo: 63 },
    { key: "warehouse-mtls", ownerKey: "data", name: "warehouse-mtls.demo.trstctl.local", targetState: "deployed", profile: "service-mtls-30d", protocol: "acme", deployment: "warehouse/envoy/mtls", connector: "envoy", daysAgo: 41 },
    { key: "shadow-cleanup", ownerKey: "security", name: "shadow-cleanup.demo.trstctl.local", targetState: "revoked", profile: "acme-trust-authenticated-90d", protocol: "acme", deployment: "secops/remediation/shadow-cleanup", connector: "shell-ca", daysAgo: 16, revocationReason: "privilegeWithdrawn" },
    { key: "apache-pitch", ownerKey: "payments", name: "apache-payments.demo.trstctl.local", targetState: "issued", profile: "service-mtls-30d", protocol: "acme", deployment: "apache-payments:/etc/apache2/tls", preparedConnector: "apache", daysAgo: 42 },
    { key: "iis-pitch", ownerKey: "platform", name: "iis-portal.demo.trstctl.local", targetState: "issued", profile: "service-mtls-30d", protocol: "acme", deployment: "iis-portal:WebHosting/*:443", preparedConnector: "iis", daysAgo: 35 },
    { key: "f5-pitch", ownerKey: "edge", name: "edge.demo.trstctl.local", targetState: "issued", profile: "service-mtls-30d", protocol: "acme", deployment: "f5-edge:/Common/demo-edge-clientssl", preparedConnector: "f5", daysAgo: 29 },
  ];
  const importedCertificates = [
    { key: "legacy-db", ownerKey: "platform", commonName: "legacy-db.demo.trstctl.local", validDays: 7, deploymentLocation: "legacy-db-01:/etc/tls/server.crt", source: "import:cmdb", observedDaysAgo: 173 },
    { key: "warehouse-scanner", ownerKey: "edge", commonName: "warehouse-scanner.demo.trstctl.local", validDays: 365, deploymentLocation: "warehouse-scanner-17:/opt/device/client.crt", source: "import:field-device", observedDaysAgo: 166 },
    { key: "retail-pos", ownerKey: "payments", commonName: "retail-pos.demo.trstctl.local", validDays: 21, deploymentLocation: "store-102/pos-03:/tls/client.crt", source: "discovery:agent", observedDaysAgo: 142 },
    { key: "vendor-idp-saml", ownerKey: "security", commonName: "vendor-idp-saml.demo.trstctl.local", validDays: 12, deploymentLocation: "saml/vendor-idp/signing.crt", source: "discovery:ct_log", observedDaysAgo: 117 },
    { key: "otel-collector", ownerKey: "platform", commonName: "otel-collector.demo.trstctl.local", validDays: 60, deploymentLocation: "observability/otel-collector:/certs/client.crt", source: "discovery:network", observedDaysAgo: 94 },
    { key: "partner-mtls", ownerKey: "payments", commonName: "partner-mtls.demo.trstctl.local", validDays: 120, deploymentLocation: "partners/acquirer-a/mtls.crt", source: "discovery:cloud:aws-acm", observedDaysAgo: 78 },
    { key: "minio-s3", ownerKey: "data", commonName: "minio-s3.demo.trstctl.local", validDays: 14, deploymentLocation: "data/minio/tls/public.crt", source: "discovery:cloud:gcp-secret-manager", observedDaysAgo: 57 },
    { key: "buildkite-agent", ownerKey: "release", commonName: "buildkite-agent.demo.trstctl.local", validDays: 3, deploymentLocation: "ci/buildkite/agent-12:/var/lib/buildkite/tls.crt", source: "discovery:drift", observedDaysAgo: 29 },
    { key: "postfix-edge", ownerKey: "edge", commonName: "postfix-edge.demo.trstctl.local", validDays: 45, deploymentLocation: "mail/postfix-edge:/etc/postfix/tls.crt", source: "discovery:manual", observedDaysAgo: 11 },
  ];
  const discoverySources = [
    // Network scans are relay-owned. The pre-populated stack deliberately leaves
    // this source configured-but-blocked until the evaluator enrolls a network-
    // role agent; queuing a fake "dry run" without an eligible relay would turn a
    // missing deployment prerequisite into misleading green history.
    { key: "control-plane", name: "demo-control-plane-tls", kind: "network", config: { targets: ["trstctl:8443"], segment: "demo-control-plane" }, run: false, daysAgo: 159 },
    { key: "manual-shadow", name: "manual-shadow-inventory", kind: "manual", config: { findings: manualDiscoveryFindings() }, dryRun: false, daysAgo: 147 },
    { key: "ct-watch", name: "public-ct-watch", kind: "ct_log", config: { logs: ["https://ct.googleapis.com/logs/argon2026/"], watched_domains: ["demo.trstctl.local"], max_batch: 25 }, dryRun: true, daysAgo: 99 },
    { key: "cloud-certs", name: "aws-acm-and-gcp-certs", kind: "cloud_certificate", config: { providers: [{ provider: "aws-acm", region: "us-east-1", access_key_id_ref: "env:TRSTCTL_DISCOVERY_AWS_ACCESS_KEY_ID", secret_access_key_ref: "env:TRSTCTL_DISCOVERY_AWS_SECRET_ACCESS_KEY" }, { provider: "gcp-certmanager", project: "acme-demo", location: "us-central1", token_ref: "env:TRSTCTL_DISCOVERY_GCP_TOKEN" }] }, run: false, daysAgo: 73 },
    { key: "cloud-secrets", name: "aws-and-gcp-secret-manager-certs", kind: "cloud_secret", config: { providers: [{ provider: "aws-secrets-manager", region: "us-east-1", access_key_id_ref: "env:TRSTCTL_DISCOVERY_AWS_SM_ACCESS_KEY_ID", secret_access_key_ref: "env:TRSTCTL_DISCOVERY_AWS_SM_SECRET_ACCESS_KEY", tag_key: "type", tag_value: "certificate" }, { provider: "gcp-secret-manager", project: "acme-demo", token_ref: "env:TRSTCTL_DISCOVERY_GCP_SM_TOKEN", label_key: "type", label_value: "certificate" }] }, run: false, daysAgo: 49 },
    { key: "drift", name: "edge-drift-watch", kind: "drift", config: { watched: [{ path: "/etc/trstctl/demo/edge-gateway.crt", class: "certificate", fingerprint: "demo-declared-fingerprint", mode: "0644" }], policy: { certificate: "alert_only" } }, dryRun: true, daysAgo: 27 },
  ];
  const agentTokens = [
    { key: "edge-fleet", daysAgo: 150 },
    { key: "warehouse-fleet", daysAgo: 88 },
    { key: "incident-repair", daysAgo: 12 },
  ];
  const notifications = [
    { key: "expiry-legacy-db", severity: "critical", daysAgo: 7 },
    { key: "ct-shadow", severity: "high", daysAgo: 38 },
    { key: "drift-buildkite", severity: "medium", daysAgo: 20 },
    { key: "rotation-payments", severity: "low", daysAgo: 4 },
  ];
  const events = [];
  const add = (surface, name, days, detail = {}) => events.push({ surface, name, at: daysAgo(days), daysAgo: days, ...detail });
  add("issuers", "issuer cataloged: trstctl Demo Internal CA", 180);
  for (const member of members) add("audit", `member upserted: ${member.subject}`, member.daysAgo);
  for (const owner of owners) add("audit", `owner created: ${owner.key}`, owner.daysAgo);
  for (const profile of profiles) add("audit", `profile published: ${profile.name}`, profile.daysAgo);
  for (const target of connectorTargets) add("connector targets", `connector target prepared without contact: ${target.name}`, target.daysAgo, { connector: target.connector, proof_state: target.config.proof_state });
  for (const identity of managedIdentities) {
    add("managed certificates", `identity requested: ${identity.name}`, identity.daysAgo, { protocol: identity.protocol });
    add("managed certificates", `certificate issued: ${identity.name}`, Math.max(identity.daysAgo - 1, 0), { profile: identity.profile });
    if (identity.targetState === "deployed") add("deploys", `certificate deployed: ${identity.name}`, Math.max(identity.daysAgo - 2, 0), { connector: identity.connector });
    if (identity.targetState === "revoked") add("audit", `certificate revoked: ${identity.name}`, Math.max(identity.daysAgo - 3, 0), { reason: identity.revocationReason });
  }
  for (const cert of importedCertificates) add("discovered certificates", `certificate observed: ${cert.commonName}`, cert.observedDaysAgo, { source: cert.source });
  for (const source of discoverySources) {
    add("jobs and runs", `discovery source upserted: ${source.name}`, source.daysAgo, { kind: source.kind });
    if (source.run !== false) add("jobs and runs", `discovery run queued: ${source.name}`, Math.max(source.daysAgo - 1, 0), { dry_run: source.dryRun === true });
  }
  for (const token of agentTokens) add("agents", `agent enrollment token minted: ${token.key}`, token.daysAgo);
  for (const notification of notifications) add("notifications", `notification planned: ${notification.key}`, notification.daysAgo, { severity: notification.severity });
  return { members, owners, profiles, connectorTargets, managedIdentities, importedCertificates, discoverySources, agentTokens, notifications, events };
}

function manualDiscoveryFindings() {
  return [
    { kind: "x509_certificate", ref: "shadow-ingress.demo.trstctl.local:443", provenance: "manual:shadow-inventory", fingerprint: "demo-shadow-ingress-fingerprint", risk_score: 82, metadata: { observed_at: daysAgo(147), owner_hint: "security", action: "investigate" } },
    { kind: "x509_certificate", ref: "old-vpn.demo.trstctl.local:443", provenance: "manual:appliance-export", fingerprint: "demo-old-vpn-fingerprint", risk_score: 91, metadata: { observed_at: daysAgo(118), owner_hint: "platform", action: "retire" } },
    { kind: "api-key", ref: "ci/buildkite/release-token", provenance: "manual:ci-audit", fingerprint: "demo-buildkite-token-fingerprint", risk_score: 74, metadata: { observed_at: daysAgo(29), owner_hint: "release", action: "rotate" } },
  ];
}

function plannedAPICalls(history) {
  return [
    ...history.members.map((m) => `PUT /api/v1/access/members/${m.subject}`),
    ...history.owners.map(() => "POST /api/v1/owners"),
    ...history.profiles.map(() => "POST /api/v1/profiles"),
    ...history.connectorTargets.map(() => "POST /api/v1/connectors/targets"),
    "POST /api/v1/issuers",
    ...history.managedIdentities.flatMap(() => ["POST /api/v1/identities", "POST /api/v1/identities/{id}/transitions"]),
    ...history.importedCertificates.map(() => "POST /api/v1/certificates"),
    "POST /api/v1/secrets/store",
    "PUT /api/v1/secrets/store/{name}",
    "POST /api/v1/secrets/store",
    "POST /api/v1/secrets/store",
    "POST /api/v1/secrets/store",
    "POST /api/v1/secrets/shares",
    "POST /api/v1/secrets/pki",
    "POST /api/v1/transit/keys",
    "POST /api/v1/transit/encrypt",
    "POST /api/v1/transit/keys/rotate",
    "POST /api/v1/transit/rewrap",
    "POST /api/v1/transit/sign",
    "POST /api/v1/transit/verify",
    "POST /api/v1/managed-keys",
    "POST /api/v1/managed-keys/approvals",
    "POST /api/v1/managed-keys/approvals",
    "POST /api/v1/managed-keys/rotate",
    "POST /api/v1/access/api-tokens",
    "POST /api/v1/ephemeral/api-keys",
    ...history.agentTokens.map(() => "POST /api/v1/agents/enrollment-tokens"),
    "POST /api/v1/discovery/segments",
    ...history.discoverySources.map(() => "POST /api/v1/discovery/sources"),
    ...history.discoverySources.filter((s) => s.run !== false).map(() => "POST /api/v1/discovery/runs"),
    "GET /api/v1/discovery/runs",
    "GET /api/v1/discovery/findings",
    "GET /api/v1/notifications",
  ];
}

function assertNoCommittedSecretMaterial() {
  const body = readFileSync(new URL(import.meta.url), "utf8");
  const privateKey = "PRIVATE " + "KEY";
  const patterns = [
    new RegExp("BEGIN [A-Z ]*" + privateKey),
    /AKIA[0-9A-Z]{16}/,
    /xox[baprs]-[0-9A-Za-z-]{20,}/,
    /ghp_[0-9A-Za-z]{30,}/,
    /glpat-[0-9A-Za-z_-]{20,}/,
    new RegExp("-----BEGIN OPENSSH " + privateKey + "-----"),
  ];
  for (const pattern of patterns) {
    if (pattern.test(body)) {
      throw new Error(`seed source contains material matching ${pattern}`);
    }
  }
}

function redactSeedDiagnostic(error) {
  let text = error instanceof Error ? error.message : "non-Error seed failure";
  text = text
    .replace(/-----BEGIN [^-]+-----[\s\S]*?-----END [^-]+-----/g, "[redacted PEM material]")
    .replace(/\bBearer\s+[A-Za-z0-9._~+/=-]+/gi, "Bearer [redacted]")
    .replace(/("(?:authorization|password|passphrase|private_key|privatekey|secret|token|value)"\s*:\s*")[^"]*(")/gi, "$1[redacted]$2")
    .replace(/\b((?:password|passphrase|secret|token|authorization)=)[^\s&]+/gi, "$1[redacted]");
  return text.slice(0, 4096);
}

function writeSeedDiagnostic(error) {
  const body = `${new Date().toISOString()}\n${redactSeedDiagnostic(error)}\n`;
  writeFileSync(seedDiagnosticFile, body, { encoding: "utf8", mode: 0o600 });
}

function checkSeedPlan() {
  const history = buildDemoHistory();
  const calls = plannedAPICalls(history);
  const requiredSurfaces = [
    "issuers",
    "agents",
    "managed certificates",
    "discovered certificates",
    "jobs and runs",
    "deploys",
    "connector targets",
    "audit",
    "notifications",
  ];
  const surfaces = new Set(history.events.map((event) => event.surface));
  const missing = requiredSurfaces.filter((surface) => !surfaces.has(surface));
  if (missing.length > 0) {
    throw new Error(`demo history misses surfaces: ${missing.join(", ")}`);
  }
  const maxAge = Math.max(...history.events.map((event) => event.daysAgo));
  if (maxAge < 179) {
    throw new Error(`demo history reaches only ${maxAge} days; want about 180`);
  }
  if (history.events.length < 50) {
    throw new Error(`demo history has ${history.events.length} events; want at least 50`);
  }
  for (const route of ["POST /api/v1/issuers", "POST /api/v1/connectors/targets", "POST /api/v1/certificates", "POST /api/v1/discovery/runs", "GET /api/v1/notifications"]) {
    if (!calls.includes(route)) {
      throw new Error(`demo seed plan does not cover ${route}`);
    }
  }
  assertNoCommittedSecretMaterial();
  console.log("trstctl demo seed check passed");
  console.log(`  180-day history: ${history.events.length} planned events from ${daysAgo(maxAge)} to ${demoNow.toISOString()}`);
  console.log("  surfaces: issuers, agents, managed certificates, discovered certificates, jobs and runs, deploys, connector targets, audit, notifications");
  console.log(`  served API calls: ${calls.length} planned calls, all mutations carry stable idempotency keys`);
  console.log("  no secret material: source scan passed; demo secret values are generated at runtime");
}

function run(cmd, args, opts = {}) {
  const res = spawnSync(cmd, args, { encoding: "utf8", ...opts });
  if (res.status !== 0) {
    throw new Error(`${cmd} ${args.join(" ")} failed: ${res.stderr || res.stdout}`);
  }
  return res.stdout.trim();
}

async function waitForHealth() {
  for (let i = 0; i < 60; i += 1) {
    try {
      const res = await fetch(`${server}/healthz`);
      if (res.ok) {
        return;
      }
    } catch {
      // keep waiting
    }
    await sleep(1000);
  }
  throw new Error(`trstctl did not become healthy at ${server}`);
}

function mintBootstrapToken(subject = "demo-seeder") {
  if (!/^[a-z0-9-]{1,64}$/.test(subject)) {
    throw new Error(`demo bootstrap subject is not a bounded safe label: ${subject}`);
  }
  const tokenFile = subject === "demo-seeder" ? bootstrapTokenFile : `${bootstrapTokenFile}.${subject}`;
  // The demo seed is a single Compose init job and creation below uses flag=wx;
  // a second writer cannot replace its token.
  if (existsSync(tokenFile)) {
    const persisted = readFileSync(tokenFile, "utf8").trim();
    if (!persisted) {
      throw new Error(`persisted demo bootstrap token is empty at ${tokenFile}`);
    }
    return persisted;
  }
  const env = { ...process.env };
  const token = run("/usr/local/bin/trstctl", [
    "token",
    "create",
    "--tenant",
    tenant,
    "--tenant-name",
    "Acme Robotics Demo",
    "--subject",
    subject,
    "--scopes",
    "*",
  ], { env });
  // codeql[js/file-system-race]
  writeFileSync(tokenFile, `${token}\n`, { encoding: "utf8", mode: 0o600, flag: "wx" });
  return token;
}

async function api(method, path, body, idem, okStatuses = [], actorBearer = bearer) {
  const headers = { authorization: `Bearer ${actorBearer}` };
  if (body !== undefined) {
    headers["content-type"] = "application/json";
  }
  if (idem) {
    headers["idempotency-key"] = idem;
  }
  const init = { method, headers };
  if (body !== undefined) {
    init.body = JSON.stringify(body);
  }
  for (let attempt = 0; attempt < 20; attempt += 1) {
    let res;
    let text;
    try {
      const target = new URL(path, serverURL);
      if (target.origin !== serverURL.origin) {
        throw new Error("demo API path escaped the configured server origin");
      }
      // lgtm[js/file-access-to-http] The file-backed bootstrap token is used
      // only as an Authorization header to this validated same-origin endpoint;
      // redirect following is disabled so it cannot leave that origin.
      res = await fetch(target, { ...init, redirect: "error" });
      text = await res.text();
    } catch (err) {
      if (attempt === 19) {
        throw err;
      }
      await sleep(1000);
      continue;
    }
    if ((res.status >= 200 && res.status < 300) || okStatuses.includes(res.status)) {
      if (!text) {
        return undefined;
      }
      try {
        return JSON.parse(text);
      } catch {
        return text;
      }
    }
    if (res.status >= 500 && attempt < 19) {
      await sleep(1000);
      continue;
    }
    throw new Error(`${method} ${path} returned ${res.status}: ${text}`);
  }
  throw new Error(`${method} ${path} exhausted retries`);
}

function canonicalValue(value) {
  if (Array.isArray(value)) {
    return value.map(canonicalValue);
  }
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, canonicalValue(value[key])]),
    );
  }
  return value;
}

function canonicalJSON(value) {
  return JSON.stringify(canonicalValue(value));
}

// Observation timestamps make the demo look old enough to exercise expiry and
// audit views, but they are not part of a resource's logical identity. Remove
// only those seed-owned timestamps before comparing preserved data. Everything
// else must match exactly, so a same-name resource with different policy or
// routing cannot be mistaken for the demo resource.
function stableSeedSemantics(value) {
  if (Array.isArray(value)) {
    return value.map(stableSeedSemantics);
  }
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value)
        .filter(([key]) => key !== "demo_observed_at" && key !== "observed_at")
        .map(([key, item]) => [key, stableSeedSemantics(item)]),
    );
  }
  return value;
}

function seedInventoryDigest(value) {
  return createHash("sha256").update(canonicalJSON(value)).digest("hex");
}

function seedManifest(history) {
  return {
    seed_version: seedVersion,
    members: history.members.map(({ key, subject, body }) => ({ key, subject, body })),
    owners: history.owners.map(({ key, body }) => ({ key, body })),
    profiles: history.profiles.map(({ key, name, spec }) => ({ key, name, spec })),
    connector_targets: history.connectorTargets.map(({ daysAgo: _daysAgo, ...target }) => target),
    identities: history.managedIdentities.map(({ daysAgo: _daysAgo, ...identity }) => identity),
    imported_certificates: history.importedCertificates.map(({ observedDaysAgo: _observedDaysAgo, ...certificate }) => certificate),
    discovery_segment: demoDiscoverySegment,
    discovery_sources: history.discoverySources.map(
      ({ daysAgo: _daysAgo, ...source }) => stableSeedSemantics(source),
    ),
  };
}

function checkpointSource(manifestDigest, inventoryDigest) {
  return `${seedVersion}:complete:${manifestDigest}:${inventoryDigest}`;
}

function checkpointDisposition(source, manifestDigest) {
  if (typeof source !== "string") return { kind: "conflict" };
  const parts = source.split(":");
  if (parts.length !== 4 || parts[1] !== "complete" ||
      !/^[0-9a-f]{64}$/.test(parts[2]) || !/^[0-9a-f]{64}$/.test(parts[3])) {
    return { kind: "conflict" };
  }
  if (parts[0] === seedVersion && parts[2] === manifestDigest) {
    return { kind: "current", inventoryDigest: parts[3] };
  }
  if (migratableSeedVersions.has(parts[0])) {
    return { kind: "migrate", previousVersion: parts[0] };
  }
  return { kind: "conflict" };
}

async function listAll(path, maximum = 1000) {
  const items = [];
  let cursor = "";
  for (let page = 0; page < 100; page += 1) {
    const separator = path.includes("?") ? "&" : "?";
    const cursorQuery = cursor ? `&cursor=${encodeURIComponent(cursor)}` : "";
    const response = await api("GET", `${path}${separator}limit=100${cursorQuery}`);
    const pageItems = Array.isArray(response?.items) ? response.items : [];
    items.push(...pageItems);
    if (items.length > maximum) {
      throw new Error(`${path} exceeded the bounded ${maximum}-row demo seed scan`);
    }
    cursor = response?.next_cursor || "";
    if (!cursor) {
      return items;
    }
  }
  throw new Error(`${path} exceeded the bounded 100-page demo seed scan`);
}

function findUniqueLogicalRecord(items, predicate, label) {
  const matches = items.filter(predicate);
  if (matches.length > 1) {
    throw new Error(`${label} is duplicated ${matches.length} times in preserved demo data`);
  }
  return matches[0];
}

function assertFields(record, expected, label) {
  for (const [field, want] of Object.entries(expected)) {
    const got = record?.[field];
    if (canonicalJSON(got) !== canonicalJSON(want)) {
      throw new Error(`${label} conflicts on ${field}: got ${canonicalJSON(got)}, want ${canonicalJSON(want)}`);
    }
  }
  return record;
}

async function readSeedCheckpoint(history) {
  const members = await listAll("/api/v1/access/members?include_offboarded=true");
  const checkpoint = findUniqueLogicalRecord(
    members,
    (member) => member.subject === seedCheckpointSubject,
    `seed checkpoint ${seedCheckpointSubject}`,
  );
  if (!checkpoint) {
    return null;
  }
  const manifestDigest = seedInventoryDigest(seedManifest(history));
  const disposition = checkpointDisposition(checkpoint.source, manifestDigest);
  if (checkpoint.status !== "active" || disposition.kind === "conflict") {
    throw new Error(
      `preserved demo seed checkpoint conflicts with ${seedVersion}; bump the seed version or reset the demo volumes`,
    );
  }
  if (disposition.kind === "migrate") {
    console.log(`trstctl demo seed upgrading ${disposition.previousVersion} to ${seedVersion}`);
    return null;
  }
  return { ...checkpoint, manifest_digest: manifestDigest, inventory_digest: disposition.inventoryDigest };
}

async function writeSeedCheckpoint(history, inventory) {
  const manifestDigest = seedInventoryDigest(seedManifest(history));
  const inventoryDigest = seedInventoryDigest(inventory);
  return api("PUT", `/api/v1/access/members/${seedCheckpointSubject}`, {
    display_name: "trstctl demo seed checkpoint",
    email: "",
    roles: [],
    source: checkpointSource(manifestDigest, inventoryDigest),
  }, stableKey(`checkpoint-${manifestDigest}-${inventoryDigest}`));
}

async function validateCompletedSeed(history, checkpoint) {
  const manifestDigest = seedInventoryDigest(seedManifest(history));
  if (checkpoint.manifest_digest !== manifestDigest) {
    throw new Error(`completed demo seed manifest changed without a seed-version bump`);
  }
  console.log(`trstctl demo seed ${seedVersion} already complete; preserved data left unchanged`);
  console.log(`  Inventory digest: ${checkpoint.inventory_digest}`);
}

async function ensureMember(member, members) {
  const existing = findUniqueLogicalRecord(
    members,
    (candidate) => candidate.subject === member.subject,
    `member ${member.subject}`,
  );
  const expected = {
    display_name: member.body.display_name,
    email: member.body.email,
    roles: [...member.body.roles].sort(),
    source: member.body.source,
    status: "active",
  };
  if (existing) {
    assertFields({ ...existing, roles: [...(existing.roles || [])].sort() }, expected, `member ${member.subject}`);
    return existing;
  }
  const created = await api("PUT", `/api/v1/access/members/${member.subject}`, {
    ...member.body,
    demo_observed_at: daysAgo(member.daysAgo),
  }, stableKey(`member-${member.key}`));
  members.push(created);
  return created;
}

async function ensureOwner(owner, ownerItems) {
  const existing = findUniqueLogicalRecord(
    ownerItems,
    (candidate) => candidate.name === owner.body.name || candidate.email === owner.body.email,
    `owner ${owner.key}`,
  );
  let resolved = existing;
  if (existing) {
    assertFields(existing, {
      kind: owner.body.kind,
      name: owner.body.name,
      email: owner.body.email,
    }, `owner ${owner.key}`);
    let needsModel = false;
    for (const field of ["application_id", "service", "business_unit", "environment"]) {
      if (!existing[field]) {
        needsModel = true;
      } else if (existing[field] !== owner.body[field]) {
        throw new Error(`owner ${owner.key} conflicts on ${field}: got ${canonicalJSON(existing[field])}, want ${canonicalJSON(owner.body[field])}`);
      }
    }
    const existingChain = existing.escalation_chain || [];
    if (existingChain.length === 0) {
      needsModel = true;
    } else if (canonicalJSON(existingChain) !== canonicalJSON(owner.body.escalation_chain)) {
      throw new Error(`owner ${owner.key} conflicts on escalation_chain`);
    }
    if (needsModel) {
      resolved = await api(
        "PUT",
        `/api/v1/owners/${existing.id}`,
        owner.body,
        stableKey(`owner-${owner.key}-application-model`),
      );
    }
  } else {
    resolved = await api("POST", "/api/v1/owners", owner.body, stableKey(`owner-${owner.key}`));
    ownerItems.push(resolved);
  }
  if (!resolved.ownership_current) {
    resolved = await api(
      "POST",
      `/api/v1/owners/${resolved.id}/attest`,
      undefined,
      stableKey(`owner-${owner.key}-attest`),
    );
  }
  if (!resolved.ownership_complete || !resolved.ownership_current) {
    throw new Error(`owner ${owner.key} did not reach current attested ownership readiness`);
  }
  return resolved;
}

async function ensureProfile(profile, profileItems) {
  const existing = findUniqueLogicalRecord(
    profileItems,
    (candidate) => candidate.name === profile.name,
    `profile ${profile.name}`,
  );
  if (existing) {
    if (!existing.active) {
      throw new Error(`profile ${profile.name} exists but is not active`);
    }
    assertFields(
      { spec: stableSeedSemantics(existing.spec) },
      { spec: stableSeedSemantics(profile.spec) },
      `profile ${profile.name}`,
    );
    return existing;
  }
  const created = await api("POST", "/api/v1/profiles", {
    name: profile.name,
    spec: { ...profile.spec, demo_observed_at: daysAgo(profile.daysAgo) },
  }, stableKey(`profile-${profile.key}`));
  profileItems.push(created);
  return created;
}

async function ensureIssuer(issuerItems) {
  const name = "trstctl Demo Internal CA";
  const existing = findUniqueLogicalRecord(
    issuerItems,
    (candidate) => candidate.name === name,
    `issuer ${name}`,
  );
  if (existing) {
    return assertFields(existing, { kind: "x509_ca", name, internal: true }, `issuer ${name}`);
  }
  const created = await api("POST", "/api/v1/issuers", {
    kind: "x509_ca",
    name,
    chain: [await readCA()],
    internal: true,
  }, stableKey("issuer-internal-ca"));
  issuerItems.push(created);
  return created;
}

async function ensureConnectorTarget(target, targetItems) {
  const existing = findUniqueLogicalRecord(
    targetItems,
    (candidate) => candidate.name === target.name,
    `connector target ${target.name}`,
  );
  const expected = {
    name: target.name,
    connector: target.connector,
    enabled: target.enabled,
    config: stableSeedSemantics(target.config),
  };
  if (existing) {
    if (existing.enabled !== target.enabled) {
      const updated = await api("PUT", `/api/v1/connectors/targets/${encodeURIComponent(existing.id)}`, {
        name: target.name,
        connector: target.connector,
        enabled: target.enabled,
        config: { ...target.config, demo_observed_at: daysAgo(target.daysAgo) },
      }, stableKey(`connector-target-readiness-${target.key}`));
      const index = targetItems.findIndex((candidate) => candidate.id === existing.id);
      if (index >= 0) targetItems[index] = updated;
      return assertFields(
        { ...updated, config: stableSeedSemantics(updated.config) },
        expected,
        `connector target ${target.name}`,
      );
    }
    return assertFields(
      { ...existing, config: stableSeedSemantics(existing.config) },
      expected,
      `connector target ${target.name}`,
    );
  }
  const created = await api("POST", "/api/v1/connectors/targets", {
    name: target.name,
    connector: target.connector,
    enabled: target.enabled,
    config: { ...target.config, demo_observed_at: daysAgo(target.daysAgo) },
  }, stableKey(`connector-target-${target.key}`));
  targetItems.push(created);
  return created;
}

async function ensureIdentity(item, ownerID, issuerID, identityItems) {
  const attributes = {
    environment: item.key.includes("legacy") ? "legacy" : "production",
    dns_names: [item.name],
    demo_lane: "live-clickthrough",
    demo_observed_at: daysAgo(item.daysAgo),
    deployment_location: item.deployment,
    ...(item.connector ? { connector: item.connector } : {}),
    ...(item.preparedConnector ? {
      intended_connector: item.preparedConnector,
      proof_state: "prepared_not_contacted",
    } : {}),
    profile: item.profile,
    protocol: item.protocol,
  };
  const existing = findUniqueLogicalRecord(
    identityItems,
    (candidate) => candidate.name === item.name,
    `identity ${item.name}`,
  );
  if (existing) {
    return assertFields({ ...existing, attributes: stableSeedSemantics(existing.attributes) }, {
      kind: "x509_certificate",
      name: item.name,
      owner_id: ownerID,
      issuer_id: issuerID,
      attributes: stableSeedSemantics(attributes),
    }, `identity ${item.name}`);
  }
  const created = await api("POST", "/api/v1/identities", {
    kind: "x509_certificate",
    name: item.name,
    owner_id: ownerID,
    issuer_id: issuerID,
    attributes,
  }, stableKey(`identity-${item.key}`));
  identityItems.push(created);
  return created;
}

async function advanceIdentity(item, identity, minimumCertificates, request = api, poll = pollCertificates) {
  const terminal = new Set(["revoked", "retired"]);
  let current = await request("GET", `/api/v1/identities/${identity.id}`);
  if (terminal.has(current.status) && current.status !== item.targetState) {
    throw new Error(`identity ${item.name} is ${current.status}; cannot converge it to ${item.targetState}`);
  }
  if (current.status === "requested" || current.status === "pending") {
    current = await transitionIdentityIfNeeded(
      identity.id,
      "issued",
      `demo seed: issue signer-backed certificate observed ${item.daysAgo} days ago`,
      stableKey(`identity-${item.key}-issue`),
      request,
    );
  }
  if (item.targetState !== "issued") {
    await poll(minimumCertificates);
  }
  if (item.targetState === "issued") {
    if (current.status !== "issued") {
      throw new Error(`identity ${item.name} reached ${current.status}, want issued`);
    }
    return current;
  }
  if (item.targetState === "deployed" && current.status === "issued") {
    current = await transitionIdentityIfNeeded(
      identity.id,
      "deployed",
      `demo seed: deployed through ${item.connector}`,
      stableKey(`identity-${item.key}-deploy`),
      request,
    );
  }
  if (item.targetState === "revoked" && (current.status === "issued" || current.status === "deployed")) {
    current = await transitionIdentityIfNeeded(
      identity.id,
      "revoked",
      item.revocationReason || "cessationOfOperation",
      stableKey(`identity-${item.key}-revoke`),
      request,
    );
  }
  if (current.status !== item.targetState) {
    throw new Error(`identity ${item.name} reached ${current.status}, want ${item.targetState}`);
  }
  return current;
}

async function ensureImportedCertificate(cert, ownerID, certificateItems) {
  const existing = findUniqueLogicalRecord(
    certificateItems,
    (candidate) =>
      candidate.source === cert.source &&
      candidate.deployment_location === cert.deploymentLocation &&
      Array.isArray(candidate.sans) &&
      candidate.sans.includes(cert.commonName),
    `imported certificate ${cert.commonName}`,
  );
  if (existing) {
    return assertFields(existing, { owner_id: ownerID }, `imported certificate ${cert.commonName}`);
  }
  const created = await api("POST", "/api/v1/certificates", {
    pem: makeSelfSignedCert(cert.commonName, cert.validDays),
    owner_id: ownerID,
    deployment_location: cert.deploymentLocation,
    source: cert.source,
  }, stableKey(`cert-import-${cert.key}`));
  certificateItems.push(created);
  return created;
}

async function ensureSecret(name, valueLabel, wantedVersion, ownerID, secretItems) {
  let existing = findUniqueLogicalRecord(
    secretItems,
    (candidate) => candidate.name === name,
    `secret ${name}`,
  );
  if (!existing) {
    existing = await api("POST", "/api/v1/secrets/store", {
      name,
      owner_id: ownerID,
      value: stableDemoValue(valueLabel),
    }, stableKey(`secret-${valueLabel}`));
    secretItems.push(existing);
  }
  if (!Number.isInteger(existing.version) || existing.version < 1) {
    throw new Error(`secret ${name} has invalid version ${existing.version}`);
  }
  if (existing.version > wantedVersion) {
    throw new Error(`secret ${name} is version ${existing.version}, beyond demo target ${wantedVersion}`);
  }
  if (existing.version < wantedVersion) {
    existing = await api("PUT", `/api/v1/secrets/store/${name}`, {
      value: stableDemoValue(`${valueLabel}-rotated`),
    }, stableKey(`secret-${valueLabel}-rotate`));
  }
  return existing;
}

async function ensureDiscoverySource(sourceDef, sourceItems) {
  const existing = findUniqueLogicalRecord(
    sourceItems,
    (candidate) => candidate.name === sourceDef.name,
    `discovery source ${sourceDef.name}`,
  );
  if (existing) {
    return assertFields(
      { ...existing, config: stableSeedSemantics(existing.config) },
      { kind: sourceDef.kind, config: stableSeedSemantics(sourceDef.config) },
      `discovery source ${sourceDef.name}`,
    );
  }
  const created = await api("POST", "/api/v1/discovery/sources", {
    name: sourceDef.name,
    kind: sourceDef.kind,
    config: {
      ...sourceDef.config,
      demo_observed_at: daysAgo(sourceDef.daysAgo),
    },
  }, stableKey(`discovery-source-${sourceDef.key}`));
  sourceItems.push(created);
  return created;
}

async function ensureDiscoverySegment(segments) {
  const existing = findUniqueLogicalRecord(
    segments,
    (candidate) => candidate.name === demoDiscoverySegment.name,
    `discovery segment ${demoDiscoverySegment.name}`,
  );
  if (existing) {
    if (existing.status === "excluded") {
      throw new Error(`discovery segment ${demoDiscoverySegment.name} conflicts: it is excluded`);
    }
    return assertFields(
      { ...existing, ranges: [...(existing.ranges || [])].sort() },
      {
        name: demoDiscoverySegment.name,
        ranges: [...demoDiscoverySegment.ranges].sort(),
        staleness_hours: demoDiscoverySegment.staleness_hours,
      },
      `discovery segment ${demoDiscoverySegment.name}`,
    );
  }
  const created = await api(
    "POST",
    "/api/v1/discovery/segments",
    demoDiscoverySegment,
    stableKey("discovery-segment-control-plane"),
  );
  segments.push(created);
  return created;
}

async function collectSeedInventory(history, resolved) {
  const members = await listAll("/api/v1/access/members?include_offboarded=true");
  const owners = await listAll("/api/v1/owners");
  const identities = await listAll("/api/v1/identities");
  const profilesResponse = await api("GET", "/api/v1/profiles");
  const profiles = Array.isArray(profilesResponse?.items) ? profilesResponse.items : [];
  const issuers = await listAll("/api/v1/issuers");
  const certificates = await listAll("/api/v1/certificates");
  const secretsResponse = await api("GET", "/api/v1/secrets/store?limit=100");
  const secrets = Array.isArray(secretsResponse?.items) ? secretsResponse.items : [];
  const sources = await listAll("/api/v1/discovery/sources");
  const connectorTargets = await listAll("/api/v1/connectors/targets");
  const coverage = await api("GET", "/api/v1/discovery/coverage");
  const segments = Array.isArray(coverage?.segments) ? coverage.segments : [];

  const inventory = {
    members: history.members.map((definition) => {
      const row = findUniqueLogicalRecord(members, (candidate) => candidate.subject === definition.subject, `member ${definition.subject}`);
      if (!row || row.status !== "active") throw new Error(`completed seed is missing active member ${definition.subject}`);
      return { key: definition.key, subject: row.subject, display_name: row.display_name, email: row.email, roles: [...(row.roles || [])].sort(), source: row.source };
    }),
    owners: history.owners.map((definition) => {
      const row = findUniqueLogicalRecord(
        owners,
        (candidate) => candidate.name === definition.body.name && candidate.email === definition.body.email,
        `owner ${definition.key}`,
      );
      if (!row) throw new Error(`completed seed is missing owner ${definition.key}`);
      assertFields(row, definition.body, `owner ${definition.key}`);
      return { key: definition.key, id: row.id, kind: row.kind, name: row.name, email: row.email };
    }),
    profiles: history.profiles.map((definition) => {
      const row = findUniqueLogicalRecord(profiles, (candidate) => candidate.name === definition.name, `profile ${definition.name}`);
      if (!row || !row.active) throw new Error(`completed seed is missing active profile ${definition.name}`);
      assertFields(
        { spec: stableSeedSemantics(row.spec) },
        { spec: stableSeedSemantics(definition.spec) },
        `profile ${definition.name}`,
      );
      return { key: definition.key, id: row.id, name: row.name, spec: stableSeedSemantics(row.spec) };
    }),
    issuers: ["trstctl Demo Internal CA"].map((name) => {
      const row = findUniqueLogicalRecord(issuers, (candidate) => candidate.name === name, `issuer ${name}`);
      if (!row) throw new Error(`completed seed is missing issuer ${name}`);
      return { id: row.id, kind: row.kind, name: row.name, internal: row.internal };
    }),
    connector_targets: history.connectorTargets.map((definition) => {
      const row = findUniqueLogicalRecord(connectorTargets, (candidate) => candidate.name === definition.name, `connector target ${definition.name}`);
      if (!row) throw new Error(`completed seed is missing connector target ${definition.name}`);
      assertFields(
        { ...row, config: stableSeedSemantics(row.config) },
        { connector: definition.connector, enabled: definition.enabled, config: stableSeedSemantics(definition.config) },
        `connector target ${definition.name}`,
      );
      return { key: definition.key, id: row.id, name: row.name, connector: row.connector, enabled: row.enabled, config: stableSeedSemantics(row.config) };
    }),
    identities: history.managedIdentities.map((definition) => {
      const row = findUniqueLogicalRecord(identities, (candidate) => candidate.name === definition.name, `identity ${definition.name}`);
      if (!row) throw new Error(`completed seed is missing identity ${definition.name}`);
      if (row.status !== definition.targetState) {
        throw new Error(`completed seed identity ${definition.name} is ${row.status}, want ${definition.targetState}`);
      }
      assertFields(
        { ...row, attributes: stableSeedSemantics(row.attributes) },
        {
          name: definition.name,
          owner_id: resolved?.owners?.[definition.ownerKey]?.id || row.owner_id,
          issuer_id: resolved?.issuer?.id || row.issuer_id,
          attributes: stableSeedSemantics({
            environment: definition.key.includes("legacy") ? "legacy" : "production",
            dns_names: [definition.name],
            demo_lane: "live-clickthrough",
            deployment_location: definition.deployment,
            ...(definition.connector ? { connector: definition.connector } : {}),
            ...(definition.preparedConnector ? {
              intended_connector: definition.preparedConnector,
              proof_state: "prepared_not_contacted",
            } : {}),
            profile: definition.profile,
            protocol: definition.protocol,
          }),
        },
        `identity ${definition.name}`,
      );
      return {
        key: definition.key,
        id: row.id,
        name: row.name,
        owner_id: row.owner_id,
        issuer_id: row.issuer_id,
        status: row.status,
        attributes: stableSeedSemantics(row.attributes),
      };
    }),
    imported_certificates: history.importedCertificates.map((definition) => {
      const row = findUniqueLogicalRecord(
        certificates,
        (candidate) => candidate.source === definition.source && candidate.deployment_location === definition.deploymentLocation && candidate.sans?.includes(definition.commonName),
        `imported certificate ${definition.commonName}`,
      );
      if (!row) throw new Error(`completed seed is missing imported certificate ${definition.commonName}`);
      return { key: definition.key, id: row.id, owner_id: row.owner_id, source: row.source, deployment_location: row.deployment_location, sans: [...row.sans].sort() };
    }),
    secrets: [
      ["payments/db/password", 2],
      ["demo/stripe/api-key", 1],
      ["demo/github/actions/deploy-token", 1],
      ["demo/aws/iam/rotator", 1],
    ].map(([name, version]) => {
      const row = findUniqueLogicalRecord(secrets, (candidate) => candidate.name === name, `secret ${name}`);
      if (!row || row.version !== version) throw new Error(`completed seed secret ${name} is not at version ${version}`);
      return { name: row.name, version: row.version };
    }),
    discovery_segment: (() => {
      const row = findUniqueLogicalRecord(
        segments,
        (candidate) => candidate.name === demoDiscoverySegment.name,
        `discovery segment ${demoDiscoverySegment.name}`,
      );
      if (!row) throw new Error(`completed seed is missing discovery segment ${demoDiscoverySegment.name}`);
      if (row.status === "excluded") throw new Error(`completed seed discovery segment ${demoDiscoverySegment.name} is excluded`);
      assertFields(
        { ...row, ranges: [...(row.ranges || [])].sort() },
        {
          name: demoDiscoverySegment.name,
          ranges: [...demoDiscoverySegment.ranges].sort(),
          staleness_hours: demoDiscoverySegment.staleness_hours,
        },
        `discovery segment ${demoDiscoverySegment.name}`,
      );
      return {
        name: row.name,
        ranges: [...row.ranges].sort(),
        staleness_hours: row.staleness_hours,
      };
    })(),
    discovery_sources: history.discoverySources.map((definition) => {
      const row = findUniqueLogicalRecord(sources, (candidate) => candidate.name === definition.name, `discovery source ${definition.name}`);
      if (!row) throw new Error(`completed seed is missing discovery source ${definition.name}`);
      assertFields(
        { ...row, config: stableSeedSemantics(row.config) },
        { kind: definition.kind, config: stableSeedSemantics(definition.config) },
        `discovery source ${definition.name}`,
      );
      return { key: definition.key, id: row.id, kind: row.kind, name: row.name, config: stableSeedSemantics(row.config) };
    }),
  };
  return inventory;
}

async function readCA() {
  const path = "/public-trust/issuing-ca.crt";
  for (let i = 0; i < 60; i += 1) {
    if (existsSync(path)) {
      const pem = readFileSync(path, "utf8");
      if (pem.includes("BEGIN CERTIFICATE")) {
        return pem;
      }
    }
    await sleep(1000);
  }
  throw new Error(`demo issuing CA did not appear at ${path}`);
}

function makeSelfSignedCert(commonName, days) {
  const dir = mkdtempSync(join(tmpdir(), "trstctl-demo-cert-"));
  try {
    const key = join(dir, "leaf.key");
    const cert = join(dir, "leaf.crt");
    run("openssl", [
      "req",
      "-x509",
      "-newkey",
      "rsa:2048",
      "-nodes",
      "-keyout",
      key,
      "-out",
      cert,
      "-days",
      String(days),
      "-subj",
      `/CN=${commonName}`,
      "-addext",
      `subjectAltName=DNS:${commonName}`,
    ]);
    return readFileSync(cert, "utf8");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

async function pollCertificates(minimum) {
  for (let i = 0; i < 60; i += 1) {
    const certs = await api("GET", "/api/v1/certificates?limit=100");
    if ((certs?.items || []).length >= minimum) {
      return certs.items;
    }
    await sleep(1000);
  }
  throw new Error(`certificate inventory did not reach ${minimum} rows`);
}

async function transitionIdentityIfNeeded(identityID, targetState, reason, idemKey, request = api) {
  const current = await request("GET", `/api/v1/identities/${identityID}`);
  if (current?.status === targetState) {
    return current;
  }
  try {
    return await request("POST", `/api/v1/identities/${identityID}/transitions`, {
      to: targetState,
      reason,
    }, idemKey);
  } catch (error) {
    // Issuance and connector workers can advance the event-sourced projection
    // between the read and mutation. Accept only proof that the exact requested
    // state already won that race; every other conflict remains fatal.
    const after = await request("GET", `/api/v1/identities/${identityID}`);
    if (after?.status === targetState) {
      return after;
    }
    throw error;
  }
}

async function main() {
  if (checkMode) {
    checkSeedPlan();
    return;
  }

  const history = buildDemoHistory();
  await waitForHealth();
  bearer = mintBootstrapToken();

  const checkpoint = await readSeedCheckpoint(history);
  if (checkpoint) {
    await validateCompletedSeed(history, checkpoint);
    return;
  }

  const memberItems = await listAll("/api/v1/access/members?include_offboarded=true");
  for (const member of history.members) {
    await ensureMember(member, memberItems);
  }

  const ownerItems = await listAll("/api/v1/owners");
  const owners = {};
  for (const owner of history.owners) {
    owners[owner.key] = await ensureOwner(owner, ownerItems);
  }

  const profileResponse = await api("GET", "/api/v1/profiles");
  const profileItems = Array.isArray(profileResponse?.items) ? profileResponse.items : [];
  for (const profile of history.profiles) {
    await ensureProfile(profile, profileItems);
  }

  const issuerItems = await listAll("/api/v1/issuers");
  const issuer = await ensureIssuer(issuerItems);

  const connectorTargetItems = await listAll("/api/v1/connectors/targets");
  const connectorTargets = {};
  for (const target of history.connectorTargets) {
    connectorTargets[target.key] = await ensureConnectorTarget(target, connectorTargetItems);
  }

  const identityItems = await listAll("/api/v1/identities");
  const identities = {};
  let issuedIdentityCount = 0;
  for (const item of history.managedIdentities) {
    const ownerID = owners[item.ownerKey]?.id;
    if (!ownerID) {
      throw new Error(`demo owner ${item.ownerKey} was not created`);
    }
    identities[item.key] = await ensureIdentity(item, ownerID, issuer.id, identityItems);
    issuedIdentityCount += 1;
    await advanceIdentity(item, identities[item.key], Math.min(issuedIdentityCount, 6));
  }

  await pollCertificates(Math.min(history.managedIdentities.length, 6));
  const certificateItems = await listAll("/api/v1/certificates");
  for (const cert of history.importedCertificates) {
    const ownerID = owners[cert.ownerKey]?.id;
    if (!ownerID) throw new Error(`demo owner ${cert.ownerKey} was not created`);
    await ensureImportedCertificate(cert, ownerID, certificateItems);
  }

  const secretResponse = await api("GET", "/api/v1/secrets/store?limit=100");
  const secretItems = Array.isArray(secretResponse?.items) ? secretResponse.items : [];
  await ensureSecret("payments/db/password", "payments-db", 2, owners.payments.id, secretItems);
  await ensureSecret("demo/stripe/api-key", "demo-stripe-api-key", 1, owners.payments.id, secretItems);
  await ensureSecret("demo/github/actions/deploy-token", "demo-github-actions-deploy-token", 1, owners.release.id, secretItems);
  await ensureSecret("demo/aws/iam/rotator", "demo-aws-iam-rotator", 1, owners.platform.id, secretItems);
  await api("POST", "/api/v1/secrets/shares", {
    value: stableDemoValue("breakglass-share"),
    ttl_seconds: 86400,
  }, stableKey("secret-share-breakglass"));
  await api("POST", "/api/v1/secrets/pki", {
    common_name: "db-client.demo.trstctl.local",
    ttl_seconds: 3600,
  }, stableKey("secret-pki-db-client"));

  await api("POST", "/api/v1/transit/keys", { name: "payments-data", kind: "aead" }, stableKey("transit-payments-aead"), [409]);
  const encrypted = await api("POST", "/api/v1/transit/encrypt", {
    key: "payments-data",
    plaintext: b64(stableDemoValue("card-token")),
    aad: b64("tenant=acme-demo"),
  }, stableKey("transit-payments-encrypt"));
  await api("POST", "/api/v1/transit/keys/rotate", { name: "payments-data" }, stableKey("transit-payments-rotate"), [409]);
  if (encrypted?.ciphertext) {
    await api("POST", "/api/v1/transit/rewrap", {
      key: "payments-data",
      ciphertext: encrypted.ciphertext,
      aad: b64("tenant=acme-demo"),
    }, stableKey("transit-payments-rewrap"));
  }
  await api("POST", "/api/v1/transit/keys", { name: "release-signing", kind: "sign" }, stableKey("transit-release-signing-v2"), [409]);
  const signed = await api("POST", "/api/v1/transit/sign", {
    key: "release-signing",
    message: b64("oci-image-digest-demo"),
  }, stableKey("transit-release-sign"));
  if (signed?.signature && signed?.public_der) {
    await api("POST", "/api/v1/transit/verify", {
      message: b64("oci-image-digest-demo"),
      signature: signed.signature,
      public_der: signed.public_der,
    }, stableKey("transit-release-verify"));
  }

  let managedKey = null;
  for (let i = 0; i < 20; i += 1) {
    try {
      managedKey = await api("POST", "/api/v1/managed-keys", {
        algorithm: "RSA-2048",
      }, stableKey("managed-key-rsa"));
      break;
    } catch (err) {
      if (i === 19) {
        throw err;
      }
      await sleep(1500);
    }
  }
  if (managedKey?.key_id) {
    const rotateBody = { key_id: managedKey.key_id };
    const rotateKey = stableKey("managed-key-rsa-rotate");
    // The first attempt opens the request and proves that destructive key actions
    // fail closed. Two separately authenticated principals then approve the exact
    // key/action pair before the original requester retries it.
    const rotateAttempt = await api("POST", "/api/v1/managed-keys/rotate", {
      key_id: managedKey.key_id,
    }, rotateKey, [403]);
    if (rotateAttempt?.status === 403) {
      const queue = await api("GET", "/api/v1/approval-requests?status=pending&limit=100");
      const matchingRequests = (queue?.items || []).filter((request) =>
        request.resource_kind === "managed_key" &&
        request.resource_id === managedKey.key_id &&
        request.action === "managedkey:rotate" &&
        request.requester === "demo-seeder"
      );
      if (matchingRequests.length !== 1 || !matchingRequests[0].id || !matchingRequests[0].intent_digest) {
        throw new Error("managed-key rotate did not expose one exact immutable approval request");
      }
      const approvalRequest = matchingRequests[0];
      const approvalBody = {
        key_id: managedKey.key_id,
        action: "rotate",
        request_id: approvalRequest.id,
        intent_digest: approvalRequest.intent_digest,
      };
      for (const [index, subject] of ["demo-key-custodian-one", "demo-key-custodian-two"].entries()) {
        const approverBearer = mintBootstrapToken(subject);
        await api(
          "POST",
          "/api/v1/managed-keys/approvals",
          approvalBody,
          stableKey(`managed-key-rsa-rotate-approval-${index + 1}`),
          [],
          approverBearer,
        );
      }
    }
    await api("POST", "/api/v1/managed-keys/rotate", rotateBody, rotateKey);
  }

  const apiTokenItems = await listAll("/api/v1/access/api-tokens?subject=ci-release-bot");
  let demoAPIToken = findUniqueLogicalRecord(
    apiTokenItems,
    (token) => token.subject === "ci-release-bot" && !token.revoked_at,
    "API token ci-release-bot",
  );
  if (demoAPIToken) {
    assertFields(
      { ...demoAPIToken, scopes: [...(demoAPIToken.scopes || [])].sort() },
      { subject: "ci-release-bot", scopes: ["certs:read", "graph:read", "keys:read", "secrets:read"] },
      "API token ci-release-bot",
    );
  } else {
    demoAPIToken = await api("POST", "/api/v1/access/api-tokens", {
      subject: "ci-release-bot",
      scopes: ["certs:read", "secrets:read", "keys:read", "graph:read"],
    }, stableKey("access-token-release-bot"));
    // The API returns the raw credential once. The demo proves creation but does
    // not need to use it, so drop it immediately and never render it to logs.
    delete demoAPIToken.token;
  }
  await api("POST", "/api/v1/ephemeral/api-keys", {
    subject: "incident-rotator",
    scopes: ["certs:read", "keys:read"],
    ttl_seconds: 1800,
  }, stableKey("ephemeral-api-key-incident-rotator"));
  for (const token of history.agentTokens) {
    await api("POST", "/api/v1/agents/enrollment-tokens", undefined, stableKey(`agent-enrollment-token-${token.key}`));
  }

  const coverage = await api("GET", "/api/v1/discovery/coverage");
  const segmentItems = Array.isArray(coverage?.segments) ? coverage.segments : [];
  await ensureDiscoverySegment(segmentItems);

  const sourceItems = await listAll("/api/v1/discovery/sources");
  for (const sourceDef of history.discoverySources) {
    const source = await ensureDiscoverySource(sourceDef, sourceItems);
    if (sourceDef.run !== false) {
      await api("POST", "/api/v1/discovery/runs", {
        source_id: source.id,
        dry_run: sourceDef.dryRun === true,
      }, stableKey(`discovery-run-${sourceDef.key}`));
    }
  }

  const certs = await api("GET", "/api/v1/certificates?limit=100");
  const ownersList = await api("GET", "/api/v1/owners?limit=100");
  const secrets = await api("GET", "/api/v1/secrets/store?limit=100");
  const runs = await api("GET", "/api/v1/discovery/runs?limit=100");
  const findings = await api("GET", "/api/v1/discovery/findings?limit=100");
  const notifications = await api("GET", "/api/v1/notifications?limit=100");

  const inventory = await collectSeedInventory(history, { owners, issuer, connectorTargets });
  await writeSeedCheckpoint(history, inventory);
  const committedCheckpoint = await readSeedCheckpoint(history);
  if (!committedCheckpoint) {
    throw new Error("demo seed checkpoint was not projected after the final phase");
  }
  await validateCompletedSeed(history, committedCheckpoint);

  for (const line of seedCompletionSummary({
    url: demoURL,
    tenant,
    plannedEvents: history.events.length,
    owners: (ownersList?.items || []).length,
    certificates: (certs?.items || []).length,
    secrets: (secrets?.items || []).length,
    runs: (runs?.items || []).length,
    findings: (findings?.items || []).length,
    notifications: (notifications?.items || []).length,
  })) {
    console.log(line);
  }
}

function seedCompletionSummary({ url, tenant, plannedEvents, owners, certificates, secrets, runs, findings, notifications }) {
  return [
    "",
    "trstctl demo seed complete",
    `  URL: ${url}`,
    "  Browser login: click Sign in with SSO, then use demo-admin@trstctl.local",
    `  Tenant: ${tenant}`,
    `  Planned 180-day history events: ${plannedEvents}`,
    `  Owners: ${owners}`,
    `  Certificate inventory rows: ${certificates}`,
    `  Stored secrets: ${secrets}`,
    `  Discovery runs: ${runs}`,
    `  Discovery findings: ${findings}`,
    `  Notifications: ${notifications}`,
    "  Raw credential values: withheld from logs; create or retrieve credentials only through an authorized workflow",
    "",
  ];
}

export {
  advanceIdentity,
  checkpointSource,
  checkpointDisposition,
  findUniqueLogicalRecord,
  seedInventoryDigest,
  seedCompletionSummary,
  redactSeedDiagnostic,
  stableDemoValue,
  stableSeedSemantics,
};

const invokedAsProgram = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (invokedAsProgram) {
  main().catch((error) => {
    // Errors can retain request objects in their stack/cause chain. Keep demo
    // logs credential-free. Preserve only a bounded redacted summary in the
    // seed-owned mode-0600 volume so operators have an actionable route/status.
    try {
      writeSeedDiagnostic(error);
    } catch {
      // The shared Docker log remains generic even when the protected volume is
      // unavailable; never fall back to printing the raw error object.
    }
    console.error("demo seed failed; inspect the protected container diagnostics");
    process.exit(1);
  });
}
