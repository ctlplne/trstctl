import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";

const tenant = process.env.TRSTCTL_TENANT || "11111111-1111-4111-8111-111111111111";
const server = process.env.TRSTCTL_SERVER || "https://trstctl:8443";
const demoURL = process.env.TRSTCTL_DEMO_URL || "https://localhost:9443";
const seedVersion = "demo-seed-v1";
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

function runtimeDemoValue(label) {
  return `demo-${label}-${randomUUID()}`;
}

function buildDemoHistory() {
  const members = [
    { key: "demo-admin", subject: "demo-admin", body: { display_name: "Demo Admin", email: "demo-admin@trstctl.local", roles: ["admin"], source: "demo-seed" }, daysAgo: 180 },
    { key: "se-operator", subject: "se-demo-operator", body: { display_name: "Solutions Engineer", email: "se-demo-operator@trstctl.local", roles: ["operator", "auditor"], source: "demo-seed" }, daysAgo: 174 },
    { key: "payments-bot", subject: "payments-bot", body: { display_name: "Payments Deploy Bot", email: "payments-bot@trstctl.local", roles: ["ra-officer"], source: "demo-seed" }, daysAgo: 151 },
    { key: "secops-analyst", subject: "secops-analyst", body: { display_name: "SecOps Analyst", email: "secops-analyst@trstctl.local", roles: ["auditor"], source: "demo-seed" }, daysAgo: 83 },
  ];
  const owners = [
    { key: "platform", body: { kind: "team", name: "Platform SRE", email: "platform-sre@acme.example" }, daysAgo: 180 },
    { key: "payments", body: { kind: "workload", name: "Payments API", email: "payments-api@acme.example" }, daysAgo: 168 },
    { key: "edge", body: { kind: "workload", name: "Edge Gateway", email: "edge-gateway@acme.example" }, daysAgo: 162 },
    { key: "release", body: { kind: "service", name: "CI Release Bot", email: "release-bot@acme.example" }, daysAgo: 143 },
    { key: "mobile", body: { kind: "workload", name: "Mobile MDM", email: "mobile-mdm@acme.example" }, daysAgo: 121 },
    { key: "data", body: { kind: "workload", name: "Data Warehouse", email: "data-platform@acme.example" }, daysAgo: 96 },
    { key: "iot", body: { kind: "workload", name: "Factory IoT Gateways", email: "factory-iot@acme.example" }, daysAgo: 61 },
    { key: "security", body: { kind: "team", name: "Security Engineering", email: "security@acme.example" }, daysAgo: 38 },
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
  const managedIdentities = [
    { key: "payments-api", ownerKey: "payments", name: "payments-api.demo.trstctl.local", targetState: "issued", profile: "service-mtls-30d", protocol: "acme", deployment: "k8s/payments/deployment/payments-api", connector: "envoy", daysAgo: 168 },
    { key: "edge-gateway", ownerKey: "edge", name: "edge-gateway.demo.trstctl.local", targetState: "deployed", profile: "service-mtls-30d", protocol: "acme", deployment: "edge/traefik/gateway", connector: "traefik", daysAgo: 151 },
    { key: "release-bot", ownerKey: "release", name: "release-bot.demo.trstctl.local", targetState: "issued", profile: "humanless-api-key-1h", protocol: "api", deployment: "github-actions/release", connector: "api-token", daysAgo: 132 },
    { key: "legacy-vpn", ownerKey: "platform", name: "legacy-vpn.demo.trstctl.local", targetState: "revoked", profile: "service-mtls-30d", protocol: "manual", deployment: "vpn-appliance-02:/etc/ssl/vpn.crt", connector: "manual", daysAgo: 118, revocationReason: "cessationOfOperation" },
    { key: "mobile-mdm", ownerKey: "mobile", name: "mdm-scep.demo.trstctl.local", targetState: "deployed", profile: "scep-intune-mobile-7d", protocol: "scep", deployment: "intune/profile/mobile-mdm", connector: "intune", daysAgo: 84 },
    { key: "iot-est-gateway", ownerKey: "iot", name: "iot-est-gateway.demo.trstctl.local", targetState: "deployed", profile: "est-serverkeygen-iot-24h", protocol: "est", deployment: "factory-floor/gateway-17", connector: "caddy", daysAgo: 63 },
    { key: "warehouse-mtls", ownerKey: "data", name: "warehouse-mtls.demo.trstctl.local", targetState: "deployed", profile: "service-mtls-30d", protocol: "acme", deployment: "warehouse/envoy/mtls", connector: "envoy", daysAgo: 41 },
    { key: "shadow-cleanup", ownerKey: "security", name: "shadow-cleanup.demo.trstctl.local", targetState: "revoked", profile: "acme-trust-authenticated-90d", protocol: "acme", deployment: "secops/remediation/shadow-cleanup", connector: "shell-ca", daysAgo: 16, revocationReason: "privilegeWithdrawn" },
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
    { key: "control-plane", name: "demo-control-plane-tls", kind: "network", config: { targets: ["trstctl:8443"] }, dryRun: true, daysAgo: 159 },
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
  return { members, owners, profiles, managedIdentities, importedCertificates, discoverySources, agentTokens, notifications, events };
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
    "POST /api/v1/issuers",
    ...history.managedIdentities.flatMap(() => ["POST /api/v1/identities", "POST /api/v1/identities/{id}/transitions"]),
    ...history.importedCertificates.map(() => "POST /api/v1/certificates"),
    "POST /api/v1/secrets/store",
    "PUT /api/v1/secrets/store/{name}",
    "POST /api/v1/secrets/store/import",
    "POST /api/v1/secrets/shares",
    "POST /api/v1/secrets/pki",
    "POST /api/v1/transit/keys",
    "POST /api/v1/transit/encrypt",
    "POST /api/v1/transit/keys/rotate",
    "POST /api/v1/transit/rewrap",
    "POST /api/v1/transit/sign",
    "POST /api/v1/transit/verify",
    "POST /api/v1/managed-keys",
    "POST /api/v1/managed-keys/rotate",
    "POST /api/v1/access/api-tokens",
    "POST /api/v1/ephemeral/api-keys",
    ...history.agentTokens.map(() => "POST /api/v1/agents/enrollment-tokens"),
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
  for (const route of ["POST /api/v1/issuers", "POST /api/v1/certificates", "POST /api/v1/discovery/runs", "GET /api/v1/notifications"]) {
    if (!calls.includes(route)) {
      throw new Error(`demo seed plan does not cover ${route}`);
    }
  }
  assertNoCommittedSecretMaterial();
  console.log("trstctl demo seed check passed");
  console.log(`  180-day history: ${history.events.length} planned events from ${daysAgo(maxAge)} to ${demoNow.toISOString()}`);
  console.log("  surfaces: issuers, agents, managed certificates, discovered certificates, jobs and runs, deploys, audit, notifications");
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

function mintBootstrapToken() {
  const env = { ...process.env };
  return run("/usr/local/bin/trstctl", [
    "token",
    "create",
    "--tenant",
    tenant,
    "--tenant-name",
    "Acme Robotics Demo",
    "--subject",
    "demo-seeder",
    "--scopes",
    "*",
  ], { env });
}

async function api(method, path, body, idem, okStatuses = []) {
  const headers = { authorization: `Bearer ${bearer}` };
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
      res = await fetch(`${server}${path}`, init);
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

async function readCA() {
  const path = "/trstctl-data/ca/issuing-ca.crt";
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

async function main() {
  if (checkMode) {
    checkSeedPlan();
    return;
  }

  const history = buildDemoHistory();
  await waitForHealth();
  bearer = mintBootstrapToken();

  for (const member of history.members) {
    await api("PUT", `/api/v1/access/members/${member.subject}`, {
      ...member.body,
      demo_observed_at: daysAgo(member.daysAgo),
    }, stableKey(`member-${member.key}`));
  }

  const owners = {};
  for (const owner of history.owners) {
    owners[owner.key] = await api("POST", "/api/v1/owners", owner.body, stableKey(`owner-${owner.key}`));
  }

  for (const profile of history.profiles) {
    await api("POST", "/api/v1/profiles", {
      name: profile.name,
      spec: { ...profile.spec, demo_observed_at: daysAgo(profile.daysAgo) },
    }, stableKey(`profile-${profile.key}`));
  }

  const issuer = await api("POST", "/api/v1/issuers", {
    kind: "x509_ca",
    name: "trstctl Demo Internal CA",
    chain: [await readCA()],
    internal: true,
  }, stableKey("issuer-internal-ca"));

  const identities = {};
  let issuedIdentityCount = 0;
  for (const item of history.managedIdentities) {
    const ownerID = owners[item.ownerKey]?.id;
    if (!ownerID) {
      throw new Error(`demo owner ${item.ownerKey} was not created`);
    }
    identities[item.key] = await api("POST", "/api/v1/identities", {
      kind: "x509_certificate",
      name: item.name,
      owner_id: ownerID,
      issuer_id: issuer.id,
      attributes: {
        environment: item.key.includes("legacy") ? "legacy" : "production",
        dns_names: [item.name],
        demo_lane: "live-clickthrough",
        demo_observed_at: daysAgo(item.daysAgo),
        deployment_location: item.deployment,
        connector: item.connector,
        profile: item.profile,
        protocol: item.protocol,
      },
    }, stableKey(`identity-${item.key}`));
    await api("POST", `/api/v1/identities/${identities[item.key].id}/transitions`, {
      to: "issued",
      reason: `demo seed: issue signer-backed certificate observed ${item.daysAgo} days ago`,
    }, stableKey(`identity-${item.key}-issue`));
    issuedIdentityCount += 1;
    if (item.targetState === "deployed") {
      await pollCertificates(Math.min(issuedIdentityCount, 6));
      await api("POST", `/api/v1/identities/${identities[item.key].id}/transitions`, {
        to: "deployed",
        reason: `demo seed: deployed through ${item.connector}`,
      }, stableKey(`identity-${item.key}-deploy`));
    }
    if (item.targetState === "revoked") {
      await pollCertificates(Math.min(issuedIdentityCount, 6));
      await api("POST", `/api/v1/identities/${identities[item.key].id}/transitions`, {
        to: "revoked",
        reason: item.revocationReason || "cessationOfOperation",
      }, stableKey(`identity-${item.key}-revoke`));
    }
  }

  await pollCertificates(Math.min(history.managedIdentities.length, 6));
  for (const cert of history.importedCertificates) {
    await api("POST", "/api/v1/certificates", {
      pem: makeSelfSignedCert(cert.commonName, cert.validDays),
      owner_id: owners[cert.ownerKey]?.id,
      deployment_location: cert.deploymentLocation,
      source: cert.source,
    }, stableKey(`cert-import-${cert.key}`));
  }

  await api("POST", "/api/v1/secrets/store", {
    name: "payments/db/password",
    value: runtimeDemoValue("payments-db-password"),
  }, stableKey("secret-payments-db"));
  await api("PUT", "/api/v1/secrets/store/payments/db/password", {
    value: runtimeDemoValue("payments-db-password-rotated"),
  }, stableKey("secret-payments-db-rotate"));
  await api("POST", "/api/v1/secrets/store/import", {
    prefix: "demo",
    values: {
      "stripe/api-key": runtimeDemoValue("stripe-api-key"),
      "github/actions/deploy-token": runtimeDemoValue("github-actions-deploy-token"),
      "aws/iam/rotator": runtimeDemoValue("aws-iam-rotator"),
    },
  }, stableKey("secret-import-tree"));
  const share = await api("POST", "/api/v1/secrets/shares", {
    value: runtimeDemoValue("breakglass-share"),
    ttl_seconds: 86400,
  }, stableKey("secret-share-breakglass"));
  await api("POST", "/api/v1/secrets/pki", {
    common_name: "db-client.demo.trstctl.local",
    ttl_seconds: 3600,
  }, stableKey("secret-pki-db-client"));

  await api("POST", "/api/v1/transit/keys", { name: "payments-data", kind: "aead" }, stableKey("transit-payments-aead"), [409]);
  const encrypted = await api("POST", "/api/v1/transit/encrypt", {
    key: "payments-data",
    plaintext: b64(runtimeDemoValue("card-token")),
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
    await api("POST", "/api/v1/managed-keys/rotate", {
      key_id: managedKey.key_id,
    }, stableKey("managed-key-rsa-rotate"));
  }

  const demoAPIToken = await api("POST", "/api/v1/access/api-tokens", {
    subject: "ci-release-bot",
    scopes: ["certs:read", "secrets:read", "keys:read", "graph:read"],
    expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
  }, stableKey("access-token-release-bot"));
  const jitToken = await api("POST", "/api/v1/ephemeral/api-keys", {
    subject: "incident-rotator",
    scopes: ["certs:read", "keys:read"],
    ttl_seconds: 1800,
  }, stableKey("ephemeral-api-key-incident-rotator"));
  const enrollmentTokens = [];
  for (const token of history.agentTokens) {
    enrollmentTokens.push(await api("POST", "/api/v1/agents/enrollment-tokens", undefined, stableKey(`agent-enrollment-token-${token.key}`)));
  }

  for (const sourceDef of history.discoverySources) {
    const source = await api("POST", "/api/v1/discovery/sources", {
      name: sourceDef.name,
      kind: sourceDef.kind,
      config: {
        ...sourceDef.config,
        demo_observed_at: daysAgo(sourceDef.daysAgo),
      },
    }, stableKey(`discovery-source-${sourceDef.key}`));
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

  console.log("");
  console.log("trstctl demo seed complete");
  console.log(`  URL: ${demoURL}`);
  console.log("  Browser login: click Sign in with SSO, then use demo-admin@trstctl.local");
  console.log(`  Tenant: ${tenant}`);
  console.log(`  Planned 180-day history events: ${history.events.length}`);
  console.log(`  Owners: ${(ownersList?.items || []).length}`);
  console.log(`  Certificate inventory rows: ${(certs?.items || []).length}`);
  console.log(`  Stored secrets: ${(secrets?.items || []).length}`);
  console.log(`  Discovery runs: ${(runs?.items || []).length}`);
  console.log(`  Discovery findings: ${(findings?.items || []).length}`);
  console.log(`  Notifications: ${(notifications?.items || []).length}`);
  console.log(`  One-time share token: ${share?.token || "(replay hidden)"}`);
  console.log(`  Demo API token for ci-release-bot: ${demoAPIToken?.token || "(replay hidden)"}`);
  console.log(`  Ephemeral incident token: ${jitToken?.token || "(replay hidden)"}`);
  console.log(`  Agent enrollment token: ${enrollmentTokens.find((token) => token?.token)?.token || "(replay hidden)"}`);
  console.log("");
}

main().catch((err) => {
  console.error(`demo seed failed: ${err.stack || err.message}`);
  process.exit(1);
});
