import { appendFileSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import net from "node:net";
import tls from "node:tls";

const server = process.env.TRSTCTL_LAB_SERVER ?? "https://trstctl:8443";
const bearer = readFileSync("/seed-state/bootstrap.token", "utf8").trim();
// Pebble creates a fresh issuing hierarchy for every disposable lab. Bootstrap
// captures that run's public root; the static minica certificate authenticates
// Pebble's API TLS but does not validate the leaf certificates it issues.
const pebbleRoot = readFileSync("/lab-evidence/runtime-pebble-root.crt");
const matrix = JSON.parse(readFileSync("/lab/journey-matrix.json", "utf8"));
const startedAt = new Date().toISOString();
const runNonce = startedAt.replace(/[^0-9]/g, "");
const results = [];

function sleep(ms) { return new Promise((resolve) => setTimeout(resolve, ms)); }
function clean(value) {
  return String(value ?? "")
    .replace(/Bearer\s+[A-Za-z0-9._~-]+/gi, "Bearer [redacted]")
    .replace(/-----BEGIN [^-]+-----[\s\S]*?-----END [^-]+-----/g, "[PEM redacted]")
    .slice(0, 800);
}

async function api(method, path, body, idempotencyKey) {
  const headers = { accept: "application/json", authorization: `Bearer ${bearer}` };
  if (body !== undefined) headers["content-type"] = "application/json";
  if (idempotencyKey) headers["idempotency-key"] = idempotencyKey;
  const response = await fetch(server + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  const text = await response.text();
  let parsed = {};
  try { parsed = text ? JSON.parse(text) : {}; } catch { parsed = { detail: "non-JSON response" }; }
  if (!response.ok) throw new Error(`${method} ${path}: HTTP ${response.status}: ${clean(parsed.detail ?? parsed.title)}`);
  return parsed;
}

function tlsProbe(port, servername, requirePebble = false) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect({
      host: "trstctl", port, servername,
      rejectUnauthorized: requirePebble,
      ...(requirePebble ? { ca: pebbleRoot } : {}),
      timeout: 5000,
    }, () => {
      const peer = socket.getPeerCertificate();
      const result = {
        authorized: socket.authorized,
        authorization_error: socket.authorizationError || "",
        subject_cn: peer?.subject?.CN ?? "",
        subject_alt_name: peer?.subjectaltname ?? "",
        issuer_cn: peer?.issuer?.CN ?? "",
        fingerprint_sha256: String(peer?.fingerprint256 ?? "").replaceAll(":", "").toLowerCase(),
        valid_from: peer?.valid_from ?? "",
        valid_to: peer?.valid_to ?? "",
      };
      socket.end(); resolve(result);
    });
    socket.once("timeout", () => socket.destroy(new Error("TLS probe timed out")));
    socket.once("error", reject);
  });
}

// PostgreSQL does not accept a raw TLS ClientHello. A client first sends the
// fixed eight-byte SSLRequest and upgrades the same socket only after the server
// answers "S". This proves what the real daemon serves without pretending its
// wire protocol is ordinary HTTPS or raw TLS.
function postgresTLSProbe(port, servername, requirePebble = false) {
  return new Promise((resolve, reject) => {
    const socket = net.connect({ host: "trstctl", port, timeout: 5000 });
    const fail = (error) => { socket.destroy(); reject(error); };
    socket.once("timeout", () => fail(new Error("PostgreSQL SSLRequest timed out")));
    socket.once("error", fail);
    socket.once("connect", () => {
      const request = Buffer.alloc(8);
      request.writeInt32BE(8, 0);
      request.writeInt32BE(80877103, 4);
      socket.write(request);
    });
    socket.once("data", (chunk) => {
      socket.removeListener("error", fail);
      if (chunk.length === 0 || chunk[0] !== 0x53) {
        fail(new Error("PostgreSQL listener refused TLS upgrade"));
        return;
      }
      socket.pause();
      if (chunk.length > 1) socket.unshift(chunk.subarray(1));
      const secure = tls.connect({
        socket, servername,
        rejectUnauthorized: requirePebble,
        ...(requirePebble ? { ca: pebbleRoot } : {}),
      }, () => {
        const peer = secure.getPeerCertificate();
        const result = {
          authorized: secure.authorized,
          authorization_error: secure.authorizationError || "",
          subject_cn: peer?.subject?.CN ?? "",
          subject_alt_name: peer?.subjectaltname ?? "",
          issuer_cn: peer?.issuer?.CN ?? "",
          fingerprint_sha256: String(peer?.fingerprint256 ?? "").replaceAll(":", "").toLowerCase(),
          valid_from: peer?.valid_from ?? "",
          valid_to: peer?.valid_to ?? "",
          negotiation: "postgresql-sslrequest",
        };
        secure.end(); resolve(result);
      });
      secure.once("error", reject);
      secure.resume();
    });
  });
}

async function waitFor(description, fn, timeoutMs = 180000) {
  const deadline = Date.now() + timeoutMs;
  let last;
  while (Date.now() < deadline) {
    try { last = await fn(); if (last) return last; } catch (error) { last = clean(error.message); }
    await sleep(1000);
  }
  throw new Error(`${description} did not converge: ${clean(typeof last === "string" ? last : JSON.stringify(last))}`);
}

async function ensureDNSProvider() {
  const listed = await api("GET", "/api/v1/acme/dns-01/provider-configs?limit=100");
  const existing = (listed.items ?? []).find((item) => item.name === "Local Pebble DNS validation");
  if (existing) return existing;
  return api("POST", "/api/v1/acme/dns-01/provider-configs", {
    name: "Local Pebble DNS validation",
    provider: "webhook",
    zone: "partner-lab.example.com",
    config: { endpoint: "http://127.0.0.1:8056" },
    credential_refs: {},
    caa_issuer_domain: "pebble.local",
    allowed_methods: ["dns-01"],
    allow_wildcards: false,
    allow_upstream_dv: true,
  }, "partner-lab-dns-provider-v1");
}

async function ownerID() {
  const listed = await api("GET", "/api/v1/owners?limit=100");
  const owner = (listed.items ?? []).find((item) => item.name === "Payments API") ?? listed.items?.[0];
  if (!owner?.id) throw new Error("seeded owner inventory is empty");
  return owner.id;
}

async function waitForAgent() {
  return waitFor("front-door collector enrollment", async () => {
    const listed = await api("GET", "/api/v1/agents?limit=100");
    // The agent collection deliberately uses `agents`, not the generic `items`
    // envelope used by most inventory routes. Presence is the live heartbeat
    // verdict; status is the enrollment lifecycle state.
    return (listed.agents ?? []).find((agent) =>
      agent.name === "partner-lab-frontdoors" &&
      agent.status === "active" &&
      agent.presence?.state === "online" &&
      ["host", "network"].every((role) => (agent.roles ?? []).includes(role))
    ) || false;
  }, 90000);
}

const targets = [
  { connector: "apache", dns: "apache.partner-lab.example.com", port: 10443, config: { cert_path: "/lab/tls/apache.crt", key_path: "/lab/tls/apache.key" } },
  { connector: "nginx", dns: "nginx.partner-lab.example.com", port: 10444, config: { cert_path: "/lab/tls/nginx.crt", key_path: "/lab/tls/nginx.key" } },
  { connector: "haproxy", dns: "haproxy.partner-lab.example.com", port: 10445, config: { crt_path: "/lab/tls/haproxy.pem", config_path: "/lab/haproxy.cfg" } },
  { connector: "caddy", dns: "caddy.partner-lab.example.com", port: 10446, config: { cert_path: "/lab/tls/caddy.crt", key_path: "/lab/tls/caddy.key" } },
  { connector: "traefik", dns: "traefik.partner-lab.example.com", port: 10447, config: { cert_path: "/lab/tls/traefik.crt", key_path: "/lab/tls/traefik.key", config_path: "/lab/tls/traefik-dynamic.yml" } },
  {
    connector: "postgresql", dns: "postgresql.partner-lab.example.com", port: 10448,
    config: { cert_path: "/lab/tls/postgresql.crt", key_path: "/lab/tls/postgresql.key" },
    probe: postgresTLSProbe,
    raw_tls_discovery: false,
    stages: ["understand", "configure", "preview", "execute", "observe", "recover", "verify", "automate"],
    remaining_stage: "protocol-aware discovery",
  },
];

function probeTarget(target, requirePebble = false) {
  return (target.probe ?? tlsProbe)(target.port, target.dns, requirePebble);
}

function normalizedFingerprint(value) {
  return String(value ?? "").replace(/^sha256:/i, "").replaceAll(":", "").toLowerCase();
}

async function waitForDelivery(identityID, targetName, connector, description, excludedID = "", excludedFingerprint = "") {
  return waitFor(description, async () => {
    return findDelivery((item) => item.id !== excludedID && item.target === targetName &&
      item.connector === connector && ["delivered", "verified"].includes(item.status) && normalizedFingerprint(item.fingerprint) &&
      normalizedFingerprint(item.fingerprint) !== normalizedFingerprint(excludedFingerprint),
    identityID);
  });
}

// A retained partner lab intentionally accumulates evidence. Delivery ids are
// UUIDs and the API paginates by UUID order, not creation time, so reading only
// the first page eventually makes a fresh receipt disappear at random. Walk the
// bounded cursor chain and stop as soon as the exact predicate is found.
async function findDelivery(predicate, identityID = "") {
  let after = "";
  for (let pageNumber = 0; pageNumber < 100; pageNumber += 1) {
    const query = new URLSearchParams({ limit: "100" });
    if (identityID) query.set("identity_id", identityID);
    if (after) query.set("cursor", after);
    const page = await api("GET", `/api/v1/connectors/deliveries?${query.toString()}`);
    const found = (page.items ?? []).find(predicate);
    if (found) return found;
    after = String(page.next_cursor ?? "");
    if (!after) return false;
  }
  throw new Error("connector delivery pagination exceeded 100 pages");
}

async function ensureNetworkDiscoverySource() {
  const segmentName = "partner-lab-loopback";
  const coverage = await api("GET", "/api/v1/discovery/coverage");
  let segment = (coverage.segments ?? []).find((item) => item.name === segmentName);
  if (!segment) {
    segment = await api("POST", "/api/v1/discovery/segments", {
      name: segmentName,
      ranges: ["127.0.0.1"],
      staleness_hours: 1,
    }, "partner-lab-discovery-segment-v1");
  }
  const sources = await api("GET", "/api/v1/discovery/sources?limit=100");
  let source = (sources.items ?? []).find((item) => item.name === "partner-lab-front-door-tls-v2");
  if (!source) {
    source = await api("POST", "/api/v1/discovery/sources", {
      name: "partner-lab-front-door-tls-v2",
      kind: "network",
      config: {
        segment: segmentName,
        targets: targets.filter((target) => target.raw_tls_discovery !== false).map((target) => `127.0.0.1:${target.port}`),
        // Loopback is denied by the scanner unless the operator explicitly
        // opts in. This lab's declared segment is the exact one-host address,
        // so the exception cannot broaden to RFC1918 or arbitrary endpoints.
        allow_loopback: true,
      },
    }, "partner-lab-discovery-source-v2");
  }
  const preview = await api("POST", "/api/v1/discovery/plans/preview", {
    name: source.name,
    kind: source.kind,
    config: source.config,
  });
  const rawTLSTargetCount = targets.filter((target) => target.raw_tls_discovery !== false).length;
  if (!preview.ready || preview.side_effects || preview.normalized_target_count !== rawTLSTargetCount) {
    throw new Error(`network discovery preview was not ready, effect-free, and bound to ${rawTLSTargetCount} raw-TLS targets`);
  }
  return { source, segment, preview };
}

async function runNetworkDiscovery(source, phase) {
  const queued = await api("POST", "/api/v1/discovery/runs", {
    source_id: source.id,
    dry_run: false,
  }, `partner-lab-discovery-${phase}-${Date.now()}`);
  const completed = await waitFor(`${phase} front-door network discovery`, async () => {
    const run = await api("GET", `/api/v1/discovery/runs/${encodeURIComponent(queued.id)}`);
    if (["failed", "partial"].includes(run.status)) throw new Error(`${phase} discovery ended ${run.status}: ${clean(run.error)}`);
    return run.status === "succeeded" ? run : false;
  }, 90000);
  const page = await api("GET", `/api/v1/discovery/findings?run_id=${encodeURIComponent(completed.id)}&limit=100`);
  const findings = page.items ?? [];
  const rawTLSTargetCount = targets.filter((target) => target.raw_tls_discovery !== false).length;
  if (completed.discovered !== rawTLSTargetCount || findings.length !== rawTLSTargetCount) {
    throw new Error(`${phase} discovery observed ${findings.length}/${rawTLSTargetCount} expected raw-TLS listeners`);
  }
  return {
    id: `network-discovery-${phase}`,
    class: "real_local",
    status: "pass",
    stages: ["configure", "preview", "execute", "observe", "verify", "automate"],
    run_id: completed.id,
    source_id: source.id,
    segment: completed.segment,
    executed_by_agent_id: completed.executed_by_agent_id,
    targets: completed.targets,
    discovered: completed.discovered,
    findings: findings.map((item) => ({ ref: item.ref, fingerprint: item.fingerprint })),
  };
}

async function runTargetJourney(target, owner) {
  const before = await probeTarget(target, false);
	const targetName = `Partner lab ${target.connector.toUpperCase()} listener ${runNonce}`;
	const targetConfig = {
		...target.config,
		executor: "agent",
		required_agent_role: "host",
		lab_class: "real_local",
	};
	if (target.raw_tls_discovery !== false) {
		targetConfig.verify_address = `127.0.0.1:${target.port}`;
		targetConfig.verify_server_name = target.dns;
	}
  const plan = {
    owner_id: owner,
    identity_name: target.dns,
    target: {
      name: targetName,
      connector: target.connector,
      enabled: true,
      config: targetConfig,
    },
    issuer: { source: "external", id: "local-pebble" },
    reason: `partner lab ${target.connector} external-CA lifecycle`,
  };
  const preview = await api("POST", "/api/v1/lifecycle/endpoint-bindings/preview", plan);
  if (!preview.ready || !preview.effect_free || !preview.request_fingerprint) throw new Error("endpoint-binding preview was not ready and effect-free");
  // Bind retained-lab idempotency to the exact reviewed plan. An identical
  // rerun returns the original identity and target; a deliberate plan change
  // gets a distinct key instead of colliding with stale request bytes.
  const planKey = String(preview.request_fingerprint).replace(/^sha256:/, "");
  const created = await api("POST", "/api/v1/lifecycle/endpoint-bindings", {
    ...plan, preview_fingerprint: preview.request_fingerprint,
  }, `partner-lab-binding-${target.connector}-${planKey}`);
  const delivery = await waitForDelivery(created.identity.id, created.target.name, target.connector,
    `${target.connector} identity-bound delivery receipt`);
  const after = await waitFor(`${target.connector} external certificate deployment`, async () => {
    const probe = await probeTarget(target, true);
    return probe.authorized && probe.subject_alt_name.split(", ").includes(`DNS:${target.dns}`) &&
      probe.fingerprint_sha256 === normalizedFingerprint(delivery.fingerprint) ? probe : false;
  });
  const dryRun = await api("POST", `/api/v1/connectors/targets/${encodeURIComponent(created.target.id)}/test`, {}, `partner-lab-dry-run-${target.connector}-${created.target.id}`);
  await waitFor(`${target.connector} target-vantage dry run`, async () => {
    return findDelivery((item) => item.target === created.target.name && item.connector === target.connector && item.status === "dry_run_planned");
  }, 60000);
  return {
    id: target.connector,
    class: "real_local",
    status: "pass",
    stages: target.stages ?? ["discover", "understand", "configure", "preview", "execute", "observe", "verify", "automate"],
		...(target.remaining_stage ? { remaining_stage: target.remaining_stage } : {}),
    issuer: created.issuer,
    identity_id: created.identity.id,
    target_id: created.target.id,
    target_name: created.target.name,
    delivery_id: delivery.id,
    delivery_status: delivery.status,
    preview_fingerprint: preview.request_fingerprint,
    before_fingerprint: before.fingerprint_sha256,
    after_fingerprint: after.fingerprint_sha256,
    changed_from_baseline: before.fingerprint_sha256 !== after.fingerprint_sha256,
    tls: after,
    dry_run_status: dryRun.status,
  };
}

async function runRenewAndRollbackJourney(deployed, target) {
	const label = target.connector.toUpperCase();
	const reason = `partner lab proves ${target.connector} renewal and executable host rollback`;
	const transition = { to: "renewing", reason };
  const preview = await api("POST", `/api/v1/identities/${encodeURIComponent(deployed.identity_id)}/transitions/preview`, transition);
  if (!preview.ready || preview.from !== "deployed" || preview.to !== "renewing" ||
      (preview.preview_writes ?? []).length !== 0 || (preview.preview_external_effects ?? []).length !== 0) {
    throw new Error("renewal preview was not ready, effect-free, and bound to the deployed identity");
  }
	await api("POST", `/api/v1/identities/${encodeURIComponent(deployed.identity_id)}/transitions`, {
		...transition,
		expected_version: preview.expected_version,
	}, `partner-lab-${target.connector}-renew-${runNonce}`);
	const renewalDelivery = await waitForDelivery(deployed.identity_id, deployed.target_name, target.connector,
		`${label} successor delivery receipt`, deployed.delivery_id, deployed.after_fingerprint);
	const renewed = await waitFor(`${label} successor certificate deployment`, async () => {
		const probe = await probeTarget(target, true);
		return probe.authorized && probe.fingerprint_sha256 !== deployed.after_fingerprint &&
			probe.fingerprint_sha256 === normalizedFingerprint(renewalDelivery.fingerprint) ? probe : false;
	});

	const queued = await api("POST", `/api/v1/connectors/targets/${encodeURIComponent(deployed.target_id)}/rollback`, {
		identity_id: deployed.identity_id,
		reason: "partner lab restores the proven predecessor after renewal",
	}, `partner-lab-${target.connector}-rollback-${runNonce}`);
	if (queued.status !== "rollback_queued") throw new Error(`rollback API status was ${clean(queued.status)}, not rollback_queued`);
	const receipt = await waitFor(`${label} executed rollback receipt`, async () => {
		const item = await findDelivery((candidate) => candidate.outbox_id === queued.outbox_id &&
			["rolled_back", "rollback_refused", "rollback_failed", "failed"].includes(candidate.status), deployed.identity_id);
		if (!item) return false;
		if (item.status !== "rolled_back") {
			throw new Error(`rollback ended ${clean(item.status)}: ${clean(item.detail || item.reason)}`);
		}
		return item;
	}, 60000);
	const restored = await waitFor(`${label} predecessor restoration`, async () => {
		const probe = await probeTarget(target, true);
		return probe.authorized && probe.fingerprint_sha256 === deployed.after_fingerprint &&
			probe.fingerprint_sha256 === normalizedFingerprint(receipt.fingerprint) ? probe : false;
	});
	return {
		id: `${target.connector}-renew-and-rollback`,
    class: "real_local",
    status: "pass",
    stages: ["understand", "preview", "execute", "observe", "recover", "verify", "automate"],
    identity_id: deployed.identity_id,
    target_id: deployed.target_id,
    renewal_preview_fingerprint: preview.request_fingerprint,
    renewal_delivery_id: renewalDelivery.id,
    renewal_delivery_status: renewalDelivery.status,
    predecessor_fingerprint: deployed.after_fingerprint,
    successor_fingerprint: renewed.fingerprint_sha256,
    restored_fingerprint: restored.fingerprint_sha256,
    rollback_receipt_id: receipt.id,
    rollback_status: receipt.status,
  };
}

try {
  await ensureDNSProvider();
  const owner = await ownerID();
  const agent = await waitForAgent();
  results.push({ id: "front-door-collector", class: "real_local", status: "pass", agent_id: agent.id, roles: agent.roles ?? ["host", "network"] });
  const discovery = await ensureNetworkDiscoverySource();
  results.push(await runNetworkDiscovery(discovery.source, "baseline"));
  for (const target of targets) {
    try { results.push(await runTargetJourney(target, owner)); }
    catch (error) { results.push({ id: target.connector, class: "real_local", status: "fail", error: clean(error.message) }); }
  }
	for (const target of targets) {
		const deployed = results.find((item) => item.id === target.connector && item.status === "pass");
		if (!deployed) continue;
		try { results.push(await runRenewAndRollbackJourney(deployed, target)); }
		catch (error) { results.push({ id: `${target.connector}-renew-and-rollback`, class: "real_local", status: "fail", error: clean(error.message) }); }
	}
  results.push(await runNetworkDiscovery(discovery.source, "after-deploy"));
  try {
    const alertEvidencePath = "/lab-evidence/alerts.ndjson";
    const countAlertReceipts = () => existsSync(alertEvidencePath)
      ? readFileSync(alertEvidencePath, "utf8").split("\n").filter(Boolean).length
      : 0;
    const beforeAlertReceipts = countAlertReceipts();
    const queued = await api("POST", "/api/v1/notification-channels/opsgenie/test", {
      subject: "Partner lab expiry alert path",
      severity: "critical",
      detail: "Synthetic local delivery proving the same bounded incident channel used by certificate expiry automation.",
    }, `partner-lab-alert-${Date.now()}`);
    const afterAlertReceipts = await waitFor("local alert sink delivery", async () => {
      const count = countAlertReceipts();
      return count > beforeAlertReceipts ? count : false;
    }, 60000);
    results.push({
      id: "expiry-alert-delivery", class: "real_local", status: "pass",
      outbox_id: queued.outbox_id, destination: queued.destination,
      sink_receipts_before: beforeAlertReceipts, sink_receipts_after: afterAlertReceipts,
    });
  } catch (error) {
    results.push({ id: "expiry-alert-delivery", class: "real_local", status: "fail", error: clean(error.message) });
  }
} catch (error) {
  results.push({ id: "lab-bootstrap", class: "real_local", status: "fail", error: clean(error.message) });
}

results.push({ id: "connector-contract-census", class: "faithful_local", status: "scheduled", command: matrix.journeys.find((item) => item.id === "connector-contract-census")?.command });
results.push({ id: "iis-windows-required", class: "external_only", status: "blocked_external", local_coverage: "exact PowerShell, netsh, PFX, rollback, refusal, and API assembly contracts", wall: "a real Windows kernel, IIS certificate store, and HTTP.sys binding are not supplied by Linux containers" });

const failed = results.filter((item) => item.status === "fail");
const receipt = {
  schema_version: 1,
  run_kind: "persistent-partner-lab",
  started_at: startedAt,
  finished_at: new Date().toISOString(),
  status: failed.length ? "fail" : "pass",
  continue_after_failure: true,
  state_retained: true,
  results,
  blocked_external: results.filter((item) => item.status === "blocked_external"),
  secret_handling: "The receipt contains public certificate metadata, resource IDs, statuses, and redacted errors only. Bearer tokens, cookies, private keys, certificate bodies, and alert credentials are excluded.",
};
const encoded = `${JSON.stringify(receipt, null, 2)}\n`;
writeFileSync("/lab-evidence/latest.json", encoded, { mode: 0o600 });
appendFileSync("/lab-evidence/history.ndjson", `${JSON.stringify(receipt)}\n`, { mode: 0o600 });
console.log(JSON.stringify({ status: receipt.status, journeys: results.length, failures: failed.length, evidence: "/lab-evidence/latest.json" }));
if (failed.length) process.exitCode = 1;
