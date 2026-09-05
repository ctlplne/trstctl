import { chmodSync, chownSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import https from "node:https";

const server = "https://trstctl:8443";
const token = readFileSync("/seed-state/bootstrap.token", "utf8").trim();
if (!token) throw new Error("demo seed bootstrap token is empty");

async function api(method, path, body, idempotencyKey) {
  const headers = { accept: "application/json", authorization: `Bearer ${token}` };
  if (body !== undefined) headers["content-type"] = "application/json";
  if (idempotencyKey) headers["idempotency-key"] = idempotencyKey;
  const response = await fetch(server + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  const text = await response.text();
  let parsed = {};
  try { parsed = text ? JSON.parse(text) : {}; } catch { parsed = { detail: "non-JSON response" }; }
  if (!response.ok) throw new Error(`${method} ${path} returned HTTP ${response.status}: ${parsed.detail ?? parsed.title ?? "request failed"}`);
  return parsed;
}

function run(command, args) {
	const result = spawnSync(command, args, { encoding: "utf8" });
	if (result.status !== 0) throw new Error(`${command} failed: ${result.stderr || result.stdout}`);
}

function readPebbleIssuingRoot() {
  const serverRoot = readFileSync("/lab-ca/pebble.minica.crt");
  return new Promise((resolve, reject) => {
    const request = https.get({
      hostname: "pebble",
      port: 15000,
      path: "/roots/0",
      servername: "localhost",
      ca: serverRoot,
      timeout: 5000,
    }, (response) => {
      const chunks = [];
      let size = 0;
      response.on("data", (chunk) => {
        size += chunk.length;
        if (size > 64 * 1024) request.destroy(new Error("Pebble root response exceeded 64 KiB"));
        else chunks.push(chunk);
      });
      response.on("end", () => {
        const body = Buffer.concat(chunks).toString("utf8");
        if (response.statusCode !== 200 || !body.includes("-----BEGIN CERTIFICATE-----")) {
          reject(new Error(`Pebble root endpoint returned HTTP ${response.statusCode ?? 0} without a certificate`));
          return;
        }
        resolve(body);
      });
    });
    request.once("timeout", () => request.destroy(new Error("Pebble root request timed out")));
    request.once("error", reject);
  });
}

async function waitForHealth() {
  for (let attempt = 0; attempt < 90; attempt += 1) {
    try { if ((await fetch(server + "/healthz")).ok) return; } catch {}
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
  throw new Error("control plane did not become healthy in 90 seconds");
}

await waitForHealth();
for (const path of ["/frontdoors-state", "/frontdoors-state/rollbacks", "/frontdoors-tls", "/lab-evidence"]) {
  mkdirSync(path, { recursive: true, mode: 0o700 });
  chownSync(path, 65532, 65532);
  chmodSync(path, 0o700);
}
const pebbleIssuingRoot = await readPebbleIssuingRoot();
writeFileSync("/lab-evidence/runtime-pebble-root.crt", pebbleIssuingRoot, { mode: 0o600 });
chownSync("/lab-evidence/runtime-pebble-root.crt", 65532, 65532);
chmodSync("/lab-evidence/runtime-pebble-root.crt", 0o600);

const bundle = `${readFileSync("/public-trust/control-plane.crt", "utf8").trim()}\n${readFileSync("/trstctl-data/ca/agent-ca.crt", "utf8").trim()}\n`;
writeFileSync("/frontdoors-state/ca-bundle.pem", bundle, { mode: 0o600 });

const subjects = [
  ["apache", "apache.partner-lab.example.com"],
  ["nginx", "nginx.partner-lab.example.com"],
  ["haproxy", "haproxy.partner-lab.example.com"],
  ["caddy", "caddy.partner-lab.example.com"],
  ["traefik", "traefik.partner-lab.example.com"],
];
for (const [name, dns] of subjects) {
  const cert = `/frontdoors-tls/${name}.crt`;
  const key = `/frontdoors-tls/${name}.key`;
  const pem = `/frontdoors-tls/${name}.pem`;
  if (!existsSync(cert) || !existsSync(key)) {
    run("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", cert,
      "-subj", `/CN=${dns}`, "-addext", `subjectAltName=DNS:${dns}`,
      "-addext", "basicConstraints=critical,CA:FALSE",
      "-addext", "keyUsage=critical,digitalSignature,keyEncipherment",
      "-addext", "extendedKeyUsage=serverAuth", "-days", "1"]);
  }
  if (name === "haproxy") writeFileSync(pem, `${readFileSync(cert, "utf8").trim()}\n${readFileSync(key, "utf8").trim()}\n`, { mode: 0o600 });
}

const certPath = "/frontdoors-state/agent.crt";
const tokenPath = "/frontdoors-state/bootstrap.token";
if (!existsSync(certPath) && !existsSync(tokenPath)) {
  const minted = await api("POST", "/api/v1/agents/enrollment-tokens", {
    allowed_identity: "partner-lab-frontdoors",
    roles: ["host", "network"],
  }, `partner-lab-frontdoors-enrollment-${Date.now()}`);
  if (typeof minted.token !== "string" || minted.token.length < 20) throw new Error("agent token response was empty");
  writeFileSync(tokenPath, minted.token, { mode: 0o600, flag: "wx" });
}

for (const path of ["/frontdoors-state/ca-bundle.pem", tokenPath, ...subjects.flatMap(([name]) => [
  `/frontdoors-tls/${name}.crt`, `/frontdoors-tls/${name}.key`, ...(name === "haproxy" ? [`/frontdoors-tls/${name}.pem`] : []),
])]) {
  if (!existsSync(path)) continue;
  chownSync(path, 65532, 65532);
  chmodSync(path, 0o600);
}
writeFileSync("/lab-evidence/bootstrap.json", `${JSON.stringify({
  schema_version: 1,
  status: "ready",
  prepared_at: new Date().toISOString(),
  agent_identity: "partner-lab-frontdoors",
  agent_roles: ["host", "network"],
  real_targets: subjects.map(([connector, dns_name]) => ({ connector, dns_name })),
  secret_handling: "one-time token and private keys were written 0600 to named volumes and were not printed",
}, null, 2)}\n`, { mode: 0o600 });
console.log("partner lab bootstrap completed; secret values were not printed");
