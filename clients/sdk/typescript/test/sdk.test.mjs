import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";

const sdkDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

let loaded;
async function loadSdk() {
  if (loaded) return loaded;
  const out = mkdtempSync(path.join(tmpdir(), "trstctl-ts-sdk-"));
  writeFileSync(path.join(out, "package.json"), '{"type":"module"}\n');
  execFileSync(
    process.execPath,
    [
      path.join(sdkDir, "node_modules", "typescript", "bin", "tsc"),
      "--target",
      "ES2022",
      "--module",
      "ES2022",
      "--moduleResolution",
      "Bundler",
      "--lib",
      "ES2022,DOM",
      "--strict",
      "--skipLibCheck",
      "--esModuleInterop",
      "--outDir",
      out,
      path.join(sdkDir, "src/index.ts"),
    ],
    { cwd: sdkDir, stdio: "inherit" },
  );
  loaded = import(pathToFileURL(path.join(out, "index.js")).href).finally(() => {
    process.once("exit", () => rmSync(out, { recursive: true, force: true }));
  });
  return loaded;
}

function json(status, body, headers = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", ...headers },
  });
}

function problem(status, body, headers = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/problem+json", ...headers },
  });
}

test("workload handoff preserves exact signed IDs and absent legacy fields", async () => {
  const { TrstctlClient } = await loadSdk();
  const id = "spiffe://served.test/_trstctl/v1/tenant/11111111-1111-4111-8111-111111111111/attested/method/k8s_sat/subject/ns/QA/sa/Web";
  for (const [method, route, list] of [
    ["POST", "/api/v1/broker/agent-identities", false],
    ["POST", "/api/v1/workloads/attested-issuance", false],
    ["POST", "/api/v1/ephemeral", false],
    ["GET", "/api/v1/broker/agent-identities/certificate-7", false],
    ["GET", "/api/v1/broker/agent-identities", true],
  ]) {
    for (const retained of [false, true]) {
      // Transport fixture only; served tests independently inspect real leaves.
      const row = { subject: "friendly-label", ...(retained ? {} : { spiffe_id: id }) };
      const body = list ? { items: [row], next_cursor: "" } : row;
      let calls = 0;
      const client = new TrstctlClient({
        baseUrl: "https://served.test", token: "fixture-token", retry: { maxAttempts: 1 },
        fetch: async (url, init) => {
          calls++;
          assert.equal(new URL(url).pathname, route);
          assert.equal(init.method, method);
          assert.equal(Boolean(init.headers["Idempotency-Key"]), method === "POST");
          return json(200, body);
        },
      });
      assert.deepEqual(await client.request(route, { method, ...(method === "POST" ? { body: {} } : {}) }), body);
      assert.equal(calls, 1);
    }
  }
});

test("auth, tenant, idempotency, and core resources use the served paths", async () => {
  const { TrstctlClient } = await loadSdk();
  const calls = [];
  const fetch = async (url, init = {}) => {
    calls.push({ url: String(url), init });
    const method = init.method ?? "GET";
    const pathName = new URL(String(url)).pathname;
    if (method === "POST" && pathName === "/api/v1/owners") {
      return json(201, { id: "owner-1", kind: "workload", name: "payments" });
    }
    if (method === "POST" && pathName === "/api/v1/identities") {
      return json(201, { id: "identity-1", kind: "x509_certificate", name: "payments", owner_id: "owner-1", status: "pending" });
    }
    if (method === "POST" && pathName === "/api/v1/identities/identity-1/transitions") {
      return json(200, { id: "identity-1", kind: "x509_certificate", name: "payments", owner_id: "owner-1", status: "issued" });
    }
    if (method === "GET" && pathName === "/api/v1/certificates") {
      assert.equal(new URL(String(url)).searchParams.get("limit"), "50");
      return json(200, { items: [{ id: "cert-1", subject: "CN=payments" }] });
    }
    if (method === "GET" && pathName === "/api/v1/owners") {
      const cursor = new URL(String(url)).searchParams.get("cursor");
      return cursor
        ? json(200, { items: [{ id: "owner-2", kind: "workload", name: "api" }] })
        : json(200, { items: [{ id: "owner-1", kind: "workload", name: "payments" }], next_cursor: "next" });
    }
    return problem(404, { title: "not found" });
  };

  const client = new TrstctlClient({
    baseUrl: "https://trstctl.example.test/",
    token: "trst_fixture",
    tenant: "tenant-a",
    fetch,
    retry: { maxAttempts: 1 },
  });

  const issued = await client.issueFirstCertificate("payments");
  assert.equal(issued.status, "issued");

  const certs = await client.listCertificates({ limit: 50 });
  assert.equal(certs.items[0].id, "cert-1");

  const owners = [];
  for await (const owner of client.owners({ limit: 1 })) owners.push(owner.name);
  assert.deepEqual(owners, ["payments", "api"]);

  const mutationCalls = calls.filter((c) => c.init.method === "POST");
  assert.equal(mutationCalls.length, 3);
  for (const call of calls) {
    assert.equal(call.init.headers.Authorization, "Bearer trst_fixture");
    assert.equal(call.init.headers["X-Tenant-ID"], "tenant-a");
    assert.equal(call.init.headers["User-Agent"], "trstctl-ts-sdk/1");
  }
  for (const call of mutationCalls) {
    assert.match(call.init.headers["Idempotency-Key"], /^idem-|^[0-9a-f-]{36}$/i);
    assert.equal(call.init.headers["Content-Type"], "application/json");
  }
});

test("retry preserves mutation idempotency and parses problem+json", async () => {
  const { TrstctlClient, isProblem } = await loadSdk();
  const calls = [];
  const fetch = async (url, init = {}) => {
    calls.push({ url: String(url), init });
    if (calls.length === 1) return problem(429, { title: "rate limited", detail: "slow down", reason: "burst" }, { "Retry-After": "0" });
    return json(201, { id: "owner-1", kind: "workload", name: "payments" });
  };
  const client = new TrstctlClient({
    baseUrl: "https://trstctl.example.test",
    token: "trst_fixture",
    fetch,
    retry: { maxAttempts: 2, baseDelayMs: 1, maxDelayMs: 1 },
  });

  const owner = await client.createOwner({ kind: "workload", name: "payments" });
  assert.equal(owner.id, "owner-1");
  assert.equal(calls.length, 2);
  assert.equal(calls[0].init.headers["Idempotency-Key"], calls[1].init.headers["Idempotency-Key"]);

  const noRetry = new TrstctlClient({
    baseUrl: "https://trstctl.example.test",
    fetch: async () => problem(400, { title: "bad request", detail: "missing field", code: "bad_request" }),
    retry: { maxAttempts: 1 },
  });
  await assert.rejects(
    () => noRetry.getIdentity("missing"),
    (err) => {
      assert.equal(isProblem(err), true);
      assert.equal(err.httpStatus, 400);
      assert.equal(err.title, "bad request");
      assert.equal(err.detail, "missing field");
      assert.equal(err.extensions.code, "bad_request");
      return true;
    },
  );
});

test("A250: secrets, PKI and revocation use the served routes, hold the key across a Retry-After retry", async () => {
  const { TrstctlClient } = await loadSdk();
  const keys = {};
  const stored = {};
  let firstCreate = 0;
  let retriedAfter = 0;
  const fetch = async (url, init = {}) => {
    const method = init.method ?? "GET";
    const route = `${method} ${new URL(String(url)).pathname}`;
    (keys[route] ??= []).push(init.headers["Idempotency-Key"]);
    const body = init.body ? JSON.parse(init.body) : {};
    if (route === "POST /api/v1/secrets/store") {
      if (keys[route].length === 1) {
        firstCreate = Date.now();
        return problem(503, { title: "busy" }, { "Retry-After": "1" });
      }
      retriedAfter = Date.now() - firstCreate;
      stored[body.name] = { value: body.value, version: 1 };
      return json(201, { name: body.name, version: 1 });
    }
    if (route === "GET /api/v1/secrets/store/app/db%20password") {
      return json(200, { name: "app/db password", ...stored["app/db password"] });
    }
    if (route === "PUT /api/v1/secrets/store/app/db%20password") {
      const next = stored["app/db password"].version + 1;
      stored["app/db password"] = { value: body.value, version: next };
      return json(200, { name: "app/db password", version: next });
    }
    if (route === "DELETE /api/v1/secrets/store/app/db%20password") {
      return new Response(null, { status: 204 });
    }
    if (route === "POST /api/v1/secrets/pki") {
      assert.deepEqual(body, { common_name: "sdk.lab.test", ttl_seconds: 300 });
      return json(201, { certificate_id: "c-1", serial: "0a", common_name: "sdk.lab.test", certificate: "PEM", private_key: "KEY" });
    }
    if (route === "POST /api/v1/certificates/bulk-revoke") {
      assert.deepEqual(body, { certificate_ids: ["c-1"], reason: "superseded" });
      return json(200, { total_matched: 1, total_revoked: 1, total_skipped: 0, total_failed: 0, items: [{ id: "c-1", status: "revoked" }] });
    }
    return problem(404, { title: `no route ${route}` });
  };
  const client = new TrstctlClient({ baseUrl: "https://served.test", token: "fixture-token", fetch, retry: { maxAttempts: 3, baseDelayMs: 10, maxDelayMs: 5000 } });

  const created = await client.createSecret("app/db password", "v1");
  assert.equal(created.version, 1);
  assert.ok(retriedAfter >= 1000, `the retry came ${retriedAfter} ms after Retry-After: 1`);
  const createKeys = keys["POST /api/v1/secrets/store"];
  assert.equal(createKeys.length, 2);
  assert.ok(createKeys[0]);
  assert.equal(createKeys[0], createKeys[1]);
  assert.deepEqual(await client.getSecret("app/db password"), { name: "app/db password", value: "v1", version: 1 });
  assert.equal((await client.rotateSecret("app/db password", "v2", "rotate-1")).version, 2);
  assert.equal(keys["PUT /api/v1/secrets/store/app/db%20password"][0], "rotate-1");
  assert.equal(await client.deleteSecret("app/db password"), undefined);
  const pki = await client.issuePkiSecret("sdk.lab.test", 300);
  const revoked = await client.revokeCertificates([pki.certificate_id], "superseded");
  assert.equal(revoked.total_revoked, 1);
  for (const [route, sent] of Object.entries(keys)) {
    if (!route.startsWith("GET ")) for (const key of sent) assert.ok(key, `${route} carried no Idempotency-Key`);
  }
  await assert.rejects(client.revokeCertificates([], "superseded"), /no certificate IDs/);
});
