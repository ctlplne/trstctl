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
