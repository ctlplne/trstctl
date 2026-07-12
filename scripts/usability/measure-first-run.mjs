#!/usr/bin/env node
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { performance } from "node:perf_hooks";
import { spawnSync } from "node:child_process";

const root = resolve(new URL("../..", import.meta.url).pathname);
let out = resolve(root, "scripts/usability/first-run-receipt.json");

for (let i = 2; i < process.argv.length; i += 1) {
  const arg = process.argv[i];
  if (arg === "--out") {
    const value = process.argv[i + 1];
    if (!value) {
      fail("--out requires a path");
    }
    out = resolve(process.cwd(), value);
    i += 1;
    continue;
  }
  fail(`unknown argument: ${arg}`);
}

const command = ["npm", "--prefix", "web", "run", "test", "--", "first-run.test.tsx"];
const started = performance.now();
const result = spawnSync(command[0], command.slice(1), {
  cwd: root,
  encoding: "utf8",
  env: process.env,
});
const durationMS = Number((performance.now() - started).toFixed(2));

if (result.status !== 0) {
  process.stdout.write(result.stdout ?? "");
  process.stderr.write(result.stderr ?? "");
  fail(`first-run wizard measurement command failed with exit ${result.status}`);
}

const targetMS = 15 * 60 * 1000;
const receipt = {
  schema_version: 1,
  id: "USABILITY-SLO-001",
  generated_at: process.env.TRSTCTL_USABILITY_RECEIPT_GENERATED_AT || new Date().toISOString(),
  journey: "first-run wizard to issue, deploy, integrate, and enroll",
  measurement_method:
    "Automated Vitest/jsdom user-event walk of the first-run wizard: confirm the signer-backed internal CA, issue the first certificate, deploy it through a served connector, issue through a served upstream CA, open a served dynamic-secret lease, mint an enrollment token, and detect the first agent.",
  command,
  test_anchor: "web/src/__tests__/first-run.test.tsx",
  served_contract_anchors: [
    "web/src/pages/Wizard.tsx",
    "web/src/lib/api.ts",
    "internal/api/api.go",
    "internal/server/bootstrap.go"
  ],
  scope:
    "Measures the assisted UI journey and API-client contract in CI. It excludes human reading/typing time, host package download time, real network latency, and the physical agent installation step.",
  slo: {
    target: "USABILITY-SLO-001: assisted first-run wizard path stays inside a 15 minute time-to-first-certificate budget.",
    target_ms: targetMS,
    freshness_days: 180
  },
  measurements: [
    {
      name: "served_capability_wizard_contract_walk",
      duration_ms: durationMS,
      met: durationMS <= targetMS,
      samples: 1
    }
  ],
  summary: {
    ok: result.status === 0,
    met: durationMS <= targetMS,
    duration_ms: durationMS,
    target_ms: targetMS
  },
  stdout_tail: tail(result.stdout)
};

mkdirSync(dirname(out), { recursive: true });
writeFileSync(out, `${JSON.stringify(receipt, null, 2)}\n`);
console.error(`wrote ${out}`);

function tail(value) {
  const lines = String(value ?? "").trim().split(/\r?\n/).filter(Boolean);
  return lines.slice(-12);
}

function fail(message) {
  console.error(`FAIL: ${message}`);
  process.exit(2);
}
