#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, "../..");
const reportPath = path.join(repoRoot, "deploy/supply-chain/dependency-freshness.json");

function fail(message) {
  console.error(`FAIL: ${message}`);
  process.exitCode = 1;
}

function readJSON(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function parseDateOnly(value, field) {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(value)) {
    fail(`${field} must be YYYY-MM-DD`);
    return null;
  }
  const parsed = new Date(`${value}T00:00:00Z`);
  if (Number.isNaN(parsed.getTime())) {
    fail(`${field} is not a valid date: ${value}`);
    return null;
  }
  return parsed;
}

function utcToday() {
  const now = new Date();
  return new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()));
}

function daysBetween(start, end) {
  return Math.floor((end.getTime() - start.getTime()) / 86400000);
}

function parseGoModDirectVersions() {
  const goMod = fs.readFileSync(path.join(repoRoot, "go.mod"), "utf8");
  const versions = new Map();
  for (const line of goMod.split(/\r?\n/)) {
    const match = line.match(/^\s*([^\s()]+)\s+(v[^\s]+)(?:\s+\/\/.*)?$/);
    if (match) {
      versions.set(match[1], match[2]);
    }
  }
  return versions;
}

function parsePackageLockVersions() {
  const lock = readJSON(path.join(repoRoot, "web/package-lock.json"));
  const versions = new Map();
  for (const [pkgPath, meta] of Object.entries(lock.packages ?? {})) {
    if (!pkgPath.startsWith("node_modules/") || !meta?.version) {
      continue;
    }
    versions.set(pkgPath.slice("node_modules/".length), meta.version);
  }
  return versions;
}

const requiredSLOClasses = new Set(["critical-go-runtime", "web-runtime", "developer-tooling", "release-infrastructure"]);
const requiredTracked = new Set([
  "github.com/fergusstrange/embedded-postgres",
  "github.com/nats-io/nats-server/v2",
  "github.com/open-policy-agent/opa",
  "github.com/tetratelabs/wazero",
  "github.com/jackc/pgx/v5",
  "google.golang.org/grpc",
  "react",
  "react-dom",
  "react-router-dom",
  "vite",
  "vitest",
  "tailwindcss",
  "typescript",
]);

const report = readJSON(reportPath);
if (report.schema_version !== 1) {
  fail(`schema_version must be 1, got ${report.schema_version}`);
}

const observedAt = parseDateOnly(report.observed_at, "observed_at");
const maxAge = Number(report.max_report_age_days);
if (!Number.isInteger(maxAge) || maxAge <= 0 || maxAge > 45) {
  fail("max_report_age_days must be a positive integer no larger than 45");
}
if (observedAt) {
  const ageDays = daysBetween(observedAt, utcToday());
  if (ageDays < 0) {
    fail(`observed_at is in the future: ${report.observed_at}`);
  } else if (ageDays > maxAge) {
    fail(`dependency freshness report is ${ageDays} days old, over the ${maxAge}-day budget`);
  }
}

const sloClasses = new Set();
for (const slo of report.freshness_slos ?? []) {
  if (!slo.class || !slo.owner || !Number.isInteger(slo.max_age_days) || slo.max_age_days <= 0) {
    fail(`freshness_slos rows must carry class, owner, and positive max_age_days: ${JSON.stringify(slo)}`);
    continue;
  }
  sloClasses.add(slo.class);
}
for (const required of requiredSLOClasses) {
  if (!sloClasses.has(required)) {
    fail(`missing freshness SLO class ${required}`);
  }
}

const goVersions = parseGoModDirectVersions();
const npmVersions = parsePackageLockVersions();
const tracked = new Set();
const today = utcToday();

for (const upgrade of report.tracked_upgrades ?? []) {
  tracked.add(upgrade.name);
  for (const field of ["ecosystem", "name", "current_version", "latest_observed_version", "update_type", "freshness_slo_class", "owner", "status", "next_review_by", "rationale"]) {
    if (typeof upgrade[field] !== "string" || upgrade[field].trim() === "") {
      fail(`tracked upgrade ${upgrade.name ?? "(unknown)"} has empty ${field}`);
    }
  }
  if (!sloClasses.has(upgrade.freshness_slo_class)) {
    fail(`tracked upgrade ${upgrade.name} references unknown SLO class ${upgrade.freshness_slo_class}`);
  }

  const nextReview = parseDateOnly(upgrade.next_review_by, `${upgrade.name}.next_review_by`);
  if (nextReview && nextReview < today) {
    fail(`tracked upgrade ${upgrade.name} next_review_by ${upgrade.next_review_by} is in the past`);
  }

  if (upgrade.status === "accepted_deferral") {
    const until = parseDateOnly(upgrade.deferral_until, `${upgrade.name}.deferral_until`);
    if (until && until < today) {
      fail(`tracked upgrade ${upgrade.name} deferral_until ${upgrade.deferral_until} is in the past`);
    }
  }

  if (upgrade.ecosystem === "gomod") {
    const actual = goVersions.get(upgrade.name);
    if (!actual) {
      fail(`tracked Go module ${upgrade.name} is not a direct go.mod dependency`);
    } else if (actual !== upgrade.current_version) {
      fail(`tracked Go module ${upgrade.name} current_version=${upgrade.current_version}, go.mod has ${actual}`);
    }
  } else if (upgrade.ecosystem === "npm") {
    const actual = npmVersions.get(upgrade.name);
    if (!actual) {
      fail(`tracked npm package ${upgrade.name} is not present in web/package-lock.json`);
    } else if (actual !== upgrade.current_version) {
      fail(`tracked npm package ${upgrade.name} current_version=${upgrade.current_version}, package-lock has ${actual}`);
    }
  } else {
    fail(`unsupported ecosystem ${upgrade.ecosystem} for ${upgrade.name}`);
  }
}

for (const required of requiredTracked) {
  if (!tracked.has(required)) {
    fail(`missing tracked dependency ${required}`);
  }
}

if (process.exitCode) {
  process.exit(process.exitCode);
}

console.log(`dependency freshness report OK: ${report.tracked_upgrades.length} tracked upgrades, observed ${report.observed_at}`);
