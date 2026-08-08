#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, "../..");
const reportPath = path.join(repoRoot, "deploy/supply-chain/dependency-freshness.json");
// The committed report is the only thing that gates a build: the Makefile target and
// the CI job pass no argument. The single accepted argument is "-", which reads a report
// from stdin, so the CODE-111 guard test can feed the checker a mutated copy of the real
// report and prove the age budget actually fails without writing to the tracked file.
const reportArg = process.argv[2] ?? "";
if (reportArg !== "" && reportArg !== "-") {
  console.error(`FAIL: the only accepted argument is "-" (read the report from stdin), got ${reportArg}`);
  process.exit(1);
}

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

function addDays(date, days) {
  return new Date(date.getTime() + days * 86400000);
}

function formatDateOnly(date) {
  return date.toISOString().slice(0, 10);
}

// AH-fad87256: an age budget and a major-version gap are different debts. A row can sit
// well inside its class age budget and still be two majors behind -- where TypeScript was
// (5.9.3 against a published 7.0.2, in the 90-day developer-tooling class) while this gate
// printed OK. majorOf parses the leading integer of a version and fails closed on anything
// it cannot read as a major, so an unparseable version is never silently skipped.
function majorOf(value, field) {
  const match = /^v?(\d+)\./.exec(typeof value === "string" ? value : "");
  if (!match) {
    fail(`${field} must start with a numeric major version, got ${value}`);
    return null;
  }
  return Number(match[1]);
}

// maxMajorGap is the cap: zero or one major behind is ordinary upgrade-queue work governed
// by the age budget; more than that needs an accepted_deferral that still covers today.
const maxMajorGap = 1;

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
const requiredSecurityLinks = new Set([
  "SEC-f19bdd00",
  "SEC-de4eb072",
  "SEC-5b43d4b3",
  "S-7268c77e",
]);

const report = reportArg === "-" ? JSON.parse(fs.readFileSync(0, "utf8")) : readJSON(reportPath);
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

for (const finding of requiredSecurityLinks) {
  const note = report.security_finding_links?.[finding];
  if (typeof note !== "string" || note.trim() === "") {
    fail(`missing dependency security finding link ${finding}`);
  }
}

const sloClasses = new Set();
const ageBudgetDays = new Map();
for (const slo of report.freshness_slos ?? []) {
  if (!slo.class || !slo.owner || !Number.isInteger(slo.max_age_days) || slo.max_age_days <= 0) {
    fail(`freshness_slos rows must carry class, owner, and positive max_age_days: ${JSON.stringify(slo)}`);
    continue;
  }
  sloClasses.add(slo.class);
  ageBudgetDays.set(slo.class, slo.max_age_days);
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

  let deferralUntil = null;
  if (upgrade.status === "accepted_deferral") {
    deferralUntil = parseDateOnly(upgrade.deferral_until, `${upgrade.name}.deferral_until`);
    if (deferralUntil && deferralUntil < today) {
      fail(`tracked upgrade ${upgrade.name} deferral_until ${upgrade.deferral_until} is in the past`);
    }
  }

  // AH-fad87256: the major-version gap cap. More than one major behind is allowed only
  // while an accepted_deferral is live, so a multi-major pin stays a dated, argued decision
  // instead of drift the age budget alone cannot see. A current_version whose major is
  // newer than the observed latest means the observation is stale, not that the row is
  // ahead, so that fails too.
  const currentMajor = majorOf(upgrade.current_version, `${upgrade.name}.current_version`);
  const latestMajor = majorOf(upgrade.latest_observed_version, `${upgrade.name}.latest_observed_version`);
  if (currentMajor !== null && latestMajor !== null) {
    const majorGap = latestMajor - currentMajor;
    if (majorGap < 0) {
      fail(`tracked upgrade ${upgrade.name} current_version ${upgrade.current_version} is a newer major than latest_observed_version ${upgrade.latest_observed_version}: re-observe the row`);
    } else if (majorGap > maxMajorGap) {
      if (upgrade.status !== "accepted_deferral") {
        fail(`tracked upgrade ${upgrade.name} is ${majorGap} majors behind (${upgrade.current_version} against ${upgrade.latest_observed_version}), over the ${maxMajorGap}-major gap cap: upgrade it, or record status accepted_deferral with a dated deferral_until whose rationale names the next hop`);
      } else if (!deferralUntil || deferralUntil < today) {
        fail(`tracked upgrade ${upgrade.name} is ${majorGap} majors behind (${upgrade.current_version} against ${upgrade.latest_observed_version}), over the ${maxMajorGap}-major gap cap, and its deferral_until ${upgrade.deferral_until || "(missing)"} does not cover today`);
      }
    }
  }

  // CODE-111: the declared SLO has to bite. Every row that is not already "current"
  // records behind_since -- the earliest date this repository observed the row as not
  // current -- and that age is measured against the max_age_days of its class. Rolling
  // next_review_by forward no longer keeps a stale dependency compliant; the only way
  // past the budget is an accepted_deferral whose deferral_until still covers today.
  if (upgrade.status !== "current") {
    if (typeof upgrade.behind_since !== "string" || upgrade.behind_since.trim() === "") {
      fail(`tracked upgrade ${upgrade.name} has status ${upgrade.status} and must record behind_since (YYYY-MM-DD), the date it was first observed behind its latest release`);
    } else {
      const behindSince = parseDateOnly(upgrade.behind_since, `${upgrade.name}.behind_since`);
      const budgetDays = ageBudgetDays.get(upgrade.freshness_slo_class);
      if (behindSince && behindSince > today) {
        fail(`tracked upgrade ${upgrade.name} behind_since ${upgrade.behind_since} is in the future`);
      } else if (behindSince && budgetDays !== undefined) {
        const behindDays = daysBetween(behindSince, today);
        const breached = behindDays > budgetDays;
        const deferralLive = upgrade.status === "accepted_deferral" && deferralUntil && deferralUntil >= today;

        if (breached && upgrade.status !== "accepted_deferral") {
          fail(`tracked upgrade ${upgrade.name} has been behind since ${upgrade.behind_since} (${behindDays} days), over the ${budgetDays}-day ${upgrade.freshness_slo_class} budget: upgrade it, or record status accepted_deferral with a dated deferral_until`);
        } else if (breached && !deferralLive) {
          fail(`tracked upgrade ${upgrade.name} has been behind since ${upgrade.behind_since} (${budgetDays} day budget, ${behindDays} days behind), over the ${budgetDays}-day ${upgrade.freshness_slo_class} budget, and its deferral_until ${upgrade.deferral_until || "(missing)"} does not cover today`);
        } else {
          // AUD-15: a review scheduled AFTER the deadline it exists to protect is
          // a deadline the policy has already given up on.
          //
          // This is what let five critical-go-runtime rows go red the moment the
          // budget started biting. They were authored 36 days behind with a review
          // 30 days out, so they were always going to breach nine days before
          // anyone was scheduled to look. Nothing was misfiled: a 45-day budget
          // measured from the upstream release date, combined with a 30-day report
          // cycle, GUARANTEES that for any row already 15+ days behind when the
          // report is written. A policy that cannot satisfy itself must be
          // impossible to commit, not discovered when CI turns red.
          //
          // The deadline is the deferral_until when one is live, because that date
          // -- not the original budget -- is the promise the row is making. It is
          // skipped only for a row that has already breached with no cover, where
          // the failure above is the point and scheduling advice is noise.
          const reviewDeadline = deferralLive ? deferralUntil : addDays(behindSince, budgetDays);
          if (nextReview && reviewDeadline && nextReview > reviewDeadline) {
            const which = deferralLive
              ? `its deferral_until ${upgrade.deferral_until}`
              : `the ${budgetDays}-day ${upgrade.freshness_slo_class} budget, which expires ${formatDateOnly(reviewDeadline)}`;
            fail(`tracked upgrade ${upgrade.name} schedules next_review_by ${upgrade.next_review_by} AFTER ${which}: a review booked past its own deadline cannot prevent the breach it exists to prevent, so move the review earlier or record a deferral that covers it`);
          }
        }
      }
    }
  } else if (typeof upgrade.behind_since === "string" && upgrade.behind_since.trim() !== "") {
    fail(`tracked upgrade ${upgrade.name} is status current but still records behind_since ${upgrade.behind_since}`);
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
