#!/usr/bin/env node
// Generate the console's typed capability contract from the one canonical
// feature catalog. This is the frontend half of the bidirectional parity gate:
// backend/catalog changes cannot become a green release until the generated
// contract and the real console route/surface guards agree.
//
// Usage:
//   node scripts/gen-feature-contracts.mjs
//   node scripts/gen-feature-contracts.mjs --check

import { existsSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const WEB = path.resolve(__dirname, "..");
const REPO = path.resolve(WEB, "..");
const CATALOG = path.resolve(REPO, "internal", "featureparity", "feature-map-backlog.json");
const OUT = path.resolve(WEB, "src", "lib", "feature-contracts.gen.ts");

const TOOLS = ["discover", "certificates", "workloads_machines", "secrets", "software_trust", "operations", "platform_integrations"];
const MATURITIES = ["absent", "api_cli_only", "observe_only", "partial_workflow", "complete_vertical_slice"];
const STAGE_STATUSES = ["complete", "not_applicable", "intentional_api_only", "blocked", "missing"];
const STAGE_NAMES = ["discover", "understand", "configure", "preview", "execute", "observe", "recover", "verify", "automate"];
const CLASSIFICATIONS = ["primary", "supporting"];
const SIDE_EFFECTS = ["read_only", "mutating", "mixed"];
const OPERATIONAL_STAGES = new Set(["configure", "preview", "execute", "recover", "verify", "automate"]);
const REPOSITORY_EVIDENCE_PREFIXES = ["clients/", "cmd/", "deploy/", "docs/", "ee/", "internal/", "scripts/", "tools/", "web/"];

function fail(message) {
  throw new Error(`invalid canonical capability catalog: ${message}`);
}

function exactArray(actual, expected, field) {
  if (!Array.isArray(actual) || actual.length !== expected.length || actual.some((value, index) => value !== expected[index])) {
    fail(`${field} must exactly equal ${JSON.stringify(expected)}`);
  }
}

function requiredString(value, field) {
  if (typeof value !== "string" || value.trim() === "") fail(`${field} must be a non-empty string`);
}

function stringArray(value, field, allowEmpty = false) {
  if (!Array.isArray(value) || (!allowEmpty && value.length === 0) || value.some((entry) => typeof entry !== "string" || entry.trim() === "")) {
    fail(`${field} must be ${allowEmpty ? "an" : "a non-empty"} array of non-empty strings`);
  }
}

function computeMaturity(stages) {
  const cells = STAGE_NAMES.map((name) => stages[name]);
  const complete = cells.filter((cell) => cell.status === "complete").length;
  const hasGap = cells.some((cell) => !["complete", "not_applicable"].includes(cell.status));
  const intentionalAPI = cells.filter((cell) => cell.status === "intentional_api_only").length;
  if (complete === 0) return "absent";
  if (!hasGap) return "complete_vertical_slice";
  if (
    stages.automate.status === "complete" &&
    intentionalAPI > 0 &&
    STAGE_NAMES.filter((name) => name !== "automate").every((name) => stages[name].status !== "complete")
  ) {
    return "api_cli_only";
  }
  if (
    stages.discover.status === "complete" &&
    stages.understand.status === "complete" &&
    stages.observe.status === "complete" &&
    stages.configure.status !== "complete" &&
    stages.execute.status !== "complete"
  ) {
    return "observe_only";
  }
  return "partial_workflow";
}

export function validateCatalog(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail("root must be an object");
  const catalog = value;
  if (catalog.schema_version !== 3) fail(`schema_version=${String(catalog.schema_version)}, want 3`);
  exactArray(catalog.canonical_tools, TOOLS, "canonical_tools");
  exactArray(catalog.maturity_values, MATURITIES, "maturity_values");
  exactArray(catalog.stage_status_values, STAGE_STATUSES, "stage_status_values");
  if (!Array.isArray(catalog.items) || catalog.items.length !== 79) fail("items must contain exactly 79 canonical capabilities");

  const ids = new Set();
  for (const [index, item] of catalog.items.entries()) {
    if (!item || typeof item !== "object" || Array.isArray(item)) fail(`items[${index}] must be an object`);
    const prefix = `items[${index}]`;
    requiredString(item.feature_id, `${prefix}.feature_id`);
    if (!/^F(?:[1-9]|[1-7][0-9]|79)$/.test(item.feature_id)) fail(`${prefix}.feature_id=${item.feature_id} is outside F1..F79`);
    if (ids.has(item.feature_id)) fail(`duplicate feature_id ${item.feature_id}`);
    ids.add(item.feature_id);
    requiredString(item.feature, `${prefix}.feature`);
    requiredString(item.domain, `${prefix}.domain`);
    requiredString(item.phase, `${prefix}.phase`);
    if (!Number.isInteger(item.priority)) fail(`${prefix}.priority must be an integer`);

    const contract = item.contract;
    if (!contract || typeof contract !== "object" || Array.isArray(contract)) fail(`${prefix}.contract must be an object`);
    for (const field of [
      "purpose",
      "permission_authority",
      "edition",
      "side_effects",
      "secret_data_handling",
      "owner",
      "target_checkpoint",
      "candidate_sha",
      "freshness",
    ]) {
      requiredString(contract[field], `${prefix}.contract.${field}`);
    }
    if (!TOOLS.includes(contract.tool)) fail(`${prefix}.contract.tool=${String(contract.tool)} is unknown`);
    if (!CLASSIFICATIONS.includes(contract.classification)) fail(`${prefix}.contract.classification=${String(contract.classification)} is unknown`);
    if (!SIDE_EFFECTS.includes(contract.side_effects)) fail(`${prefix}.contract.side_effects=${String(contract.side_effects)} is unknown`);
    if (!MATURITIES.includes(contract.maturity)) fail(`${prefix}.contract.maturity=${String(contract.maturity)} is unknown`);
    if (typeof contract.release_blocking !== "boolean") fail(`${prefix}.contract.release_blocking must be boolean`);
    if (!contract.console_route.startsWith("/")) fail(`${prefix}.contract.console_route must be an absolute product route`);
    stringArray(contract.navigation_entrypoints, `${prefix}.contract.navigation_entrypoints`);
    stringArray(contract.dependencies, `${prefix}.contract.dependencies`, true);
    if (!/^[0-9a-f]{40}$/.test(contract.candidate_sha)) fail(`${prefix}.contract.candidate_sha must be an exact lowercase SHA`);
    if (!/^\d{4}-\d{2}-\d{2}$/.test(contract.freshness) || Number.isNaN(Date.parse(`${contract.freshness}T00:00:00Z`))) {
      fail(`${prefix}.contract.freshness must be YYYY-MM-DD`);
    }

    const stages = contract.stages;
    if (!stages || typeof stages !== "object" || Array.isArray(stages)) fail(`${prefix}.contract.stages must be an object`);
    for (const stageName of STAGE_NAMES) {
      const stage = stages[stageName];
      if (!stage || typeof stage !== "object" || Array.isArray(stage)) fail(`${prefix}.contract.stages.${stageName} must be an object`);
      if (!STAGE_STATUSES.includes(stage.status)) fail(`${prefix}.contract.stages.${stageName}.status=${String(stage.status)} is unknown`);
      if (stage.status === "complete") {
        stringArray(stage.evidence, `${prefix}.contract.stages.${stageName}.evidence`);
        if (typeof stage.reason === "string" && stage.reason.trim() !== "")
          fail(`${prefix}.contract.stages.${stageName} cannot have both complete evidence and a reason`);
        if (OPERATIONAL_STAGES.has(stageName) && stage.evidence.every((entry) => entry === "web/src/lib/navigation.ts")) {
          fail(`${prefix}.contract.stages.${stageName} relies only on the route registry instead of workflow evidence`);
        }
        for (const evidence of stage.evidence) {
          if (!REPOSITORY_EVIDENCE_PREFIXES.some((candidate) => evidence.startsWith(candidate))) continue;
          const absolute = path.resolve(REPO, evidence);
          if (absolute !== REPO && !absolute.startsWith(`${REPO}${path.sep}`))
            fail(`${prefix}.contract.stages.${stageName} evidence path escapes the repository`);
          if (!existsSync(absolute)) fail(`${prefix}.contract.stages.${stageName} evidence path does not exist: ${evidence}`);
        }
      } else {
        requiredString(stage.reason, `${prefix}.contract.stages.${stageName}.reason`);
        if (Array.isArray(stage.evidence) && stage.evidence.length > 0) fail(`${prefix}.contract.stages.${stageName} cannot claim evidence while incomplete`);
      }
    }
    if (contract.classification === "primary") {
      for (const stageName of STAGE_NAMES.filter((name) => name !== "automate")) {
        if (stages[stageName].status === "intentional_api_only") fail(`${prefix}.contract primary stage ${stageName} cannot be intentional_api_only`);
      }
    }
    const maturity = computeMaturity(stages);
    if (contract.maturity !== maturity) fail(`${prefix}.contract.maturity=${contract.maturity} contradicts computed maturity=${maturity}`);
    const releaseBlocking = contract.classification === "primary" && maturity !== "complete_vertical_slice";
    if (contract.release_blocking !== releaseBlocking) fail(`${prefix}.contract.release_blocking contradicts classification and computed maturity`);
  }
  return catalog;
}

export function loadCanonicalCatalog() {
  return validateCatalog(JSON.parse(readFileSync(CATALOG, "utf8")));
}

function project(item) {
  const c = item.contract;
  return {
    featureId: item.feature_id,
    feature: item.feature,
    domain: item.domain,
    phase: item.phase,
    priority: item.priority,
    contract: {
      purpose: c.purpose,
      tool: c.tool,
      classification: c.classification,
      releaseBlocking: c.release_blocking,
      consoleRoute: c.console_route,
      navigationEntrypoints: c.navigation_entrypoints,
      permissionAuthority: c.permission_authority,
      edition: c.edition,
      dependencies: c.dependencies,
      sideEffects: c.side_effects,
      secretDataHandling: c.secret_data_handling,
      maturity: c.maturity,
      stages: Object.fromEntries(STAGE_NAMES.map((stageName) => [stageName, c.stages[stageName]])),
      owner: c.owner,
      targetCheckpoint: c.target_checkpoint,
      candidateSHA: c.candidate_sha,
      freshness: c.freshness,
    },
  };
}

export function generateFromCatalog(value) {
  const catalog = validateCatalog(value);
  const projected = catalog.items.map(project);
  const ids = projected.map((item) => item.featureId);
  return (
    `// Code generated from internal/featureparity/feature-map-backlog.json by\n` +
    `// web/scripts/gen-feature-contracts.mjs. DO NOT EDIT by hand.\n` +
    `// Regenerate with: npm run gen:feature-contracts\n\n` +
    `export const canonicalTools = ${JSON.stringify(TOOLS)} as const;\n` +
    `export const capabilityMaturities = ${JSON.stringify(MATURITIES)} as const;\n` +
    `export const capabilityStageNames = ${JSON.stringify(STAGE_NAMES)} as const;\n` +
    `export const capabilityStageStatuses = ${JSON.stringify(STAGE_STATUSES)} as const;\n` +
    `export const canonicalCapabilityIDs = ${JSON.stringify(ids)} as const;\n\n` +
    `export type CanonicalTool = (typeof canonicalTools)[number];\n` +
    `export type CapabilityMaturity = (typeof capabilityMaturities)[number];\n` +
    `export type CapabilityStageName = (typeof capabilityStageNames)[number];\n` +
    `export type CapabilityStageStatus = (typeof capabilityStageStatuses)[number];\n` +
    `export type CanonicalCapabilityID = (typeof canonicalCapabilityIDs)[number];\n\n` +
    `export interface CapabilityStage {\n  readonly status: CapabilityStageStatus;\n  readonly reason?: string;\n  readonly evidence?: readonly string[];\n}\n\n` +
    `export interface CanonicalCapability {\n` +
    `  readonly featureId: CanonicalCapabilityID;\n  readonly feature: string;\n  readonly domain: string;\n  readonly phase: string;\n  readonly priority: number;\n` +
    `  readonly contract: {\n    readonly purpose: string;\n    readonly tool: CanonicalTool;\n    readonly classification: "primary" | "supporting";\n` +
    `    readonly releaseBlocking: boolean;\n    readonly consoleRoute: string;\n    readonly navigationEntrypoints: readonly string[];\n` +
    `    readonly permissionAuthority: string;\n    readonly edition: string;\n    readonly dependencies: readonly string[];\n` +
    `    readonly sideEffects: "read_only" | "mutating" | "mixed";\n    readonly secretDataHandling: string;\n    readonly maturity: CapabilityMaturity;\n` +
    `    readonly stages: Readonly<Record<CapabilityStageName, CapabilityStage>>;\n    readonly owner: string;\n    readonly targetCheckpoint: string;\n` +
    `    readonly candidateSHA: string;\n    readonly freshness: string;\n  };\n}\n\n` +
    `export const canonicalCapabilities = ${JSON.stringify(projected, null, 2)} as const satisfies readonly CanonicalCapability[];\n`
  );
}

export function generate() {
  return generateFromCatalog(loadCanonicalCatalog());
}

export function readGenerated() {
  try {
    return readFileSync(OUT, "utf8");
  } catch {
    return "";
  }
}

function main() {
  const generated = generate();
  if (process.argv.includes("--check")) {
    if (readGenerated() !== generated) {
      console.error(
        "Frontend capability contract drift: src/lib/feature-contracts.gen.ts is stale.\n" +
          "Run `npm run gen:feature-contracts`, review the generated capability/route changes, and commit them.",
      );
      process.exit(1);
    }
    console.log("OK: src/lib/feature-contracts.gen.ts matches the canonical capability catalog.");
    return;
  }
  writeFileSync(OUT, generated);
  console.log("wrote src/lib/feature-contracts.gen.ts from internal/featureparity/feature-map-backlog.json");
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) main();

export { CATALOG, MATURITIES, OUT, STAGE_NAMES, STAGE_STATUSES, TOOLS, WEB, computeMaturity };
