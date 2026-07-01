#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import ts from "typescript";

function findRepoRoot(startDir = process.cwd()) {
  let dir = path.resolve(startDir);
  for (;;) {
    if (fs.existsSync(path.join(dir, "go.mod"))) return dir;
    const parent = path.dirname(dir);
    if (parent === dir) throw new Error(`could not find repo root from ${startDir}`);
    dir = parent;
  }
}

function unwrapExpression(expression) {
  let current = expression;
  while (
    ts.isAsExpression(current) ||
    ts.isTypeAssertionExpression(current) ||
    ts.isParenthesizedExpression(current) ||
    ts.isSatisfiesExpression(current)
  ) {
    current = current.expression;
  }
  return current;
}

function loadAppRoutePaths(repoRoot) {
  const navigationPath = path.join(repoRoot, "web", "src", "lib", "navigation.ts");
  const sourceText = fs.readFileSync(navigationPath, "utf8");
  const sourceFile = ts.createSourceFile(navigationPath, sourceText, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  let routes;

  function visit(node) {
    if (ts.isVariableStatement(node)) {
      for (const declaration of node.declarationList.declarations) {
        if (!ts.isIdentifier(declaration.name) || declaration.name.text !== "appRoutePaths" || !declaration.initializer) continue;
        const initializer = unwrapExpression(declaration.initializer);
        if (!ts.isArrayLiteralExpression(initializer)) {
          throw new Error("appRoutePaths must remain an array literal");
        }
        routes = initializer.elements.map((element) => {
          const value = unwrapExpression(element);
          if (!ts.isStringLiteralLike(value)) throw new Error("appRoutePaths entries must be string literals");
          return normalizeRoute(value.text);
        });
      }
    }
    ts.forEachChild(node, visit);
  }

  visit(sourceFile);
  if (!routes) throw new Error("could not find appRoutePaths in web/src/lib/navigation.ts");
  return new Set(routes);
}

function normalizeRoute(route) {
  const clean = route.split(/[?#]/, 1)[0];
  return clean.length > 1 ? clean.replace(/\/+$/, "") : clean;
}

const ignoredRoutePrefixes = [
  "/api",
  "/auth",
  "/mcp",
  "/metrics",
  "/healthz",
  "/readyz",
  "/.well-known",
];

function isServedAppRouteCandidate(route) {
  if (!route.startsWith("/")) return false;
  if (ignoredRoutePrefixes.some((prefix) => route === prefix || route.startsWith(`${prefix}/`))) return false;
  if (/\.[A-Za-z0-9]+$/.test(route)) return false;
  return true;
}

function routeTokens(value) {
  const routes = [];
  const routePattern = /(^|[\s([{"'`:;,])((?:\/[A-Za-z0-9._~-]+)+)(?=$|[\s)\]}"'`,;.!?])/g;
  for (const match of value.matchAll(routePattern)) {
    routes.push(normalizeRoute(match[2]));
  }
  return routes;
}

function collectRouteEvidenceStrings(backlog) {
  const out = [];
  for (const [index, route] of (backlog.frontend_routes_observed ?? []).entries()) {
    out.push([`frontend_routes_observed[${index}]`, route]);
  }
  for (const [itemIndex, item] of (backlog.items ?? []).entries()) {
    if (item.current_frontend_mapping) out.push([`items[${itemIndex}].current_frontend_mapping`, item.current_frontend_mapping]);
    if (item.target_gui_mapping) out.push([`items[${itemIndex}].target_gui_mapping`, item.target_gui_mapping]);
    for (const facet of ["ui", "a11y"]) {
      const cell = item.facet_evidence?.[facet];
      for (const [evidenceIndex, evidence] of (cell?.evidence ?? []).entries()) {
        out.push([`items[${itemIndex}].facet_evidence.${facet}.evidence[${evidenceIndex}]`, evidence]);
      }
      if (cell?.na) out.push([`items[${itemIndex}].facet_evidence.${facet}.na`, cell.na]);
    }
  }
  return out;
}

function main() {
  const repoRoot = findRepoRoot();
  const registeredRoutes = loadAppRoutePaths(repoRoot);
  const backlogPath = path.join(repoRoot, "internal", "featureparity", "feature-map-backlog.json");
  const backlog = JSON.parse(fs.readFileSync(backlogPath, "utf8"));
  const failures = new Set();

  for (const [location, value] of collectRouteEvidenceStrings(backlog)) {
    for (const route of routeTokens(value)) {
      if (isServedAppRouteCandidate(route) && !registeredRoutes.has(route)) {
        failures.add(`${location} cites absent app route ${route}`);
      }
    }
  }

  if (failures.size > 0) {
    console.error("feature-map route evidence cites routes that AppRoutes/appRoutePaths do not serve:");
    for (const failure of [...failures].sort()) console.error(`- ${failure}`);
    process.exitCode = 1;
    return;
  }

  console.log(`ok: feature-map route evidence cites only ${registeredRoutes.size} registered app routes`);
}

main();
