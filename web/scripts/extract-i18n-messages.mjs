#!/usr/bin/env node
// Extract user-facing source literals into a committed catalog guard.
//
// This is intentionally dependency-free. It is not the translator-facing runtime
// catalog; it is the safety rail that stops the existing UI string debt from
// growing outside the i18n boundary while pages migrate to typed message keys.

import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import ts from "typescript";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const WEB = path.resolve(__dirname, "..");
const SRC = path.resolve(WEB, "src");
const OUT = path.resolve(SRC, "i18n", "extractedMessages.gen.ts");
const BUDGET = path.resolve(SRC, "i18n", "extractedMessages.budget.json");
const CHECK = process.argv.includes("--check");

const excludedPathParts = [
  `${path.sep}__tests__${path.sep}`,
  `${path.sep}test${path.sep}`,
  `${path.sep}i18n${path.sep}`,
  `${path.sep}lib${path.sep}api-types.gen.ts`,
  `${path.sep}vite-env.d.ts`,
  // S-C8: Storybook stories are a dev-only workbench; their fixture copy is
  // never shipped UI and must not enter the extraction budget.
  `.stories.`,
  // The styleguide is the internal living spec: its sample labels and fixture
  // values are intentionally not customer copy, so they stay out of the
  // extraction ratchet the same way test fixtures do.
  `${path.sep}pages${path.sep}Styleguide.tsx`,
  // C-I1 exemption re-audit (DA-14): demoData is the preview-mode showcase —
  // real tenants never see it (ia_ratchets guards its imports), and its
  // fabricated fixtures are intentionally not translated copy. journeyMatrix
  // is the persona-smoke test matrix: its heading strings must byte-match the
  // live H1s (which are themselves keyed), so keying the matrix would only
  // duplicate the catalog and defeat its cross-check purpose.
  `${path.sep}lib${path.sep}demoData.ts`,
  `${path.sep}lib${path.sep}journeyMatrix.ts`,
];

// C-I1 re-audit (DA-14): candidates come from the TypeScript AST instead of
// regexes. JSX text nodes, whitelisted JSX string attributes, and whitelisted
// object-property string literals are the entire user-facing surface; comments,
// type positions, and generics can no longer masquerade as UI copy.
const attrNames = new Set(["aria-label", "aria-description", "placeholder", "title", "alt"]);
const propNames = new Set(["label", "title", "description", "heading", "summary", "message", "detail", "emptyTitle", "emptyDescription", "tooltip", "copy"]);

function astCandidates(file, source) {
  const scriptKind = file.endsWith(".tsx") ? ts.ScriptKind.TSX : ts.ScriptKind.TS;
  const sf = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true, scriptKind);
  const out = [];
  const visit = (node) => {
    if (ts.isJsxText(node)) {
      out.push({ value: node.text, index: node.getStart(sf) });
    } else if (ts.isJsxAttribute(node) && node.initializer && ts.isStringLiteral(node.initializer)) {
      const name = node.name.getText(sf);
      if (attrNames.has(name)) out.push({ value: node.initializer.text, index: node.initializer.getStart(sf) });
    } else if (ts.isPropertyAssignment(node) && ts.isStringLiteral(node.initializer)) {
      const name = ts.isIdentifier(node.name) || ts.isStringLiteral(node.name) ? node.name.text : "";
      if (propNames.has(name)) out.push({ value: node.initializer.text, index: node.initializer.getStart(sf) });
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return out;
}

function walk(dir) {
  const out = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      out.push(...walk(full));
      continue;
    }
    if (!/\.(ts|tsx)$/.test(entry.name)) continue;
    if (/\.test\.(ts|tsx)$/.test(entry.name)) continue;
    if (excludedPathParts.some((part) => full.includes(part))) continue;
    out.push(full);
  }
  return out.sort();
}

function normalize(value) {
  return value.replace(/\s+/g, " ").trim();
}

function isUserFacing(value) {
  if (!value || value.length < 2) return false;
  if (!/[A-Za-z]/.test(value)) return false;
  if (/[{}[\];=]/.test(value)) return false;
  if (/\b(?:const|expect|mock|return|useState|Record)\b/.test(value)) return false;
  if (/^(true|false|null|undefined|return|import|export)$/i.test(value)) return false;
  if (/^[a-z0-9-]+:[a-z0-9-]+$/i.test(value)) return false;
  return true;
}

function lineFor(source, index) {
  let line = 1;
  for (let i = 0; i < index; i += 1) {
    if (source.charCodeAt(i) === 10) line += 1;
  }
  return line;
}

function keyFor(value) {
  const slug = value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, ".")
    .replace(/^\.+|\.+$/g, "")
    .slice(0, 42)
    .replace(/\.$/, "");
  const hash = createHash("sha256").update(value).digest("hex").slice(0, 10);
  return `source.${slug || "message"}.${hash}`;
}

function extract() {
  const byValue = new Map();
  for (const file of walk(SRC)) {
    const source = readFileSync(file, "utf8");
    const rel = path.relative(WEB, file);
    for (const candidate of astCandidates(file, source)) {
      const value = normalize(candidate.value);
      if (!isUserFacing(value)) continue;
      const sourceRef = `${rel}:${lineFor(source, candidate.index)}`;
      const current = byValue.get(value) ?? {
        key: keyFor(value),
        defaultMessage: value,
        sources: new Set(),
      };
      current.sources.add(sourceRef);
      byValue.set(value, current);
    }
  }
  return [...byValue.values()].map((entry) => ({ ...entry, sources: [...entry.sources].sort() })).sort((left, right) => left.key.localeCompare(right.key));
}

function emit(entries) {
  const rows = entries
    .map((entry) => {
      const sources = entry.sources.map((source) => `      ${JSON.stringify(source)},`).join("\n");
      return [
        "  {",
        `    key: ${JSON.stringify(entry.key)},`,
        `    defaultMessage: ${JSON.stringify(entry.defaultMessage)},`,
        "    sources: [",
        sources,
        "    ],",
        "  },",
      ].join("\n");
    })
    .join("\n");

  return [
    "// Code generated by web/scripts/extract-i18n-messages.mjs.",
    "// DO NOT EDIT by hand. Regenerate with: npm run i18n:extract",
    "//",
    "// This catalog captures user-facing source literals that have not yet moved",
    "// to typed runtime message keys. The --check mode blocks new hard-coded UI",
    "// copy unless the catalog is intentionally regenerated.",
    "",
    "export const extractedMessages: Array<{ key: string; defaultMessage: string; sources: string[] }> = [",
    rows,
    "] as const;",
    "",
    'export type ExtractedMessageKey = (typeof extractedMessages)[number]["key"];',
    "",
  ].join("\n");
}

function loadBudget() {
  if (!existsSync(BUDGET)) {
    throw new Error("web/src/i18n/extractedMessages.budget.json is missing");
  }
  const budget = JSON.parse(readFileSync(BUDGET, "utf8"));
  if (!Number.isInteger(budget.maxExtractedMessages) || budget.maxExtractedMessages < 0) {
    throw new Error("maxExtractedMessages must be a non-negative integer");
  }
  return budget.maxExtractedMessages;
}

const entries = extract();
const next = emit(entries);

if (CHECK) {
  const current = existsSync(OUT) ? readFileSync(OUT, "utf8") : "";
  if (current !== next) {
    console.error("web/src/i18n/extractedMessages.gen.ts is stale; run npm run i18n:extract");
    process.exit(1);
  }
  const maxExtractedMessages = loadBudget();
  if (entries.length > maxExtractedMessages) {
    console.error(
      `extractedMessages contains ${entries.length} source literals, above the migration budget of ${maxExtractedMessages}; move new copy into typed runtime message keys or lower the budget after migration`,
    );
    process.exit(1);
  }
} else {
  writeFileSync(OUT, next);
}
