#!/usr/bin/env node
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";

const root = resolve(new URL("../..", import.meta.url).pathname);
let out = resolve(root, "scripts/accessibility/accessibility-evidence-receipt.json");

for (let i = 2; i < process.argv.length; i += 1) {
  const arg = process.argv[i];
  if (arg === "--out") {
    const value = process.argv[i + 1];
    if (!value) fail("--out requires a path");
    out = resolve(process.cwd(), value);
    i += 1;
    continue;
  }
  fail(`unknown argument: ${arg}`);
}

const anchors = [
  "docs/accessibility-vpat.md",
  "docs/web-console.md",
  "web/README.md",
  "web/src/__tests__/reduced_motion_and_a11y.test.tsx",
  "web/src/__tests__/shell_a11y_and_theme.test.tsx",
  "web/src/__tests__/route_focus.test.tsx",
];

for (const anchor of anchors) {
  if (!existsSync(resolve(root, anchor))) {
    fail(`missing accessibility evidence anchor: ${anchor}`);
  }
}

const packet = readFileSync(resolve(root, "docs/accessibility-vpat.md"), "utf8");
const requiredMarkers = [
  ["VPAT", /VPAT|Voluntary Product Accessibility Template/],
  ["manual assistive", /manual assistive/i],
  ["screen reader audit", /screen reader audit/i],
  ["WCAG 2.1 AA", /WCAG 2\.1 AA/i],
  ["retest cadence", /Retest cadence/i],
];

for (const [label, pattern] of requiredMarkers) {
  if (!pattern.test(packet)) fail(`docs/accessibility-vpat.md missing ${label}`);
}

const receipt = {
  schema_version: 1,
  id: "A11Y-EVIDENCE-001",
  generated_at: process.env.TRSTCTL_A11Y_RECEIPT_GENERATED_AT || new Date().toISOString(),
  product: "trstctl web console",
  status: "documented",
  vpat_artifact: "docs/accessibility-vpat.md",
  ci_artifact: "a11y-evidence-receipt",
  evidence_scope: [
    "served React web console",
    "authenticated shell navigation",
    "shared data grid and dialog primitives",
    "keyboard-only and screen-reader-labeled flows",
    "reduced-motion and RTL behavior",
  ],
  automated_gates: [
    "npm --prefix web run lint",
    "npm --prefix web run typecheck",
    "npm --prefix web run test:coverage",
    "npm --prefix web run build",
  ],
  manual_assistive_technology_receipts: [
    {
      id: "A11Y-MANUAL-KEYBOARD-2026-07-02",
      result: "no blocking keyboard-only defect recorded",
      artifact: "docs/accessibility-vpat.md#manual-assistive-technology-audit-receipts",
    },
    {
      id: "A11Y-MANUAL-SCREEN-READER-2026-07-02",
      result: "screen reader audit checklist documented for the served shell contract",
      artifact: "docs/accessibility-vpat.md#manual-assistive-technology-audit-receipts",
    },
  ],
  known_exceptions: [
    "This repository packet is the engineering evidence source, not a signed third-party VPAT form.",
    "Buyer-specific VPAT responses must record exact browser, operating system, and assistive-technology versions.",
  ],
  anchors,
};

mkdirSync(dirname(out), { recursive: true });
writeFileSync(out, `${JSON.stringify(receipt, null, 2)}\n`);
console.error(`wrote ${out}`);

function fail(message) {
  console.error(`FAIL: ${message}`);
  process.exit(2);
}
