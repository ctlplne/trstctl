#!/usr/bin/env node

import { readdir, readFile, stat } from "node:fs/promises";
import path from "node:path";

const severityPoints = { Critical: 25, High: 10, Medium: 4, Low: 1, Info: 0 };
const confidenceFactor = { High: 1, Medium: 0.7, Low: 0.4 };
const scoreTolerance = 0.05;

const failures = [];
const args = parseArgs(process.argv.slice(2));
const repoRoot = path.resolve(args.repo ?? process.cwd());
const auditDir = path.resolve(args["audit-dir"] ?? path.join(repoRoot, "..", "trustctl-audit", "outputs"));

const reports = await loadReports(auditDir);
const priorReports = reports.filter((r) => /^(0[1-9]|1[0-9]|20)-.*\.html$/.test(r.file));
if (priorReports.length !== 20) {
  fail(`expected 20 prior audit JSON appendices, found ${priorReports.length}`);
}

const allFindings = priorReports.flatMap((r) =>
  (r.json.findings ?? []).map((finding) => ({ report: r.file, finding })),
);
if (allFindings.length !== 153) {
  fail(`expected 153 prior findings, found ${allFindings.length}`);
}

verifyScores(priorReports);
verifyIDsAndCrossRefs(allFindings, reports);
await verifyCitations(allFindings);
verifyStrengthEvidence(reports);

if (failures.length > 0) {
  console.error("audit corpus verification FAILED");
  for (const failure of failures) {
    console.error(`- ${failure}`);
  }
  process.exit(1);
}

console.log("audit corpus verification OK");

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (!arg.startsWith("--")) {
      fail(`unexpected argument ${arg}`);
      continue;
    }
    const key = arg.slice(2);
    const value = argv[i + 1];
    if (!value || value.startsWith("--")) {
      fail(`missing value for ${arg}`);
      continue;
    }
    out[key] = value;
    i++;
  }
  return out;
}

async function loadReports(dir) {
  const files = (await readdir(dir))
    .filter((file) => /^\d\d-.*\.html$/.test(file))
    .sort();
  const loaded = [];
  for (const file of files) {
    const html = await readFile(path.join(dir, file), "utf8");
    const json = extractDiligenceJSON(file, html);
    loaded.push({ file, json });
  }
  return loaded;
}

function extractDiligenceJSON(file, html) {
  const match = html.match(/<script[^>]*id=["']diligence-findings["'][^>]*>([\s\S]*?)<\/script>/);
  if (!match) {
    fail(`${file}: missing diligence-findings JSON appendix`);
    return {};
  }
  try {
    return JSON.parse(match[1]);
  } catch (err) {
    fail(`${file}: diligence-findings JSON does not parse: ${err.message}`);
    return {};
  }
}

function verifyScores(reports) {
  let rawMismatches = 0;
  let weightedMismatches = 0;
  let countMismatches = 0;

  for (const report of reports) {
    let raw = 100;
    let weighted = 100;
    const counts = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };

    for (const finding of report.json.findings ?? []) {
      const severity = finding.severity;
      if (!(severity in severityPoints)) {
        fail(`${report.file} ${finding.id}: unknown severity ${severity}`);
        continue;
      }
      counts[severity]++;
      const rawPoints = finding.score_impact?.raw_points ?? severityPoints[severity];
      const weightedPoints =
        finding.score_impact?.weighted_points ??
        rawPoints * (confidenceFactor[finding.confidence] ?? 1);
      raw -= rawPoints;
      weighted -= weightedPoints;
    }

    const reportedRaw = report.json.score_raw ?? report.json.score;
    const reportedWeighted = report.json.score_weighted ?? report.json.score;
    if (!close(raw, reportedRaw)) {
      rawMismatches++;
      fail(`${report.file}: raw score recomputes to ${round(raw)}, report says ${reportedRaw}`);
    }
    if (!close(weighted, reportedWeighted)) {
      weightedMismatches++;
      fail(
        `${report.file}: weighted score recomputes to ${round(weighted)}, report says ${reportedWeighted}`,
      );
    }

    const reportedCounts = report.json.severity_counts ?? {};
    for (const [severity, count] of Object.entries(counts)) {
      const reported = reportedCounts[severity] ?? reportedCounts[severity.toLowerCase()] ?? 0;
      if (reported !== count) {
        countMismatches++;
        fail(`${report.file}: ${severity} count recomputes to ${count}, report says ${reported}`);
      }
    }
  }

  console.log(`score_raw_mismatches=${rawMismatches}`);
  console.log(`score_weighted_mismatches=${weightedMismatches}`);
  console.log(`severity_count_mismatches=${countMismatches}`);
}

function verifyIDsAndCrossRefs(findings, reports) {
  const ids = new Map();
  const duplicates = [];
  for (const { report, finding } of findings) {
    if (ids.has(finding.id)) {
      duplicates.push(finding.id);
    } else {
      ids.set(finding.id, report);
    }
  }

  const domains = new Set([...ids.keys()].map((id) => id.split("-")[0]));
  for (const report of reports) {
    for (const finding of report.json.findings ?? []) {
      if (typeof finding.id === "string" && finding.id.includes("-")) {
        domains.add(finding.id.split("-")[0]);
      }
    }
  }
  domains.add("PRODUCT");
  const missingRefs = [];
  for (const { report, finding } of findings) {
    for (const ref of finding.cross_references ?? []) {
      if (/^[A-Z]+-\d+$/.test(ref)) {
        if (!ids.has(ref)) {
          missingRefs.push(`${report} ${finding.id} -> ${ref}`);
        }
      } else if (/^[A-Z]+$/.test(ref)) {
        if (!domains.has(ref)) {
          missingRefs.push(`${report} ${finding.id} -> ${ref}`);
        }
      }
    }
  }

  if (duplicates.length > 0) {
    fail(`duplicate finding IDs: ${duplicates.sort().join(", ")}`);
  }
  if (missingRefs.length > 0) {
    fail(`unresolved cross_references: ${missingRefs.sort().join(", ")}`);
  }
  console.log(`duplicate_ids=${duplicates.length}`);
  console.log(`missing_cross_refs=${missingRefs.length}`);
}

async function verifyCitations(findings) {
  let materialFindings = 0;
  let citationChecks = 0;
  let materialCitationChecks = 0;
  const uniquePaths = new Set();
  const missing = [];

  for (const { report, finding } of findings) {
    const material = finding.severity === "Critical" || finding.severity === "High";
    if (material) {
      materialFindings++;
    }
    const evidenceItems = Array.isArray(finding.evidence)
      ? finding.evidence
      : [finding.evidence ?? ""];
    for (const evidence of evidenceItems) {
      for (const ref of extractCitationRefs(evidence)) {
        citationChecks++;
        if (material) {
          materialCitationChecks++;
        }
        const target = resolveCitation(ref);
        uniquePaths.add(target.path);
        try {
          const info = await stat(target.path);
          if (target.line != null && info.isFile()) {
            await verifyLineInFile(target.path, target.line, ref);
          }
        } catch (err) {
          missing.push(`${report} ${finding.id}: ${ref} -> ${target.path}`);
        }
      }
    }
  }

  if (materialFindings !== 41) {
    fail(`expected 41 material Critical/High findings, found ${materialFindings}`);
  }
  if (citationChecks < 166) {
    fail(`expected at least 166 citation checks, found ${citationChecks}`);
  }
  if (materialCitationChecks < 150) {
    fail(`expected at least 150 material citation checks, found ${materialCitationChecks}`);
  }
  if (missing.length > 0) {
    fail(`fabricated or drifted citations: ${missing.sort().join("; ")}`);
  }

  console.log(`material_findings=${materialFindings}`);
  console.log(`citation_checks=${citationChecks}`);
  console.log(`material_citation_checks=${materialCitationChecks}`);
  console.log(`unique_citation_paths=${uniquePaths.size}`);
  console.log(`fabricated_or_drifted_citations=${missing.length}`);
}

function extractCitationRefs(text) {
  const refs = [];
  const citationRE =
    /(?:^|[\s`"'(<])((?:(?:\.github|\.clusterfuzzlite|cmd|internal|docs|deploy|web|tools|scripts|clients|plugins|outputs)(?:\/[A-Za-z0-9_.${}-]+)+|Makefile|README\.md|go\.mod|go\.sum)(?::\d+(?:-\d+)?)?)/g;
  let match;
  while ((match = citationRE.exec(text)) !== null) {
    const ref = match[1].replace(/[),.;`'"<>]+$/g, "");
    if (!ref.includes("...")) {
      refs.push(ref);
    }
  }
  return refs;
}

function resolveCitation(ref) {
  const lineMatch = ref.match(/:(\d+)(?:-\d+)?$/);
  const clean = ref.replace(/:\d+(?:-\d+)?$/, "");
  const base = clean.startsWith("outputs/")
    ? path.join(auditDir, clean.slice("outputs/".length))
    : path.join(repoRoot, clean);
  return { path: base, line: lineMatch ? Number(lineMatch[1]) : null };
}

async function verifyLineInFile(file, line, ref) {
  const body = await readFile(file, "utf8");
  const lineCount = body.split(/\r?\n/).length;
  if (line < 1 || line > lineCount) {
    throw new Error(`${ref} points outside ${file} (${lineCount} lines)`);
  }
}

function verifyStrengthEvidence(reports) {
  const verifyReport = reports.find((report) => report.file === "21-VERIFY.html");
  if (!verifyReport) {
    fail("21-VERIFY.html missing from audit outputs");
    return;
  }
  const byID = new Map((verifyReport.json.findings ?? []).map((finding) => [finding.id, finding]));
  for (const [id, want] of Object.entries({
    "VERIFY-101": [
      "166/166 sampled citation checks VERIFIED, 0 DRIFTED, 0 FABRICATED",
    ],
    "VERIFY-102": [
      "0 raw-score mismatches",
      "0 weighted-score mismatches",
      "0 reported severity-count score mismatches",
    ],
    "VERIFY-103": [
      "Parsed 153 finding IDs across 20 prior reports",
      "0 duplicate IDs",
      "0 missing IDs in machine-readable cross_references arrays",
    ],
  })) {
    const finding = byID.get(id);
    if (!finding) {
      fail(`21-VERIFY.html missing ${id}`);
      continue;
    }
    const evidence = (finding.evidence ?? []).join("\n");
    for (const phrase of want) {
      if (!evidence.includes(phrase)) {
        fail(`${id} evidence no longer contains ${phrase}`);
      }
    }
  }
}

function close(a, b) {
  return Math.abs(Number(a) - Number(b)) <= scoreTolerance;
}

function round(n) {
  return Math.round(Number(n) * 10) / 10;
}

function fail(message) {
  failures.push(message);
}
