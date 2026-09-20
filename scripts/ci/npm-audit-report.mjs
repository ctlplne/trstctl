// SPDX-License-Identifier: BUSL-1.1
// npm audit v2 report reader. A scanner exit is not a report-schema proof.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const severities = ['info', 'low', 'moderate', 'high', 'critical'];
const dependencyKinds = ['prod', 'dev', 'optional', 'peer', 'peerOptional', 'total'];
const surfaceIDs = ['web', 'typescript-sdk-generator', 'pulumi-iac'];
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const count = value => Number.isSafeInteger(value) && value >= 0;

const text = value => typeof value === 'string' && value.length > 0;
const rank = severity => severities.indexOf(severity);

function dependencyCensus(dependencies) {
  for (const key of dependencyKinds) {
    if (!count(dependencies[key])) throw new Error(`invalid dependency count: ${key}`);
  }
  // Arborist counts every inventory node, including the root. Its reported
  // total excludes that root. prod is disjoint from all four overlapping flags;
  // each remaining node must appear in at least one of those flag counts.
  const inventory = BigInt(dependencies.total) + 1n;
  const prod = BigInt(dependencies.prod);
  const flags = ['dev', 'optional', 'peer', 'peerOptional'].map(key => BigInt(dependencies[key]));
  if (prod > inventory || flags.some(value => value > inventory - prod) ||
      flags.reduce((sum, value) => sum + value, 0n) < inventory - prod) {
    throw new Error('impossible dependency inventory counts');
  }
}

function advisoryRank(via, name) {
  if (!object(via) || !count(via.source) || via.source === 0 ||
      via.name !== name || via.dependency !== name || !text(via.title) ||
      !text(via.url) || !text(via.range) || rank(via.severity) < 0) {
    throw new Error(`incomplete direct advisory: ${name}`);
  }
  // Old npm endpoints can omit CWE/CVSS. Unknown optional values remain
  // unknown; they do not replace the advisory's explicit severity.
  if ('cwe' in via && via.cwe !== null &&
      (!Array.isArray(via.cwe) || !via.cwe.every(text))) {
    throw new Error(`invalid advisory CWE: ${name}`);
  }
  if ('cvss' in via && via.cvss !== null &&
      (!object(via.cvss) || !Number.isFinite(via.cvss.score) ||
       via.cvss.score < 0 || via.cvss.score > 10 ||
       !(via.cvss.vectorString === null || text(via.cvss.vectorString)))) {
    throw new Error(`invalid advisory CVSS: ${name}`);
  }
  return rank(via.severity);
}

function vulnerabilityRow(name, row, inventory) {
  if (!text(name) || !object(row) || row.name !== name || rank(row.severity) < 0 ||
      typeof row.isDirect !== 'boolean' || !Array.isArray(row.via) || row.via.length === 0 ||
      !Array.isArray(row.effects) || !row.effects.every(text) ||
      !Array.isArray(row.nodes) || row.nodes.length === 0 || !row.nodes.every(text) ||
      new Set(row.nodes).size !== row.nodes.length || !text(row.range) ||
      !(typeof row.fixAvailable === 'boolean' ||
        (object(row.fixAvailable) && text(row.fixAvailable.name) && text(row.fixAvailable.version) &&
         (!('isSemVerMajor' in row.fixAvailable) || typeof row.fixAvailable.isSemVerMajor === 'boolean')))) {
    throw new Error(`incomplete vulnerability row: ${name}`);
  }
  let directMaximum = -1;
  let references = 0;
  for (const via of row.via) {
    if (typeof via === 'string') {
      if (!text(via) || via === name || !Object.hasOwn(inventory, via)) {
        throw new Error(`missing metavulnerability dependency: ${name}`);
      }
      references++;
    } else {
      directMaximum = Math.max(directMaximum, advisoryRank(via, name));
    }
  }
  // A string carries a dependency name, not its originating advisory subset.
  // Do not equate this row with that dependency's possibly higher maximum.
  // Its own row remains in the report and receives the same severity gate.
  if (rank(row.severity) < directMaximum ||
      (references === 0 && rank(row.severity) !== directMaximum)) {
    throw new Error(`advisory and row severity disagree: ${name}`);
  }
}

function advisoryOrigins(inventory) {
  // Metavulnerabilities start from actual advisory objects. Propagate that
  // fact through dependency references without recursion or a severity guess.
  const parents = new Map(Object.keys(inventory).map(name => [name, []]));
  const known = new Set();
  for (const [name, row] of Object.entries(inventory)) {
    for (const via of row.via) {
      if (typeof via === 'string') parents.get(via).push(name);
      else known.add(name);
    }
  }
  const pending = [...known];
  for (let i = 0; i < pending.length; i++) {
    for (const name of parents.get(pending[i])) {
      if (!known.has(name)) { known.add(name); pending.push(name); }
    }
  }
  if (known.size !== Object.keys(inventory).length) {
    throw new Error('metavulnerability component has no actual advisory');
  }
}

export function parseReport(raw) {
  if (!raw.trim()) throw new Error('empty npm audit report');
  const report = JSON.parse(raw);
  if (!object(report) || report.auditReportVersion !== 2 || 'error' in report ||
      !object(report.vulnerabilities) || !object(report.metadata) ||
      !object(report.metadata.vulnerabilities) || !object(report.metadata.dependencies)) {
    throw new Error('unsupported or incomplete npm audit v2 report');
  }
  const counts = report.metadata.vulnerabilities;
  const dependencies = report.metadata.dependencies;
  for (const key of [...severities, 'total']) {
    if (!count(counts[key])) throw new Error(`invalid vulnerability count: ${key}`);
  }
  dependencyCensus(dependencies);
  if (Object.keys(report.vulnerabilities).length > dependencies.total) {
    throw new Error('vulnerable packages exceed dependency inventory');
  }
  const observed = Object.fromEntries(severities.map(key => [key, 0]));
  for (const [name, row] of Object.entries(report.vulnerabilities)) {
    vulnerabilityRow(name, row, report.vulnerabilities);
    if (row.nodes.length > dependencies.total) throw new Error('vulnerable nodes exceed dependency inventory');
    observed[row.severity]++;
  }
  advisoryOrigins(report.vulnerabilities);
  if (severities.some(key => observed[key] !== counts[key]) ||
      counts.total !== Object.keys(report.vulnerabilities).length ||
      counts.total !== severities.reduce((sum, key) => sum + counts[key], 0)) {
    throw new Error('vulnerability inventory and counts disagree');
  }
  return { counts: { ...counts }, dependencies: { ...dependencies } };
}

function fileRecord(filename) {
  const raw = fs.readFileSync(filename);
  return { path: filename, bytes: raw.length, sha256: crypto.createHash('sha256').update(raw).digest('hex') };
}

export function assess(raw, exitCode) {
  if (!Number.isInteger(exitCode) || exitCode < 0 || exitCode > 255) throw new Error('invalid native exit');
  try {
    const parsed = parseReport(raw);
    return { ...parsed, scan_completed: true,
      result: exitCode === 0 && parsed.counts.high === 0 && parsed.counts.critical === 0 ? 'pass' : 'fail' };
  } catch (error) {
    return { counts: null, dependencies: null, scan_completed: false, result: 'fail', parse_error: String(error.message) };
  }
}

export function aggregate(surfaces, failed) {
  const complete = surfaces.length === surfaceIDs.length &&
    surfaceIDs.every((id, i) => surfaces[i].id === id) && surfaces.every(s => s.scan_completed === true);
  const totals = complete ? Object.fromEntries([...severities, 'total'].map(key =>
    [key, surfaces.reduce((sum, row) => sum + row.counts[key], 0)])) : null;
  return { scan_completed: complete, totals,
    result: !failed && complete && surfaces.every(s => s.result === 'pass') ? 'pass' : 'fail' };
}

function main(args) {
  if (args[0] === 'surface') {
    const [_, reportPath, stderrPath, surfacePath, repo, id, label, prefix, dependencyScope, statusText, argsText] = args;
    const value = assess(fs.readFileSync(reportPath, 'utf8'), Number(statusText));
    const surface = { id, label, path: path.relative(repo, prefix) || '.', dependency_scope: dependencyScope,
      audit_level: 'high', npm_args: argsText ? argsText.split(/\s+/).filter(Boolean) : [],
      ...value, exit_code: Number(statusText), raw_report: fileRecord(reportPath), raw_stderr: fileRecord(stderrPath) };
    fs.appendFileSync(surfacePath, `${JSON.stringify(surface)}\n`);
    console.log(value.counts ? [...severities, 'total'].map(k => `${k}=${value.counts[k]}`).join(' ') : `invalid report: ${value.parse_error}`);
    return value.result === 'pass' ? 0 : 1;
  }
  if (args[0] === 'aggregate') {
    const [_, surfacePath, receiptPath, npmVersion, nodeVersion, failuresText, evidenceDirectory] = args;
    const surfaces = fs.readFileSync(surfacePath, 'utf8').split(/\n/).filter(Boolean).map(line => JSON.parse(line));
    const receipt = { schema: 'trstctl.npm-audit-dependency-surfaces.v1', generated_at: new Date().toISOString(),
      scanner: { name: 'npm audit', npm_version: npmVersion, node_version: nodeVersion }, audit_level: 'high',
      evidence_directory: evidenceDirectory, surfaces, ...aggregate(surfaces, Number(failuresText) !== 0) };
    fs.writeFileSync(receiptPath, `${JSON.stringify(receipt, null, 2)}\n`, { mode: 0o600 });
    return receipt.result === 'pass' ? 0 : 1;
  }
  throw new Error('expected surface or aggregate mode');
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { process.exitCode = main(process.argv.slice(2)); }
  catch (error) { console.error(`npm audit report rejected: ${error.message}`); process.exitCode = 1; }
}
