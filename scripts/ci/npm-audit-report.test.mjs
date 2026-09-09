// SPDX-License-Identifier: MPL-2.0
import test from 'node:test';
import assert from 'node:assert/strict';
import { parseReport, assess, aggregate } from './npm-audit-report.mjs';

const clean = () => ({ auditReportVersion: 2, vulnerabilities: {}, metadata: {
  vulnerabilities: { info: 0, low: 0, moderate: 0, high: 0, critical: 0, total: 0 },
  dependencies: { prod: 2, dev: 1, optional: 0, peer: 0, peerOptional: 0, total: 2 } } });
const raw = value => JSON.stringify(value);
function advisory(severity) {
  const doc = clean();
  doc.vulnerabilities.demo = { name: 'demo', severity, isDirect: true,
    via: [{ source: 1, name: 'demo', dependency: 'demo', title: 'Synthetic advisory',
      url: 'https://example.invalid/advisory', severity, range: '*' }],
    effects: [], nodes: ['node_modules/demo'], range: '*', fixAvailable: false };
  doc.metadata.vulnerabilities[severity] = 1;
  doc.metadata.vulnerabilities.total = 1;
  return doc;
}
test('valid empty advisory inventory retains actual dependency census', () => {
  const result = assess(raw(clean()), 0);
  assert.equal(result.result, 'pass'); assert.equal(result.scan_completed, true);
  assert.equal(result.dependencies.total, 2);
});
test('empty dependency fixture remains valid; broad campaign separately requires nonempty', () => {
  const doc = clean(); doc.metadata.dependencies = { prod: 1, dev: 0, optional: 0, peer: 0, peerOptional: 0, total: 0 };
  assert.equal(assess(raw(doc), 0).result, 'pass');
});
test('zero native exit cannot make empty, malformed or missing schema clean', () => {
  for (const input of ['', ' ', '{', '{}', 'null', '[]', '{"error":{"code":"EFAIL"}}']) {
    const result = assess(input, 0);
    assert.equal(result.result, 'fail'); assert.equal(result.scan_completed, false); assert.equal(result.counts, null);
  }
});
test('wrong report version and missing metadata are rejected', () => {
  for (const mutate of [d => d.auditReportVersion = 1, d => delete d.metadata.dependencies, d => delete d.metadata.vulnerabilities, d => delete d.vulnerabilities]) {
    const doc = clean(); mutate(doc); assert.throws(() => parseReport(raw(doc)));
  }
});
test('counts cannot be missing, coerced, negative or fractional', () => {
  for (const value of [null, true, '0', -1, 0.5, Number.MAX_SAFE_INTEGER + 1]) {
    const doc = clean(); doc.metadata.vulnerabilities.high = value;
    assert.equal(assess(raw(doc), 0).scan_completed, false);
    const dep = clean(); dep.metadata.dependencies.total = value;
    assert.equal(assess(raw(dep), 0).scan_completed, false);
  }
});
test('nonzero native exit stays failed with valid zero-finding JSON', () => {
  assert.equal(assess(raw(clean()), 1).result, 'fail');
});
test('high and critical advisories fail even with false zero native status', () => {
  for (const severity of ['high', 'critical']) assert.equal(assess(raw(advisory(severity)), 0).result, 'fail');
});
test('lower severity remains visible under unchanged product high threshold', () => {
  const result = assess(raw(advisory('low')), 0);
  assert.equal(result.result, 'pass'); assert.equal(result.counts.low, 1); assert.equal(result.counts.total, 1);
});
test('native rows and metadata must agree', () => {
  const doc = advisory('low'); doc.metadata.vulnerabilities.low = 0; doc.metadata.vulnerabilities.total = 0;
  assert.equal(assess(raw(doc), 0).scan_completed, false);
});
test('all three distinct expected surfaces must complete', () => {
  const rows = ['web', 'typescript-sdk-generator', 'pulumi-iac'].map(id => ({ id, ...assess(raw(clean()), 0) }));
  assert.equal(aggregate(rows, false).result, 'pass');
  assert.equal(aggregate(rows.slice(0, 2), false).result, 'fail');
  assert.equal(aggregate([rows[0], rows[0], rows[2]], false).result, 'fail');
  assert.equal(aggregate(rows, true).result, 'fail');
  rows[1] = { id: rows[1].id, ...assess('{}', 0) };
  assert.equal(aggregate(rows, false).scan_completed, false); assert.equal(aggregate(rows, false).totals, null);
});

// Regressions for independently reviewed nested-advisory and census failures.
test('direct critical advisory cannot hide in a low row and matching low counters', () => {
  const doc = advisory('low'); doc.vulnerabilities.demo.via[0].severity = 'critical';
  const result = assess(raw(doc), 0);
  assert.equal(result.result, 'fail'); assert.equal(result.scan_completed, false);
});
test('direct-only row must equal its maximum advisory severity', () => {
  const doc = advisory('high'); doc.vulnerabilities.demo.via[0].severity = 'low';
  assert.equal(assess(raw(doc), 0).scan_completed, false);
  const valid = advisory('high'); valid.vulnerabilities.demo.via.push({ ...valid.vulnerabilities.demo.via[0], source: 2, severity: 'low' });
  assert.equal(assess(raw(valid), 1).scan_completed, true);
});
test('advisory array must contain actual typed advisory objects or dependency names', () => {
  for (const value of [null, true, 7, [], {}, '', 'missing', 'demo']) {
    const doc = advisory('low'); doc.vulnerabilities.demo.via = [value];
    assert.equal(assess(raw(doc), 0).scan_completed, false);
  }
  const empty = advisory('low'); empty.vulnerabilities.demo.via = [];
  assert.equal(assess(raw(empty), 0).scan_completed, false);
});
test('direct advisory requires exact containing package and report fields', () => {
  for (const mutate of [a => a.name = 'other', a => a.dependency = 'other', a => a.source = '1',
    a => a.source = 0, a => delete a.source, a => a.title = '', a => delete a.url,
    a => a.range = null, a => a.severity = 'unknown']) {
    const doc = advisory('low'); mutate(doc.vulnerabilities.demo.via[0]);
    assert.equal(assess(raw(doc), 0).scan_completed, false);
  }
});
test('optional direct advisory CWE and CVSS metadata is typed without inventing it', () => {
  const doc = advisory('low'); const via = doc.vulnerabilities.demo.via[0];
  via.cwe = ['CWE-79']; via.cvss = { score: 3.1, vectorString: null };
  assert.equal(assess(raw(doc), 0).result, 'pass');
  for (const bad of [7, {}, [7]]) {
    via.cwe = bad; assert.equal(assess(raw(doc), 0).scan_completed, false);
  }
  via.cwe = null; via.cvss = null;
  assert.equal(assess(raw(doc), 0).result, 'pass');
  for (const bad of [7, {}, { score: 11, vectorString: null }, { score: '3.1', vectorString: null }]) {
    via.cvss = bad; assert.equal(assess(raw(doc), 0).scan_completed, false);
  }
});
test('effects nodes and fix objects cannot contain malformed members', () => {
  for (const mutate of [r => r.effects = [null], r => r.nodes = [7], r => r.nodes = [],
    r => r.nodes = ['a', 'a'], r => r.fixAvailable = {},
    r => r.fixAvailable = { name: 'demo', version: '1.0.0', isSemVerMajor: 'yes' }]) {
    const doc = advisory('low'); mutate(doc.vulnerabilities.demo);
    assert.equal(assess(raw(doc), 0).scan_completed, false);
  }
  for (const fix of [true, false, { name: 'demo', version: '1.0.0' }, { name: 'demo', version: '1.0.0', isSemVerMajor: false }]) {
    const doc = advisory('low'); doc.vulnerabilities.demo.fixAvailable = fix;
    assert.equal(assess(raw(doc), 0).result, 'pass');
  }
});
function referencedReport() {
  const doc = advisory('critical');
  doc.vulnerabilities.wrapper = { name: 'wrapper', severity: 'low', isDirect: true,
    via: ['demo'], effects: [], nodes: ['node_modules/wrapper'], range: '*', fixAvailable: false };
  doc.vulnerabilities.demo.effects = ['wrapper'];
  doc.metadata.vulnerabilities.low = 1; doc.metadata.vulnerabilities.total = 2;
  return doc;
}
test('metavulnerability reference need not equal dependency maximum but dependency remains gated', () => {
  const doc = referencedReport(); const result = assess(raw(doc), 0);
  assert.equal(result.scan_completed, true); assert.equal(result.result, 'fail');
  assert.equal(result.counts.critical, 1); assert.equal(result.counts.low, 1);
});
test('duplicate dependency references remain supported and are not counted as new packages', () => {
  const doc = referencedReport(); doc.vulnerabilities.wrapper.via.push('demo');
  const result = assess(raw(doc), 1);
  assert.equal(result.scan_completed, true); assert.equal(result.counts.total, 2);
});
test('a malformed referenced row cannot borrow another row validity', () => {
  const doc = referencedReport(); doc.vulnerabilities.demo.via = [];
  assert.equal(assess(raw(doc), 0).scan_completed, false);
});
test('impossible root-only dependency census cannot be called empty and clean', () => {
  const doc = clean(); doc.metadata.dependencies.total = 0;
  const result = assess(raw(doc), 0);
  assert.equal(result.result, 'fail'); assert.equal(result.scan_completed, false);
});
test('valid overlapping dependency flags are not summed as disjoint packages', () => {
  const doc = clean(); doc.metadata.dependencies = { prod: 1, dev: 2, optional: 2, peer: 1, peerOptional: 1, total: 2 };
  assert.equal(assess(raw(doc), 0).result, 'pass');
});
test('category counts must fit the non-production inventory and cover it', () => {
  for (const deps of [
    { prod: 2, dev: 2, optional: 0, peer: 0, peerOptional: 0, total: 2 },
    { prod: 0, dev: 0, optional: 0, peer: 0, peerOptional: 0, total: 2 },
    { prod: 1, dev: 1, optional: 0, peer: 0, peerOptional: 0, total: 2 }]) {
    const doc = clean(); doc.metadata.dependencies = deps;
    assert.equal(assess(raw(doc), 0).scan_completed, false);
  }
});
test('dependency overlap arithmetic stays exact at safe-integer boundary', () => {
  const doc = clean(); doc.metadata.dependencies = { prod: 1, dev: Number.MAX_SAFE_INTEGER,
    optional: Number.MAX_SAFE_INTEGER, peer: 0, peerOptional: 0, total: Number.MAX_SAFE_INTEGER };
  assert.equal(assess(raw(doc), 0).result, 'pass');
  doc.metadata.dependencies.prod = 2;
  assert.equal(assess(raw(doc), 0).scan_completed, false);
});

test('metavulnerability cycles require a reachable actual advisory', () => {
  const doc = referencedReport(); doc.vulnerabilities.demo.via = ['wrapper'];
  assert.equal(assess(raw(doc), 0).scan_completed, false);
  doc.vulnerabilities.demo.via.push(advisory('critical').vulnerabilities.demo.via[0]);
  assert.equal(assess(raw(doc), 1).scan_completed, true);
});
test('vulnerable package and node counts must fit the actual dependency inventory', () => {
  const doc = advisory('low'); doc.metadata.dependencies = { prod: 1, dev: 0, optional: 0, peer: 0, peerOptional: 0, total: 0 };
  assert.equal(assess(raw(doc), 0).scan_completed, false);
  const crowded = advisory('low'); crowded.vulnerabilities.demo.nodes = ['a', 'b', 'c'];
  assert.equal(assess(raw(crowded), 0).scan_completed, false);
});
