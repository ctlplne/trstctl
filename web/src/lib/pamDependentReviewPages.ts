import type { PAMDependentRef, PAMServiceDependentReviewEntry, PAMServiceDependentReviewHost, PAMServiceDependentReviewPageRequest } from "@/lib/api-types.gen";

type ReviewRoot = { header: { id: string }; header_digest: string };
export type DependentReviewDraftRow = { ref: PAMDependentRef; probe: string };
const digestPlaceholder = "0".repeat(64);
const maxPageBytes = 65536;

// Go's public JSON wire escapes HTML and the two JavaScript line separators.
// Measure that representation too; request bytes alone undercount native names.
export function nativeReviewPageBytes(id: string, number: number, request: PAMServiceDependentReviewPageRequest): number {
  const wire = JSON.stringify({
    version: 1,
    id,
    header_digest: request.header_digest,
    page_number: number,
    previous_digest: request.previous_digest,
    hosts: request.hosts,
    entries: request.entries?.length ? request.entries : null,
    digest: digestPlaceholder,
  }).replace(/[<>&\u2028\u2029]/g, (c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0"));
  return new TextEncoder().encode(wire).length;
}

// Only one upload page is materialized at a time. Whole-account completeness
// and digest authority remain the server's seal, never a browser hash.
export function* dependentReviewPages(
  root: ReviewRoot,
  selectedHosts: readonly PAMServiceDependentReviewHost[],
  rows: readonly DependentReviewDraftRow[],
  invalid: string,
): Generator<PAMServiceDependentReviewPageRequest> {
  const hosts = new Map<string, PAMServiceDependentReviewHost>();
  for (const host of selectedHosts) {
    const id = host.binding.agent_id;
    if (!id || hosts.has(id)) throw new Error(invalid);
    hosts.set(id, host);
  }
  if (!hosts.size) throw new Error(invalid);
  let number = 0;
  let declarations: PAMServiceDependentReviewHost[] = [];
  let entries: PAMServiceDependentReviewEntry[] = [];
  const request = (h: PAMServiceDependentReviewHost[], e: PAMServiceDependentReviewEntry[]): PAMServiceDependentReviewPageRequest => ({
    header_digest: root.header_digest,
    previous_digest: digestPlaceholder,
    hosts: h,
    entries: e,
  });
  const fits = (h: PAMServiceDependentReviewHost[], e: PAMServiceDependentReviewEntry[]) => {
    const value = request(h, e);
    return nativeReviewPageBytes(root.header.id, number, value) <= maxPageBytes && new TextEncoder().encode(JSON.stringify(value)).length <= maxPageBytes;
  };
  // Explicit declarations preserve selected hosts with zero native dependents.
  for (const host of hosts.values()) {
    if (!fits([...declarations, host], [])) {
      if (!declarations.length) throw new Error(invalid);
      yield request(declarations, []);
      number++;
      declarations = [];
      if (!fits([host], [])) throw new Error(invalid);
    }
    declarations.push(host);
  }
  if (declarations.length) {
    yield request(declarations, []);
    number++;
  }
  declarations = [];
  for (const row of rows) {
    const host = hosts.get(row.ref.agent_id);
    if (!host || !row.probe.trim()) throw new Error(invalid);
    const entry: PAMServiceDependentReviewEntry = { host, ref: row.ref, probe_id: row.probe.trim() };
    let nextHosts = declarations.some((h) => h.binding.agent_id === row.ref.agent_id) ? declarations : [...declarations, host];
    if (!fits(nextHosts, [...entries, entry])) {
      if (!entries.length) throw new Error(invalid);
      yield request(declarations, entries);
      number++;
      declarations = [];
      entries = [];
      nextHosts = [host];
      if (!fits(nextHosts, [entry])) throw new Error(invalid);
    }
    declarations = nextHosts;
    entries.push(entry);
  }
  if (entries.length) yield request(declarations, entries);
}
