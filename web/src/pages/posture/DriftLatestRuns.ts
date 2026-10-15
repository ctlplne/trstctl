import type { DiscoveryMonitoring, DiscoveryRun, DiscoverySource } from "@/lib/api";

/** The monitoring projection names the newest run for each source. A global
 * first page of history cannot answer that question once other sources have
 * filled the page, so fetch only the exact missing IDs. Never offer recovery
 * based on an older row when the authoritative latest read is unavailable. */
export async function loadLatestDriftRuns(
  sources: DiscoverySource[],
  page: DiscoveryRun[],
  monitoring: DiscoveryMonitoring,
  getRun: (id: string) => Promise<DiscoveryRun>,
): Promise<Record<string, DiscoveryRun | null>> {
  const bySource = new Map(monitoring.sources.map((source) => [source.source_id, source]));
  const byID = new Map(page.map((run) => [run.id, run]));
  const result: Record<string, DiscoveryRun | null> = {};
  const driftSources = sources.filter((source) => source.kind === "drift");
  const missingIDs = new Set<string>();

  for (const source of driftSources) {
    const monitored = bySource.get(source.id);
    if (!monitored || monitored.kind !== "drift") throw new Error(`Latest drift run is unavailable for ${source.name}`);
    if (monitored.last_run_id && !byID.has(monitored.last_run_id)) missingIDs.add(monitored.last_run_id);
  }
  const fetched = await Promise.all(Array.from(missingIDs, (id) => getRun(id)));
  for (const run of fetched) byID.set(run.id, run);

  for (const source of driftSources) {
    const monitored = bySource.get(source.id);
    if (!monitored) throw new Error(`Latest drift run is unavailable for ${source.name}`);
    if (!monitored.last_run_id) {
      result[source.id] = null;
      continue;
    }
    const run = byID.get(monitored.last_run_id);
    if (!run || run.source_id !== source.id || run.status !== monitored.last_run_status) {
      throw new Error(`Latest drift run readback does not match monitoring for ${source.name}`);
    }
    result[source.id] = run;
  }
  return result;
}
