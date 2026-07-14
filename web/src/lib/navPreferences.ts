/** Sidebar navigation preferences: which rail groups the operator collapsed.
 * Pure UI metadata (no identifiers, no auth material) — the same class of
 * benign persistence as the theme choice and DataGrid view metadata, kept in
 * its own module so the security-sink scan can allow it explicitly. */

const NAV_COLLAPSE_KEY = "trstctl-nav-collapsed";

/** Group label keys that no longer exist after the S-A1 rail re-group. A
 * returning user's persisted collapse set may still name them; dropping them on
 * read keeps stale entries from lingering forever (they are harmless but
 * confuse the "[]" empty-state assertions and any future audit of the key). */
const RETIRED_GROUP_KEYS = new Set<string>([
  "nav.group.issuanceCas",
  "nav.group.inventoryDiscovery",
  "nav.group.incidentsJit",
  "nav.group.riskInsight",
  "nav.group.platform",
]);

export function readCollapsedGroups(): Set<string> {
  try {
    const raw = localStorage.getItem(NAV_COLLAPSE_KEY);
    if (!raw) return new Set();
    const parsed = JSON.parse(raw) as unknown;
    const values = Array.isArray(parsed) ? parsed.filter((value): value is string => typeof value === "string" && !RETIRED_GROUP_KEYS.has(value)) : [];
    return new Set(values);
  } catch {
    return new Set();
  }
}

export function persistCollapsedGroups(collapsed: Set<string>): void {
  try {
    localStorage.setItem(NAV_COLLAPSE_KEY, JSON.stringify(Array.from(collapsed)));
  } catch {
    // Storage unavailable: collapse state is a convenience only.
  }
}

/** Active module selection for the S-B2 switcher. Pure UI metadata (a module
 * id string), same benign-persistence class as the collapse state above. */
const NAV_MODULE_KEY = "trstctl-nav-module";

export function readActiveModule(): string | null {
  try {
    return localStorage.getItem(NAV_MODULE_KEY);
  } catch {
    return null;
  }
}

export function persistActiveModule(moduleId: string): void {
  try {
    localStorage.setItem(NAV_MODULE_KEY, moduleId);
  } catch {
    // Storage unavailable: module selection is a convenience only.
  }
}
