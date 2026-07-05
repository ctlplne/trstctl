/** Sidebar navigation preferences: which rail groups the operator collapsed.
 * Pure UI metadata (no identifiers, no auth material) — the same class of
 * benign persistence as the theme choice and DataGrid view metadata, kept in
 * its own module so the security-sink scan can allow it explicitly. */

const NAV_COLLAPSE_KEY = "trstctl-nav-collapsed";

export function readCollapsedGroups(): Set<string> {
  try {
    const raw = localStorage.getItem(NAV_COLLAPSE_KEY);
    if (!raw) return new Set();
    const parsed = JSON.parse(raw) as unknown;
    return new Set(Array.isArray(parsed) ? parsed.filter((value): value is string => typeof value === "string") : []);
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
