export type GridViewPrimitive = string | number | boolean | null;

export interface StoredGridSort {
  columnId: string;
  direction: "asc" | "desc";
}

export interface SavedGridView {
  id: string;
  name: string;
  createdAt: string;
  columnOrder: string[];
  visibleColumnIds: string[];
  sort?: StoredGridSort;
  metadata: Record<string, GridViewPrimitive>;
}

export interface GridPreferences {
  columnOrder?: string[];
  visibleColumnIds?: string[];
  views: SavedGridView[];
}

const storagePrefix = "trstctl-grid-view:";

export function gridStorageName(key: string): string {
  return `${storagePrefix}${key}`;
}

export function readGridPreferences(key: string): GridPreferences {
  if (typeof localStorage === "undefined") return { views: [] };
  try {
    const raw = localStorage.getItem(gridStorageName(key));
    if (!raw) return { views: [] };
    const parsed = JSON.parse(raw) as Partial<GridPreferences>;
    return {
      columnOrder: Array.isArray(parsed.columnOrder) ? parsed.columnOrder.filter(isString) : undefined,
      visibleColumnIds: Array.isArray(parsed.visibleColumnIds) ? parsed.visibleColumnIds.filter(isString) : undefined,
      views: Array.isArray(parsed.views) ? parsed.views.filter(isSavedView) : [],
    };
  } catch {
    return { views: [] };
  }
}

export function writeGridPreferences(key: string, preferences: GridPreferences) {
  if (typeof localStorage === "undefined") return;
  const safe: GridPreferences = {
    columnOrder: preferences.columnOrder?.filter(isString),
    visibleColumnIds: preferences.visibleColumnIds?.filter(isString),
    views: preferences.views.map(sanitizeView),
  };
  localStorage.setItem(gridStorageName(key), JSON.stringify(safe));
}

export function sanitizeViewMetadata(metadata: Record<string, unknown> | undefined): Record<string, GridViewPrimitive> {
  const safe: Record<string, GridViewPrimitive> = {};
  for (const [key, value] of Object.entries(metadata ?? {})) {
    if (isSensitiveMetadataKey(key) || isSensitiveMetadataValue(value)) {
      continue;
    }
    if (typeof value === "string" || typeof value === "number" || typeof value === "boolean" || value === null) {
      safe[key] = value;
    }
  }
  return safe;
}

function sanitizeView(view: SavedGridView): SavedGridView {
  return {
    id: view.id,
    name: view.name,
    createdAt: view.createdAt,
    columnOrder: view.columnOrder.filter(isString),
    visibleColumnIds: view.visibleColumnIds.filter(isString),
    sort: view.sort,
    metadata: sanitizeViewMetadata(view.metadata),
  };
}

function isSavedView(value: unknown): value is SavedGridView {
  if (!value || typeof value !== "object") return false;
  const view = value as SavedGridView;
  return (
    isString(view.id) &&
    isString(view.name) &&
    isString(view.createdAt) &&
    Array.isArray(view.columnOrder) &&
    Array.isArray(view.visibleColumnIds)
  );
}

function isString(value: unknown): value is string {
  return typeof value === "string";
}

function isSensitiveMetadataKey(key: string): boolean {
  return /token|secret|password|bearer|credential|private|pem|payload|rawRecord|rowPayload|trst_/i.test(key);
}

function isSensitiveMetadataValue(value: unknown): boolean {
  return (
    typeof value === "string" &&
    /(bearer\s+[a-z0-9._~+/=-]+|trst_[a-z0-9._-]+|-----BEGIN [A-Z ]*PRIVATE KEY-----|token=|password=|secret=)/i.test(value)
  );
}
