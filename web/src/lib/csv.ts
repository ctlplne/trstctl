/** Storage-free on-demand CSV export for inventory grids.
 *
 * This is the export half of U8-3 (saved views live in the security-sanitized
 * gridViews module). It touches no browser storage and emits RFC-4180-ish CSV
 * so an operator can pull the current view as evidence without a scheduled
 * report pipeline (which the backend does not serve). */
function escapeCell(value: unknown): string {
  const text = value == null ? "" : String(value);
  return /[",\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

export function toCSV(columns: string[], rows: Array<Record<string, unknown>>): string {
  const header = columns.map(escapeCell).join(",");
  const body = rows.map((row) => columns.map((column) => escapeCell(row[column])).join(","));
  return [header, ...body].join("\n");
}
