import { ApiError, UnauthorizedError, csrfHeaders, previewRefusal, previewTransportIsIsolated } from "./apiTransport";
import type { AuditQuery } from "./api";
import { auditQueryParams, auditReadSignal } from "./auditQuery";

// Downloading an audit record stream (epic J1).
//
// This lives outside the generic API client because it is not a JSON request.
// Every other method parses a body into a typed value; this one takes a blob and
// hands it to the browser as a file. Routing it through req<T> would mean
// parsing a year of audit events into a string the page then has to hold, which
// is the opposite of what a download is for.

/** The formats that stream records rather than returning a signed bundle. */
export type AuditStreamFormat = "ndjson" | "csv" | "splunk-hec" | "sentinel";

function fileExtension(format: string): string {
  return format === "csv" ? "csv" : "ndjson";
}

/**
 * Download an audit export in a record-stream format.
 *
 * Returns the filename it saved, so a caller can tell the operator where the
 * download went rather than leaving a silent click.
 *
 * The object URL is revoked on every path, including a failed click: a leaked
 * one pins the entire export in memory for the life of the tab, and an audit
 * export is exactly the download large enough for that to matter.
 */
export async function downloadAuditExport(options: AuditQuery | undefined, format: string, signal?: AbortSignal): Promise<string> {
  if (previewTransportIsIsolated()) throw previewRefusal();
  const params = auditQueryParams(options);
  params.set("format", format);

  const readSignal = auditReadSignal(signal);
  const res = await fetch(`/api/v1/audit/export?${params.toString()}`, {
    credentials: "include",
    headers: { ...csrfHeaders("GET") },
    signal: readSignal,
  });
  if (res.status === 401) throw new UnauthorizedError();
  if (!res.ok) throw new ApiError(res.status, await res.text());

  const filename = `trstctl-audit.${fileExtension(format)}`;
  const blob = await res.blob();
  readSignal.throwIfAborted();
  const url = URL.createObjectURL(blob);
  try {
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
  } finally {
    URL.revokeObjectURL(url);
  }
  return filename;
}
