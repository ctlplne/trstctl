import type { DiscoveryFinding } from "@/lib/api";

/** A DN such as CN=web.example is certificate evidence, not the hostname used
 * by endpoint enrollment. Prefer a single observed SAN; keep the editable
 * fallback when multiple names require an operator's choice. */
export function suggestedIdentityName(finding: DiscoveryFinding): string {
  const kind = finding.kind.toLowerCase().replaceAll("-", "_");
  const sans = finding.metadata.sans;
  if (["certificate", "tls_certificate", "x509_certificate"].includes(kind) && Array.isArray(sans) && sans.every((name) => typeof name === "string")) {
    const names = [...new Set(sans.map((name: string) => name.trim()).filter(Boolean))];
    if (names.length === 1) return names[0];
  }
  for (const key of ["principal", "subject", "service", "name"]) {
    const value = finding.metadata[key];
    if (typeof value === "string" && value.trim()) return value.trim();
  }
  return finding.ref;
}
