import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { formatDate, formatDateTime, formatNumber, formatPlural } from "@/i18n/format";

// This test file lives at web/src/__tests__/, so web/src is its parent dir.
const SRC = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function walkSources(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      out.push(...walkSources(full));
    } else if (/\.(ts|tsx)$/.test(entry.name)) {
      out.push(full);
    }
  }
  return out;
}

describe("central locale/timezone/plural policy (PRODUCT-004)", () => {
  it("formats dates through Intl with an explicit locale and timezone", () => {
    // A fixed instant renders deterministically when the timezone is pinned.
    expect(formatDate("2026-06-19T23:30:00Z", { locale: "en-US", timeZone: "UTC" })).toBe("Jun 19, 2026");
    // Same instant, a timezone east of UTC, rolls to the next calendar day.
    expect(formatDate("2026-06-19T23:30:00Z", { locale: "en-US", timeZone: "Asia/Tokyo" })).toBe("Jun 20, 2026");
    // Locale still resolves and renders the year.
    expect(formatDate("2026-06-19T12:00:00Z", { locale: "ar-XB", timeZone: "UTC" })).toMatch(/2026/);
  });

  it("formats date-times through Intl with timezone applied", () => {
    // Use \s for the time separator so the assertion tolerates ICU builds that
    // emit a regular space or a narrow no-break space before the meridiem.
    expect(formatDateTime("2026-06-19T12:00:00Z", { locale: "en-US", timeZone: "UTC" })).toMatch(/^Jun 19, 2026,\s12:00\sPM$/);
    expect(formatDateTime("2026-06-19T12:00:00Z", { locale: "en-US", timeZone: "America/New_York" })).toMatch(/8:00\sAM/);
  });

  it("returns stable placeholders for empty/invalid values", () => {
    expect(formatDate(undefined)).toBe("-");
    expect(formatDate("")).toBe("-");
    expect(formatDate("not-a-date")).toBe("not-a-date");
  });

  it("formats numbers and plurals through Intl with locale", () => {
    expect(formatNumber(123456, { locale: "en-US", timeZone: "UTC" })).toBe("123,456");
    expect(formatPlural(1, { one: "node", other: "nodes" }, { locale: "en-US", timeZone: "UTC" })).toBe("node");
    expect(formatPlural(2, { one: "node", other: "nodes" }, { locale: "en-US", timeZone: "UTC" })).toBe("nodes");
  });

  it("keeps ad-hoc toLocaleDateString/toLocaleString out of the shipped sources", () => {
    // The approved formatting boundary is web/src/i18n/format.ts, which uses
    // Intl.* directly. No page or component may call toLocale* ad hoc; this is
    // the same invariant as the audit grep over web/src.
    const pattern = /toLocale(DateString|String)\(/;
    const offenders: string[] = [];
    for (const file of walkSources(SRC)) {
      if (file.endsWith(path.join("i18n", "format.ts"))) continue; // approved helper
      if (/\.test\.(ts|tsx)$/.test(file)) continue; // tests may reference the API name
      const source = readFileSync(file, "utf8");
      if (pattern.test(source)) offenders.push(path.relative(SRC, file));
    }
    expect(offenders, `ad-hoc toLocale* call sites found: ${offenders.join(", ")}`).toEqual([]);
  });

  it("routes representative pages through the central format helpers", () => {
    for (const page of ["Certificates.tsx", "Secrets.tsx", "Risk.tsx", "Discovery.tsx", "Identities.tsx", "Agents.tsx", "RequestCredential.tsx"]) {
      const source = readFileSync(path.join(SRC, "pages", page), "utf8");
      expect(source, `${page} should import the central format policy`).toMatch(/from "@\/i18n\/format"/);
    }
    const dashboard = readFileSync(path.join(SRC, "pages", "Dashboard.tsx"), "utf8");
    expect(dashboard).toMatch(/from "@\/i18n\/format"/);
  });
});
