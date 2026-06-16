import { describe, it, expect } from "vitest";
import { readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";

// PROTECT track (sprint R11): the SURFACE-I01 lock for the SPA's clean XSS posture.
// The audit verified by grep that web/src contains no XSS sink (no
// dangerouslySetInnerHTML, no raw innerHTML assignment, no eval) and stores no auth
// token in localStorage/sessionStorage (only the theme). This guard re-runs that
// scan in CI (cd web && npm test) so a future component cannot quietly reintroduce a
// sink. It changes NO behavior; it fails if a sink or a token-in-storage appears.

const SRC = path.resolve(__dirname, "..");

// Source files to scan: every .ts/.tsx under web/src, excluding the tests themselves
// (a test may legitimately mention these strings to assert against them).
function sourceFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const full = path.join(dir, entry);
    const st = statSync(full);
    if (st.isDirectory()) {
      if (entry === "node_modules") continue;
      out.push(...sourceFiles(full));
      continue;
    }
    if (!/\.(ts|tsx)$/.test(entry)) continue;
    // Skip test files and the test-setup shim.
    if (/\.test\.(ts|tsx)$/.test(entry)) continue;
    if (full.includes(`${path.sep}__tests__${path.sep}`)) continue;
    if (full.includes(`${path.sep}test${path.sep}`)) continue;
    out.push(full);
  }
  return out;
}

describe("SPA security sinks (SURFACE-I01)", () => {
  const files = sourceFiles(SRC);

  it("scans a non-trivial number of source files (guard is meaningful)", () => {
    // If this drops to ~0 the glob broke and the checks below would be vacuous.
    expect(files.length).toBeGreaterThan(5);
  });

  it("has no XSS sink: no dangerouslySetInnerHTML, raw innerHTML assignment, or eval", () => {
    const offenders: string[] = [];
    // Raw innerHTML *assignment* (x.innerHTML = ...) is the sink; we match the
    // property followed by an '='. dangerouslySetInnerHTML and eval( are flagged
    // outright.
    const innerHTMLAssign = /\.innerHTML\s*=/;
    const outerHTMLAssign = /\.outerHTML\s*=/;
    for (const f of files) {
      const body = readFileSync(f, "utf8");
      const rel = path.relative(SRC, f);
      if (body.includes("dangerouslySetInnerHTML")) {
        offenders.push(`${rel}: dangerouslySetInnerHTML`);
      }
      if (innerHTMLAssign.test(body)) {
        offenders.push(`${rel}: raw innerHTML assignment`);
      }
      if (outerHTMLAssign.test(body)) {
        offenders.push(`${rel}: raw outerHTML assignment`);
      }
      // eval( as a call (allow words like "evaluate"); require a non-word char before.
      if (/(^|[^A-Za-z0-9_])eval\s*\(/.test(body)) {
        offenders.push(`${rel}: eval(`);
      }
    }
    expect(offenders, `XSS sink(s) found in web/src:\n${offenders.join("\n")}`).toEqual([]);
  });

  it("stores no auth token in localStorage/sessionStorage (only the theme uses storage)", () => {
    const offenders: string[] = [];
    for (const f of files) {
      const body = readFileSync(f, "utf8");
      const rel = path.relative(SRC, f);
      // No sessionStorage anywhere.
      if (/\bsessionStorage\b/.test(body)) {
        offenders.push(`${rel}: uses sessionStorage`);
      }
      // localStorage is allowed ONLY in the ThemeProvider (the theme preference).
      if (/\blocalStorage\b/.test(body) && !rel.includes("ThemeProvider")) {
        offenders.push(`${rel}: uses localStorage outside ThemeProvider (auth state must live in an HttpOnly cookie, not web storage)`);
      }
      // Belt-and-braces: never write a token/secret into web storage.
      if (/\.setItem\([^)]*\b(token|secret|password|bearer|trst_)\b/i.test(body)) {
        offenders.push(`${rel}: writes a token/secret into web storage`);
      }
    }
    expect(offenders, `auth-in-web-storage finding(s):\n${offenders.join("\n")}`).toEqual([]);
  });
});
