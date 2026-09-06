import { describe, expect, it } from "vitest";
import { readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import { ApiError } from "@/lib/api";
import { apiProblemContext, apiProblemMessage } from "@/lib/apiProblem";

// WEB-APIPROBLEM-001 (AH-bc10425e). The console used to carry eight page-local
// copies of apiProblemMessage. Approvals and Identities had lost the 429 branch,
// so a rate-limited request there rendered a bare problem detail with no
// Retry-After hint; the other six disagreed on prefixing and on punctuation.
// This guard pins the two surviving shapes, pins that they emit the SAME 429
// text, and fails if a ninth local copy appears. The eslint no-restricted-syntax
// rule in web/eslint.config.js enforces the same rule at lint time.

const SRC = path.resolve(__dirname, "..");
const SHARED = path.resolve(SRC, "lib", "apiProblem.ts");

function sourceFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const full = path.join(dir, entry);
    if (statSync(full).isDirectory()) {
      out.push(...sourceFiles(full));
      continue;
    }
    if (/\.tsx?$/.test(entry) && !/\.(test|spec)\.tsx?$/.test(entry)) out.push(full);
  }
  return out;
}

describe("apiProblemMessage", () => {
  it("prefers the RFC 7807 detail, then the title, then the raw body", () => {
    expect(apiProblemMessage(new ApiError(422, JSON.stringify({ detail: "d", title: "t" })), "fb")).toBe("d");
    expect(apiProblemMessage(new ApiError(422, JSON.stringify({ title: "t" })), "fb")).toBe("t");
    expect(apiProblemMessage(new ApiError(500, "database unavailable"), "fb")).toBe("database unavailable");
  });

  it("never renders a blank alert for an empty or whitespace-only body", () => {
    expect(apiProblemMessage(new ApiError(500, "   "), "fb")).toBe("request failed (500)");
    expect(apiProblemMessage(new ApiError(500, ""), "fb")).toBe("request failed (500)");
  });

  it("carries the 429 retry hint with its subject", () => {
    const err = new ApiError(429, "queue full", 30);
    expect(apiProblemMessage(err, "Could not load approvals")).toBe("Could not load approvals: retry in 30s");
  });

  it("still names the rate limit when the server sent no Retry-After", () => {
    expect(apiProblemMessage(new ApiError(429, ""), "fb")).toBe("rate limited (429)");
  });

  it("uses the fallback only for a non-Error throw, never String(err)", () => {
    expect(apiProblemMessage(new Error("boom"), "fb")).toBe("boom");
    expect(apiProblemMessage({ nope: true }, "fb")).toBe("fb");
  });
});

describe("apiProblemContext", () => {
  it("prefixes the same message with the caller's context", () => {
    const err = new ApiError(422, JSON.stringify({ detail: "audit export window too large" }));
    expect(apiProblemContext(err, "Could not export evidence")).toBe("Could not export evidence: audit export window too large");
    expect(apiProblemContext(new Error("boom"), "Action failed")).toBe("Action failed: boom");
    expect(apiProblemContext({ nope: true }, "Action failed")).toBe("Action failed");
  });

  it("emits the identical 429 text as apiProblemMessage", () => {
    const err = new ApiError(429, "queue full", 30);
    expect(apiProblemContext(err, "Could not compute reachability")).toBe("Could not compute reachability: retry in 30s");
    expect(apiProblemContext(err, "x")).toBe(apiProblemMessage(err, "x"));
  });
});

describe("WEB-APIPROBLEM-001: one error renderer", () => {
  it("declares apiProblemMessage/apiProblemContext nowhere but src/lib/apiProblem.ts", () => {
    const offenders = sourceFiles(SRC)
      .filter((file) => path.resolve(file) !== SHARED)
      .filter((file) => /(function|const)\s+apiProblem(Message|Context)\b/.test(readFileSync(file, "utf8")));
    expect(offenders.map((file) => path.relative(SRC, file))).toEqual([]);
  });
});

describe("ApiError message", () => {
  it("surfaces the server's problem detail with the status and keeps the generic wording otherwise", () => {
    const detailed = new ApiError(422, JSON.stringify({ type: "about:blank", title: "Unprocessable", status: 422, detail: "selected external CA needs a DNS-01 provider config; no CA was substituted" }));
    expect(detailed.message).toBe("selected external CA needs a DNS-01 provider config; no CA was substituted (HTTP 422)");
    expect(new ApiError(422, JSON.stringify({ title: "Unprocessable", status: 422 })).message).toBe("Unprocessable (HTTP 422)");
    expect(new ApiError(500, "<html>oops</html>").message).toBe("request failed (500)");
    expect(new ApiError(500, "{not json").message).toBe("request failed (500)");
    expect(new ApiError(429, "", 7).message).toBe("rate limited (429) — retry in 7s");
  });
});
