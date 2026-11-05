import { chmodSync, mkdtempSync, mkdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { afterEach, describe, expect, it } from "vitest";
import { loadDemoOperatorCredentials } from "../../e2e/operator-credentials";

const directories: string[] = [];
afterEach(() => {
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});
function fixture(body: unknown, mode = 0o600): string {
  const directory = mkdtempSync(join(tmpdir(), "trstctl-e2e-login-"));
  directories.push(directory);
  const path = join(directory, "operators.json");
  writeFileSync(path, typeof body === "string" ? body : JSON.stringify(body), { mode });
  chmodSync(path, mode);
  return path;
}
function document() {
  return {
    version: 1,
    users: [
      { subject: "eval-custodian-1", password: "custodian-fixture" },
      { subject: "eval-admin", password: "administrator-fixture" },
    ],
  };
}

describe("private evaluation operator fixture", () => {
  it("selects the administrator rather than the first custodian", () => {
    const value = loadDemoOperatorCredentials(fixture(document()));
    expect(value.subject).toBe("eval-admin");
    expect(value.password.length).toBe(21);
  });
  it("refuses group-readable credentials", () => {
    expect(() => loadDemoOperatorCredentials(fixture(document(), 0o640))).toThrow("private regular file");
  });
  it("refuses a symlink even to a private credential file", () => {
    const path = fixture(document());
    const link = `${path}.link`;
    symlinkSync(path, link);
    expect(() => loadDemoOperatorCredentials(link)).toThrow();
  });
  it("refuses a directory", () => {
    const path = fixture(document());
    const directory = `${path}.dir`;
    mkdirSync(directory, { mode: 0o700 });
    expect(() => loadDemoOperatorCredentials(directory)).toThrow("private regular file");
  });
  it("bounds credential-file input", () => {
    expect(() => loadDemoOperatorCredentials(fixture(" ".repeat(64 * 1024 + 1)))).toThrow("too large");
  });
  it("does not include malformed credential bytes in an error", () => {
    const sensitive = "fabricated-private-fixture";
    const path = fixture(`{"users":[{"password":"${sensitive}`);
    let message = "";
    try {
      loadDemoOperatorCredentials(path);
    } catch (error) {
      message = String(error);
    }
    expect(message).toContain("not valid JSON");
    expect(message).not.toContain(sensitive);
  });
  it.each([null, {}, { version: 2, users: [] }, { version: 1, users: [] }, { version: 1, users: [{ subject: "eval-admin", password: "" }] }])(
    "refuses an invalid or missing administrator record",
    (body) => {
      expect(() => loadDemoOperatorCredentials(fixture(body))).toThrow();
    },
  );
});
