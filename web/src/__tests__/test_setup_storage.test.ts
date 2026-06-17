import { describe, expect, it } from "vitest";

describe("vitest storage setup", () => {
  it("provides deterministic browser storage globals for theme and shell tests", () => {
    expect(window.localStorage).toBeDefined();
    expect(window.sessionStorage).toBeDefined();
    expect(globalThis.localStorage).toBe(window.localStorage);
    expect(globalThis.sessionStorage).toBe(window.sessionStorage);

    localStorage.clear();
    localStorage.setItem("trstctl-theme", "dark");
    expect(localStorage.getItem("trstctl-theme")).toBe("dark");

    localStorage.clear();
    expect(localStorage.getItem("trstctl-theme")).toBeNull();
  });
});
