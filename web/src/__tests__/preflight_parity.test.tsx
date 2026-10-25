import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

// Tailwind CSS v4's preflight changed element defaults that v3 left to the
// browser. When the console moved to v4 it was compared pixel by pixel with the
// v3 build, and these rules keep the v3 look. They live in the base layer, so a
// control that styles itself with utilities still wins.
const css = readFileSync(path.join(process.cwd(), "src/index.css"), "utf8")
  .replace(/\/\*[\s\S]*?\*\//g, "")
  .replace(/\s+/g, " ");

function blocks(prelude: string): string {
  const found: string[] = [];
  for (let start = css.indexOf(`${prelude} {`); start >= 0; start = css.indexOf(`${prelude} {`, start + 1)) {
    let depth = 0;
    let end = start;
    for (; end < css.length; end++) {
      if (css[end] === "{") depth++;
      if (css[end] === "}" && --depth === 0) break;
    }
    found.push(css.slice(start, end + 1));
  }
  return found.join(" ");
}

const base = blocks("@layer base");
const theme = blocks("@theme");

describe("Tailwind 4 preflight parity", () => {
  it.each([
    [
      "the native file-picker button",
      "::file-selector-button { margin: revert; padding: revert; border: revert; border-radius: revert; background-color: revert; color: revert; }",
    ],
    ["the v3 placeholder gray", "input::placeholder, textarea::placeholder { color: #9ca3af; }"],
    ["proportional digits in form controls", "button, input, select, optgroup, textarea { font-variant-numeric: normal; }"],
    ["the pointer cursor on buttons", 'button, [role="button"] { cursor: pointer; }'],
    ["the arrow cursor on disabled controls", ":disabled { cursor: default; }"],
  ])("keeps %s in the base layer", (_name, rule) => {
    expect(base).toContain(rule);
  });

  it("keeps the v3 fallback color for rings without a color class", () => {
    expect(theme).toContain("--default-ring-color: #3b82f680;");
  });
});
