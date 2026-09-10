import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { measureEntry } from "./check-entry-size.mjs";

function fixture(t, files) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "trstctl-entry-size-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  for (const [name, code] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(root, name)), { recursive: true });
    fs.writeFileSync(path.join(root, name), code);
  }
  return root;
}

test("counts transitive shared imports and preloads once, excluding lazy routes", (t) => {
  const root = fixture(t, {
    "index.html": '<script type="module" src="/assets/entry.js"></script><link rel="modulepreload" href="/assets/preload.js">',
    "assets/entry.js": 'import "./shared.js"; export { value } from "./shared.js"; export const lazy = () => import("./lazy.js");',
    "assets/shared.js": 'import "./entry.js"; export const value = "shared";',
    "assets/preload.js": 'import "./shared.js";',
    "assets/lazy.js": 'export const expensive = "not eager";',
  });
  const result = measureEntry(root);
  assert.deepEqual(result.files.map((f) => f.file).sort(), ["assets/entry.js", "assets/preload.js", "assets/shared.js", "index.html"]);
  assert.equal(
    result.bytes,
    result.files.reduce((sum, f) => sum + f.bytes, 0),
  );
  fs.appendFileSync(
    path.join(root, "assets/shared.js"),
    `\nexport const extra=${JSON.stringify(Array.from({ length: 200 }, (_, i) => `unique-${i * i}`).join(" "))};`,
  );
  assert.ok(measureEntry(root).bytes > result.bytes);
});

test("missing and external dependencies fail rather than undercount", (t) => {
  const root = fixture(t, { "index.html": '<script type="module" src="/entry.js"></script>', "entry.js": 'import "./missing.js";' });
  assert.throws(() => measureEntry(root), /ENOENT/);
  fs.writeFileSync(path.join(root, "entry.js"), 'import "https://example.invalid/remote.js";');
  assert.throws(() => measureEntry(root), /unsupported entry dependency/);
});

test("a dependency symlink cannot escape the built artifact", (t) => {
  const root = fixture(t, { "index.html": '<script type="module" src="/entry.js"></script>', "entry.js": 'import "./escape.js";' });
  fs.symlinkSync(import.meta.filename, path.join(root, "escape.js"));
  assert.throws(() => measureEntry(root), /escapes dist/);
});

test("an empty page cannot report a zero-byte shell", (t) => {
  const root = fixture(t, { "index.html": "<html></html>" });
  assert.throws(() => measureEntry(root), /no external module entry/);
});

test("inline startup code contributes bytes and unsupported executable scripts refuse", (t) => {
  const root = fixture(t, { "index.html": '<script type="module" src="/entry.js"></script>', "entry.js": "export const ready = true;" });
  const original = measureEntry(root).bytes;
  fs.appendFileSync(
    path.join(root, "index.html"),
    `<script>globalThis.theme=${JSON.stringify(Array.from({ length: 100 }, (_, i) => String(i * i)).join("-"))};</script>`,
  );
  assert.ok(measureEntry(root).bytes > original);
  fs.appendFileSync(path.join(root, "index.html"), '<script src="/classic.js"></script>');
  assert.throws(() => measureEntry(root), /external classic/);
  fs.writeFileSync(path.join(root, "index.html"), '<script type="module" src="/entry.js"></script><script type="module">import "./hidden.js";</script>');
  assert.throws(() => measureEntry(root), /inline module/);
});

test("unquoted attributes and duplicate attributes follow browser parsing", (t) => {
  const root = fixture(t, {
    "index.html":
      '<script type="module" src="/entry.js"></script><script type=module src=/extra.js></script><script type="module" src="/first.js" src="/ignored.js"></script>',
    "entry.js": "export const ready=true;",
    "extra.js": "export const additional=true;",
    "first.js": "export const firstAttribute=true;",
  });
  assert.deepEqual(
    measureEntry(root)
      .files.map((file) => file.file)
      .sort(),
    ["entry.js", "extra.js", "first.js", "index.html"],
  );
});
