import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { brotliCompressSync, constants } from "node:zlib";
import { JSDOM } from "jsdom";
import ts from "typescript";

// Count what the browser must load for the shell, including shared chunks.
// A route's dynamic import remains lazy; a modulepreload in index.html is eager.
export function measureEntry(dist) {
  const root = fs.realpathSync(dist);
  const index = path.join(root, "index.html");
  const html = fs.readFileSync(index, "utf8");
  // Count the HTML once as well: it carries the inline startup script. This
  // deliberately includes its markup rather than silently excluding that JS.
  const compressedSize = (code) => brotliCompressSync(code, { params: { [constants.BROTLI_PARAM_QUALITY]: 11 } }).length;
  const files = new Map([[index, compressedSize(html)]]);
  function localFile(specifier, parent) {
    if (!specifier || /[?#\\]/.test(specifier) || /^[a-z][a-z0-9+.-]*:/i.test(specifier) || specifier.startsWith("//")) {
      throw new Error(`unsupported entry dependency ${JSON.stringify(specifier)}`);
    }
    const resolved = fs.realpathSync(specifier.startsWith("/") ? path.join(root, specifier) : path.resolve(path.dirname(parent), specifier));
    if (!resolved.startsWith(root + path.sep)) throw new Error(`entry dependency escapes dist: ${specifier}`);
    if (!/\.m?js$/.test(resolved)) throw new Error(`entry dependency is not JavaScript: ${specifier}`);
    return resolved;
  }
  function visit(file) {
    if (files.has(file)) return;
    const code = fs.readFileSync(file);
    files.set(file, compressedSize(code));
    const source = ts.createSourceFile(file, code.toString("utf8"), ts.ScriptTarget.Latest, true, ts.ScriptKind.JS);
    for (const statement of source.statements) {
      if (!ts.isImportDeclaration(statement) && !ts.isExportDeclaration(statement)) continue;
      const module = statement.moduleSpecifier;
      if (module && ts.isStringLiteral(module)) visit(localFile(module.text, file));
    }
  }
  let entries = 0;
  // Use the existing inert HTML parser so quoted/unquoted and duplicate
  // attributes have browser semantics. No resources or scripts are enabled.
  const { window } = new JSDOM(html);
  const startupElements = [...window.document.querySelectorAll("script, link")].map((element) => ({
    script: element.localName === "script",
    namespace: element.namespaceURI,
    attrs: Object.fromEntries([...element.attributes].map((attribute) => [attribute.name, attribute.value])),
  }));
  window.close();
  for (const { script, namespace, attrs } of startupElements) {
    if (namespace !== "http://www.w3.org/1999/xhtml") throw new Error("unsupported non-HTML startup element");
    if (script && attrs.src && attrs.type !== "module") throw new Error("unsupported external classic startup script");
    if (script && attrs.type === "module" && !attrs.src) throw new Error("unsupported inline module startup script");
    if (script && attrs.type === "module" && attrs.src) {
      entries++;
      visit(localFile(attrs.src, index));
    } else if (!script && attrs.rel?.split(/\s+/).includes("modulepreload")) {
      visit(localFile(attrs.href, index));
    }
  }
  if (entries === 0) throw new Error("index.html has no external module entry");
  return {
    bytes: [...files.values()].reduce((sum, size) => sum + size, 0),
    files: [...files].map(([file, bytes]) => ({ file: path.relative(root, file), bytes })),
  };
}

// Every page the console loads lazily, each measured alone (BUDGET-O1): the
// chunk Vite names after a module in src/pages, "<Page>-<8-character hash>.js".
// The largest-page ceiling used to measure one page's chunk by name (Secrets)
// while three larger pages went unmeasured. A module without a chunk of its
// own is bundled into a page or the entry and is skipped; a page with two
// chunks of its name fails rather than undercounting.
export function measurePages(dist, pageNames) {
  const assets = path.join(fs.realpathSync(dist), "assets");
  const compressedSize = (code) => brotliCompressSync(code, { params: { [constants.BROTLI_PARAM_QUALITY]: 11 } }).length;
  const chunks = fs.readdirSync(assets).filter((name) => name.endsWith(".js"));
  const pages = [];
  for (const page of pageNames) {
    const named = chunks.filter((name) => name.startsWith(`${page}-`) && /^[A-Za-z0-9_-]{8}\.js$/.test(name.slice(page.length + 1)));
    if (named.length > 1) throw new Error(`page ${page} has ${named.length} chunks of its name`);
    if (named.length === 1) {
      pages.push({ page, file: `assets/${named[0]}`, bytes: compressedSize(fs.readFileSync(path.join(assets, named[0]))) });
    }
  }
  if (pages.length === 0) throw new Error("no page chunk found");
  pages.sort((a, b) => b.bytes - a.bytes || a.page.localeCompare(b.page));
  return pages;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const webRoot = path.resolve(import.meta.dirname, "..");
  const pkg = JSON.parse(fs.readFileSync(path.join(webRoot, "package.json"), "utf8"));
  const entry = pkg["size-limit"].find((check) => check.path.endsWith("/index-*.js"));
  if (!entry || !/^\d+(?:\.\d+)? kB$/.test(entry.limit) || entry.gzip === true || entry.brotli === false)
    throw new Error("unsupported entry budget configuration");
  const limit = Number.parseFloat(entry.limit) * 1000;
  const dist = path.resolve(webRoot, "../internal/webui/dist");
  const result = measureEntry(dist);
  console.log(JSON.stringify({ name: "complete entry import graph (Brotli)", ...result, limit }, null, 2));
  if (result.bytes > limit) process.exitCode = 1;
  const pageBudget = pkg["page-budget"];
  if (!pageBudget || !/^\d+(?:\.\d+)? kB$/.test(pageBudget.limit)) throw new Error("unsupported page budget configuration");
  const pageLimit = Number.parseFloat(pageBudget.limit) * 1000;
  const pageNames = fs
    .readdirSync(path.join(webRoot, "src/pages"))
    .filter((name) => name.endsWith(".tsx") && !name.endsWith(".stories.tsx") && !name.endsWith(".test.tsx"))
    .map((name) => name.slice(0, -".tsx".length));
  const pages = measurePages(dist, pageNames);
  console.log(JSON.stringify({ name: pageBudget.name, largest: pages[0], measured: pages.length, largestFive: pages.slice(0, 5), limit: pageLimit }, null, 2));
  if (pages[0].bytes > pageLimit) process.exitCode = 1;
}
