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

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const webRoot = path.resolve(import.meta.dirname, "..");
  const pkg = JSON.parse(fs.readFileSync(path.join(webRoot, "package.json"), "utf8"));
  const entry = pkg["size-limit"].find((check) => check.path.endsWith("/index-*.js"));
  if (!entry || !/^\d+(?:\.\d+)? kB$/.test(entry.limit) || entry.gzip === true || entry.brotli === false)
    throw new Error("unsupported entry budget configuration");
  const limit = Number.parseFloat(entry.limit) * 1000;
  const result = measureEntry(path.resolve(webRoot, "../internal/webui/dist"));
  console.log(JSON.stringify({ name: "complete entry import graph (Brotli)", ...result, limit }, null, 2));
  if (result.bytes > limit) process.exitCode = 1;
}
