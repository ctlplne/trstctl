import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import ts from "typescript";

const webRoot = path.resolve(import.meta.dirname, "..");
const sourceRoot = path.join(webRoot, "src");
const messagesPath = path.join(sourceRoot, "i18n", "messages.ts");

function sourceFiles(directory) {
  const files = [];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const absolute = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      files.push(...sourceFiles(absolute));
      continue;
    }
    if (!/\.(ts|tsx)$/.test(entry.name)) continue;
    if (absolute === messagesPath || absolute.includes(".runtime.gen.ts") || absolute.includes(`${path.sep}i18n${path.sep}catalog.`)) continue;
    files.push(absolute);
  }
  return files;
}

const messageSource = readFileSync(messagesPath, "utf8");
const sourceFile = ts.createSourceFile(messagesPath, messageSource, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
const referencedSource = sourceFiles(sourceRoot)
  .map((file) => readFileSync(file, "utf8"))
  .join("\n");
const unused = [];

function visit(node) {
  if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.name.text === "messages") {
    let initializer = node.initializer;
    if (initializer && ts.isAsExpression(initializer)) initializer = initializer.expression;
    if (initializer && ts.isObjectLiteralExpression(initializer)) {
      for (const property of initializer.properties) {
        if (!ts.isPropertyAssignment(property) || !ts.isStringLiteral(property.name)) continue;
        const key = property.name.text;
        if (key.startsWith("source.") && !referencedSource.includes(key)) unused.push(key);
      }
    }
  }
  ts.forEachChild(node, visit);
}

visit(sourceFile);

if (unused.length > 0) {
  console.error(`Found ${unused.length} unused source message key(s):`);
  for (const key of unused) console.error(`- ${key}`);
  process.exitCode = 1;
} else {
  console.log("OK: every source.* message key is referenced by web source or a web contract test.");
}
