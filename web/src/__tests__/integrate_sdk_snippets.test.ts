import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

const repoRoot = process.cwd().endsWith(`${path.sep}web`) ? path.resolve(process.cwd(), "..") : process.cwd();

function readRepoFile(relativePath: string): string {
  return readFileSync(path.join(repoRoot, relativePath), "utf8");
}

function extractSdkReferences(): Record<string, string> {
  const source = readRepoFile("web/src/pages/Integrate.tsx");
  const block = source.match(/const sdks = \[([\s\S]*?)\];/);
  expect(block, "Integrate.tsx should define the copyable SDK list").not.toBeNull();

  return Object.fromEntries(
    [...block![1].matchAll(/\{\s*name:\s*"([^"]+)",\s*reference:\s*"((?:\\.|[^"])*)"\s*\}/g)].map(([, name, reference]) => [
      name,
      JSON.parse(`"${reference}"`) as string,
    ]),
  );
}

function tomlStringField(source: string, field: string): string {
  const match = source.match(new RegExp(`^${field}\\s*=\\s*"([^"]+)"`, "m"));
  expect(match, `${field} should be present in TOML metadata`).not.toBeNull();
  return match![1];
}

function goModulePath(source: string): string {
  const match = source.match(/^module\s+(\S+)/m);
  expect(match, "Go SDK module path should be present").not.toBeNull();
  return match![1];
}

function pomTag(source: string, tag: "groupId" | "artifactId" | "version"): string {
  const match = source.match(new RegExp(`<${tag}>([^<]+)</${tag}>`));
  expect(match, `${tag} should be present in pom.xml`).not.toBeNull();
  return match![1];
}

describe("Integrate SDK install snippets (PRODUCT-004)", () => {
  it("keeps every copyable SDK reference aligned with committed package metadata", () => {
    const references = extractSdkReferences();
    const pythonName = tomlStringField(readRepoFile("clients/sdk/python/pyproject.toml"), "name");
    const goModule = goModulePath(readRepoFile("clients/sdk/go/go.mod"));
    const tsPackage = JSON.parse(readRepoFile("clients/sdk/typescript/package.json")) as { name: string };
    const javaPom = readRepoFile("clients/sdk/java/pom.xml");
    const javaCoordinate = `${pomTag(javaPom, "groupId")}:${pomTag(javaPom, "artifactId")}:${pomTag(javaPom, "version")}`;

    expect(references).toEqual({
      "Python SDK": `pip install ${pythonName}`,
      "Go SDK": `go get ${goModule}`,
      "TypeScript SDK": "npm install ./clients/sdk/typescript",
      "Java SDK": javaCoordinate,
    });
    expect(tsPackage.name).toBe("@trstctl/sdk");
  });
});
