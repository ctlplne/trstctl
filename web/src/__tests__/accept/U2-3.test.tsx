import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { diffSecrets, EnvDiffPanel } from "@/components/secrets";
import type { SecretMeta } from "@/lib/api";

describe("U2-3 environment diff", () => {
  it("diffs two secret sets into added, removed, and changed", () => {
    const left = [
      { name: "a", version: 1 },
      { name: "b", version: 1 },
    ] as SecretMeta[];
    const right = [
      { name: "b", version: 2 },
      { name: "c", version: 1 },
    ] as SecretMeta[];
    const diff = diffSecrets(left, right);
    expect(diff.added).toEqual(["c"]);
    expect(diff.removed).toEqual(["a"]);
    expect(diff.changed).toEqual(["b"]);
  });

  it("renders a folder-to-folder diff", () => {
    const secrets = [
      { name: "prod/db/password", version: 1 },
      { name: "prod/db/user", version: 1 },
      { name: "stage/db/password", version: 1 },
      { name: "stage/db/api", version: 1 },
    ] as SecretMeta[];
    render(<EnvDiffPanel secrets={secrets} />);
    expect(screen.getByText("Environment diff")).toBeInTheDocument();
    expect(screen.getByText(/api/)).toBeInTheDocument();
    expect(screen.getByText(/user/)).toBeInTheDocument();
  });
});
