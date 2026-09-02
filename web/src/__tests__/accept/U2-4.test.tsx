import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      getSecretVersion: vi.fn(async (_name: string, version: number) => ({ name: "x", value: `v${version}val`, version })),
      recoverSecret: vi.fn(async () => ({ name: "x", version: 2 })),
    },
  };
});

import { VersionHistory } from "@/components/secrets";

describe("U2-4 version history", () => {
  it("lists versions, reveals a version, and recovers to a point in time", async () => {
    render(<VersionHistory name="x" latestVersion={3} />);
    expect(screen.getByText("version 3")).toBeInTheDocument();
    expect(screen.getByText("version 1")).toBeInTheDocument();

    await userEvent.click(screen.getAllByRole("button", { name: "Reveal" })[0]);
    expect(await screen.findByText(/v3: v3val/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Dismiss" }));
    expect(screen.queryByText(/v3: v3val/)).not.toBeInTheDocument();

    await userEvent.click(screen.getAllByRole("button", { name: "Reveal" })[0]);
    expect(await screen.findByText(/v3: v3val/)).toBeInTheDocument();

    await userEvent.type(screen.getByPlaceholderText("2026-01-01T00:00:00Z"), "2026-01-01T00:00:00Z");
    await userEvent.click(screen.getByRole("button", { name: "Recover" }));
    expect(await screen.findByText(/Recovered to version 2/)).toBeInTheDocument();
    expect(screen.queryByText(/v3: v3val/)).not.toBeInTheDocument();
  });
});
