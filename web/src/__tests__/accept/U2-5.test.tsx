import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { SecretImport } from "@/components/secrets/SecretImport";

const { importSecrets } = vi.hoisted(() => ({ importSecrets: vi.fn() }));
vi.mock("@/lib/api", async (original) => {
  const actual = await original<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, importSecrets } };
});

describe("U2-5 secret import", () => {
  it("rejects a JSON array before any batch mutation is offered", async () => {
    importSecrets.mockReset();
    const user = userEvent.setup();
    render(<SecretImport />);
    const raw = '[{"name":"qa/unsafe","value":"secret"}]';
    const file = new File([raw], "wrong-shape.json", { type: "application/json" });
    Object.defineProperty(file, "text", { value: async () => raw });

    await user.upload(screen.getByLabelText("Choose JSON import file"), file);

    expect(await screen.findByRole("alert")).toHaveTextContent("Use a JSON object with an optional prefix and a values object");
    expect(screen.queryByRole("button", { name: "Import reviewed secrets" })).not.toBeInTheDocument();
    expect(importSecrets).not.toHaveBeenCalled();
  });
});
