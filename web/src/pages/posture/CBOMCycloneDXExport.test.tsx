import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { CBOMCycloneDXExport } from "./CBOMCycloneDXExport";

const { apiMock } = vi.hoisted(() => ({ apiMock: { exportCBOMCycloneDX: vi.fn() } }));
vi.mock("@/lib/api", async (original) => {
  const actual = await original<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

const readBlob = (blob: Blob) =>
  new Promise<string>((resolve) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result));
    reader.readAsText(blob);
  });

// Q3: the console saves the CycloneDX BOM a scanner ingests, or the signed
// export for offline verification.
describe("CycloneDX CBOM export", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    apiMock.exportCBOMCycloneDX.mockResolvedValue({
      spec_version: "1.6",
      components: 3,
      bom: { bomFormat: "CycloneDX", specVersion: "1.6", components: [] },
      bom_sha256: "sha256:ab",
      signed_bom: "header.payload.signature",
      public_jwks: { keys: [] },
    });
  });

  it("saves the BOM and the signed export", async () => {
    const user = userEvent.setup();
    const saved: Blob[] = [];
    const create = vi.fn((blob: Blob) => {
      saved.push(blob);
      return "blob:cbom";
    });
    Object.assign(URL, { createObjectURL: create, revokeObjectURL: vi.fn() });
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
    render(<CBOMCycloneDXExport />);
    await user.click(screen.getByRole("button", { name: "Download CycloneDX CBOM" }));
    expect(await screen.findByRole("status")).toHaveTextContent("Saved a CBOM with 3 components.");
    expect(JSON.parse(await readBlob(saved[0]))).toMatchObject({ bomFormat: "CycloneDX", specVersion: "1.6" });
    await user.click(screen.getByRole("button", { name: "Download signed export" }));
    expect(JSON.parse(await readBlob(saved[1]))).toMatchObject({ signed_bom: "header.payload.signature" });
    expect(apiMock.exportCBOMCycloneDX).toHaveBeenCalledTimes(2);
    expect(click).toHaveBeenCalledTimes(2);
  });
});
