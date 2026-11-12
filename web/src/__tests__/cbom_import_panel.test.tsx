// SPDX-License-Identifier: BUSL-1.1

import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { IntlProvider } from "@/i18n/I18nProvider";
import { CBOMImportPanel } from "@/pages/posture/CBOMImportPanel";
import { ApiError, api } from "@/lib/api";

const bom = '{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}\n';
const inventory = {
  items: [],
  migration_progress: { out_of_policy_assets: 0, percent_migrated: 0, post_quantum_ready_assets: 0, quantum_vulnerable_assets: 0, total_assets: 0 },
};

function renderPanel(onImported = vi.fn()) {
  render(
    <IntlProvider initialLocale="en-US" initialTimeZone="UTC">
      <CBOMImportPanel onImported={onImported} />
    </IntlProvider>,
  );
  return onImported;
}

// X6-L4: the Posture page imports a CycloneDX CBOM file as it is, under the
// source it names, and says what the import recorded.
describe("CBOM import", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    vi.spyOn(api, "listCBOMAssets").mockResolvedValue(inventory);
  });

  it("imports the chosen file's exact bytes under its source and reports the import", async () => {
    const spy = vi.spyOn(api, "importCBOM").mockResolvedValue({
      run_id: "run-7",
      source: "vendor:acme-router",
      version: 2,
      components: 14,
      findings: 3,
      asset_ids: [],
      replayed: false,
    });
    const user = userEvent.setup();
    const onImported = renderPanel();
    expect(screen.getByRole("button", { name: "Import CBOM" })).toBeDisabled();
    await user.type(screen.getByLabelText(/Source name/), "acme-router");
    await user.upload(screen.getByLabelText("CycloneDX CBOM (JSON)"), new File([bom], "router-cbom.json", { type: "application/json" }));
    await user.click(screen.getByRole("button", { name: "Import CBOM" }));
    await waitFor(() => expect(spy).toHaveBeenCalledWith("vendor:acme-router", bom, expect.any(String)));
    expect(await screen.findByText("Imported vendor:acme-router version 2: 14 components, 3 findings (run run-7).")).toBeInTheDocument();
    await waitFor(() => expect(onImported).toHaveBeenCalledWith(expect.objectContaining({ run_id: "run-7" }), inventory));
  });

  it("says how many of the BOM's certificates the certificate inventory holds (X6-L6)", async () => {
    vi.spyOn(api, "importCBOM").mockResolvedValue({
      run_id: "run-9",
      source: "vendor:acme-hsm",
      version: 3,
      components: 6,
      findings: 4,
      asset_ids: [],
      certificate_ids: ["c1", "c2"],
      replayed: false,
    });
    const user = userEvent.setup();
    renderPanel();
    await user.type(screen.getByLabelText(/Source name/), "acme-hsm");
    await user.upload(screen.getByLabelText("CycloneDX CBOM (JSON)"), new File([bom], "hsm-cbom.json", { type: "application/json" }));
    await user.click(screen.getByRole("button", { name: "Import CBOM" }));
    expect(await screen.findByText("2 certificates named their fingerprint and are in the certificate inventory with their expiry.")).toBeInTheDocument();
  });

  it("names the source kind and says when the same file changed nothing", async () => {
    const spy = vi.spyOn(api, "importCBOM").mockResolvedValue({
      run_id: "run-1",
      source: "image:registry.example/app:1.4",
      version: 1,
      components: 9,
      findings: 0,
      asset_ids: [],
      replayed: true,
    });
    const user = userEvent.setup();
    renderPanel();
    await user.selectOptions(screen.getByLabelText("Source kind"), "image");
    await user.type(screen.getByLabelText(/Source name/), "registry.example/app:1.4");
    await user.upload(screen.getByLabelText("CycloneDX CBOM (JSON)"), new File([bom], "image-cbom.json", { type: "application/json" }));
    await user.click(screen.getByRole("button", { name: "Import CBOM" }));
    await waitFor(() => expect(spy).toHaveBeenCalledWith("image:registry.example/app:1.4", bom, expect.any(String)));
    expect(await screen.findByText("image:registry.example/app:1.4 version 1 already holds this exact file; nothing changed.")).toBeInTheDocument();
  });

  it("keeps the request's key on a retry and shows the server's refusal", async () => {
    const spy = vi.spyOn(api, "importCBOM").mockRejectedValueOnce(new ApiError(400, "the CBOM is not a JSON document"));
    const user = userEvent.setup();
    renderPanel();
    await user.type(screen.getByLabelText(/Source name/), "acme-router");
    await user.upload(screen.getByLabelText("CycloneDX CBOM (JSON)"), new File(["not json"], "broken.json", { type: "application/json" }));
    await user.click(screen.getByRole("button", { name: "Import CBOM" }));
    expect(await screen.findByRole("alert")).toBeInTheDocument();
    spy.mockResolvedValueOnce({ run_id: "run-8", source: "vendor:acme-router", version: 3, components: 0, findings: 0, asset_ids: [], replayed: false });
    await user.click(screen.getByRole("button", { name: "Import CBOM" }));
    await waitFor(() => expect(spy).toHaveBeenCalledTimes(2));
    expect(spy.mock.calls[1][2]).toBe(spy.mock.calls[0][2]);
  });
});
