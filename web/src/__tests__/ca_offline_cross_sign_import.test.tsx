import { createHash, webcrypto } from "node:crypto";
import { beforeEach, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { CAOfflineCrossSignPanel } from "@/pages/cahierarchy/CAHierarchyOfflineCrossSignParts";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    previewCACeremony: vi.fn(),
    createCACeremony: vi.fn(),
    caCeremony: vi.fn(),
    importOfflineRootCrossSign: vi.fn(),
    getCACrossSignReceipt: vi.fn(),
  },
}));
vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: apiMock };
});

const issuerID = "00000000-0000-4000-8000-000000000041";
const ceremonyID = "00000000-0000-4000-8000-000000000042";
const target = "-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n";
const cross = "-----BEGIN CERTIFICATE-----\nREVG\n-----END CERTIFICATE-----\n";
const targetSHA = createHash("sha256").update("ABC").digest("hex");
const authority = {
  id: issuerID,
  tenant_id: "tenant-a",
  common_name: "QA disconnected root",
  kind: "root",
  status: "active",
  signer_handle: "",
  certificate_pem: target,
  serial: "41",
  max_path_len: 1,
  created_at: "2026-10-18T00:00:00Z",
};

beforeEach(() => {
  for (const mock of Object.values(apiMock)) mock.mockReset();
  Object.defineProperty(globalThis.crypto, "subtle", { configurable: true, value: webcrypto.subtle });
});

it("reviews exact public certificates, binds quorum and imports only the unchanged package", async () => {
  const purpose = "offline-cross-sign:exact-public-package";
  const fingerprint = createHash("sha256")
    .update(JSON.stringify({ purpose, threshold: 2 }))
    .digest("hex");
  apiMock.previewCACeremony.mockResolvedValue({
    ready: true,
    approval_threshold: 2,
    request_fingerprint: fingerprint,
    preview_writes: [],
    preview_external_effects: [],
  });
  apiMock.createCACeremony.mockResolvedValue({ id: ceremonyID, purpose, threshold: 2, approvals: 0, status: "pending" });
  apiMock.caCeremony
    .mockResolvedValueOnce({ id: ceremonyID, purpose, threshold: 2, approvals: 2, status: "pending" })
    .mockResolvedValueOnce({ id: ceremonyID, purpose, threshold: 2, approvals: 2, status: "completed" });
  apiMock.importOfflineRootCrossSign.mockResolvedValue({
    ceremony_id: ceremonyID,
    issuer_authority_id: issuerID,
    target_sha256: targetSHA,
    certificate_pem: cross,
    imported: true,
  });
  const user = userEvent.setup();
  render(<CAOfflineCrossSignPanel authorities={[authority]} />);
  await user.selectOptions(screen.getByLabelText("Active offline root issuer"), issuerID);
  fireEvent.change(screen.getByLabelText("Target CA certificate PEM"), { target: { value: target } });
  fireEvent.change(screen.getByLabelText("Offline-root cross-certificate PEM"), { target: { value: cross } });
  await user.click(screen.getByRole("button", { name: "Review offline cross-sign import" }));
  await waitFor(() =>
    expect(apiMock.previewCACeremony).toHaveBeenCalledWith(
      expect.objectContaining({
        operation: "import_offline_cross_sign",
        authority_id: issuerID,
        target_certificate_pem: target,
        cross_certificate_pem: cross,
        threshold: 2,
      }),
    ),
  );
  fireEvent.change(screen.getByLabelText("Offline-root cross-certificate PEM"), { target: { value: target } });
  expect(screen.getByRole("button", { name: "Start reviewed cross-sign ceremony" })).toBeDisabled();
  fireEvent.change(screen.getByLabelText("Offline-root cross-certificate PEM"), { target: { value: cross } });
  await user.click(screen.getByRole("button", { name: "Start reviewed cross-sign ceremony" }));
  await waitFor(() => expect(apiMock.createCACeremony).toHaveBeenCalledWith(apiMock.previewCACeremony.mock.calls.at(-1)?.[0]));
  await user.click(screen.getByRole("button", { name: "Refresh offline cross-sign ceremony" }));
  expect(await screen.findByText(/2\/2 distinct approvals/)).toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "Import approved cross-certificate" }));
  await waitFor(() =>
    expect(apiMock.importOfflineRootCrossSign).toHaveBeenCalledWith(issuerID, {
      ceremony_id: ceremonyID,
      target_certificate_pem: target,
      cross_certificate_pem: cross,
    }),
  );
  expect(screen.getByLabelText("Recovered public cross-certificate PEM")).toHaveValue(cross);
});

it("recovers the durable public receipt by ceremony ID after a browser reload", async () => {
  apiMock.caCeremony.mockResolvedValue({ id: ceremonyID, purpose: "offline-cross-sign:completed", threshold: 2, approvals: 2, status: "completed" });
  apiMock.getCACrossSignReceipt.mockResolvedValue({
    ceremony_id: ceremonyID,
    issuer_authority_id: issuerID,
    target_sha256: targetSHA,
    certificate_pem: cross,
    imported: true,
  });
  const user = userEvent.setup();
  render(<CAOfflineCrossSignPanel authorities={[]} />);
  fireEvent.change(screen.getByLabelText("Offline cross-sign ceremony ID"), { target: { value: ceremonyID } });
  await user.click(screen.getByRole("button", { name: "Refresh offline cross-sign ceremony" }));
  await waitFor(() => expect(apiMock.getCACrossSignReceipt).toHaveBeenCalledWith(ceremonyID));
  expect(screen.getByText(/Imported on server; public receipt recovered/)).toBeInTheDocument();
  expect(screen.getByText(/This browser has not compared the original certificates/)).toBeInTheDocument();
  expect(screen.queryByText(/No public certificates reviewed in this browser/)).not.toBeInTheDocument();
  expect(screen.queryByText(/reviewed certificates do not match this ceremony/)).not.toBeInTheDocument();
  expect(screen.getByLabelText("Recovered public cross-certificate PEM")).toHaveValue(cross);
});
