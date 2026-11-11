// SPDX-License-Identifier: BUSL-1.1

import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { IntlProvider } from "@/i18n/I18nProvider";
import { AppQueryProvider } from "@/lib/query";
import { FactoryBatchesPanel } from "@/components/FactoryBatchesPanel";

const { apiMock, principal } = vi.hoisted(() => ({
  apiMock: {
    factoryBatches: vi.fn(),
    factoryBatch: vi.fn(),
    createFactoryBatch: vi.fn(),
    factoryBatchManifest: vi.fn(),
    reconcileFactoryBatch: vi.fn(),
    edgeDelegations: vi.fn(),
  },
  principal: { permissions: ["issuers:write"] as string[] },
}));

vi.mock("@/lib/api", async (orig) => ({ ...(await orig<typeof import("@/lib/api")>()), api: apiMock }));
vi.mock("@/auth/AuthProvider", async (orig) => ({
  ...(await orig<typeof import("@/auth/AuthProvider")>()),
  useAuth: () => ({ user: principal }),
}));

const delegation = { id: "d-1", host: "factory-line-1", common_name: "Line 1 edge CA", status: "active" };
const batch = {
  id: "b-1",
  delegation_id: "d-1",
  label: "spring-run",
  quota: 500,
  birth_ttl_seconds: 86400,
  created_by: "ops@example.test",
  created_at: "2026-11-10T08:00:00Z",
  recorded: 2,
  over_quota: 0,
  enrolled: 1,
};
const detail = {
  ...batch,
  births: [
    {
      serial: "0a1b",
      device_name: "sensor-0001",
      fingerprint: "sha256:aa",
      not_after: "2026-11-11T08:00:00Z",
      over_quota: false,
      enrolled: true,
      enrolled_at: "2026-11-10T09:00:00Z",
      operational_serial: "7f2c",
      renewals: 1,
    },
    { serial: "0a1c", device_name: "sensor-0002", fingerprint: "sha256:bb", not_after: "2026-11-11T08:00:00Z", over_quota: true, enrolled: false, renewals: 0 },
  ],
};
const pemA = "-----BEGIN CERTIFICATE-----\nQA-BIRTH-A\n-----END CERTIFICATE-----";
const pemB = "-----BEGIN CERTIFICATE-----\nQA-BIRTH-B\n-----END CERTIFICATE-----";

function renderPanel() {
  return render(
    <IntlProvider initialLocale="en-US" initialTimeZone="UTC">
      <AppQueryProvider>
        <FactoryBatchesPanel />
      </AppQueryProvider>
    </IntlProvider>,
  );
}

// P12-L3: the console shows device first-boot batches: each batch's quota and
// reconciled births, a batch's devices and their enrollment, and lets an
// issuer create a batch, save the station manifest and reconcile a journal.
describe("Device first-boot batches", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    principal.permissions = ["issuers:write"];
    apiMock.factoryBatches.mockResolvedValue({ items: [batch] });
    apiMock.edgeDelegations.mockResolvedValue({ items: [delegation], guidance: "" });
    apiMock.factoryBatch.mockResolvedValue(detail);
  });

  it("lists batches and shows a batch's births and each device's enrollment", async () => {
    const user = userEvent.setup();
    renderPanel();
    const table = await screen.findByRole("table", { name: "First-boot batches" });
    expect(within(table).getByText("500 devices; births valid 24 h")).toBeInTheDocument();
    expect(within(table).getByText("2 recorded, 1 enrolled, 0 over quota")).toBeInTheDocument();
    await user.click(within(table).getByRole("button", { name: "spring-run" }));
    const births = await screen.findByRole("table", { name: "Births in spring-run" });
    expect(apiMock.factoryBatch).toHaveBeenCalledWith("b-1");
    const rows = within(births).getAllByRole("row");
    expect(rows[1]).toHaveTextContent("sensor-0001");
    expect(rows[1]).toHaveTextContent(/Enrolled .*: operational certificate 7f2c, 1 renewals/);
    expect(rows[2]).toHaveTextContent("Not enrolled yet");
    expect(rows[2]).toHaveTextContent("Over the batch quota");
  });

  it("creates a batch under an active delegation, keeping one key for the request", async () => {
    apiMock.factoryBatches.mockResolvedValue({ items: [] });
    apiMock.createFactoryBatch.mockResolvedValue({ ...batch, id: "b-2", label: "summer-run" });
    const user = userEvent.setup();
    renderPanel();
    expect(await screen.findByText("No first-boot batches yet.")).toBeInTheDocument();
    await user.type(await screen.findByLabelText("Batch label"), "summer-run");
    await user.clear(screen.getByLabelText("Quota (devices)"));
    await user.type(screen.getByLabelText("Quota (devices)"), "250");
    await user.clear(screen.getByLabelText("Birth certificate lifetime (hours)"));
    await user.type(screen.getByLabelText("Birth certificate lifetime (hours)"), "12");
    await user.click(screen.getByRole("button", { name: "Create batch" }));
    expect(apiMock.createFactoryBatch).toHaveBeenCalledWith(
      { delegation_id: "d-1", label: "summer-run", quota: 250, birth_ttl_seconds: 43200 },
      expect.any(String),
    );
  });

  it("saves the station manifest and reconciles the station's journal", async () => {
    apiMock.factoryBatchManifest.mockResolvedValue({
      batch_id: "b-1",
      tenant_id: "t-1",
      delegation_id: "d-1",
      delegation_fingerprint: "sha256:dd",
      label: "spring-run",
      quota: 500,
      birth_ttl_seconds: 86400,
      est_path: "/.well-known/est/factory",
    });
    apiMock.reconcileFactoryBatch.mockResolvedValue({ recorded: 2, over_quota: 0, already: 0, rejected: 0 });
    const createObjectURL = vi.fn(() => "blob:manifest");
    Object.assign(URL, { createObjectURL, revokeObjectURL: vi.fn() });
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => undefined);
    const user = userEvent.setup();
    renderPanel();
    await user.click(await screen.findByRole("button", { name: "spring-run" }));
    await user.click(await screen.findByRole("button", { name: "Download station manifest" }));
    expect(apiMock.factoryBatchManifest).toHaveBeenCalledWith("b-1");
    expect(createObjectURL).toHaveBeenCalled();
    expect(click).toHaveBeenCalled();

    await user.type(screen.getByLabelText("Station host"), "factory-line-1");
    fireEvent.change(screen.getByLabelText("Birth certificates from the journal (PEM)"), { target: { value: `${pemA}\n${pemB}\n` } });
    await user.click(screen.getByRole("button", { name: "Reconcile journal" }));
    expect(apiMock.reconcileFactoryBatch).toHaveBeenCalledWith(
      "b-1",
      { host: "factory-line-1", batch_id: "b-1", certificates_pem: [pemA, pemB] },
      expect.any(String),
    );
    expect(await screen.findByText("Recorded 2, over quota 0, already recorded 0, rejected 0.")).toBeInTheDocument();
  });

  it("offers no create or reconcile without issuers:write", async () => {
    principal.permissions = ["issuers:read"];
    const user = userEvent.setup();
    renderPanel();
    await user.click(await screen.findByRole("button", { name: "spring-run" }));
    expect(await screen.findByRole("table", { name: "Births in spring-run" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Create batch" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Reconcile journal" })).not.toBeInTheDocument();
  });
});
