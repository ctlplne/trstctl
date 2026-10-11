import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { webcrypto } from "node:crypto";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { IntlProvider } from "@/i18n/I18nProvider";
import { AppQueryProvider } from "@/lib/query";
import type { CAAuthority } from "@/lib/api";
import { CACrossSignPanel } from "@/pages/cahierarchy/CAHierarchyCrossSignParts";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    caCeremony: vi.fn(),
    getCACrossSignReceipt: vi.fn(),
    previewCACeremony: vi.fn(),
    createCACeremony: vi.fn(),
    crossSignCAAuthority: vi.fn(),
  },
}));
vi.mock("@/lib/api", () => ({ api: apiMock }));

beforeEach(() => {
  for (const mock of Object.values(apiMock)) mock.mockReset();
});
afterEach(() => vi.unstubAllGlobals());

it("recovers a public cross-certificate after reload and never offers unapproved signing", async () => {
  const user = userEvent.setup();
  const id = "11111111-1111-4111-8111-111111111111";
  let completed = false;
  apiMock.caCeremony.mockImplementation(async () => ({ id, status: completed ? "completed" : "pending", approvals: completed ? 2 : 1, threshold: 2 }));
  apiMock.getCACrossSignReceipt.mockResolvedValue({
    ceremony_id: id,
    issuer_authority_id: "22222222-2222-4222-8222-222222222222",
    target_sha256: "a".repeat(64),
    certificate_pem: "-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n",
    imported: false,
  });
  render(
    <AppQueryProvider>
      <IntlProvider>
        <CACrossSignPanel authorities={[]} />
      </IntlProvider>
    </AppQueryProvider>,
  );
  await user.type(screen.getByLabelText("Ceremony ID"), id);
  expect(await screen.findByText("1/2")).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Cross-sign approved target" })).not.toBeInTheDocument();
  expect(apiMock.crossSignCAAuthority).not.toHaveBeenCalled();
  completed = true;
  await user.click(screen.getByRole("button", { name: "Refresh ceremony and receipt" }));
  await waitFor(() => expect(apiMock.getCACrossSignReceipt).toHaveBeenCalledWith(id));
  expect(screen.getByRole("textbox", { name: "Public cross-certificate PEM" })).toHaveValue("-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n");
  expect(screen.getByText("Step 3 of 3")).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Review exact cross-sign plan" })).not.toBeInTheDocument();
  expect(apiMock.crossSignCAAuthority).not.toHaveBeenCalled();
});

it("previews the first authority certificate from an inventoried chain", async () => {
  vi.stubGlobal("crypto", webcrypto);
  const user = userEvent.setup();
  const first = "-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n";
  const parent = "-----BEGIN CERTIFICATE-----\nBAUG\n-----END CERTIFICATE-----\n";
  const issuerID = "22222222-2222-4222-8222-222222222222";
  const targetID = "33333333-3333-4333-8333-333333333333";
  const base = { created_at: "2026-10-11T00:00:00Z", kind: "intermediate", max_path_len: 1, serial: "1", status: "active", tenant_id: "tenant" };
  apiMock.previewCACeremony.mockResolvedValue({ ready: true, authority: { common_name: "Issuer" }, approval_threshold: 2, request_fingerprint: "reviewed" });
  render(
    <AppQueryProvider>
      <IntlProvider>
        <CACrossSignPanel
          authorities={
            [
              { ...base, id: issuerID, common_name: "Issuer", signer_handle: "signer", certificate_pem: first },
              { ...base, id: targetID, common_name: "Target", signer_handle: "", certificate_pem: first + parent },
            ] satisfies CAAuthority[]
          }
        />
      </IntlProvider>
    </AppQueryProvider>,
  );
  await user.selectOptions(screen.getByRole("combobox", { name: "Signer-backed issuer" }), issuerID);
  await user.selectOptions(screen.getByRole("combobox", { name: "Target CA certificate" }), targetID);
  await user.type(screen.getByRole("textbox", { name: "Trust-path change reason" }), "Local trust continuity");
  await user.click(screen.getByRole("button", { name: "Review exact cross-sign plan" }));
  await waitFor(() => expect(apiMock.previewCACeremony).toHaveBeenCalledOnce());
  expect(apiMock.previewCACeremony.mock.calls[0][0].target_certificate_pem).toBe(first);
  expect(screen.queryByText("Select exactly one public CA certificate.")).not.toBeInTheDocument();
});
