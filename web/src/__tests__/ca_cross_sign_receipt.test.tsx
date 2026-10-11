import { beforeEach, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { IntlProvider } from "@/i18n/I18nProvider";
import { AppQueryProvider } from "@/lib/query";
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
  expect(apiMock.crossSignCAAuthority).not.toHaveBeenCalled();
});
