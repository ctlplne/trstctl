// SPDX-License-Identifier: BUSL-1.1

import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { IntlProvider } from "@/i18n/I18nProvider";
import { AppQueryProvider } from "@/lib/query";
import { EABCredentialsPanel } from "@/pages/protocols/EABCredentialsPanel";

const { apiMock, principal } = vi.hoisted(() => ({
  apiMock: {
    acmeEABCredentials: vi.fn(),
    updateACMEEABPolicy: vi.fn(),
    setACMEEABCredentialDisabled: vi.fn(),
    rotateACMEEABCredential: vi.fn(),
  },
  principal: { permissions: ["issuers:read", "issuers:write"] as string[] },
}));

vi.mock("@/lib/api", async (orig) => ({ ...(await orig<typeof import("@/lib/api")>()), api: apiMock }));
vi.mock("@/auth/AuthProvider", async (orig) => ({
  ...(await orig<typeof import("@/auth/AuthProvider")>()),
  useAuth: () => ({ user: principal }),
}));

const credential = {
  key_id: "mail-team",
  state: "active",
  allowed_identifiers: ["@p15l3.test"],
  accounts_bound: 1,
  orders_created: 2,
  orders_denied: 1,
  disabled_in_config: false,
  disabled_by_operator: false,
};

function renderPanel() {
  return render(
    <IntlProvider>
      <AppQueryProvider>
        <EABCredentialsPanel />
      </AppQueryProvider>
    </IntlProvider>,
  );
}

describe("EAB credentials panel", () => {
  beforeEach(() => {
    apiMock.acmeEABCredentials.mockReset();
    apiMock.updateACMEEABPolicy.mockReset();
    apiMock.acmeEABCredentials.mockResolvedValue({ served: true, required: true, generated_at: "2026-11-14T12:00:00Z", items: [credential] });
    apiMock.updateACMEEABPolicy.mockResolvedValue({ ...credential, allowed_identifiers: ["@*.p15l3.test", "*.hosts.p15l3.test"] });
  });

  it("P15-L3 shows a mailbox scope and saves mailbox and name entries together", async () => {
    const user = userEvent.setup();
    renderPanel();
    expect(await screen.findByText("@p15l3.test")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Policy" }));
    expect(screen.getByText(/for mailboxes, @domain, @\*\.domain or one address/)).toBeInTheDocument();
    const field = screen.getByLabelText("Allowed identifiers");
    await user.clear(field);
    await user.type(field, "@*.p15l3.test, *.hosts.p15l3.test");
    await user.click(screen.getByRole("button", { name: /Save/i }));
    await waitFor(() =>
      expect(apiMock.updateACMEEABPolicy).toHaveBeenCalledWith(
        "mail-team",
        expect.objectContaining({ allowed_identifiers: ["@*.p15l3.test", "*.hosts.p15l3.test"] }),
      ),
    );
  });
});
