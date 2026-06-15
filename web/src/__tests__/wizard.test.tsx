import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { Wizard } from "@/pages/Wizard";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    createIssuer: vi.fn(),
    createEnrollmentToken: vi.fn(),
    agents: vi.fn(),
    issueCertificate: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: apiMock };
});

function renderWizard() {
  return render(
    <MemoryRouter>
      <Wizard pollMs={50} />
    </MemoryRouter>,
  );
}

describe("first-run wizard", () => {
  beforeEach(() => {
    apiMock.createIssuer.mockReset().mockResolvedValue({ id: "iss-1", kind: "acme", name: "Let's Encrypt" });
    apiMock.createEnrollmentToken.mockReset().mockResolvedValue({ token: "BOOT-TOKEN-XYZ" });
    apiMock.agents.mockReset().mockResolvedValue([{ id: "ag-1", name: "edge-01", status: "online" }]);
    apiMock.issueCertificate.mockReset().mockResolvedValue({ id: "id-1", name: "payments", status: "issued" });
  });

  it("walks connect-CA → install-agent → issue-first-cert and issues a certificate", async () => {
    const user = userEvent.setup();
    renderWizard();

    // Step 1 — connect a CA.
    expect(screen.getByRole("heading", { name: /connect a (certificate authority|ca)/i })).toBeInTheDocument();
    await user.type(screen.getByLabelText(/name/i), "Let's Encrypt");
    await user.click(screen.getByRole("button", { name: /connect/i }));
    await waitFor(() => expect(apiMock.createIssuer).toHaveBeenCalledTimes(1));

    // Step 2 — install an agent: a one-time token is minted and shown in the
    // install command, then the wizard detects the agent's registration.
    await waitFor(() => expect(apiMock.createEnrollmentToken).toHaveBeenCalled());
    expect(await screen.findByText(/BOOT-TOKEN-XYZ/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /check (for agent|now)/i }));
    await waitFor(() => expect(screen.getByText(/edge-01/)).toBeInTheDocument());
    await user.click(screen.getByRole("button", { name: /continue|next/i }));

    // Step 3 — issue the first certificate.
    expect(await screen.findByRole("heading", { name: /issue your first cert/i })).toBeInTheDocument();
    await user.type(screen.getByLabelText(/name/i), "payments");
    await user.click(screen.getByRole("button", { name: /issue/i }));

    await waitFor(() => expect(apiMock.issueCertificate).toHaveBeenCalledWith(expect.objectContaining({ name: "payments" })));
    expect(await screen.findByText(/first certificate (has been )?issued/i)).toBeInTheDocument();
  });

  it("surfaces a failure to connect the CA without advancing", async () => {
    apiMock.createIssuer.mockRejectedValueOnce(new Error("boom"));
    const user = userEvent.setup();
    renderWizard();

    await user.type(screen.getByLabelText(/name/i), "bad");
    await user.click(screen.getByRole("button", { name: /connect/i }));

    expect(await screen.findByRole("alert")).toHaveTextContent(/boom|could not|failed/i);
    // Still on step 1 — the agent step never started.
    expect(apiMock.createEnrollmentToken).not.toHaveBeenCalled();
  });
});
