import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { Wizard } from "@/pages/Wizard";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    createIssuer: vi.fn(),
    issuers: vi.fn(),
    createEnrollmentToken: vi.fn(),
    agents: vi.fn(),
    issueCertificate: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

function renderWizard() {
  return render(
    <MemoryRouter>
      <Wizard pollMs={10} />
    </MemoryRouter>,
  );
}

describe("DESIGN-001 first-certificate onboarding cues", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    for (const mock of Object.values(apiMock)) mock.mockReset();
    apiMock.issuers.mockResolvedValue([{ id: "iss-1", tenant_id: "t1", name: "Internal CA", kind: "x509_ca", internal: true }]);
    apiMock.createEnrollmentToken.mockResolvedValue({ token: "BOOT-TOKEN-DESIGN-001" });
    apiMock.agents.mockResolvedValue([{ id: "agent-1", tenant_id: "t1", name: "edge-01", status: "online" }]);
    apiMock.issueCertificate.mockResolvedValue({ id: "id-1", tenant_id: "t1", name: "payments", kind: "x509_certificate", status: "issued" });
  });

  it("keeps the wizard order aligned with docs and names the issuance credential boundary", async () => {
    const user = userEvent.setup();
    renderWizard();

    expect(screen.getByRole("heading", { name: "Connect an issuer" })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Use internal CA" }));
    await waitFor(() => expect(apiMock.issuers).toHaveBeenCalledTimes(1));
    await user.click(screen.getByRole("button", { name: "Next: issue certificate" }));

    expect(await screen.findByRole("heading", { name: "Issue your first certificate" })).toBeInTheDocument();
    expect(screen.getByText(/operator credential with certificate issuance authority/i)).toBeInTheDocument();
    await user.type(screen.getByLabelText("Service name"), "payments");
    await user.click(screen.getByRole("button", { name: "Issue certificate" }));
    await waitFor(() => expect(apiMock.issueCertificate).toHaveBeenCalledWith({ name: "payments" }));
    await user.click(screen.getByRole("button", { name: "Next: enroll agent" }));

    expect(await screen.findByRole("heading", { name: "Enroll an agent" })).toBeInTheDocument();
    expect(await screen.findByText("BOOT-TOKEN-DESIGN-001")).toBeInTheDocument();
    expect(screen.getByText(/agent enrollment tokens cannot issue certificates/i)).toBeInTheDocument();
  });
});
