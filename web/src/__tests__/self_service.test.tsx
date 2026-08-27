import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { axe } from "vitest-axe";
import { ApiError } from "@/lib/api";
import { ThemeProvider } from "@/components/ThemeProvider";
import { AuthProvider } from "@/auth/AuthProvider";
import { AppRoutes } from "@/App";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    me: vi.fn(),
    authMethods: vi.fn().mockResolvedValue({ oidc: true, saml: false, ldap: false }),
    profiles: vi.fn(),
    owners: vi.fn(),
    issuanceRequests: vi.fn(),
    previewIssuanceRequest: vi.fn(),
    createIssuanceRequest: vi.fn(),
    // Kept until the failing-first assertion proves the page still uses the
    // identity mutation instead of the first-class request API.
    identities: vi.fn(),
    createIdentity: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: apiMock };
});

function renderAt(path: string) {
  return render(
    <ThemeProvider>
      <AuthProvider>
        <MemoryRouter initialEntries={[path]}>
          <AppRoutes />
        </MemoryRouter>
      </AuthProvider>
    </ThemeProvider>,
  );
}

const activeProfile = {
  id: "prof-1",
  name: "web-server",
  version: 2,
  active: true,
  created_by: "ra@example.test",
  spec: { max_validity: "2160h", allowed_ekus: ["serverAuth"] },
};

const selectedOwner = {
  id: "11111111-1111-4111-8111-111111111119",
  tenant_id: "t1",
  kind: "team",
  name: "Payments platform",
  email: "payments@example.test",
  escalation_chain: [],
  ownership_attested: true,
  ownership_complete: true,
  ownership_current: true,
};

const otherOwner = {
  ...selectedOwner,
  id: "22222222-2222-4222-8222-222222222229",
  name: "Data platform",
  email: "data@example.test",
};

describe("self-service credential requests", () => {
  beforeEach(() => {
    for (const mock of Object.values(apiMock)) mock.mockReset();
    apiMock.authMethods.mockResolvedValue({ oidc: true, saml: false, ldap: false });
    apiMock.me.mockResolvedValue({ permissions: ["*"], subject: "dev-1", tenant_id: "t1", email: "dev@example.test" });
    apiMock.profiles.mockResolvedValue([activeProfile]);
    apiMock.owners.mockResolvedValue([otherOwner, selectedOwner]);
    apiMock.issuanceRequests.mockResolvedValue({ items: [], open: 0, guidance: "" });
    apiMock.previewIssuanceRequest.mockImplementation(async (input: { subject: string; owner_id: string; profile?: string; csr_pem?: string }) => ({
      ready: true,
      subject: input.subject,
      owner_id: input.owner_id,
      owner_name: selectedOwner.name,
      owner_kind: selectedOwner.kind,
      profile: input.profile,
      profile_name: "web-server",
      profile_version: 2,
      requester: "dev-1",
      csr_supplied: Boolean(input.csr_pem),
      key_origin: input.csr_pem ? "requester_csr" : "deprecated_control_plane_generation",
      approval_required: true,
      approval_permission: "certs:issue",
      issuance_permissions: ["identities:write", "certs:issue"],
      preview_writes: [],
      preview_external_effects: [],
      submission_effects: [
        "Append one tenant-scoped issuance request event.",
        "Create one requested work item for an independent approver.",
        "Mint no certificate until a later approved issuance step.",
      ],
      steps: ["Submit request", "Independent approval", "Signer-backed issuance", "Durable certificate evidence"],
      warnings: input.csr_pem ? [] : ["No CSR was supplied; requester-held keys are safer."],
      blockers: [],
      guidance: "This preview performed no write and contacted no certificate authority.",
    }));
    apiMock.identities.mockResolvedValue([]);
  });

  it("routes to a focused requester portal, submits a profile-bound request, and tracks accepted status", async () => {
    const requested = {
      id: "req-1",
      tenant_id: "t1",
      owner_id: selectedOwner.id,
      subject: "payments-api",
      profile: "web-server:2",
      requester: "dev-1",
      justification: "staging TLS",
      status: "requested",
      expires_at: "2026-06-27T04:00:00Z",
      created_at: "2026-06-20T04:00:00Z",
    };
    apiMock.createIssuanceRequest.mockResolvedValue(requested);
    const user = userEvent.setup();
    renderAt("/request");

    expect(await screen.findByRole("heading", { name: "Request a certificate" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Request a certificate/i })).toHaveAttribute("href", "/request");

    // Step 1 — choose the issuance profile.
    await waitFor(() => expect(screen.getByLabelText("Profile")).toHaveDisplayValue("web-server v2 active"));
    await user.click(screen.getByRole("button", { name: "Next: name it" }));

    // Step 2 — a session subject is never guessed to be an owner UUID. The
    // requester chooses one tenant-visible owner by name.
    expect(screen.getByLabelText("Owner")).toHaveDisplayValue("Choose an owner");
    await user.type(screen.getByLabelText("Search owners"), "payments");
    expect(screen.queryByRole("option", { name: /Data platform/i })).not.toBeInTheDocument();
    await user.selectOptions(screen.getByLabelText("Owner"), selectedOwner.id);
    await user.type(screen.getByLabelText("Credential name"), "payments-api");
    await user.type(screen.getByLabelText("Business purpose"), "staging TLS");
    await user.click(screen.getByRole("button", { name: "Next: review" }));

    // Step 3 — the server validates and normalizes the exact request without
    // writing anything. Submission stays fail-closed until that effect-free
    // preview is green.
    expect(screen.getByText("staging TLS")).toBeInTheDocument();
    await waitFor(() =>
      expect(apiMock.previewIssuanceRequest).toHaveBeenCalledWith({
        subject: "payments-api",
        profile: "web-server:2",
        owner_id: selectedOwner.id,
        justification: "staging TLS",
        origin: "console",
      }),
    );
    expect(await screen.findByRole("status", { name: "Request preview ready" })).toHaveTextContent(
      "This preview performed no write and contacted no certificate authority.",
    );
    expect(screen.getByText(/Mint no certificate until a later approved issuance step/i)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Submit request" }));

    await waitFor(() =>
      expect(apiMock.createIssuanceRequest).toHaveBeenCalledWith({
        subject: "payments-api",
        profile: "web-server:2",
        owner_id: selectedOwner.id,
        justification: "staging TLS",
        origin: "console",
      }),
    );
    expect(apiMock.createIdentity).not.toHaveBeenCalled();
    expect(await screen.findByRole("status")).toHaveTextContent(
      "Request accepted for payments-api. It is awaiting approval; no certificate has been minted yet.",
    );
    expect(screen.getByRole("row", { name: /payments-api.*web-server:2.*Awaiting approval.*requested/i })).toBeInTheDocument();
    expect(screen.queryByText(/has been issued/i)).not.toBeInTheDocument();
  });

  it("submits the same canonical request that was previewed when pasted fields contain surrounding whitespace", async () => {
    const csr = "-----BEGIN CERTIFICATE REQUEST-----\nPUBLIC CSR\n-----END CERTIFICATE REQUEST-----";
    apiMock.createIssuanceRequest.mockResolvedValue({
      id: "req-canonical-1",
      tenant_id: "t1",
      owner_id: selectedOwner.id,
      subject: "payments-api",
      profile: "web-server:2",
      requester: "dev-1",
      justification: "staging TLS",
      status: "requested",
      expires_at: "2026-06-27T04:00:00Z",
      created_at: "2026-06-20T04:00:00Z",
    });
    const user = userEvent.setup();
    renderAt("/request");

    await waitFor(() => expect(screen.getByLabelText("Profile")).toHaveDisplayValue("web-server v2 active"));
    await user.click(screen.getByRole("button", { name: "Next: name it" }));
    await user.selectOptions(screen.getByLabelText("Owner"), selectedOwner.id);
    await user.type(screen.getByLabelText("Credential name"), "  payments-api  ");
    await user.type(screen.getByLabelText("Business purpose"), "  staging TLS  ");
    await user.type(screen.getByLabelText("Certificate signing request (PKCS#10)"), `${csr}\n`);
    await user.click(screen.getByRole("button", { name: "Next: review" }));

    expect(await screen.findByRole("status", { name: "Request preview ready" })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Submit request" }));

    await waitFor(() =>
      expect(apiMock.createIssuanceRequest).toHaveBeenCalledWith({
        subject: "payments-api",
        profile: "web-server:2",
        owner_id: selectedOwner.id,
        justification: "staging TLS",
        origin: "console",
        csr_pem: csr,
      }),
    );
    expect(screen.queryByText(/preview is missing or stale/i)).not.toBeInTheDocument();
  });

  it("fails closed when the exact preview is unavailable and links every prerequisite", async () => {
    apiMock.previewIssuanceRequest.mockRejectedValueOnce(new ApiError(503, JSON.stringify({ detail: "profile admission is unavailable" })));
    const user = userEvent.setup();
    renderAt("/request");

    await waitFor(() => expect(screen.getByLabelText("Profile")).toHaveDisplayValue("web-server v2 active"));
    await user.click(screen.getByRole("button", { name: "Next: name it" }));
    await user.selectOptions(screen.getByLabelText("Owner"), selectedOwner.id);
    await user.type(screen.getByLabelText("Credential name"), "payments-api");
    await user.click(screen.getByRole("button", { name: "Next: review" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("profile admission is unavailable");
    expect(screen.getByRole("button", { name: "Submit request" })).toBeDisabled();
    expect(apiMock.createIssuanceRequest).not.toHaveBeenCalled();
    expect(screen.getByRole("link", { name: "Configure certificate rules" })).toHaveAttribute("href", "/profiles");
    expect(screen.getByRole("link", { name: "Configure ownership" })).toHaveAttribute("href", "/owners");
    expect(screen.getByRole("link", { name: "Configure certificate authorities" })).toHaveAttribute("href", "/ca-hierarchy");
  });

  it("lists only the current requester's items with honest request status", async () => {
    apiMock.issuanceRequests.mockResolvedValue({
      open: 2,
      guidance: "",
      items: [
        {
          id: "mine-1",
          tenant_id: "t1",
          subject: "checkout-api",
          profile: "web-server:2",
          owner_id: selectedOwner.id,
          requester: "dev-1",
          status: "requested",
          expires_at: "2026-06-27T04:00:00Z",
          created_at: "2026-06-20T04:00:00Z",
        },
        {
          id: "mine-2",
          tenant_id: "t1",
          subject: "billing-api",
          profile: "web-server:2",
          owner_id: selectedOwner.id,
          requester: "dev-1",
          status: "approved",
          expires_at: "2026-06-27T04:00:00Z",
          created_at: "2026-06-19T04:00:00Z",
        },
        {
          id: "other-1",
          tenant_id: "t1",
          subject: "other-team",
          profile: "web-server:2",
          owner_id: "22222222-2222-4222-8222-222222222229",
          requester: "other@example.test",
          status: "requested",
          expires_at: "2026-06-27T04:00:00Z",
          created_at: "2026-06-18T04:00:00Z",
        },
      ],
    });

    renderAt("/request");

    expect(await screen.findByRole("row", { name: /checkout-api.*Awaiting approval/i })).toBeInTheDocument();
    expect(screen.getByRole("row", { name: /billing-api.*Approved/i })).toBeInTheDocument();
    expect(screen.queryByText("other-team")).not.toBeInTheDocument();
  });

  it("covers empty and problem states without exposing the operator identity table", async () => {
    apiMock.profiles.mockResolvedValueOnce([]);
    const empty = renderAt("/request");
    expect(await screen.findByText("No active profiles")).toBeInTheDocument();
    expect(await screen.findByText("No requests yet")).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Identities" })).not.toBeInTheDocument();
    empty.unmount();

    apiMock.profiles.mockRejectedValueOnce(new ApiError(503, JSON.stringify({ detail: "profile store unavailable" })));
    apiMock.owners.mockRejectedValueOnce(new ApiError(503, JSON.stringify({ detail: "owner list unavailable" })));
    apiMock.issuanceRequests.mockRejectedValueOnce(new ApiError(503, JSON.stringify({ detail: "request list unavailable" })));
    renderAt("/request");

    expect(await screen.findByText("profile store unavailable")).toBeInTheDocument();
    expect(await screen.findByText("owner list unavailable")).toBeInTheDocument();
    expect(await screen.findByText("request list unavailable")).toBeInTheDocument();
  });

  it("keeps the requester portal accessible", async () => {
    const { container } = renderAt("/request");
    await screen.findByRole("heading", { name: "Request a certificate" });
    await waitFor(() => expect(screen.getByLabelText("Profile")).toHaveDisplayValue("web-server v2 active"));
    expect(await axe(container)).toHaveNoViolations();
  });
});
