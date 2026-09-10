import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { ThemeProvider } from "@/components/ThemeProvider";
import { AuthProvider } from "@/auth/AuthProvider";
import { AppRoutes } from "@/App";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    me: vi.fn(),
    authMethods: vi.fn().mockResolvedValue({ oidc: true, saml: false, ldap: false }),
    aiStatus: vi.fn(),
    enterpriseSupportStatus: vi.fn(),
    aiQuery: vi.fn(),
    aiRCA: vi.fn(),
    mcpTools: vi.fn(),
    callMCPTool: vi.fn(),
  },
}));

vi.mock("@/lib/bootstrapApi", async (orig) => {
  const actual = await orig<typeof import("@/lib/bootstrapApi")>();
  return { ...actual, bootstrapApi: apiMock };
});

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

describe("POL-04 login and assistant polish", () => {
  beforeEach(() => {
    for (const mock of Object.values(apiMock)) mock.mockReset();
    apiMock.authMethods.mockResolvedValue({ oidc: true, saml: false, ldap: false });
    apiMock.me.mockResolvedValue({ permissions: ["*"], subject: "user-1", tenant_id: "t1", email: "u@example.test" });
    apiMock.aiStatus.mockResolvedValue({
      enabled: true,
      model_configured: true,
      model_mode: "local",
      model_name: "llama3.1",
      runtime: "ollama",
      endpoint_host: "127.0.0.1:11434",
      egress: "local-endpoint",
      redaction: "default-redactor",
      residual_refusal_gate: true,
      rate_max: 60,
      rate_window_seconds: 60,
    });
    apiMock.enterpriseSupportStatus.mockResolvedValue({
      served: true,
      capability: "enterprise-support",
      tier: "community",
      license_state: "community",
      support_mode: "off",
      license_feature: "ha_support",
      contract_boundary: "Named contacts live in the commercial agreement.",
      support_tiers: [],
      sla_targets: [],
      professional_services: [],
      evidence_refs: [],
    });
    apiMock.mcpTools.mockResolvedValue({ read_only: true, tools: ["credential.lookup"] });
  });

  it("uses plain login copy without control-plane or in-memory-tenant jargon", async () => {
    const { UnauthorizedError } = await import("@/lib/api");
    apiMock.me.mockRejectedValue(new UnauthorizedError());
    renderAt("/");

    expect(await screen.findByRole("button", { name: /Continue with SSO/i })).toBeInTheDocument();
    expect(screen.queryByText(/Control plane/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/in-memory tenant/i)).not.toBeInTheDocument();
    expect(screen.getByText(/Credentials for machines and apps/i)).toBeInTheDocument();
    expect(screen.getByText(/sample data in this browser/i)).toBeInTheDocument();
  });

  it("collapses Product help diagnostics by default and explains acronyms and answer badges", async () => {
    apiMock.aiQuery.mockResolvedValue({
      text: "Rotate the payment certificate first.",
      citations: ["certificates#cert-1"],
      sufficient: true,
      grounded: true,
    });
    const user = userEvent.setup();
    renderAt("/assistant");

    expect(await screen.findByRole("heading", { name: "Product help" })).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "AI runtime boundary" })).not.toBeInTheDocument();
    await user.click(await screen.findByRole("button", { name: "Ask a question" }));
    expect(screen.getByText("Runtime and privacy details").closest("details")).not.toHaveAttribute("open");

    expect(screen.getByTitle(/Cryptographic Bill of Materials/i)).toHaveTextContent("CBOM");

    await user.click(screen.getByText("Runtime and privacy details"));
    expect(await screen.findByRole("heading", { name: "AI runtime boundary" })).toBeInTheDocument();
    expect(screen.getByText("local: llama3.1")).toBeInTheDocument();
    expect(screen.getByText("127.0.0.1:11434")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Use read-only tools" }));
    expect(screen.getAllByTitle(/Model Context Protocol/i).length).toBeGreaterThan(0);
    await user.click(screen.getByRole("button", { name: "Ask a question" }));

    await user.type(screen.getByLabelText("Question"), "What should rotate first?");
    await user.click(screen.getByRole("button", { name: /^Ask$/i }));

    expect(await screen.findByText("Rotate the payment certificate first.")).toBeInTheDocument();
    expect(screen.getByTitle(/Grounded means the answer cites tenant evidence/i)).toHaveTextContent("Grounded");
    expect(screen.getByTitle(/Sufficient means the cited evidence is enough/i)).toHaveTextContent("Sufficient");
  });
});
