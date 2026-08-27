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

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: apiMock };
});

function renderAssistant() {
  return render(
    <ThemeProvider>
      <AuthProvider>
        <MemoryRouter initialEntries={["/assistant"]}>
          <AppRoutes />
        </MemoryRouter>
      </AuthProvider>
    </ThemeProvider>,
  );
}

async function openProductHelp(user: ReturnType<typeof userEvent.setup>) {
  await user.click(await screen.findByRole("button", { name: "Ask a question" }));
  await screen.findByRole("heading", { name: "Ask Product help" });
}

describe("assistant console workflow", () => {
  beforeEach(() => {
    for (const mock of Object.values(apiMock)) mock.mockReset();
    apiMock.authMethods.mockResolvedValue({ oidc: true, saml: false, ldap: false });
    apiMock.me.mockResolvedValue({ permissions: ["*"], subject: "user-1", tenant_id: "t1", email: "u@example.test" });
    apiMock.aiStatus.mockResolvedValue({
      enabled: true,
      model_configured: false,
      model_mode: "off",
      egress: "none",
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
    apiMock.mcpTools.mockResolvedValue({
      identity: "spiffe://example.org/mcp-server",
      read_only: true,
      tools: ["credential.lookup", "audit.tail"],
    });
  });

  it("checks availability before showing the calm Product help action", async () => {
    const user = userEvent.setup();
    renderAssistant();

    expect(await screen.findByRole("heading", { name: "Product help" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Product help" })).toHaveAttribute("aria-current", "page");
    expect(screen.getByText("How to complete a task or understand a term without leaving context.")).toBeInTheDocument();
    expect(screen.getByText("Sources, permissions, privacy boundary, exact references.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Ask a question" })).toBeInTheDocument();
    expect(screen.queryByLabelText("Question")).not.toBeInTheDocument();
    expect(screen.queryByText("Read-only tools are unavailable")).not.toBeInTheDocument();
    expect(apiMock.aiStatus).toHaveBeenCalledTimes(1);
    expect(apiMock.enterpriseSupportStatus).toHaveBeenCalledTimes(1);
    expect(apiMock.mcpTools).not.toHaveBeenCalled();

    await user.click(screen.getByRole("button", { name: "Ask a question" }));

    expect(await screen.findByRole("heading", { name: "Ask Product help" })).toHaveFocus();
    expect(screen.getByLabelText("Question")).toBeInTheDocument();
    expect(screen.getByText(/reads only evidence your role can access/i)).toBeInTheDocument();
    expect(apiMock.aiStatus).toHaveBeenCalledTimes(1);
    expect(apiMock.mcpTools).not.toHaveBeenCalled();
  });

  it("reuses the availability check when runtime details open and loads tools only on demand", async () => {
    const user = userEvent.setup();
    renderAssistant();

    await user.click(await screen.findByRole("button", { name: "Ask a question" }));
    expect(apiMock.aiStatus).toHaveBeenCalledTimes(1);
    expect(apiMock.mcpTools).not.toHaveBeenCalled();

    await user.click(screen.getByText("Runtime and privacy details"));
    expect(await screen.findByRole("heading", { name: "AI runtime boundary" })).toBeInTheDocument();
    expect(apiMock.aiStatus).toHaveBeenCalledTimes(1);
    expect(apiMock.mcpTools).not.toHaveBeenCalled();

    await user.click(screen.getByRole("button", { name: "Use read-only tools" }));
    expect(await screen.findByRole("heading", { name: /Read-only tool boundary/ })).toBeInTheDocument();
    expect(apiMock.mcpTools).toHaveBeenCalledTimes(1);
  });

  it("discloses a disabled backend before input and provides safe support handoffs", async () => {
    apiMock.aiStatus.mockResolvedValue({
      enabled: false,
      model_configured: false,
      model_mode: "off",
      egress: "none",
      pii_egress: "redact",
      redaction: "default-redactor",
      residual_refusal_gate: true,
    });
    renderAssistant();

    expect(await screen.findByRole("heading", { name: "Product help is not available on this server" })).toBeInTheDocument();
    expect(screen.getByText("No question was sent.")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Ask a question" })).not.toBeInTheDocument();
    expect(screen.queryByLabelText("Question")).not.toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Troubleshoot the deployment" })).toHaveAttribute(
      "href",
      "https://github.com/ctlplne/trstctl/blob/main/docs/troubleshooting.md",
    );
    expect(screen.getByRole("link", { name: "Report an ordinary product defect" })).toHaveAttribute(
      "href",
      "https://github.com/ctlplne/trstctl/issues/new/choose",
    );
    expect(screen.getByRole("link", { name: "Report a possible security vulnerability privately" })).toHaveAttribute(
      "href",
      "https://github.com/ctlplne/trstctl/security/advisories/new",
    );
    expect(screen.getByText(/Review a support bundle before sharing it/i)).toBeInTheDocument();
    expect(screen.getByText(/use the named design-partner channel/i)).toBeInTheDocument();
    expect(apiMock.aiQuery).not.toHaveBeenCalled();
  });

  it("shows the contract-owned support handoff for a licensed deployment", async () => {
    apiMock.aiStatus.mockResolvedValue({
      enabled: false,
      model_configured: false,
      model_mode: "off",
      egress: "none",
      pii_egress: "redact",
      redaction: "default-redactor",
      residual_refusal_gate: true,
    });
    apiMock.enterpriseSupportStatus.mockResolvedValue({
      served: true,
      capability: "enterprise-support",
      tier: "enterprise",
      license_state: "active",
      support_mode: "enabled",
      license_feature: "ha_support",
      contract_boundary: "Named contacts live in the commercial agreement.",
      support_tiers: [],
      sla_targets: [],
      professional_services: [],
      evidence_refs: [],
    });
    renderAssistant();

    expect(await screen.findByRole("heading", { name: "Licensed support" })).toBeInTheDocument();
    expect(screen.getByText(/Use the named email or portal in your support order/i)).toBeInTheDocument();
    expect(screen.getByText(/The signed license proves entitlement, not the contact address/i)).toBeInTheDocument();
  });

  it("routes operators to a grounded query workflow with cited evidence", async () => {
    apiMock.aiQuery.mockResolvedValue({
      text: "CN=payments.example.com should rotate first.",
      citations: ["certificates#cert-1", "owners#owner-7"],
      sufficient: true,
      grounded: true,
    });
    const user = userEvent.setup();
    renderAssistant();

    expect(await screen.findByRole("heading", { name: "Product help" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Product help" })).toHaveAttribute("aria-current", "page");
    expect(screen.queryByRole("heading", { name: "AI runtime boundary" })).not.toBeInTheDocument();
    await openProductHelp(user);
    await user.click(screen.getByText("Runtime and privacy details"));
    expect(await screen.findByRole("heading", { name: "AI runtime boundary" })).toBeInTheDocument();
    expect(await screen.findByText("not configured")).toBeInTheDocument();
    expect(screen.getByText(/Redaction boundary: default-redactor/)).toBeInTheDocument();
    expect(screen.getByText("Structured query preview")).toBeInTheDocument();
    expect(screen.getByText(/Tenant\/RBAC filtering is applied/)).toBeInTheDocument();

    await user.type(screen.getByLabelText("Question"), "What should rotate first?");
    await user.click(screen.getByRole("button", { name: /^Ask$/i }));

    expect(await screen.findByText("CN=payments.example.com should rotate first.")).toBeInTheDocument();
    expect(screen.getByText("certificates#cert-1")).toBeInTheDocument();
    expect(screen.getByText("owners#owner-7")).toBeInTheDocument();
    expect(apiMock.aiQuery).toHaveBeenCalledWith(
      expect.objectContaining({
        question: "What should rotate first?",
        surfaces: expect.arrayContaining(["certificates", "owners", "graph"]),
        limit: 25,
      }),
    );
  });

  it("shows served AI model mode, endpoint host, and egress posture", async () => {
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
      rate_max: 3,
      rate_window_seconds: 60,
    });
    const user = userEvent.setup();
    renderAssistant();

    await openProductHelp(user);
    await user.click(screen.getByText("Runtime and privacy details"));
    expect(await screen.findByText("local: llama3.1")).toBeInTheDocument();
    expect(screen.getByText("local-endpoint")).toBeInTheDocument();
    expect(screen.getByText("127.0.0.1:11434")).toBeInTheDocument();
    expect(screen.getByText(/residual refusal gate: active/i)).toBeInTheDocument();
    expect(apiMock.aiStatus).toHaveBeenCalledTimes(1);
  });

  it("fails closed before input when runtime readiness is unknown and recovers only after a successful retry", async () => {
    apiMock.aiStatus.mockRejectedValueOnce(new Error("model endpoint included a private token"));
    const user = userEvent.setup();
    renderAssistant();

    expect(await screen.findByRole("heading", { name: "Product help readiness is unknown" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Ask a question" })).not.toBeInTheDocument();
    expect(screen.queryByLabelText("Question")).not.toBeInTheDocument();
    expect(screen.queryByText("not configured")).not.toBeInTheDocument();
    expect(screen.queryByText(/Redaction boundary:/)).not.toBeInTheDocument();
    expect(screen.queryByText(/private token/)).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Check again" }));

    expect(await screen.findByRole("button", { name: "Ask a question" })).toBeInTheDocument();
    expect(apiMock.aiStatus).toHaveBeenCalledTimes(2);
  });

  it.each([
    ["redact", "Redacted before model egress", "Personal data is removed before prompts leave the control plane."],
    ["block", "Blocked on detection", "Prompts with personal data are refused before model egress."],
    ["allow", "Allowed by policy", "Personal data may leave only under explicit operator policy."],
  ])("renders the %s personal-data egress posture without raw PII", async (piiEgress, label, detail) => {
    apiMock.aiStatus.mockResolvedValue({
      enabled: true,
      model_configured: true,
      model_mode: "cloud",
      model_name: "gpt-policy",
      runtime: "openai-compatible",
      provider: "ada.lovelace@example.test",
      endpoint_host: "models.example.test",
      egress: "cloud",
      pii_egress: piiEgress,
      redaction: "default-redactor",
      residual_refusal_gate: true,
      rate_max: 3,
      rate_window_seconds: 60,
    });
    const user = userEvent.setup();
    renderAssistant();

    await openProductHelp(user);
    await user.click(screen.getByText("Runtime and privacy details"));
    expect(await screen.findByText("Personal data")).toBeInTheDocument();
    expect(screen.getByText(label)).toBeInTheDocument();
    expect(screen.getByText(detail)).toBeInTheDocument();
    expect(screen.queryByText("ada.lovelace@example.test")).not.toBeInTheDocument();
  });

  it("renders RCA redaction and no-evidence state instead of hiding the answer", async () => {
    apiMock.aiRCA.mockResolvedValue({
      text: "No causal chain was proven. Residual secret material: [redacted].",
      citations: [],
      sufficient: false,
      grounded: false,
    });
    const user = userEvent.setup();
    renderAssistant();

    await openProductHelp(user);
    await user.click(screen.getByRole("button", { name: "Investigate a cause" }));
    expect(screen.getByText("RCA evidence workspace")).toBeInTheDocument();
    await user.type(screen.getByLabelText("Question"), "Why is the service high risk?");
    await user.click(screen.getByRole("button", { name: /^Analyze$/i }));

    expect(await screen.findByText(/Residual secret material: \[redacted\]/)).toBeInTheDocument();
    expect(screen.getByText("No cited evidence")).toBeInTheDocument();
    expect(screen.getByText("Insufficient")).toBeInTheDocument();
    expect(screen.getByText("No exact references were returned.")).toBeInTheDocument();
  });

  it("shows permission errors without leaking backend problem details", async () => {
    const { ApiError } = await import("@/lib/api");
    apiMock.aiQuery.mockRejectedValue(new ApiError(403, '{"detail":"tenant t2 exists"}'));
    const user = userEvent.setup();
    renderAssistant();

    await openProductHelp(user);
    await user.type(screen.getByLabelText("Question"), "Show another tenant.");
    await user.click(screen.getByRole("button", { name: /^Ask$/i }));

    expect(await screen.findByRole("alert")).toHaveTextContent("Permission denied for this evidence scope.");
    expect(screen.queryByText(/tenant t2 exists/)).not.toBeInTheDocument();
  });

  it("falls back to the same support handoff if readiness changes after the initial check", async () => {
    const { ApiError } = await import("@/lib/api");
    apiMock.aiQuery.mockRejectedValue(new ApiError(503, JSON.stringify({ detail: "ai.enable_api disabled" })));
    const user = userEvent.setup();
    renderAssistant();

    await openProductHelp(user);
    await user.click(screen.getByText("Runtime and privacy details"));
    await user.type(screen.getByLabelText("Question"), "Can you answer?");
    await user.click(screen.getByRole("button", { name: /^Ask$/i }));

    expect(await screen.findByRole("heading", { name: "Product help is not available on this server" })).toBeInTheDocument();
    expect(screen.queryByLabelText("Question")).not.toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Troubleshoot the deployment" })).toBeInTheDocument();
  });

  it("shows an empty state when no MCP tools are exposed", async () => {
    apiMock.mcpTools.mockResolvedValue({ read_only: true, tools: [] });
    const user = userEvent.setup();
    renderAssistant();

    await openProductHelp(user);
    await user.click(screen.getByRole("button", { name: "Use read-only tools" }));

    expect(screen.getByRole("heading", { name: /Read-only tool boundary/ })).toBeInTheDocument();
    expect(await screen.findByText("No MCP tools are available for this tenant.")).toBeInTheDocument();
  });

  it("explains when the MCP tool surface is not enabled", async () => {
    const { ApiError } = await import("@/lib/api");
    apiMock.mcpTools.mockRejectedValue(new ApiError(503, JSON.stringify({ title: "Service Unavailable", status: 503, detail: "AI surface is not enabled" })));
    const user = userEvent.setup();

    renderAssistant();

    await openProductHelp(user);
    await user.click(screen.getByRole("button", { name: "Use read-only tools" }));
    expect(await screen.findByText("Read-only tools are unavailable")).toBeInTheDocument();
    expect(screen.getByText("AI surface is not enabled")).toBeInTheDocument();
  });

  it("recovers read-only tool discovery only after an explicit successful retry", async () => {
    const { ApiError } = await import("@/lib/api");
    apiMock.mcpTools.mockRejectedValueOnce(new ApiError(503, JSON.stringify({ detail: "AI surface is not enabled" })));
    const user = userEvent.setup();
    renderAssistant();

    await openProductHelp(user);
    await user.click(screen.getByRole("button", { name: "Use read-only tools" }));
    expect(await screen.findByText("Read-only tools are unavailable")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Retry tool check" }));

    expect(await screen.findByLabelText("Tool")).toBeInTheDocument();
    expect(apiMock.mcpTools).toHaveBeenCalledTimes(2);
  });

  it("does not route write-capable MCP tools through the read-only subject form", async () => {
    apiMock.mcpTools.mockResolvedValue({
      identity: "spiffe://example.org/mcp-server",
      read_only: false,
      tools: ["issue_certificate"],
    });
    apiMock.callMCPTool.mockResolvedValue({
      tool: "issue_certificate",
      text: "issued certificate serial 1234",
      citations: ["ca_issued_cert:1234"],
    });
    const user = userEvent.setup();
    renderAssistant();

    await openProductHelp(user);
    await user.click(screen.getByRole("button", { name: "Use read-only tools" }));

    if (screen.queryByLabelText("Tool")) {
      await screen.findByDisplayValue("issue_certificate");
    }
    const subjectInput = screen.queryByLabelText("Subject");
    if (subjectInput) {
      await user.type(subjectInput, "payments");
    }
    const invokeButton = screen.queryByRole("button", { name: /^Invoke$/i });
    if (invokeButton) {
      await user.click(invokeButton);
    }

    expect(apiMock.callMCPTool).not.toHaveBeenCalledWith("issue_certificate", { subject: "payments" });
    expect(await screen.findByText(/Write-capable MCP tools require operation-specific controls/i)).toBeInTheDocument();
    expect(screen.queryByLabelText("Subject")).not.toBeInTheDocument();
  });

  it("invokes a selected read-only MCP tool and renders its citations", async () => {
    apiMock.callMCPTool.mockResolvedValue({
      tool: "credential.lookup",
      text: "Found the active payment certificate.",
      citations: ["graph#node-9"],
    });
    const user = userEvent.setup();
    renderAssistant();

    await openProductHelp(user);
    await user.click(screen.getByRole("button", { name: "Use read-only tools" }));
    expect(screen.getByText(/Tools are read-only/)).toBeInTheDocument();
    await screen.findByLabelText("Tool");
    await user.type(screen.getByLabelText("Subject"), "payments");
    await user.click(screen.getByRole("button", { name: /^Invoke$/i }));

    expect(await screen.findByText("Found the active payment certificate.")).toBeInTheDocument();
    expect(screen.getByText("graph#node-9")).toBeInTheDocument();
    expect(apiMock.callMCPTool).toHaveBeenCalledWith("credential.lookup", { subject: "payments" });
  });
});
