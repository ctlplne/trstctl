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
    aiStatus: vi.fn(),
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

describe("assistant console workflow", () => {
  beforeEach(() => {
    for (const mock of Object.values(apiMock)) mock.mockReset();
    apiMock.me.mockResolvedValue({ subject: "user-1", tenant_id: "t1", email: "u@example.test" });
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
    apiMock.mcpTools.mockResolvedValue({
      identity: "spiffe://example.org/mcp-server",
      read_only: true,
      tools: ["credential.lookup", "audit.tail"],
    });
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

    expect(await screen.findByRole("heading", { name: "Assistant" })).toBeInTheDocument();
    // Assistant is now a surfaced sidebar destination (audit U1), shown as the current page.
    expect(screen.getByRole("link", { name: /Assistant/i })).toHaveAttribute("aria-current", "page");
    expect(screen.queryByRole("heading", { name: "AI runtime boundary" })).not.toBeInTheDocument();
    await user.click(screen.getByText("Advanced runtime diagnostics"));
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

    await user.click(await screen.findByText("Advanced runtime diagnostics"));
    expect(await screen.findByText("local: llama3.1")).toBeInTheDocument();
    expect(screen.getByText("local-endpoint")).toBeInTheDocument();
    expect(screen.getByText("127.0.0.1:11434")).toBeInTheDocument();
    expect(screen.getByText(/residual refusal gate: active/i)).toBeInTheDocument();
    expect(apiMock.aiStatus).toHaveBeenCalledTimes(1);
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

    await screen.findByRole("heading", { name: "Assistant" });
    await user.click(screen.getByRole("button", { name: "RCA" }));
    expect(screen.getByText("RCA evidence workspace")).toBeInTheDocument();
    await user.type(screen.getByLabelText("Question"), "Why is the service high risk?");
    await user.click(screen.getByRole("button", { name: /^Analyze$/i }));

    expect(await screen.findByText(/Residual secret material: \[redacted\]/)).toBeInTheDocument();
    expect(screen.getByText("No cited evidence")).toBeInTheDocument();
    expect(screen.getByText("Insufficient")).toBeInTheDocument();
    expect(screen.getByText("No citations returned.")).toBeInTheDocument();
  });

  it("shows permission errors without leaking backend problem details", async () => {
    const { ApiError } = await import("@/lib/api");
    apiMock.aiQuery.mockRejectedValue(new ApiError(403, '{"detail":"tenant t2 exists"}'));
    const user = userEvent.setup();
    renderAssistant();

    await screen.findByRole("heading", { name: "Assistant" });
    await user.type(screen.getByLabelText("Question"), "Show another tenant.");
    await user.click(screen.getByRole("button", { name: /^Ask$/i }));

    expect(await screen.findByRole("alert")).toHaveTextContent("Permission denied for this evidence scope.");
    expect(screen.queryByText(/tenant t2 exists/)).not.toBeInTheDocument();
  });

  it("shows the fail-closed disabled state when the AI surface is off", async () => {
    const { ApiError } = await import("@/lib/api");
    apiMock.aiQuery.mockRejectedValue(new ApiError(503, JSON.stringify({ detail: "ai.enable_api disabled" })));
    const user = userEvent.setup();
    renderAssistant();

    await screen.findByRole("heading", { name: "Assistant" });
    await user.click(screen.getByText("Advanced runtime diagnostics"));
    await user.type(screen.getByLabelText("Question"), "Can you answer?");
    await user.click(screen.getByRole("button", { name: /^Ask$/i }));

    expect(await screen.findByRole("alert")).toHaveTextContent("Assistant surface is not enabled.");
    expect(screen.getByText(/fail closed when disabled/i)).toBeInTheDocument();
  });

  it("shows an empty state when no MCP tools are exposed", async () => {
    apiMock.mcpTools.mockResolvedValue({ read_only: true, tools: [] });
    const user = userEvent.setup();
    renderAssistant();

    await screen.findByRole("heading", { name: "Assistant" });
    await user.click(screen.getByRole("button", { name: "MCP tools" }));

    expect(screen.getByRole("heading", { name: /MCP permission boundary/ })).toBeInTheDocument();
    expect(await screen.findByText("No MCP tools are available for this tenant.")).toBeInTheDocument();
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

    await screen.findByRole("heading", { name: "Assistant" });
    await user.click(screen.getByRole("button", { name: "MCP tools" }));

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

    await screen.findByRole("heading", { name: "Assistant" });
    await user.click(screen.getByRole("button", { name: "MCP tools" }));
    expect(screen.getByText(/Tools are read-only/)).toBeInTheDocument();
    await screen.findByLabelText("Tool");
    await user.type(screen.getByLabelText("Subject"), "payments");
    await user.click(screen.getByRole("button", { name: /^Invoke$/i }));

    expect(await screen.findByText("Found the active payment certificate.")).toBeInTheDocument();
    expect(screen.getByText("graph#node-9")).toBeInTheDocument();
    expect(apiMock.callMCPTool).toHaveBeenCalledWith("credential.lookup", { subject: "payments" });
  });
});
