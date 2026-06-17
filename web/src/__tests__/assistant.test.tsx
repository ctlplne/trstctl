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
    expect(screen.getByRole("link", { name: /Assistant/i })).toHaveAttribute("href", "/assistant");

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

  it("shows an empty state when no MCP tools are exposed", async () => {
    apiMock.mcpTools.mockResolvedValue({ read_only: true, tools: [] });
    const user = userEvent.setup();
    renderAssistant();

    await screen.findByRole("heading", { name: "Assistant" });
    await user.click(screen.getByRole("button", { name: "MCP tools" }));

    expect(await screen.findByText("No MCP tools are available for this tenant.")).toBeInTheDocument();
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
    await screen.findByLabelText("Tool");
    await user.type(screen.getByLabelText("Subject"), "payments");
    await user.click(screen.getByRole("button", { name: /^Invoke$/i }));

    expect(await screen.findByText("Found the active payment certificate.")).toBeInTheDocument();
    expect(screen.getByText("graph#node-9")).toBeInTheDocument();
    expect(apiMock.callMCPTool).toHaveBeenCalledWith("credential.lookup", { subject: "payments" });
  });
});
