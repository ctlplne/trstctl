import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { ThemeProvider } from "@/components/ThemeProvider";
import { AuthProvider } from "@/auth/AuthProvider";
import { AppRoutes } from "@/App";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    me: vi.fn(),
    createAPIToken: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

const explorerSpec = {
  openapi: "3.1.0",
  info: { title: "trstctl API", version: "v1" },
  paths: {
    "/api/v1/certificates": {
      get: {
        operationId: "listCertificates",
        summary: "Query the certificate inventory",
        parameters: [
          {
            name: "limit",
            in: "query",
            schema: { type: "integer" },
          },
        ],
        responses: {
          "200": { content: { "application/json": { schema: { $ref: "#/components/schemas/CertificateList" } } } },
          "4XX": { content: { "application/problem+json": { schema: { $ref: "#/components/schemas/Problem" } } } },
        },
        security: [{ BearerAuth: [] }, { SessionCookie: [] }],
        "x-trstctl-permission": "certs:read",
      },
    },
    "/api/v1/identities": {
      post: {
        operationId: "createIdentity",
        summary: "Create an identity",
        requestBody: {
          required: true,
          content: { "application/json": { schema: { $ref: "#/components/schemas/IdentityRequest" } } },
        },
        responses: {
          "201": { content: { "application/json": { schema: { $ref: "#/components/schemas/Identity" } } } },
          "4XX": { content: { "application/problem+json": { schema: { $ref: "#/components/schemas/Problem" } } } },
        },
        security: [{ BearerAuth: [] }, { SessionCookie: [] }],
        "x-trstctl-permission": "identities:write",
      },
    },
  },
  components: {
    schemas: {
      IdentityRequest: {
        type: "object",
        required: ["kind", "name", "owner_id"],
        properties: {
          kind: { type: "string", enum: ["x509_certificate"] },
          name: { type: "string" },
          owner_id: { type: "string", format: "uuid" },
        },
      },
    },
  },
};

function renderRoute() {
  return render(
    <ThemeProvider>
      <AuthProvider>
        <MemoryRouter initialEntries={["/integrate/api"]}>
          <AppRoutes />
        </MemoryRouter>
      </AuthProvider>
    </ThemeProvider>,
  );
}

describe("DESIGN-002 runnable API explorer", () => {
  beforeEach(() => {
    apiMock.me.mockResolvedValue({ subject: "docs-operator", tenant_id: "tenant-1", email: "docs@example.test" });
    apiMock.createAPIToken.mockResolvedValue({
      id: "00000000-0000-4000-8000-000000000099",
      tenant_id: "tenant-1",
      subject: "docs@example.test",
      scopes: ["certs:read"],
      created_at: "2026-06-29T12:00:00Z",
      expires_at: "2026-06-29T12:15:00Z",
      token: "trst_test_docs_token",
    });
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url === "/api/v1/openapi.json") {
        return new Response(JSON.stringify(explorerSpec), { status: 200, headers: { "Content-Type": "application/json" } });
      }
      expect(url).toBe("/api/v1/certificates");
      expect(init?.method).toBe("GET");
      expect((init?.headers as Record<string, string>).Authorization).toBe("Bearer trst_test_docs_token");
      return new Response(
        JSON.stringify({
          type: "https://trstctl.example/problems/forbidden",
          title: "Forbidden",
          status: 403,
          detail: "docs token lacks inventory access in this tenant",
        }),
        { status: 403, statusText: "Forbidden", headers: { "Content-Type": "application/problem+json" } },
      );
    });
    vi.stubGlobal("fetch", fetchMock);
  });

  it("opens the route, selects an operation, mints a scoped test key, runs it, and renders problem responses", async () => {
    const user = userEvent.setup();
    renderRoute();

    expect(await screen.findByRole("heading", { name: "API explorer" })).toBeInTheDocument();
    await user.click(await screen.findByRole("button", { name: /listCertificates/i }));
    expect(screen.getAllByText("certs:read").length).toBeGreaterThan(0);

    await user.click(screen.getByRole("button", { name: "Generate test key" }));
    await waitFor(() =>
      expect(apiMock.createAPIToken).toHaveBeenCalledWith(
        expect.objectContaining({
          subject: "docs@example.test",
          scopes: ["certs:read"],
          expires_at: expect.any(String),
        }),
      ),
    );
    expect(await screen.findByText(/Scoped test key ready for certs:read/i)).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Run request" }));

    expect(await screen.findByRole("heading", { name: "Problem response" })).toBeInTheDocument();
    expect(screen.getByText("application/problem+json")).toBeInTheDocument();
    expect(screen.getByText("Forbidden")).toBeInTheDocument();
    expect(screen.getByText("docs token lacks inventory access in this tenant")).toBeInTheDocument();
    expect(globalThis.fetch).toHaveBeenCalledWith(
      "/api/v1/certificates",
      expect.objectContaining({
        method: "GET",
        headers: expect.objectContaining({ Authorization: "Bearer trst_test_docs_token" }),
      }),
    );
  });
});
