import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { ThemeProvider } from "@/components/ThemeProvider";
import { AuthProvider } from "@/auth/AuthProvider";
import { AppRoutes } from "@/App";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    me: vi.fn(),
    authMethods: vi.fn().mockResolvedValue({ oidc: true, saml: false, ldap: false }),
    createAPIToken: vi.fn(),
    revokeAPIToken: vi.fn(),
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
            schema: { type: "integer", minimum: 1, maximum: 100 },
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
        parameters: [
          {
            name: "Idempotency-Key",
            in: "header",
            required: true,
            schema: { type: "string" },
          },
        ],
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
    "/api/v1/identities/{id}": {
      get: {
        operationId: "getIdentity",
        summary: "Get an identity",
        parameters: [
          {
            name: "id",
            in: "path",
            required: true,
            schema: { type: "string", format: "uuid" },
          },
        ],
        responses: {
          "200": { content: { "application/json": { schema: { $ref: "#/components/schemas/Identity" } } } },
          "4XX": { content: { "application/problem+json": { schema: { $ref: "#/components/schemas/Problem" } } } },
        },
        security: [{ BearerAuth: [] }, { SessionCookie: [] }],
        "x-trstctl-permission": "identities:read",
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
    apiMock.me.mockResolvedValue({ permissions: ["*"], subject: "docs-operator", tenant_id: "tenant-1", email: "docs@example.test" });
    apiMock.createAPIToken.mockImplementation(async (input: { scopes: string[]; expires_at: string }) => ({
      id: "00000000-0000-4000-8000-000000000099",
      tenant_id: "tenant-1",
      subject: "docs@example.test",
      scopes: input.scopes,
      created_at: new Date().toISOString(),
      expires_at: input.expires_at,
      token: "trst_test_docs_token",
    }));
    apiMock.revokeAPIToken.mockResolvedValue(undefined);
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url === "/api/v1/openapi.json") {
        return new Response(JSON.stringify(explorerSpec), { status: 200, headers: { "Content-Type": "application/json" } });
      }
      expect(url).toBe("/api/v1/certificates?limit=1");
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

    const limit = screen.getByRole("textbox", { name: "Value for limit query parameter" });
    await user.type(limit, "0");
    expect(screen.getAllByText("limit must be at least 1.")).toHaveLength(2);
    await user.clear(limit);
    await user.type(limit, "1");
    expect(screen.getByText(/GET \/api\/v1\/certificates\?limit=1/)).toBeInTheDocument();

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
      "/api/v1/certificates?limit=1",
      expect.objectContaining({
        method: "GET",
        headers: expect.objectContaining({ Authorization: "Bearer trst_test_docs_token" }),
      }),
    );
  });

  it("uses a validated real path value instead of a generated placeholder", async () => {
    const user = userEvent.setup();
    const identityID = "a68416f3-21ee-4762-a327-08cad85275e4";
    vi.mocked(globalThis.fetch).mockImplementation(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url === "/api/v1/openapi.json") {
        return new Response(JSON.stringify(explorerSpec), { status: 200, headers: { "Content-Type": "application/json" } });
      }
      expect(url).toBe(`/api/v1/identities/${identityID}`);
      return new Response(JSON.stringify({ id: identityID }), { status: 200, headers: { "Content-Type": "application/json" } });
    });
    renderRoute();

    await user.click(await screen.findByRole("button", { name: /getIdentity/i }));
    const pathID = screen.getByRole("textbox", { name: "Value for id path parameter" });
    await user.clear(pathID);
    await user.type(pathID, "not-a-uuid");
    expect(screen.getAllByText("id must be a UUID.")).toHaveLength(2);
    expect(screen.getByRole("button", { name: "Run request" })).toBeDisabled();

    await user.clear(pathID);
    await user.type(pathID, identityID);
    await user.click(screen.getByRole("button", { name: "Generate test key" }));
    await user.click(await screen.findByRole("button", { name: "Run request" }));
    await waitFor(() => expect(globalThis.fetch).toHaveBeenCalledWith(`/api/v1/identities/${identityID}`, expect.objectContaining({ method: "GET" })));
  });

  it("requires an edited valid body and explicit review before a mutation", async () => {
    const user = userEvent.setup();
    vi.mocked(globalThis.fetch).mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url === "/api/v1/openapi.json") {
        return new Response(JSON.stringify(explorerSpec), { status: 200, headers: { "Content-Type": "application/json" } });
      }
      expect(url).toBe("/api/v1/identities");
      expect(init).toEqual(
        expect.objectContaining({
          method: "POST",
          headers: expect.objectContaining({ "Idempotency-Key": "aud69-create-identity" }),
          body: JSON.stringify({ kind: "x509_certificate", name: "payments-api", owner_id: "a68416f3-21ee-4762-a327-08cad85275e4" }),
        }),
      );
      return new Response(JSON.stringify({ id: "d472d5fe-e521-465a-af92-a058f071a348" }), {
        status: 201,
        headers: { "Content-Type": "application/json" },
      });
    });
    renderRoute();

    await user.click(await screen.findByRole("button", { name: /createIdentity/i }));
    const body = screen.getByRole("textbox", { name: "Request body JSON" });
    fireEvent.change(body, { target: { value: "{" } });
    expect(screen.getAllByText(/Request body is not valid JSON/)).toHaveLength(2);

    fireEvent.change(body, { target: { value: JSON.stringify({ kind: "x509_certificate", name: "payments-api" }) } });
    expect(screen.getAllByText("owner_id is required.")).toHaveLength(2);

    fireEvent.change(body, {
      target: { value: JSON.stringify({ kind: "x509_certificate", name: "payments-api", owner_id: "a68416f3-21ee-4762-a327-08cad85275e4" }) },
    });
    const idempotencyKey = screen.getByRole("textbox", { name: "Value for Idempotency-Key header parameter" });
    await user.clear(idempotencyKey);
    await user.type(idempotencyKey, "aud69-create-identity");
    await user.click(screen.getByRole("button", { name: "Generate test key" }));

    const run = await screen.findByRole("button", { name: "Run request" });
    expect(run).toBeDisabled();
    expect(screen.getByText(/POST \/api\/v1\/identities/)).toBeInTheDocument();
    expect(screen.getByText(/Idempotency-Key: aud69-create-identity/)).toBeInTheDocument();
    expect(screen.getAllByText(/payments-api/)).toHaveLength(2);

    await user.click(screen.getByRole("checkbox", { name: /I reviewed this exact mutation request/ }));
    expect(run).toBeEnabled();
    await user.type(idempotencyKey, "-changed");
    expect(run).toBeDisabled();
    await user.clear(idempotencyKey);
    await user.type(idempotencyKey, "aud69-create-identity");
    await user.click(screen.getByRole("checkbox", { name: /I reviewed this exact mutation request/ }));
    expect(run).toBeEnabled();
    await user.click(run);
    await waitFor(() => expect(globalThis.fetch).toHaveBeenCalledWith("/api/v1/identities", expect.objectContaining({ method: "POST" })));
  });

  it("cancels an in-flight request through AbortController", async () => {
    const user = userEvent.setup();
    let requestSignal: AbortSignal | null = null;
    vi.mocked(globalThis.fetch).mockImplementation((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url === "/api/v1/openapi.json") {
        return Promise.resolve(new Response(JSON.stringify(explorerSpec), { status: 200, headers: { "Content-Type": "application/json" } }));
      }
      requestSignal = init?.signal ?? null;
      return new Promise<Response>((_resolve, reject) => {
        requestSignal?.addEventListener("abort", () => reject(new DOMException("Aborted", "AbortError")));
      });
    });
    renderRoute();

    await user.click(await screen.findByRole("button", { name: /listCertificates/i }));
    await user.click(screen.getByRole("button", { name: "Generate test key" }));
    await user.click(await screen.findByRole("button", { name: "Run request" }));
    await user.click(await screen.findByRole("button", { name: "Cancel request" }));

    expect((requestSignal as unknown as AbortSignal).aborted).toBe(true);
    expect(await screen.findByText("Request cancelled.")).toBeInTheDocument();
  });

  it("disables expired keys and revokes live test keys", async () => {
    const user = userEvent.setup();
    apiMock.createAPIToken.mockResolvedValueOnce({
      id: "00000000-0000-4000-8000-000000000098",
      tenant_id: "tenant-1",
      subject: "docs@example.test",
      scopes: ["certs:read"],
      created_at: "2026-06-29T12:00:00Z",
      expires_at: "2026-06-29T12:15:00Z",
      token: "trst_expired_docs_token",
    });
    renderRoute();

    await user.click(await screen.findByRole("button", { name: /listCertificates/i }));
    await user.click(screen.getByRole("button", { name: "Generate test key" }));
    expect(await screen.findByText("Test key expired.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Run request" })).toBeDisabled();

    await user.click(screen.getByRole("button", { name: "Generate test key" }));
    await user.click(await screen.findByRole("button", { name: "Revoke test key" }));
    await waitFor(() => expect(apiMock.revokeAPIToken).toHaveBeenCalledWith("00000000-0000-4000-8000-000000000099"));
    expect(screen.getByText("Test key revoked.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Run request" })).toBeDisabled();
  });
});
