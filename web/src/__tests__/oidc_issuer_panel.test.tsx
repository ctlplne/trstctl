// SPDX-License-Identifier: BUSL-1.1

import { beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { IntlProvider } from "@/i18n/I18nProvider";
import { AppQueryProvider } from "@/lib/query";
import { OIDCIssuerPanel } from "@/pages/workloads/OIDCIssuerPanel";

const { apiMock, principal } = vi.hoisted(() => ({
  apiMock: {
    oidcIssuer: vi.fn(),
    workloadJWTKeys: vi.fn(),
    rotateWorkloadJWTKey: vi.fn(),
  },
  principal: { permissions: ["certs:read", "issuers:write"] as string[] },
}));

vi.mock("@/lib/api", async (orig) => ({ ...(await orig<typeof import("@/lib/api")>()), api: apiMock }));
vi.mock("@/auth/AuthProvider", async (orig) => ({
  ...(await orig<typeof import("@/auth/AuthProvider")>()),
  useAuth: () => ({ user: principal }),
}));

const issuer = {
  issuer: "https://issuer.example.test/oidc/t-1",
  discovery_url: "https://issuer.example.test/oidc/t-1/.well-known/openid-configuration",
  jwks_uri: "https://issuer.example.test/oidc/t-1/jwks.json",
  algorithms: ["ES256"],
  token_endpoint: "https://issuer.example.test/oauth2/token",
  token_lifetime_seconds: 300,
  issued_token_types: ["urn:ietf:params:oauth:token-type:jwt", "urn:ietf:params:oauth:token-type:access_token"],
  opaque_token_audiences: ["https://legacy.example.test"],
  introspection_endpoint: "/api/v1/workloads/tokens/introspect",
};
const firstKey = { key_id: "spiffe-jwt", generation: 1, state: "active" };
const rotatedKeys = {
  keys: [
    { ...firstKey, retires_at: "2026-11-13T00:00:00Z" },
    {
      key_id: "spiffe-jwt-g2",
      generation: 2,
      state: "next",
      published_at: "2026-11-11T00:00:00Z",
      activates_at: "2026-11-12T00:00:00Z",
    },
  ],
};

function renderPanel() {
  return render(
    <IntlProvider initialLocale="en-US" initialTimeZone="UTC">
      <AppQueryProvider>
        <OIDCIssuerPanel />
      </AppQueryProvider>
    </IntlProvider>,
  );
}

// N5 / N5-L3: the console shows the OpenID issuer a cloud registers and the
// signing keys behind it, and rotates the key: the next key is published
// ahead of signing and the replaced key stays published for a retain window.
describe("OpenID issuer and signing keys", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    principal.permissions = ["certs:read", "issuers:write"];
    apiMock.oidcIssuer.mockResolvedValue(issuer);
    apiMock.workloadJWTKeys.mockResolvedValue({ keys: [firstKey] });
  });

  it("shows the issuer and rotates the signing key with the chosen windows, keeping one key for the request", async () => {
    apiMock.rotateWorkloadJWTKey.mockResolvedValue(rotatedKeys);
    const user = userEvent.setup();
    renderPanel();
    expect(await screen.findByText(issuer.issuer)).toBeInTheDocument();
    expect(screen.getByText(issuer.jwks_uri)).toBeInTheDocument();
    // M4-L3: the exchange issues JWT-SVIDs and RFC 9068 JWT access tokens.
    expect(screen.getByText("JWT-SVID, JWT access token (RFC 9068)")).toBeInTheDocument();
    expect(screen.getByText("https://legacy.example.test")).toBeInTheDocument();
    expect(screen.getByText("/api/v1/workloads/tokens/introspect")).toBeInTheDocument();
    const table = await screen.findByRole("table", { name: "Workload JWT signing keys" });
    expect(within(table).getAllByRole("row")[1]).toHaveTextContent(/spiffe-jwt.*Signing.*First key/);

    await user.clear(screen.getByLabelText("Publish ahead (hours)"));
    await user.type(screen.getByLabelText("Publish ahead (hours)"), "48");
    await user.clear(screen.getByLabelText("Keep the replaced key (hours)"));
    await user.type(screen.getByLabelText("Keep the replaced key (hours)"), "72");
    apiMock.workloadJWTKeys.mockResolvedValue(rotatedKeys);
    await user.click(screen.getByRole("button", { name: "Rotate signing key" }));
    expect(apiMock.rotateWorkloadJWTKey).toHaveBeenCalledWith({ publish_ahead_seconds: 172800, retain_seconds: 259200 }, expect.any(String));
    expect(await screen.findByRole("status")).toHaveTextContent("The next key is published");
    const rows = within(await screen.findByRole("table", { name: "Workload JWT signing keys" })).getAllByRole("row");
    expect(await within(rows[2] ?? rows[1]).findByText("spiffe-jwt-g2")).toBeInTheDocument();
    expect(screen.getByText(/Key spiffe-jwt-g2 is published and signs from/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Rotate signing key" })).not.toBeInTheDocument();
  });

  it("says how to get RS256 for a cloud that accepts only RS256, and stops once the issuer signs it (OD-6)", async () => {
    renderPanel();
    expect(await screen.findByText(issuer.issuer)).toBeInTheDocument();
    expect(screen.getByText(/needs protocols\.spiffe\.jwt_key_algorithm set to RS256/)).toBeInTheDocument();
    cleanup();
    apiMock.oidcIssuer.mockResolvedValue({ ...issuer, algorithms: ["RS256"] });
    renderPanel();
    expect(await screen.findByText("RS256")).toBeInTheDocument();
    expect(screen.queryByText(/needs protocols\.spiffe\.jwt_key_algorithm/)).not.toBeInTheDocument();
  });

  it("keeps the idempotency key when a rotation is retried after a failure", async () => {
    apiMock.rotateWorkloadJWTKey.mockRejectedValueOnce(new Error("the signer is unavailable")).mockResolvedValueOnce(rotatedKeys);
    const user = userEvent.setup();
    renderPanel();
    await user.click(await screen.findByRole("button", { name: "Rotate signing key" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("the signer is unavailable");
    await user.click(screen.getByRole("button", { name: "Rotate signing key" }));
    expect(apiMock.rotateWorkloadJWTKey).toHaveBeenCalledTimes(2);
    const [first, second] = apiMock.rotateWorkloadJWTKey.mock.calls;
    expect(first[0]).toEqual({ publish_ahead_seconds: 86400, retain_seconds: 86400 });
    expect(second[1]).toBe(first[1]);
  });

  it("shows the keys read-only without issuers:write, and says when no issuer is published", async () => {
    principal.permissions = ["certs:read"];
    apiMock.oidcIssuer.mockRejectedValue(new Error("this control plane publishes no OpenID issuer"));
    renderPanel();
    expect(await screen.findByText(/publishes no OpenID issuer/)).toBeInTheDocument();
    expect(await screen.findByRole("table", { name: "Workload JWT signing keys" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Rotate signing key" })).not.toBeInTheDocument();
  });
});
