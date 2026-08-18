import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { ThemeProvider } from "@/components/ThemeProvider";
import { AuthProvider } from "@/auth/AuthProvider";
import { AppRoutes } from "@/App";

const { apiMock } = vi.hoisted(() => ({
  apiMock: { me: vi.fn(), authMethods: vi.fn().mockResolvedValue({ oidc: true, saml: false, ldap: false }), auditEvents: vi.fn(), exportAudit: vi.fn() },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: apiMock };
});

const envelope = {
  schema_version: 1,
  format: "jws" as const,
  bundle: "header.signed-payload.signature",
  chain_head: "sha256:aud-51-chain-head",
  anchor: {
    kind: "rfc3161" as const,
    chain_head: "sha256:aud-51-chain-head",
    anchored_at: "2026-08-12T11:30:00Z",
    token: {
      info: {
        version: 1,
        policy: "1.3.6.1.4.1.59551.2.1",
        hash_algorithm: "SHA-256",
        hashed_message: "aW1wcmludA==",
        serial_number: 51,
        gen_time: "2026-08-12T11:30:00Z",
      },
      signature: "c2lnbmF0dXJl",
      tsa_cert: "dHNhLWNlcnQ=",
      der: "cmZjMzE2MS10b2tlbg==",
    },
  },
};

function renderAudit() {
  return render(
    <ThemeProvider>
      <AuthProvider>
        <MemoryRouter initialEntries={["/audit"]}>
          <AppRoutes />
        </MemoryRouter>
      </AuthProvider>
    </ThemeProvider>,
  );
}

describe("AUD-51 self-contained audit downloads", () => {
  beforeEach(() => {
    apiMock.me.mockReset().mockResolvedValue({ subject: "auditor", tenant_id: "t1", email: "auditor@example.test" });
    apiMock.auditEvents.mockReset().mockResolvedValue([]);
    apiMock.exportAudit.mockReset().mockResolvedValue(envelope);
  });

  it("shows the external timestamp and saves the complete canonical envelope", async () => {
    const user = userEvent.setup();
    renderAudit();
    await user.click(await screen.findByRole("button", { name: /Export evidence/i }));

    expect(await screen.findByText("Complete RFC 3161 token saved")).toBeInTheDocument();
    expect(screen.getByText("rfc3161")).toBeInTheDocument();
    expect(screen.getByText("2026-08-12T11:30:00Z")).toBeInTheDocument();
    expect(screen.getByText("sha256:aud-51-chain-head")).toBeInTheDocument();
    expect(screen.getByText(/Ready for offline verification/i)).toBeInTheDocument();

    const link = screen.getByRole("link", { name: "Download signed bundle" });
    expect(link).toHaveAttribute("download", "audit-evidence.jws.json");
    const href = link.getAttribute("href") ?? "";
    expect(href).toMatch(/^data:application\/json/);
    const saved = JSON.parse(decodeURIComponent(href.slice(href.indexOf(",") + 1)));
    expect(saved).toEqual(envelope);
    expect(saved.anchor.token.der).toBe("cmZjMzE2MS10b2tlbg==");
  });
});
