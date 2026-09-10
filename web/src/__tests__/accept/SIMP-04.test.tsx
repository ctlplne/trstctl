import { readFileSync } from "node:fs";
import path from "node:path";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { Identities } from "@/pages/Identities";
import { AppQueryProvider } from "@/lib/query";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    identities: vi.fn(),
    getIdentity: vi.fn(),
    transitionIdentity: vi.fn(),
    graphBlastRadius: vi.fn(),
    connectorDeliveries: vi.fn(),
    rotationRuns: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

function renderIdentities() {
  return render(
    <MemoryRouter>
      <AppQueryProvider>
        <Identities />
      </AppQueryProvider>
    </MemoryRouter>,
  );
}

describe("SIMP-04 identities declutter", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    for (const mock of Object.values(apiMock)) mock.mockReset();
    apiMock.identities.mockResolvedValue([
      {
        id: "id-deployed-1",
        name: "payments-tls",
        kind: "x509_certificate",
        owner_id: "owner-1",
        status: "deployed",
      },
    ]);
    apiMock.getIdentity.mockResolvedValue({
      id: "id-deployed-1",
      name: "payments-tls",
      kind: "x509_certificate",
      owner_id: "owner-1",
      issuer_id: "issuer-1",
      status: "deployed",
      attributes: { dns_names: ["payments.example.test"] },
    });
    apiMock.transitionIdentity.mockResolvedValue({ id: "id-deployed-1", name: "payments-tls", status: "renewing" });
    apiMock.graphBlastRadius.mockResolvedValue({ node: { id: "cert:id-deployed-1", kind: "credential", name: "payments-tls" }, affected: [], by_kind: {} });
    apiMock.connectorDeliveries.mockResolvedValue({
      items: [
        {
          id: "delivery-1",
          tenant_id: "tenant-1",
          identity_id: "id-deployed-1",
          destination: "connector.deploy",
          connector: "kubernetes",
          target: "prod/payments-tls",
          fingerprint: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          status: "delivered",
          attempts: 1,
          reason: "outbox_delivered",
          detail: "receipt persisted by delivery worker",
          rollback_ref: "rollback:delivery-1",
          idempotency_key: "idem-delivery-1",
          created_at: "2026-06-26T13:00:00Z",
          updated_at: "2026-06-26T13:01:00Z",
        },
      ],
    });
    apiMock.rotationRuns.mockResolvedValue({
      items: [
        {
          id: "rotation-1",
          tenant_id: "tenant-1",
          identity_id: "id-deployed-1",
          status: "succeeded",
          trigger: "scheduler",
          reason: "renew-before window reached",
          predecessor_fingerprint: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
          successor_fingerprint: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          rollback_ref: "restore sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
          idempotency_key: "idem-rotation-1",
          created_at: "2026-06-26T12:58:00Z",
          updated_at: "2026-06-26T13:02:00Z",
          completed_at: "2026-06-26T13:02:00Z",
        },
      ],
    });
  });

  it("keeps list, detail, and served evidence while removing static guardrail and endpoint prose", async () => {
    const user = userEvent.setup();
    renderIdentities();

    await waitFor(() => expect(apiMock.connectorDeliveries).toHaveBeenCalledWith({ limit: 50 }));
    expect(apiMock.rotationRuns).toHaveBeenCalledWith({ limit: 50 });
    const identitiesTable = await screen.findByRole("table", { name: /credential identities/i });
    expect(identitiesTable).toBeInTheDocument();
    await user.click(screen.getAllByText("Delivery and rotation evidence")[0]);
    expect(screen.getAllByText("kubernetes").length).toBeGreaterThan(0);
    expect(screen.getAllByText("prod/payments-tls").length).toBeGreaterThan(0);
    await user.click(screen.getByText("Show exact reason"));
    expect(screen.getByText("outbox_delivered")).toBeInTheDocument();
    expect(screen.getAllByText("scheduler").length).toBeGreaterThan(0);

    const row = within(identitiesTable).getByText("payments-tls").closest("tr")!;
    expect(row).toHaveTextContent("Delivered successfully.");
    expect(row).not.toHaveTextContent("outbox_delivered");
    await user.click(within(row).getByRole("button", { name: /view details/i }));

    const dialog = await screen.findByRole("dialog", { name: "Identity detail" });
    expect(within(dialog).getByText("X.509 certificate identity")).toBeInTheDocument();
    expect(within(dialog).getByText("Credential activity timeline")).toBeInTheDocument();
    expect(within(dialog).getByText(/payments.example.test/)).toBeInTheDocument();

    expect(screen.queryByText("Issuance guardrails")).not.toBeInTheDocument();
    expect(screen.queryByText("Revocation publication")).not.toBeInTheDocument();
    expect(document.body.textContent).not.toMatch(
      /public OCSP|CRL responders|Responder paths|Live propagation health|request-only principal cannot self-issue/i,
    );
  });

  it("removes guardrail and revocation endpoint prose from the Identities module", () => {
    const source = readFileSync(path.join(process.cwd(), "src/pages/Identities.tsx"), "utf8");
    expect(source).not.toMatch(/Issuance guardrails|RevocationPublicationPanel|Revocation publication/);
    expect(source).not.toMatch(/OCSP|CRL responders|Responder paths|Live propagation health|request-only principal cannot self-issue/);
  });
});
