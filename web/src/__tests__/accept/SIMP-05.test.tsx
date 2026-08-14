import { readFileSync } from "node:fs";
import path from "node:path";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { ToastProvider } from "@/components/ToastProvider";
import { CAHierarchy } from "@/pages/CAHierarchy";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    issuers: vi.fn(),
    createCACeremony: vi.fn(),
    approveCACeremony: vi.fn(),
    generateManagedKey: vi.fn(),
    rotateManagedKey: vi.fn(),
    revokeManagedKey: vi.fn(),
    zeroizeManagedKey: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

function renderCAHierarchy() {
  return render(
    <MemoryRouter>
      <ToastProvider>
        <CAHierarchy />
      </ToastProvider>
    </MemoryRouter>,
  );
}

describe("SIMP-05 CA hierarchy ceremony and custody wiring", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    for (const mock of Object.values(apiMock)) mock.mockReset();
    apiMock.issuers.mockResolvedValue([
      {
        id: "iss-root",
        name: "Root CA",
        kind: "x509_ca",
        internal: true,
        chain: ["Root CA"],
        public_key: "-----BEGIN PUBLIC KEY-----ROOT-----END PUBLIC KEY-----",
      },
    ]);
    apiMock.createCACeremony.mockResolvedValue({
      id: "ceremony-root-1",
      tenant_id: "tenant-1",
      purpose: "create_root:Trust Root CA",
      threshold: 2,
      status: "pending",
      approvals: 1,
      opener: "ra@example.test",
      created_at: "2026-06-26T14:00:00Z",
    });
    apiMock.approveCACeremony.mockResolvedValue({
      id: "ceremony-root-1",
      tenant_id: "tenant-1",
      purpose: "create_root:Trust Root CA",
      threshold: 2,
      status: "approved",
      approvals: 2,
      opener: "ra@example.test",
      created_at: "2026-06-26T14:00:00Z",
    });
    apiMock.generateManagedKey.mockResolvedValue({
      key_id: "kms/root-1",
      algorithm: "ECDSA-P256",
      version: 1,
      state: "active",
      public_der: "BASE64PUBLICDER",
    });
    apiMock.rotateManagedKey.mockResolvedValue({ key_id: "kms/root-1", algorithm: "ECDSA-P256", version: 2, state: "active", public_der: "ROTATEDDER" });
    apiMock.revokeManagedKey.mockResolvedValue({ key_id: "kms/root-1", algorithm: "ECDSA-P256", version: 2, state: "revoked", public_der: "ROTATEDDER" });
    apiMock.zeroizeManagedKey.mockResolvedValue({ key_id: "kms/root-1", algorithm: "ECDSA-P256", version: 2, state: "zeroized" });
  });

  it("starts and approves a real CA key ceremony from served responses", async () => {
    const user = userEvent.setup();
    renderCAHierarchy();

    expect((await screen.findAllByText("Root CA")).length).toBeGreaterThan(0);
    await user.click(screen.getByRole("button", { name: "Start root ceremony" }));

    await waitFor(() =>
      expect(apiMock.createCACeremony).toHaveBeenCalledWith({
        operation: "create_root",
        threshold: 2,
        spec: expect.objectContaining({ common_name: "Trust Root CA", signature_algorithm: "ECDSA-P256" }),
      }),
    );
    expect(await screen.findByText("ceremony-root-1")).toBeInTheDocument();
    expect(screen.getByText("1 / 2 approvals")).toBeInTheDocument();
    expect(screen.getByText("pending")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Approve ceremony ceremony-root-1" }));

    await waitFor(() => expect(apiMock.approveCACeremony).toHaveBeenCalledWith("ceremony-root-1"));
    expect(await screen.findByText("2 / 2 approvals")).toBeInTheDocument();
    expect(screen.getByText("approved")).toBeInTheDocument();
  });

  it("generates and manages a real custody key from served managed-key responses", async () => {
    const user = userEvent.setup();
    renderCAHierarchy();

    await user.click(await screen.findByRole("button", { name: "Generate managed key" }));

    await waitFor(() => expect(apiMock.generateManagedKey).toHaveBeenCalledWith({ algorithm: "ECDSA-P256" }));
    expect(await screen.findByText("kms/root-1")).toBeInTheDocument();
    expect(screen.getByText("ECDSA-P256")).toBeInTheDocument();
    expect(screen.getByText("Version 1")).toBeInTheDocument();
    expect(screen.getByText("active")).toBeInTheDocument();
    expect(screen.queryByText(/BEGIN PRIVATE KEY|PRIVATE KEY-----/)).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Rotate key kms/root-1" }));
    await waitFor(() => expect(apiMock.rotateManagedKey).toHaveBeenCalledWith("kms/root-1"));
    expect(await screen.findByText("Version 2")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Revoke key kms/root-1" }));
    await waitFor(() => expect(apiMock.revokeManagedKey).toHaveBeenCalledWith("kms/root-1"));
    expect(await screen.findByText("revoked")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Zeroize key kms/root-1" }));
    await waitFor(() => expect(apiMock.zeroizeManagedKey).toHaveBeenCalledWith("kms/root-1"));
    expect(await screen.findByText("zeroized")).toBeInTheDocument();
  });

  it("removes CA ceremony and custody fixtures from the module", () => {
    const source = readFileSync(path.join(process.cwd(), "src/pages/CAHierarchy.tsx"), "utf8");
    expect(source).not.toMatch(/ceremonySteps|custodyRows|Key custody metadata preview|CA ceremony purpose model/);
    expect(source).not.toMatch(/root:<sha256-of-ca-spec>|sealed:\/\/tenant-ca|pkcs11:\/\/slot|YubiHSM|library-tier|coming soon|fixture/i);
  });
});
