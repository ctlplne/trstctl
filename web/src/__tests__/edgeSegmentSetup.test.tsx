import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { EdgeDelegationsPanel } from "@/components/EdgeDelegationsPanel";
import { AppQueryProvider } from "@/lib/query";

const { apiMock, principal } = vi.hoisted(() => ({
  apiMock: {
    edgeSegmentPolicies: vi.fn(),
    edgeDelegations: vi.fn(),
    setEdgeSegmentPolicy: vi.fn(),
    createDiscoverySegment: vi.fn(),
  },
  principal: { permissions: ["issuers:write"] as string[] },
}));

vi.mock("@/lib/api", async (orig) => ({
  ...(await orig<typeof import("@/lib/api")>()),
  api: apiMock,
}));
vi.mock("@/auth/AuthProvider", async (orig) => ({
  ...(await orig<typeof import("@/auth/AuthProvider")>()),
  useAuth: () => ({ user: principal }),
}));

const segmentID = "14aa0370-4c49-43ac-88fd-37918bbd10c5";
const publicRoot = "-----BEGIN CERTIFICATE-----\nQA-TEST-PUBLIC-ROOT\n-----END CERTIFICATE-----";

function mount() {
  return render(
    <AppQueryProvider>
      <EdgeDelegationsPanel />
    </AppQueryProvider>,
  );
}

describe("Edge segment setup", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    principal.permissions = ["issuers:write"];
    apiMock.edgeSegmentPolicies.mockResolvedValue({ items: [], guidance: "" });
    apiMock.edgeDelegations.mockResolvedValue({ items: [], guidance: "" });
    apiMock.setEdgeSegmentPolicy.mockResolvedValue({
      segment_id: segmentID,
      enabled: true,
      attestation_roots: 1,
      permitted_dns_domains: ["edge.qa.invalid"],
      allowed_key_providers: ["tpm2"],
      updated_at: "2026-10-18T09:00:00Z",
    });
    apiMock.createDiscoverySegment.mockResolvedValue({ id: segmentID, name: "edge-lab" });
  });

  it("reviews the exact trust boundary before enabling and keeps an idempotency key", async () => {
    const user = userEvent.setup();
    mount();
    await user.click(await screen.findByRole("button", { name: "Configure edge segment" }));
    await user.type(screen.getByLabelText("Declared segment ID"), segmentID);
    await user.type(screen.getByLabelText("TPM attestation root certificate"), publicRoot);
    await user.type(screen.getByLabelText("Permitted DNS domains"), "edge.qa.invalid");
    await user.click(screen.getByRole("button", { name: "Review segment policy" }));
    expect(await screen.findByText(segmentID)).toBeInTheDocument();
    expect(screen.getByText("edge.qa.invalid")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Save reviewed segment policy" }));
    await waitFor(() =>
      expect(apiMock.setEdgeSegmentPolicy).toHaveBeenCalledWith(
        segmentID,
        expect.objectContaining({
          enabled: true,
          attestation_roots_pem: [publicRoot],
          permitted_dns_domains: ["edge.qa.invalid"],
          allowed_key_providers: ["tpm2"],
        }),
        expect.any(String),
      ),
    );
  });

  it("shows excluded DNS subtrees in the exact review before saving", async () => {
    const user = userEvent.setup();
    mount();
    await user.click(await screen.findByRole("button", { name: "Configure edge segment" }));
    await user.type(screen.getByLabelText("Declared segment ID"), segmentID);
    await user.type(screen.getByLabelText("TPM attestation root certificate"), publicRoot);
    await user.type(screen.getByLabelText("Permitted DNS domains"), "edge.qa.invalid");
    await user.type(screen.getByLabelText("Excluded DNS domains"), "blocked.edge.qa.invalid");
    await user.click(screen.getByRole("button", { name: "Review segment policy" }));
    expect(screen.getByText("Excluded DNS domains")).toBeInTheDocument();
    expect(screen.getByText("blocked.edge.qa.invalid")).toBeInTheDocument();
  });

  it("does not show a policy mutation to a reader", async () => {
    principal.permissions = ["issuers:read"];
    mount();
    expect(await screen.findByText(/No segment has opted in/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Configure edge segment" })).not.toBeInTheDocument();
  });

  it("retries a lost declaration response with the original key", async () => {
    principal.permissions = ["issuers:write", "discovery:write"];
    apiMock.createDiscoverySegment.mockRejectedValueOnce(new Error("response lost"));
    const user = userEvent.setup();
    mount();
    await user.click(await screen.findByRole("button", { name: "Configure edge segment" }));
    await user.selectOptions(screen.getByLabelText("Segment source"), "declare");
    await user.type(screen.getByLabelText("New segment name"), "edge-lab");
    await user.type(screen.getByLabelText("New segment address or CIDR"), "127.0.0.1/32");
    await user.type(screen.getByLabelText("TPM attestation root certificate"), publicRoot);
    await user.type(screen.getByLabelText("Permitted DNS domains"), "edge.qa.invalid");
    await user.click(screen.getByRole("button", { name: "Review segment policy" }));
    await user.click(screen.getByRole("button", { name: "Save reviewed segment policy" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("response lost");
    await user.click(screen.getByRole("button", { name: "Save reviewed segment policy" }));
    await waitFor(() => expect(apiMock.setEdgeSegmentPolicy).toHaveBeenCalledTimes(1));
    expect(apiMock.createDiscoverySegment).toHaveBeenCalledTimes(2);
    expect(apiMock.createDiscoverySegment.mock.calls[0][1]).toBe(apiMock.createDiscoverySegment.mock.calls[1][1]);
  });

  it("disables an existing segment without asking the API to reveal its roots", async () => {
    apiMock.edgeSegmentPolicies.mockResolvedValue({
      items: [
        {
          segment_id: segmentID,
          segment_name: "edge-lab",
          enabled: true,
          attestation_roots: 1,
          permitted_dns_domains: ["edge.qa.invalid"],
          allowed_key_providers: ["tpm2"],
          updated_at: "2026-10-18T09:00:00Z",
        },
      ],
      guidance: "",
    });
    const user = userEvent.setup();
    mount();
    await user.click(await screen.findByRole("button", { name: "Change segment policy" }));
    expect(screen.getByLabelText("Declared segment ID")).toHaveValue(segmentID);
    await user.click(screen.getByLabelText("Enable delegated edge CA issuance"));
    await user.click(screen.getByRole("button", { name: "Review segment policy" }));
    await user.click(screen.getByRole("button", { name: "Save reviewed segment policy" }));
    await waitFor(() =>
      expect(apiMock.setEdgeSegmentPolicy).toHaveBeenCalledWith(
        segmentID,
        expect.objectContaining({ enabled: false, attestation_roots_pem: [] }),
        expect.any(String),
      ),
    );
  });
});
