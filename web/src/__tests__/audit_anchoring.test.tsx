import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";
import { AppQueryProvider } from "@/lib/query";
import { AuditAnchoringPanel } from "@/pages/audit/AuditAnchoringPanel";

const { apiMock } = vi.hoisted(() => ({ apiMock: { auditAnchors: vi.fn() } }));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

const verification = "Export an unbroken run of records and verify it offline with `trstctl audit verify --tsa-root <root> --anchor-cadence <cadence>`.";

function renderPanel() {
  return render(
    <AppQueryProvider>
      <AuditAnchoringPanel />
    </AppQueryProvider>,
  );
}

describe("continuous audit anchoring (A147)", () => {
  beforeEach(() => apiMock.auditAnchors.mockReset());

  it("shows the cadence, the series and how to verify it offline", async () => {
    apiMock.auditAnchors.mockResolvedValue({
      state: "anchoring",
      cadence_seconds: 3600,
      anchor_count: 2,
      last_anchored_at: "2026-10-26T18:00:00Z",
      anchors: [
        { through_sequence: 41, chain_head: "a".repeat(64), anchored_at: "2026-10-26T18:00:00Z", token_serial: 7, token_sha256: "b".repeat(64) },
        { through_sequence: 12, chain_head: "c".repeat(64), anchored_at: "2026-10-26T17:00:00Z", token_serial: 6, token_sha256: "d".repeat(64) },
      ],
      verification,
    });
    renderPanel();
    const region = await screen.findByRole("region", { name: "Continuous anchoring" });
    expect(await within(region).findByText("Anchoring")).toBeInTheDocument();
    expect(within(region).getByText("Every 60 min")).toBeInTheDocument();
    expect(within(region).getByText("2 anchors")).toBeInTheDocument();
    expect(within(region).getByText("41")).toBeInTheDocument();
    expect(within(region).getByText("a".repeat(64))).toBeInTheDocument();
    expect(within(region).getByText(verification)).toBeInTheDocument();
  });

  it("explains why anchoring is off, and a failed pass, without inventing anchors", async () => {
    apiMock.auditAnchors.mockResolvedValue({
      state: "off",
      detail: "Continuous anchoring is off: protocols.tsa is not enabled, so there is no timestamp authority.",
      cadence_seconds: 0,
      anchor_count: 0,
      anchors: [],
      verification,
    });
    const view = renderPanel();
    expect(await screen.findByText("Off")).toBeInTheDocument();
    expect(screen.getByRole("note")).toHaveTextContent("protocols.tsa is not enabled");
    expect(screen.getByText("No anchors yet.")).toBeInTheDocument();
    expect(screen.queryByText(/^Every /)).not.toBeInTheDocument();
    view.unmount();

    apiMock.auditAnchors.mockResolvedValue({
      state: "failing",
      detail: "The last anchoring pass failed: the timestamp authority or the audit log could not be reached.",
      cadence_seconds: 3600,
      anchor_count: 0,
      anchors: [],
      verification,
    });
    renderPanel();
    expect(await screen.findByText("Failing")).toBeInTheDocument();
    expect(screen.getByRole("note")).toHaveTextContent("could not be reached");
  });
});
