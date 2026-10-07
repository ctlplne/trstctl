import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { AppQueryProvider } from "@/lib/query";
import { Audit } from "@/pages/Audit";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    auditEvents: vi.fn(),
    auditWindow: vi.fn(),
    auditFeeds: vi.fn(),
    exportAudit: vi.fn(),
    previewAuditFeed: vi.fn(),
    putAuditFeed: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (original) => {
  const actual = await original<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

function renderAudit() {
  return render(
    <AppQueryProvider>
      <MemoryRouter initialEntries={["/audit"]}>
        <main>
          <Audit />
        </main>
      </MemoryRouter>
    </AppQueryProvider>,
  );
}

describe("Route 035 change-history hierarchy", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    for (const mock of Object.values(apiMock)) mock.mockReset();
    const events = [
      {
        id: "evt-7",
        sequence: 7,
        tenant_id: "tenant-1",
        type: "identity.issued",
        time: "2026-08-21T19:20:00Z",
        hash: "sha256:change-seven",
        actor: { email: "ra@example.test" },
        data: { identity_id: "09090909-0909-4909-8909-090909090909", result: "succeeded" },
      },
    ];
    apiMock.auditEvents.mockResolvedValue(events);
    apiMock.auditWindow.mockResolvedValue({ events });
    apiMock.auditFeeds.mockResolvedValue({ items: [] });
    apiMock.exportAudit.mockResolvedValue({ format: "jws", bundle: "signed", chain_head: "sha256:change-seven" });
  });

  it("answers who changed what before exposing immutable-event machinery", async () => {
    const user = userEvent.setup();
    renderAudit();

    expect(await screen.findByRole("heading", { level: 1, name: "Change history" })).toBeInTheDocument();
    expect(screen.getByText("Who changed what, when, and whether it succeeded.", { exact: true })).toBeInTheDocument();
    expect(screen.getByText("Immutable event envelope, signatures, export, retention.", { exact: true })).toBeInTheDocument();
    expect(await screen.findByRole("heading", { level: 2, name: "1 change is ready to search" })).toBeInTheDocument();
    expect(
      screen.getByText(
        "Showing the newest matching records (1) within the selected filters, not the complete history. Search or export an exact window before making an audit decision.",
        { exact: true },
      ),
    ).toBeInTheDocument();
    expect(screen.getByText("Last change shown", { exact: true })).toBeInTheDocument();
    expect(screen.getByText("Identity issued", { exact: true })).toBeInTheDocument();
    expect(screen.getByText("ra@example.test", { exact: true })).toBeInTheDocument();
    expect(screen.getByText("Succeeded", { exact: true })).toBeInTheDocument();
    expect(document.querySelector("main")?.textContent).not.toMatch(/recent changes|latest change/i);

    const actions = screen.getByTestId("page-depth-operate");
    expect(within(actions).getAllByRole("button")).toHaveLength(1);
    expect(within(actions).getByRole("button", { name: "Search activity" })).toBeEnabled();
    expect(document.querySelectorAll("main input, main select, main textarea")).toHaveLength(0);
    expect(screen.queryByRole("table", { name: "Tenant audit events" })).not.toBeInTheDocument();
    expect(apiMock.auditFeeds).not.toHaveBeenCalled();

    for (const title of ["Search and inspect activity", "Signatures and evidence export", "Collector delivery"]) {
      expect(screen.getByText(title, { exact: true }).closest("details")).not.toHaveAttribute("open");
    }

    await user.click(within(actions).getByRole("button", { name: "Search activity" }));
    expect(await screen.findByRole("table", { name: "Tenant audit events" })).toBeInTheDocument();
    expect(screen.getByRole("searchbox", { name: "Search activity" })).toHaveFocus();
    expect(screen.getByRole("button", { name: "View event 7" })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "View event 7" }));
    expect(screen.getByRole("link", { name: "Open affected identity" })).toHaveAttribute("href", "/identities?identity=09090909-0909-4909-8909-090909090909");

    await user.click(screen.getByText("Signatures and evidence export", { exact: true }));
    expect(await screen.findByRole("heading", { name: "Hash coverage" })).toBeInTheDocument();
    expect(screen.getByText(/Hash presence is not independent verification/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Export evidence" })).toBeInTheDocument();

    await user.click(screen.getByText("Collector delivery", { exact: true }));
    await waitFor(() => expect(apiMock.auditFeeds).toHaveBeenCalledTimes(1));
    expect(await screen.findByRole("heading", { name: "Scheduled collector feeds" })).toBeInTheDocument();
    expect(screen.getByRole("form", { name: "Configure a collector feed" })).toBeInTheDocument();
  });

  it("says when the recent window is empty without inventing product activity", async () => {
    apiMock.auditEvents.mockResolvedValue([]);
    apiMock.auditWindow.mockResolvedValue({ events: [] });
    renderAudit();

    expect(await screen.findByRole("heading", { level: 2, name: "No changes found in this window" })).toBeInTheDocument();
    expect(
      screen.getByText("No live events match this window. Widen the filters, and check with the archive custodian before concluding that no change happened.", {
        exact: true,
      }),
    ).toBeInTheDocument();
    expect(screen.queryByText("Identity issued")).not.toBeInTheDocument();
  });

  it("identifies an archived predecessor when a filtered live window is empty", async () => {
    apiMock.auditEvents.mockResolvedValue([]);
    apiMock.auditWindow.mockResolvedValue({ events: [], archived_prefix: { record_count: 543, chain_head: "verified-head" } });
    renderAudit();
    expect(await screen.findByRole("heading", { level: 2, name: "Older changes are in signed archives" })).toBeInTheDocument();
    expect(screen.getByText(/543 older audit records.*archive custodian.*trstctl-cli audit verify/i)).toBeInTheDocument();
  });

  it("shows each retained revocation outcome without claiming queued or failed items succeeded", async () => {
    const events = [
      {
        id: "revocation-batch-1",
        sequence: 8,
        tenant_id: "tenant-1",
        type: "certificate.revocation.batch.applied",
        time: "2026-10-07T00:48:59Z",
        hash: "sha256:revocation-batch-1",
        actor: { subject: "custodian-1" },
        data: {
          items: [
            { id: "cert-1", matched: true, status: "revoked" },
            { id: "cert-2", matched: true, status: "queued" },
            { id: "cert-3", matched: true, status: "skipped" },
            { id: "cert-4", matched: false, status: "failed" },
          ],
        },
      },
    ];
    apiMock.auditWindow.mockResolvedValue({ events });
    renderAudit();

    expect(await screen.findByText("1 revoked · 1 queued · 1 skipped · 1 failed")).toBeInTheDocument();
    expect(screen.queryByText("Succeeded", { exact: true })).not.toBeInTheDocument();
    expect(screen.queryByText("Recorded; no success result in this event", { exact: true })).not.toBeInTheDocument();
  });

  it("does not infer a revocation result from an unknown batch item status", async () => {
    const events = [
      {
        id: "revocation-batch-unknown",
        sequence: 9,
        tenant_id: "tenant-1",
        type: "certificate.revocation.batch.applied",
        time: "2026-10-07T00:49:00Z",
        hash: "sha256:revocation-batch-unknown",
        actor: { subject: "custodian-1" },
        data: { items: [{ id: "cert-1", status: "future-status" }] },
      },
    ];
    apiMock.auditWindow.mockResolvedValue({ events });
    renderAudit();

    expect(await screen.findByText("Recorded; no success result in this event")).toBeInTheDocument();
    expect(screen.queryByText(/revoked · .* failed/)).not.toBeInTheDocument();
  });
});
