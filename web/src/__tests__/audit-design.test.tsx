import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { AppQueryProvider } from "@/lib/query";
import { Audit } from "@/pages/Audit";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    auditEvents: vi.fn(),
    auditFeeds: vi.fn(),
    exportAudit: vi.fn(),
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
    apiMock.auditEvents.mockResolvedValue([
      {
        id: "evt-7",
        sequence: 7,
        tenant_id: "tenant-1",
        type: "identity.issued",
        time: "2026-08-21T19:20:00Z",
        hash: "sha256:change-seven",
        actor: { email: "ra@example.test" },
        data: { resource_id: "payments-api", result: "succeeded" },
      },
    ]);
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
        "This is a 1-event window, not a claim about the newest or complete history. Search or export an exact window before making an audit decision.",
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

    await user.click(screen.getByText("Signatures and evidence export", { exact: true }));
    expect(await screen.findByRole("heading", { name: "Hash-chain status" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Export evidence" })).toBeInTheDocument();

    await user.click(screen.getByText("Collector delivery", { exact: true }));
    await waitFor(() => expect(apiMock.auditFeeds).toHaveBeenCalledTimes(1));
    expect(await screen.findByRole("heading", { name: "Scheduled collector feeds" })).toBeInTheDocument();
    expect(screen.getByRole("form", { name: "Configure a collector feed" })).toBeInTheDocument();
  });

  it("says when the recent window is empty without inventing product activity", async () => {
    apiMock.auditEvents.mockResolvedValue([]);
    renderAudit();

    expect(await screen.findByRole("heading", { level: 2, name: "No changes found in this window" })).toBeInTheDocument();
    expect(
      screen.getByText("Nothing is recorded in this 50-event window. Search a different time or event type before concluding that no change happened.", {
        exact: true,
      }),
    ).toBeInTheDocument();
    expect(screen.queryByText("Identity issued")).not.toBeInTheDocument();
  });
});
