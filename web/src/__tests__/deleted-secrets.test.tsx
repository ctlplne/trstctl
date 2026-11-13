import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { DeletedSecrets } from "@/pages/secrets/DeletedSecrets";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    listDeletedSecrets: vi.fn(),
    restoreDeletedSecret: vi.fn(),
    purgeDeletedSecret: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

const kept = {
  name: "orders/prod/db/password",
  version: 2,
  versions: 2,
  created_at: "2026-11-01T00:00:00Z",
  deleted_at: "2026-11-13T08:00:00Z",
  purge_after: "2026-12-13T08:00:00Z",
};

function renderPanel(onRestored = vi.fn()) {
  render(
    <MemoryRouter>
      <DeletedSecrets refreshKey={0} onRestored={onRestored} />
    </MemoryRouter>,
  );
  return onRestored;
}

// A236-L4: deleted secrets are listed without values, restored at the version
// they had (one request per secret, kept across an approval), or purged after
// a confirmation.
describe("A236-L4 deleted secrets", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("lists a deleted secret and restores it at the version it had", async () => {
    apiMock.listDeletedSecrets.mockResolvedValueOnce({ items: [kept] }).mockResolvedValueOnce({ items: [] });
    apiMock.restoreDeletedSecret.mockResolvedValue({ name: kept.name, version: 2, created_at: kept.created_at, updated_at: "2026-11-13T09:00:00Z" });
    const user = userEvent.setup();
    const onRestored = renderPanel();
    const list = await screen.findByRole("list", { name: "Deleted secrets kept for restore" });
    expect(within(list).getByText(kept.name)).toBeInTheDocument();
    expect(within(list).getByText(/Version 2, 2 versions kept; deleted .+; purged after .+\./)).toBeInTheDocument();
    await user.click(within(list).getByRole("button", { name: "Restore" }));
    expect(apiMock.restoreDeletedSecret).toHaveBeenCalledWith(kept.name, expect.any(String));
    expect(await screen.findByText(`${kept.name} is back at version 2, with its history.`)).toBeInTheDocument();
    expect(onRestored).toHaveBeenCalled();
    expect(await screen.findByText("No deleted secrets are kept.")).toBeInTheDocument();
  });

  it("names the approval a restore waits for and replays the same request", async () => {
    apiMock.listDeletedSecrets.mockResolvedValue({ items: [kept] });
    apiMock.restoreDeletedSecret.mockRejectedValueOnce(
      new Error(
        `dual control: approval_required:secret:${kept.name} request_id=11111111-2222-4333-8444-555555555555 intent_digest=sha256:` +
          "a".repeat(64) +
          ": this exact secret change awaits distinct approval",
      ),
    );
    apiMock.restoreDeletedSecret.mockResolvedValueOnce({ name: kept.name, version: 2, created_at: kept.created_at, updated_at: kept.deleted_at });
    const user = userEvent.setup();
    renderPanel();
    const list = await screen.findByRole("list", { name: "Deleted secrets kept for restore" });
    await user.click(within(list).getByRole("button", { name: "Restore" }));
    const notice = await screen.findByText(/waits for its approvers: request 11111111-2222-4333-8444-555555555555/);
    expect(within(notice).getByRole("link", { name: "Open Approvals" })).toHaveAttribute("href", "/approvals");
    await user.click(within(list).getByRole("button", { name: "Restore" }));
    const [first, second] = apiMock.restoreDeletedSecret.mock.calls;
    expect(second[1]).toBe(first[1]);
    expect(await screen.findByText(`${kept.name} is back at version 2, with its history.`)).toBeInTheDocument();
    expect(screen.queryByText(/waits for its approvers/)).not.toBeInTheDocument();
  });

  it("purges a deleted secret only after a confirmation", async () => {
    apiMock.listDeletedSecrets.mockResolvedValueOnce({ items: [kept] }).mockResolvedValueOnce({ items: [] });
    apiMock.purgeDeletedSecret.mockResolvedValue(undefined);
    const user = userEvent.setup();
    renderPanel();
    const list = await screen.findByRole("list", { name: "Deleted secrets kept for restore" });
    await user.click(within(list).getByRole("button", { name: "Purge" }));
    expect(apiMock.purgeDeletedSecret).not.toHaveBeenCalled();
    await user.click(within(list).getByRole("button", { name: `Purge ${kept.name} for good` }));
    expect(apiMock.purgeDeletedSecret).toHaveBeenCalledWith(kept.name, expect.any(String));
    expect(await screen.findByText(`${kept.name} and its history are purged.`)).toBeInTheDocument();
  });
});
