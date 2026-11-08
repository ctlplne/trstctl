import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import { AppQueryProvider } from "@/lib/query";
import { IntlProvider } from "@/i18n/I18nProvider";
import { PAMGatewayPoolsPanel, parseMembers } from "@/pages/PAMGatewayPoolsPanel";

// A278: gateway pools share sessions. The panel shows each gateway's
// health and live sessions, drains and resumes a gateway at the pool's
// revision, creates and edits pools from one gateway per line, and deletes
// a pool at its revision.

const { apiMock } = vi.hoisted(() => ({
  apiMock: { pamGatewayPools: vi.fn(), savePAMGatewayPool: vi.fn(), deletePAMGatewayPool: vi.fn() },
}));
vi.mock("@/lib/api", async (original) => {
  const actual = await original<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

const one = "a2780000-0000-4000-8000-000000000001";
const two = "a2780000-0000-4000-8000-000000000002";
const three = "a2780000-0000-4000-8000-000000000003";
const pool = {
  name: "site-a",
  revision: 3,
  saved_at: "2026-11-08T01:00:00Z",
  members: [
    { agent_id: one, address: "gw1.example:8443", health: "healthy", last_seen_at: "2026-11-08T01:10:00Z", live_sessions: 2 },
    { agent_id: two, address: "gw2.example:8443", health: "lost", last_seen_at: "2026-11-08T01:02:00Z", live_sessions: 0 },
    { agent_id: three, address: "gw3.example:8443", draining: true, health: "draining", last_seen_at: "2026-11-08T01:10:00Z", live_sessions: 1 },
  ],
};

beforeEach(() => {
  for (const mock of Object.values(apiMock)) mock.mockReset();
  apiMock.pamGatewayPools.mockResolvedValue({ items: [pool] });
  apiMock.savePAMGatewayPool.mockResolvedValue(pool);
  apiMock.deletePAMGatewayPool.mockResolvedValue({ name: "site-a", deleted: true });
});

function mount(canManage = true) {
  return render(
    <AppQueryProvider>
      <IntlProvider initialLocale="en-US" initialTimeZone="UTC">
        <PAMGatewayPoolsPanel canManage={canManage} />
      </IntlProvider>
    </AppQueryProvider>,
  );
}

describe("gateway pools", () => {
  it("shows each gateway's health and drains or resumes it at the pool's revision", async () => {
    const user = userEvent.setup();
    const view = mount();
    const table = await screen.findByRole("table", { name: "Gateways of pool site-a" });
    const rows = within(table).getAllByRole("row").slice(1);
    expect(rows.map((r) => within(r).getAllByRole("cell")[2].textContent)).toEqual(["Healthy", "Lost", "Draining"]);
    expect(rows.map((r) => within(r).getAllByRole("cell")[4].textContent)).toEqual(["2", "0", "1"]);
    expect(await axe(view.container)).toHaveNoViolations();
    await user.click(screen.getByRole("button", { name: `Drain gateway ${one}` }));
    await waitFor(() =>
      expect(apiMock.savePAMGatewayPool).toHaveBeenCalledWith(
        "site-a",
        {
          revision: 3,
          members: [
            { agent_id: one, address: "gw1.example:8443", draining: true },
            { agent_id: two, address: "gw2.example:8443" },
            { agent_id: three, address: "gw3.example:8443", draining: true },
          ],
        },
        expect.any(String),
      ),
    );
    expect(await screen.findByText(`Gateway ${one} is draining: it takes no new sessions.`)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: `Resume gateway ${three}` }));
    await waitFor(() =>
      expect(apiMock.savePAMGatewayPool).toHaveBeenLastCalledWith(
        "site-a",
        {
          revision: 3,
          members: [
            { agent_id: one, address: "gw1.example:8443" },
            { agent_id: two, address: "gw2.example:8443" },
            { agent_id: three, address: "gw3.example:8443" },
          ],
        },
        expect.any(String),
      ),
    );
  });

  it("creates a pool from one gateway per line and refuses a malformed line", async () => {
    const user = userEvent.setup();
    apiMock.pamGatewayPools.mockResolvedValue({ items: [] });
    mount();
    expect(await screen.findByText("No gateway pools: each gateway serves only its own targets.")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "New pool" }));
    const form = screen.getByRole("form", { name: "Gateway pool" });
    await user.type(within(form).getByLabelText("Pool name"), "site-b");
    await user.type(within(form).getByLabelText("Gateways"), `${one}`);
    await user.click(within(form).getByRole("button", { name: "Save pool" }));
    expect(await screen.findByText("List one gateway per line as an agent ID and a host:port.")).toBeInTheDocument();
    expect(apiMock.savePAMGatewayPool).not.toHaveBeenCalled();
    await user.clear(within(form).getByLabelText("Gateways"));
    await user.type(within(form).getByLabelText("Gateways"), `${one} gw1.example:8443{Enter}${two} gw2.example:8443`);
    await user.click(within(form).getByRole("button", { name: "Save pool" }));
    await waitFor(() =>
      expect(apiMock.savePAMGatewayPool).toHaveBeenCalledWith(
        "site-b",
        {
          members: [
            { agent_id: one, address: "gw1.example:8443" },
            { agent_id: two, address: "gw2.example:8443" },
          ],
        },
        expect.any(String),
      ),
    );
  });

  it("edits a pool keeping its draining gateways, deletes at its revision, and is read-only without the permission", async () => {
    const user = userEvent.setup();
    const view = mount();
    await user.click(await screen.findByRole("button", { name: "Edit pool site-a" }));
    const form = screen.getByRole("form", { name: "Gateway pool" });
    expect(within(form).getByLabelText("Pool name")).toHaveAttribute("readonly");
    await user.click(within(form).getByRole("button", { name: "Save pool" }));
    await waitFor(() =>
      expect(apiMock.savePAMGatewayPool).toHaveBeenCalledWith(
        "site-a",
        expect.objectContaining({ revision: 3, members: expect.arrayContaining([{ agent_id: three, address: "gw3.example:8443", draining: true }]) }),
        expect.any(String),
      ),
    );
    await user.click(screen.getByRole("button", { name: "Delete pool site-a" }));
    await waitFor(() => expect(apiMock.deletePAMGatewayPool).toHaveBeenCalledWith("site-a", 3, expect.any(String)));
    view.unmount();
    mount(false);
    await screen.findByRole("table", { name: "Gateways of pool site-a" });
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
  });
});

describe("parseMembers", () => {
  it("reads one gateway per line and keeps a gateway's draining", () => {
    expect(parseMembers(` ${one}  a:1 \n\n${two} b:2`, [{ agent_id: two, address: "b:2", draining: true, live_sessions: 0 }])).toEqual([
      { agent_id: one, address: "a:1" },
      { agent_id: two, address: "b:2", draining: true },
    ]);
    expect(parseMembers("")).toBeNull();
    expect(parseMembers(`${one} a:1 extra`)).toBeNull();
  });
});
