import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { Integrate } from "@/pages/Integrate";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    profiles: vi.fn(),
    discoverySources: vi.fn(),
    notificationRoutingPolicies: vi.fn(),
    policyDryRun: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (original) => {
  const actual = await original<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

function renderIntegrate() {
  return render(
    <MemoryRouter initialEntries={["/integrate"]}>
      <main>
        <Integrate />
      </main>
    </MemoryRouter>,
  );
}

describe("Route 037 Connect other tools hierarchy", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    for (const mock of Object.values(apiMock)) mock.mockReset();
    apiMock.profiles.mockResolvedValue([]);
    apiMock.discoverySources.mockResolvedValue({ items: [] });
    apiMock.notificationRoutingPolicies.mockResolvedValue({ items: [] });
  });

  it("answers what connects before exposing developer controls", async () => {
    const user = userEvent.setup();
    renderIntegrate();

    expect(await screen.findByRole("heading", { level: 1, name: "Connect other tools" })).toBeInTheDocument();
    expect(screen.getByText("Which external systems can send or receive trstctl data.", { exact: true })).toBeInTheDocument();
    expect(screen.getByText("Scopes, webhooks, plugin capabilities, outbox delivery.", { exact: true })).toBeInTheDocument();
    expect(screen.getByRole("heading", { level: 2, name: "How information moves" })).toBeInTheDocument();
    expect(screen.getByText("Systems send to trstctl", { exact: true })).toBeInTheDocument();
    expect(screen.getByText("trstctl sends to systems", { exact: true })).toBeInTheDocument();
    expect(screen.getByText("Automation keeps it repeatable", { exact: true })).toBeInTheDocument();

    const actions = screen.getByTestId("page-depth-operate");
    expect(within(actions).getAllByRole("button")).toHaveLength(1);
    await user.click(within(actions).getByRole("button", { name: "Add integration" }));

    const dialog = screen.getByRole("dialog", { name: "Add integration" });
    expect(within(dialog).getByRole("link", { name: /Send credentials to a destination/i })).toHaveAttribute("href", "/connectors");
    expect(within(dialog).getByRole("link", { name: /Send alerts and events/i })).toHaveAttribute("href", "/notifications");
    expect(within(dialog).getByRole("link", { name: /Sync secrets to another platform/i })).toHaveAttribute("href", "/secrets/sync");
    expect(within(dialog).getByRole("link", { name: /Connect a certificate authority/i })).toHaveAttribute("href", "/ca-hierarchy");
    expect(within(dialog).getByRole("link", { name: /Build an API integration/i })).toHaveAttribute("href", "/integrate/api");
  });

  it("loads and renders exact developer evidence only after its disclosure opens", async () => {
    const user = userEvent.setup();
    renderIntegrate();
    await screen.findByRole("heading", { level: 1, name: "Connect other tools" });

    expect(document.querySelectorAll("main input, main select, main textarea, main table")).toHaveLength(0);
    expect(apiMock.profiles).not.toHaveBeenCalled();
    expect(apiMock.discoverySources).not.toHaveBeenCalled();
    expect(apiMock.notificationRoutingPolicies).not.toHaveBeenCalled();

    await user.click(screen.getByText("Enrollment, SDKs, and infrastructure code", { exact: true }));
    expect(screen.getByText("ACME", { exact: true })).toBeInTheDocument();
    expect(screen.getByText("Python SDK", { exact: true })).toBeInTheDocument();
    expect(screen.getByText("Terraform provider", { exact: true })).toBeInTheDocument();
    expect(apiMock.profiles).not.toHaveBeenCalled();

    await user.click(screen.getByText("GitOps declarations and drift", { exact: true }));
    await waitFor(() => expect(apiMock.profiles).toHaveBeenCalledTimes(1));
    expect(apiMock.discoverySources).toHaveBeenCalledWith({ limit: 50 });
    expect(apiMock.notificationRoutingPolicies).toHaveBeenCalledTimes(1);
    expect(await screen.findByRole("table", { name: "GitOps drift comparison" })).toBeInTheDocument();
    expect(screen.getByRole("region", { name: "GitOps drift comparison scroll area" })).toHaveAttribute("tabindex", "0");

    await user.click(screen.getByText("Permissions and reliable delivery", { exact: true }));
    expect(screen.getByText("A scope is a permission boundary", { exact: true })).toBeInTheDocument();
    expect(screen.getByText("Webhooks", { exact: true })).toBeInTheDocument();
    expect(screen.getByText("Plugin capabilities", { exact: true })).toBeInTheDocument();
    expect(screen.getByText("Outbox delivery", { exact: true })).toBeInTheDocument();
  });
});
