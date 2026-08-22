import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { Integrate } from "@/pages/Integrate";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    profiles: vi.fn(),
    discoverySources: vi.fn(),
    notificationRoutingPolicies: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

describe("U8-5 integrate hub", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    for (const mock of Object.values(apiMock)) mock.mockReset();
    apiMock.profiles.mockResolvedValue([]);
    apiMock.discoverySources.mockResolvedValue({ items: [] });
    apiMock.notificationRoutingPolicies.mockResolvedValue({ items: [] });
  });

  it("lists enrollment protocols, SDKs, and IaC artifacts with copyable references", async () => {
    const user = userEvent.setup();
    render(
      <MemoryRouter>
        <Integrate />
      </MemoryRouter>,
    );
    expect(screen.getByRole("heading", { name: "Connect other tools" })).toBeInTheDocument();
    expect(screen.queryByText("ACME")).not.toBeInTheDocument();
    await user.click(screen.getByText("Enrollment, SDKs, and infrastructure code", { exact: true }));
    expect(screen.getByText("ACME")).toBeInTheDocument();
    expect(screen.getByText("EST")).toBeInTheDocument();
    expect(screen.getByText("SCEP")).toBeInTheDocument();
    expect(screen.getByText("Python SDK")).toBeInTheDocument();
    expect(screen.getByText("Terraform provider")).toBeInTheDocument();
    expect(screen.getByText("SPIRE upstream authority")).toBeInTheDocument();
    // copyable references
    expect(screen.getAllByRole("button", { name: /^Copy / }).length).toBeGreaterThan(5);
    expect(apiMock.profiles).not.toHaveBeenCalled();
  });
});
