import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { ThemeProvider } from "@/components/ThemeProvider";
import { AuthProvider } from "@/auth/AuthProvider";
import { AppRoutes } from "@/App";
import {
  featureCoverageDomains,
  featureCoverageItems,
  featureCoverageTotals,
  featureMaturityLabels,
} from "@/lib/featureCoverage";

const { apiMock } = vi.hoisted(() => ({
  apiMock: { me: vi.fn() },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, me: apiMock.me } };
});

function renderAt(path: string) {
  return render(
    <ThemeProvider>
      <AuthProvider>
        <MemoryRouter initialEntries={[path]}>
          <AppRoutes />
        </MemoryRouter>
      </AuthProvider>
    </ThemeProvider>,
  );
}

describe("feature coverage roadmap surface", () => {
  beforeEach(() => {
    apiMock.me.mockReset();
    apiMock.me.mockResolvedValue({ subject: "user-1", tenant_id: "t1", email: "u@example.test" });
  });

  it("renders every documented feature-map backlog item and every domain", async () => {
    renderAt("/coverage");

    expect(await screen.findByRole("heading", { name: "Backend-to-GUI coverage" })).toBeInTheDocument();
    const primaryNav = screen.getByRole("navigation", { name: /Primary/i });
    expect(within(primaryNav).getByRole("link", { name: /Coverage roadmap.*Observe/i })).toHaveAttribute("href", "/coverage");
    expect(screen.getByRole("searchbox", { name: "Search feature coverage" })).toBeInTheDocument();
    expect(
      screen.getByRole("table", { name: /Feature coverage map with backend status, GUI mapping, and acceptance criteria/i }),
    ).toBeInTheDocument();
    expect(screen.getAllByText("Served state:").length).toBeGreaterThan(0);
    expect(screen.getAllByText("API:").length).toBeGreaterThan(0);
    expect(screen.getAllByText("CLI:").length).toBeGreaterThan(0);
    expect(screen.getAllByText(/operations?:/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/commands?:/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/N\/A:/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(featureMaturityLabels.library).length).toBeGreaterThan(0);
    expect(screen.getAllByText(`${featureCoverageTotals.features}`).length).toBeGreaterThanOrEqual(1);

    expect(await screen.findAllByTestId("feature-row")).toHaveLength(featureCoverageItems.length);
    expect(featureCoverageItems).toHaveLength(78);
    expect(featureCoverageDomains).toHaveLength(16);

    const domains = within(screen.getByTestId("coverage-domains"));
    for (const domain of featureCoverageDomains) {
      expect(domains.getByRole("button", { name: new RegExp(domain.name) })).toBeInTheDocument();
    }
  });

  it("makes non-certificate gaps visible as disclosures instead of silent omissions", async () => {
    const user = userEvent.setup();
    renderAt("/coverage");

    await screen.findByRole("heading", { name: "Backend-to-GUI coverage" });
    await user.click(screen.getByRole("button", { name: "Disclose" }));

    expect(screen.getAllByTestId("feature-row")).toHaveLength(featureCoverageTotals.disclose);
    expect(screen.getByText("Secret sync / platform integrations")).toBeInTheDocument();
    expect(screen.getByText("Agentless cloud certificate discovery")).toBeInTheDocument();
    expect(screen.getByText("Plugin SDK with capability sandboxing")).toBeInTheDocument();
  });

  it("supports focused feature search by feature ID and keeps target mapping visible", async () => {
    const user = userEvent.setup();
    renderAt("/coverage");

    await screen.findByRole("heading", { name: "Backend-to-GUI coverage" });
    await user.type(screen.getByPlaceholderText(/Search by ID/i), "F63");

    expect(screen.getAllByTestId("feature-row")).toHaveLength(1);
    expect(screen.getByText("Native secret store")).toBeInTheDocument();
    expect(screen.getByText(/reveal requires explicit user action/i)).toBeInTheDocument();
  });
});
