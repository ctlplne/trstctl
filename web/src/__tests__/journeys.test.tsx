import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import { MemoryRouter } from "react-router-dom";
import { appRoutePaths } from "@/lib/navigation";
import { journeyDocUrl, journeys } from "@/lib/journeys";
import { journeyCensus } from "@/lib/journeyCensus.gen";
import { messages } from "@/i18n/messages";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    issuers: vi.fn(),
    identities: vi.fn(),
    certificatePage: vi.fn(),
    discoverySources: vi.fn(),
    discoveryRuns: vi.fn(),
    discoveryFindings: vi.fn(),
    profiles: vi.fn(),
    incidentExecutions: vi.fn(),
    agents: vi.fn(),
    secretPage: vi.fn(),
    members: vi.fn(),
    auditEvents: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

import { Journeys } from "@/pages/Journeys";

/** The workspace tabs each recomposed page actually registers. A journey deep
 * link with an unknown ?tab silently lands on the default tab, which breaks
 * the "one click to the right place" promise — so the map is pinned here. */
const workspaceTabs: Record<string, string[]> = {
  "/certificates": ["inventory", "health", "crlct", "renewal"],
  "/secrets": ["store", "access", "sharing", "engines", "scanning", "sync"],
  "/discovery": ["findings", "sources", "schedules", "runs"],
};

function basePath(to: string): string {
  return to.split("?")[0] || "/";
}

describe("journey definitions stay wired end to end", () => {
  it("keeps every journey id a doc slug and every step key in the catalog", () => {
    const ids = journeys.map((journey) => journey.id);
    expect(new Set(ids).size).toBe(ids.length);
    expect([...ids].sort()).toEqual(Object.keys(journeyCensus.journeys).sort());
    for (const journey of journeys) {
      expect(journey.id).toMatch(/^[a-z0-9-]+$/);
      expect(journeyDocUrl(journey)).toBe(`https://docs.trstctl.com/journeys/${journey.id}/`);
      expect(messages[journey.titleKey], `missing ${journey.titleKey}`).toBeDefined();
      expect(messages[journey.descriptionKey], `missing ${journey.descriptionKey}`).toBeDefined();
      const census = journeyCensus.journeys[journey.id];
      expect(census.status).toBe("served");
      for (const row of census.census_rows) {
        expect(row.status, `${journey.id}/${row.id} is not served`).toBe("served");
        expect(row.enforcement, `${journey.id}/${row.id} is not required`).toBe("required");
      }
      for (const step of journey.steps) {
        expect(messages[step.titleKey], `missing ${step.titleKey}`).toBeDefined();
        expect(messages[step.bodyKey], `missing ${step.bodyKey}`).toBeDefined();
        // Every step guides somewhere: a console page, a command, or both.
        expect(Boolean(step.to || step.command), `${journey.id}/${step.id} has neither a link nor a command`).toBe(true);
      }
    }
  });

  it("deep-links every console step to a registered route and a real workspace tab", () => {
    const registered = new Set<string>(appRoutePaths);
    for (const journey of journeys) {
      for (const step of journey.steps) {
        if (!step.to) continue;
        const path = basePath(step.to);
        expect(registered.has(path), `${journey.id}/${step.id} links to unregistered ${path}`).toBe(true);
        const tab = new URLSearchParams(step.to.split("?")[1] ?? "").get("tab");
        if (tab) {
          expect(workspaceTabs[path], `${journey.id}/${step.id} uses ?tab on a page without workspace tabs`).toBeDefined();
          expect(workspaceTabs[path], `${journey.id}/${step.id} links to unknown tab ${tab}`).toContain(tab);
        }
      }
    }
  });
});

describe("journeys hub", () => {
  beforeEach(() => {
    localStorage.clear();
    for (const mock of Object.values(apiMock)) mock.mockReset();
    apiMock.issuers.mockResolvedValue([{ id: "iss-1", name: "Internal CA" }]);
    apiMock.identities.mockResolvedValue([]);
    apiMock.certificatePage.mockResolvedValue({ items: [] });
    apiMock.discoverySources.mockResolvedValue({ items: [] });
    apiMock.discoveryRuns.mockResolvedValue({ items: [] });
    apiMock.discoveryFindings.mockResolvedValue({ items: [] });
    apiMock.profiles.mockResolvedValue([]);
    apiMock.incidentExecutions.mockResolvedValue({ items: [] });
    apiMock.agents.mockResolvedValue([]);
    apiMock.secretPage.mockResolvedValue({ items: [] });
    apiMock.members.mockResolvedValue({ items: [] });
    apiMock.auditEvents.mockResolvedValue([]);
  });

  function renderJourneys() {
    return render(
      <MemoryRouter initialEntries={["/journeys"]}>
        <Journeys />
      </MemoryRouter>,
    );
  }

  it("counts every step, detects served progress, and lets manual steps be marked done", async () => {
    const user = userEvent.setup();
    const { container } = renderJourneys();

    expect(await screen.findByRole("heading", { name: "Journeys" })).toBeInTheDocument();

    // The label is generated from wiring-census.json, not hand-authored page
    // copy. Every card has the same current shipped-binary proof boundary.
    expect(screen.getAllByText("Verified path · shipped wiring 81/81")).toHaveLength(journeys.length);
    expect(screen.getByRole("button", { name: /First certificate/ }).querySelector('[data-journey-census="first-certificate"]')).toBeInTheDocument();

    // Detector-backed progress: the issuer exists, so first-certificate shows 1 of 4.
    const firstCert = screen.getByRole("button", { name: /First certificate/ });
    expect(await within(firstCert).findByText("1 of 4 steps done")).toBeInTheDocument();

    // Command-heavy journeys count all steps too (no more "0 of 0").
    const fleet = screen.getByRole("button", { name: /Automate fleet TLS/ });
    expect(within(fleet).getByText("0 of 4 steps done")).toBeInTheDocument();

    await user.click(fleet);
    expect(screen.getByRole("heading", { name: "Inspect the ACME surface" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Take me there/ })).toHaveAttribute("href", "/protocols");

    // Walk to the certbot command step: copy-ready command, no console link.
    await user.click(screen.getByRole("button", { name: "Next" }));
    await user.click(screen.getByRole("button", { name: "Next" }));
    expect(screen.getByRole("heading", { name: "Point an ACME client at the directory" })).toBeInTheDocument();
    expect(screen.getByText(/certbot certonly/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Copy command/ })).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /Take me there/ })).not.toBeInTheDocument();

    // Manual completion updates the card's progress and persists locally.
    await user.click(screen.getByRole("button", { name: "Mark step done" }));
    expect(within(screen.getByRole("button", { name: /Automate fleet TLS/ })).getByText("1 of 4 steps done")).toBeInTheDocument();
    expect(localStorage.getItem("trstctl-journey-progress")).toContain("automate-fleet-tls:certbot");

    // Every journey links to its published walkthrough on the docs site.
    const docLink = screen.getByRole("link", { name: "https://docs.trstctl.com/journeys/automate-fleet-tls/" });
    expect(docLink).toHaveAttribute("href", "https://docs.trstctl.com/journeys/automate-fleet-tls/");
    expect(docLink).toHaveAttribute("target", "_blank");

    expect(await axe(container)).toHaveNoViolations();
  });
});
