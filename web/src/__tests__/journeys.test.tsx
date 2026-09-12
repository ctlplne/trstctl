import { beforeEach, describe, expect, it, vi } from "vitest";
import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import { MemoryRouter } from "react-router-dom";
import type { CapabilityView, CapabilityViewItem } from "@/lib/api-types.gen";
import { CapabilityFixtureProvider } from "@/lib/capabilities";
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

vi.mock("@/lib/bootstrapApi", async (orig) => {
  const actual = await orig<typeof import("@/lib/bootstrapApi")>();
  return { ...actual, bootstrapApi: { ...actual.bootstrapApi, ...apiMock } };
});

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

const unavailableIncidentDetail = "This operation is not mounted because its runtime dependency is not configured.";

function capabilityItem(
  capabilityId: CapabilityViewItem["capability_id"],
  allowed: string[],
  unavailable: CapabilityViewItem["actions"]["unavailable"] = [],
): CapabilityViewItem {
  return {
    capability_id: capabilityId,
    name: `Fixture ${capabilityId}`,
    purpose: "Verify journey progress from served tenant state.",
    tool: "operations",
    classification: "primary",
    console_route: "/journeys",
    maturity: "partial_workflow",
    release_blocking: true,
    edition: "core",
    runtime_state: allowed.length > 0 ? (unavailable.length > 0 ? "partially_available" : "available") : "unavailable",
    authorization_state: allowed.length > 0 ? (unavailable.length > 0 ? "partial" : "full") : "none",
    dependency_state: "none",
    dependencies: [],
    stages: [{ name: "observe", completion: "complete" }],
    actions: { allowed, scoped: [], denied: [], unavailable },
  };
}

const journeyRuntime: CapabilityView = {
  schema_version: 2,
  contract_schema_version: 3,
  license: { tier: "community", state: "community" },
  enforcement_note: "The server checks every operation again when it executes.",
  operations: [],
  items: [
    capabilityItem("F4", ["listIssuers"]),
    capabilityItem("F59", ["listIdentities"]),
    capabilityItem("F1", ["listCertificates"]),
    capabilityItem("F2", ["listDiscoverySources", "listDiscoveryRuns", "listDiscoveryFindings"]),
    capabilityItem("F53", ["listProfiles"]),
    capabilityItem("F31", [], [{ operation_id: "listIncidentExecutions", code: "dependency_not_configured", detail: unavailableIncidentDetail }]),
    capabilityItem("F3", ["listAgents"]),
    capabilityItem("F63", ["listSecrets"]),
    capabilityItem("F8", ["listMembers"]),
    capabilityItem("F9", ["searchAudit"]),
  ],
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

  function renderJourneysWithRuntime(initialEntry = "/journeys") {
    return render(
      <CapabilityFixtureProvider view={journeyRuntime}>
        <MemoryRouter initialEntries={[initialEntry]}>
          <Journeys />
        </MemoryRouter>
      </CapabilityFixtureProvider>,
    );
  }

  it("refreshes evidence without resetting the operator's selected step", async () => {
    const user = userEvent.setup();
    renderJourneysWithRuntime("/journeys?j=automate-fleet-tls");
    await waitFor(() => expect(screen.getByRole("button", { name: "Refresh status" })).toBeEnabled());
    for (let i = 0; i < 6; i++) await user.click(screen.getByRole("button", { name: "Next" }));
    expect(screen.getByRole("heading", { name: "Revoke and retire" })).toBeInTheDocument();
    apiMock.certificatePage.mockResolvedValue({ items: [{ id: "new-certificate" }] });
    await user.click(screen.getByRole("button", { name: "Refresh status" }));
    await waitFor(() => expect(screen.getByRole("button", { name: "Refresh status" })).toBeEnabled());
    expect(screen.getByRole("heading", { name: "Revoke and retire" })).toBeInTheDocument();
    expect(within(screen.getByRole("button", { name: /First certificate/ })).getByText("3 of 4 steps done")).toBeInTheDocument();
    expect(within(screen.getByRole("button", { name: /Automate fleet TLS/ })).getByText("0 of 7 steps done")).toBeInTheDocument();
    // Switching journeys still starts at the first incomplete step, including
    // when returning to a journey that was navigated earlier.
    await user.click(screen.getByRole("button", { name: /First certificate/ }));
    expect(screen.getByRole("link", { name: /Take me there/ })).toHaveAttribute("href", "/request");
    await user.click(screen.getByRole("button", { name: /Automate fleet TLS/ }));
    expect(screen.getByRole("heading", { name: "Inspect the ACME surface" })).toBeInTheDocument();
  });

  it("keeps navigation made before the initial status response arrives", async () => {
    const user = userEvent.setup();
    let resolveCertificates!: (page: { items: { id: string }[] }) => void;
    apiMock.certificatePage.mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          resolveCertificates = resolve;
        }),
    );
    renderJourneysWithRuntime("/journeys?j=automate-fleet-tls");
    await screen.findByRole("heading", { name: "Inspect the ACME surface" });
    await user.click(screen.getByRole("button", { name: "Next" }));
    await act(async () => {
      resolveCertificates({ items: [{ id: "late-certificate" }] });
    });
    await waitFor(() => expect(screen.getByRole("button", { name: "Refresh status" })).toBeEnabled());
    expect(screen.getByRole("heading", { name: "Configure the DNS authenticator" })).toBeInTheDocument();
  });

  it("keeps a manually marked current step open during status refresh", async () => {
    const user = userEvent.setup();
    renderJourneysWithRuntime("/journeys?j=automate-fleet-tls");
    await waitFor(() => expect(screen.getByRole("button", { name: "Refresh status" })).toBeEnabled());
    await user.click(screen.getByRole("button", { name: "Mark step done" }));
    await user.click(screen.getByRole("button", { name: "Refresh status" }));
    await waitFor(() => expect(screen.getByRole("button", { name: "Refresh status" })).toBeEnabled());
    expect(screen.getByRole("heading", { name: "Inspect the ACME surface" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Mark as not done" })).toBeInTheDocument();
  });

  it("counts every step, detects served progress, and lets manual steps be marked done", async () => {
    const user = userEvent.setup();
    const { container } = renderJourneys();

    expect(await screen.findByRole("heading", { name: "Guided setup" })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Previous" }));
    expect(screen.getByRole("heading", { name: "Complete the first-use guide" })).toBeInTheDocument();
    expect(screen.getAllByText(/an agent only when needed/i).length).toBeGreaterThan(0);
    await user.click(screen.getByRole("button", { name: "Next" }));

    // Engineering proof stays reachable once, without repeating a bright
    // shipped-wiring badge on all twelve outcome choices.
    expect(screen.getAllByText("Verified path · shipped wiring 81/81")).toHaveLength(1);
    const proof = screen.getByText("How we tested this").closest("details");
    expect(proof).not.toHaveAttribute("open");
    expect(proof).toHaveTextContent("Verified path · shipped wiring 81/81");
    expect(screen.getByRole("button", { name: /First certificate/ }).querySelector("[data-journey-census]")).not.toBeInTheDocument();

    // An issuer row alone is not proof that the wizard issued anything. The
    // first-use path stays open until a real certificate appears.
    const firstCert = screen.getByRole("button", { name: /First certificate/ });
    expect(await within(firstCert).findByText("0 of 4 steps done")).toBeInTheDocument();
    expect(screen.getByText("Start here")).toBeInTheDocument();
    const morePaths = screen.getByText(`More guided paths (${journeys.length - 3})`).closest("details");
    expect(morePaths).not.toHaveAttribute("open");
    expect(morePaths).toContainElement(screen.getByRole("button", { name: /Automate fleet TLS/ }));
    expect(firstCert.querySelector(".line-clamp-2")).not.toBeInTheDocument();
    expect(screen.getByTestId("compact-step-progress").querySelector(".truncate")).not.toBeInTheDocument();
    expect(screen.getByTestId("full-step-progress").querySelector(".truncate")).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Continue journey" }));
    expect(document.activeElement).toHaveAttribute("id", "journey-workspace");

    // Command-heavy journeys count all steps too (no more "0 of 0").
    await user.click(screen.getByText(`More guided paths (${journeys.length - 3})`));
    expect(morePaths).toHaveAttribute("open");
    const fleet = screen.getByRole("button", { name: /Automate fleet TLS/ });
    expect(within(fleet).getByText("0 of 7 steps done")).toBeInTheDocument();

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
    expect(within(screen.getByRole("button", { name: /Automate fleet TLS/ })).getByText("1 of 7 steps done")).toBeInTheDocument();
    expect(localStorage.getItem("trstctl-journey-progress")).toContain("automate-fleet-tls:certbot");

    await user.click(screen.getByRole("button", { name: "Next" }));
    expect(screen.getByRole("heading", { name: "Install the client certificate" })).toBeInTheDocument();
    expect(screen.getByText(/sudo nginx -t/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Next" }));
    expect(screen.getByRole("heading", { name: "Verify the actual endpoint" })).toBeInTheDocument();
    expect(screen.getByText(/openssl s_client/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Next" }));
    expect(screen.getByRole("heading", { name: "Schedule and observe renewal" })).toBeInTheDocument();
    expect(screen.getByText(/certbot renew --cert-name/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Next" }));
    expect(screen.getByRole("heading", { name: "Revoke and retire" })).toBeInTheDocument();
    expect(screen.getByText(/--reason cessationofoperation/)).toBeInTheDocument();
    expect(within(screen.getByRole("button", { name: /Automate fleet TLS/ })).getByText("1 of 7 steps done")).toBeInTheDocument();

    // Every journey links to its published walkthrough on the docs site.
    const docLink = screen.getByRole("link", { name: "https://docs.trstctl.com/journeys/automate-fleet-tls/" });
    expect(docLink).toHaveAttribute("href", "https://docs.trstctl.com/journeys/automate-fleet-tls/");
    expect(docLink).toHaveAttribute("target", "_blank");

    expect(await axe(container)).toHaveNoViolations();
  });

  it("counts the built-in setup issuer journey complete after the wizard creates its identity and certificate", async () => {
    apiMock.issuers.mockResolvedValue([]);
    apiMock.identities.mockResolvedValue([{ id: "identity-1", name: "first-service" }]);
    apiMock.certificatePage.mockResolvedValue({ items: [{ id: "certificate-1", subject: "first-service" }] });

    renderJourneys();

    const firstCert = screen.getByRole("button", { name: /First certificate/ });
    expect(await within(firstCert).findByText("4 of 4 steps done")).toBeInTheDocument();
  });

  it("shows an unavailable detector as blocked without calling it or fabricating carousel progress", async () => {
    const user = userEvent.setup();
    renderJourneysWithRuntime("/journeys?j=respond-to-compromise");

    expect(await screen.findByRole("heading", { name: "Guided setup" })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Next" }));

    expect(await screen.findByText("Unavailable")).toBeInTheDocument();
    expect(screen.getByText("This step cannot be checked yet")).toBeInTheDocument();
    expect(screen.getByText(unavailableIncidentDetail)).toBeInTheDocument();
    expect(apiMock.incidentExecutions).not.toHaveBeenCalled();
    expect(screen.getByRole("progressbar", { name: "Verified journey progress" })).toHaveAttribute("aria-valuenow", "0");
    expect(screen.getByTestId("compact-step-progress")).not.toHaveTextContent("✓");
  });
});
