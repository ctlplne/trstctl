import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { CapabilityRouteNotice } from "@/components/CapabilityTruth";
import { IntlProvider } from "@/i18n/I18nProvider";
import { CapabilityFixtureProvider } from "@/lib/capabilities";
import type { CapabilityView, CapabilityViewItem } from "@/lib/api-types.gen";

function item(overrides: Partial<CapabilityViewItem>): CapabilityViewItem {
  return {
    capability_id: "F31",
    name: "Credential compromise workflow",
    purpose: "Contain and repair a compromised credential.",
    tool: "operations",
    classification: "primary",
    console_route: "/incidents",
    maturity: "partial_workflow",
    release_blocking: true,
    edition: "core",
    runtime_state: "partially_available",
    authorization_state: "partial",
    dependency_state: "documented_not_runtime_verified",
    dependencies: ["response connector"],
    stages: [{ name: "execute", completion: "blocked", reason: "No response connector is configured." }],
    actions: {
      allowed: ["listIncidents"],
      scoped: [],
      denied: [],
      unavailable: [{ operation_id: "executeIncident", code: "dependency_not_configured", detail: "No response connector is configured." }],
    },
    ...overrides,
  };
}

const runtime: CapabilityView = {
  schema_version: 2,
  contract_schema_version: 3,
  enforcement_note: "The server checks again at execution.",
  license: { tier: "community", state: "community" },
  operations: [],
  items: [
    item({}),
    item({
      capability_id: "F32",
      name: "Fleet re-issuance",
      runtime_state: "unavailable",
      authorization_state: "none",
      actions: {
        allowed: [],
        scoped: [],
        denied: [],
        unavailable: [{ operation_id: "startFleetReissuance", code: "dependency_not_configured", detail: "Fleet orchestration is not configured." }],
      },
    }),
    item({
      capability_id: "F34",
      name: "Incident response orchestration",
      maturity: "complete_vertical_slice",
      runtime_state: "available",
      authorization_state: "full",
      dependency_state: "none",
      dependencies: [],
      stages: [{ name: "execute", completion: "complete" }],
      actions: { allowed: ["listIncidents"], scoped: [], denied: [], unavailable: [] },
    }),
  ],
};

function renderNotice(view: CapabilityView | null, options?: { error?: boolean; loading?: boolean; path?: string }) {
  return render(
    <IntlProvider initialLocale="en-US" initialTimeZone="UTC">
      <CapabilityFixtureProvider view={view} error={options?.error} loading={options?.loading}>
        <MemoryRouter initialEntries={[options?.path ?? "/incidents"]}>
          <CapabilityRouteNotice />
        </MemoryRouter>
      </CapabilityFixtureProvider>
    </IntlProvider>,
  );
}

describe("capability truth UI", () => {
  it("shows exact runtime limits without blocking the ready part of a route", async () => {
    const user = userEvent.setup();
    renderNotice(runtime);
    expect(screen.getByRole("heading", { name: "2 of 3 capabilities on this page have ready actions" })).toBeInTheDocument();
    await user.click(screen.getByText("Review 2 limitation(s)"));
    expect(screen.getByText("No response connector is configured.")).toBeInTheDocument();
    expect(screen.getByText("Fleet orchestration is not configured.")).toBeInTheDocument();
  });

  it("describes a partly available capability by its usable actions instead of calling it zero ready", async () => {
    const user = userEvent.setup();
    const developerAccess: CapabilityView = {
      ...runtime,
      items: [
        item({
          capability_id: "F64",
          name: "Developer secret access",
          console_route: "/secrets/developer",
          runtime_state: "partially_available",
          authorization_state: "full",
          stages: [{ name: "execute", completion: "complete" }],
          actions: {
            allowed: ["previewSecretAccess"],
            scoped: [],
            denied: [],
            unavailable: [{ operation_id: "importSecrets", code: "not_implemented", detail: "Atomic bulk import is not implemented." }],
          },
        }),
      ],
    };

    renderNotice(developerAccess, { path: "/secrets/developer" });
    expect(screen.getByRole("heading", { name: "1 of 1 capabilities on this page have ready actions" })).toBeInTheDocument();
    expect(screen.getByText(/Use the ready actions now/i)).toBeInTheDocument();
    expect(screen.queryByText(/0 of 1 capabilities/i)).not.toBeInTheDocument();
    await user.click(screen.getByText("Review 1 limitation(s)"));
    expect(screen.getByText("Atomic bulk import is not implemented.")).toBeInTheDocument();
  });

  it("does not expose a raw read error while explaining the fail-closed boundary", () => {
    renderNotice(null, { error: true });
    expect(screen.getByRole("heading", { name: "Capability status is temporarily unavailable" })).toBeInTheDocument();
    expect(screen.getByText(/browser will not guess or unlock anything/i)).toBeInTheDocument();
    expect(screen.queryByText(/private|stack trace|\/Users\//i)).not.toBeInTheDocument();
  });

  it("uses a status announcement while runtime truth is loading", () => {
    renderNotice(null, { loading: true });
    expect(screen.getByRole("status")).toHaveTextContent("Checking what this server and your role can do");
  });
});
