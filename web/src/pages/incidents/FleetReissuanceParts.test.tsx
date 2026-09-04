import { describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { FleetReissuanceConfiguration, FleetStartAction } from "@/pages/incidents/FleetReissuanceParts";
import { IntlProvider } from "@/i18n/I18nProvider";
import { CapabilityFixtureProvider } from "@/lib/capabilities";
import type { CapabilityView, CapabilityViewItem } from "@/lib/api-types.gen";
import { api } from "@/lib/api";
import { AppQueryProvider } from "@/lib/query";

function runtime(item: CapabilityViewItem): CapabilityView {
  return {
    schema_version: 2,
    contract_schema_version: 3,
    enforcement_note: "The server checks again at execution.",
    license: { tier: "community", state: "community" },
    operations: [],
    items: [item],
  };
}

function fleetCapability(available: boolean): CapabilityViewItem {
  return {
    capability_id: "F32",
    name: "Fleet re-issuance for CA compromise",
    purpose: "Replace credentials affected by a compromised certificate authority.",
    tool: "operations",
    classification: "primary",
    console_route: "/incidents",
    maturity: "partial_workflow",
    release_blocking: true,
    edition: "core",
    runtime_state: available ? "available" : "unavailable",
    authorization_state: available ? "full" : "none",
    dependency_state: available ? "none" : "documented_not_runtime_verified",
    dependencies: available ? [] : ["fleet orchestrator"],
    stages: [{ name: "execute", completion: available ? "complete" : "blocked", ...(available ? {} : { reason: "Fleet orchestration is not configured." }) }],
    actions: available
      ? { allowed: ["startFleetReissuance"], scoped: [], denied: [], unavailable: [] }
      : {
          allowed: [],
          scoped: [],
          denied: [],
          unavailable: [{ operation_id: "startFleetReissuance", code: "dependency_not_configured", detail: "Fleet orchestration is not configured." }],
        },
  };
}

function renderAction(view: CapabilityView, onStart = vi.fn()) {
  render(
    <IntlProvider initialLocale="en-US" initialTimeZone="UTC">
      <CapabilityFixtureProvider view={view}>
        <FleetStartAction running={false} onStart={onStart} />
      </CapabilityFixtureProvider>
    </IntlProvider>,
  );
  return onStart;
}

describe("fleet re-issuance runtime preflight", () => {
  it("turns the g15 unavailable operation into an explained disabled control", async () => {
    const onStart = renderAction(runtime(fleetCapability(false)));
    const button = screen.getByRole("button", { name: "Start fleet run" });
    expect(button).toBeDisabled();
    expect(screen.getByText("Fleet orchestration is not configured.")).toBeInTheDocument();
    await userEvent.click(button);
    expect(onStart).not.toHaveBeenCalled();
  });

  it("keeps an attached and authorized operation runnable", async () => {
    const onStart = renderAction(runtime(fleetCapability(true)));
    const button = screen.getByRole("button", { name: "Start fleet run" });
    expect(button).toBeEnabled();
    await userEvent.click(button);
    expect(onStart).toHaveBeenCalledOnce();
  });
});

describe("fleet re-issuance configuration", () => {
  it("turns served prerequisite rosters into a reviewed structured request", async () => {
    vi.spyOn(api, "issuers").mockResolvedValue([
      { id: "issuer-old", kind: "x509_ca", name: "Compromised public CA" },
      { id: "issuer-ssh", kind: "ssh_ca", name: "SSH CA" },
    ]);
    vi.spyOn(api, "caAuthorities").mockResolvedValue({
      items: [
        {
          id: "authority-new",
          tenant_id: "tenant-a",
          common_name: "Clean replacement CA",
          kind: "intermediate",
          status: "active",
          max_path_len: 0,
          serial: "02",
          signer_handle: "signer:new",
          certificate_pem: "public certificate",
          created_at: "2026-09-04T00:00:00Z",
        },
      ],
    });
    vi.spyOn(api, "identities").mockResolvedValue([
      { id: "identity-a", kind: "x509_certificate", name: "payments.example", owner_id: "owner-a", issuer_id: "issuer-old", status: "deployed" },
      { id: "identity-b", kind: "x509_certificate", name: "unrelated.example", owner_id: "owner-b", issuer_id: "issuer-other", status: "deployed" },
    ]);
    vi.spyOn(api, "agents").mockResolvedValue([
      {
        id: "agent-a",
        name: "payments-host",
        status: "active",
        discovery_capabilities: [],
        inventory_report_path: "",
        presence: { state: "online", online: true, detail: "fresh", evaluated_at: "2026-09-04T00:00:00Z" },
        relay_capabilities: [],
        role_source: "certificate",
        roles: ["host"],
        workload_api: { state: "unreported", detail: "not configured", svids_issued: 0 },
        enrollment_proxy: {
          state: "unreported",
          detail: "not configured",
          forwarded_requests: 0,
          healthy_upstreams: 0,
          refused_requests: 0,
          reported_at: "2026-09-04T00:00:00Z",
          unhealthy_upstreams: 0,
          unknown_upstreams: 0,
          upstream_failures: 0,
        },
      },
    ]);
    const onStart = vi.fn().mockResolvedValue(undefined);
    render(
      <IntlProvider initialLocale="en-US" initialTimeZone="UTC">
        <AppQueryProvider>
          <CapabilityFixtureProvider view={runtime(fleetCapability(true))}>
            <FleetReissuanceConfiguration running={false} onStart={onStart} />
          </CapabilityFixtureProvider>
        </AppQueryProvider>
      </IntlProvider>,
    );

    const user = userEvent.setup();
    await screen.findByRole("option", { name: /Compromised public CA/ });
    await user.selectOptions(screen.getByRole("combobox", { name: "Compromised issuer" }), "issuer-old");
    await user.selectOptions(screen.getByRole("combobox", { name: "Replacement CA authority" }), "authority-new");
    await user.click(screen.getByRole("button", { name: "Build migration waves" }));

    expect(await screen.findByRole("option", { name: /payments\.example/ })).toBeInTheDocument();
    expect(screen.queryByRole("option", { name: /unrelated\.example/ })).not.toBeInTheDocument();
    await user.selectOptions(screen.getByRole("combobox", { name: "Identity" }), "identity-a");
    await user.selectOptions(screen.getByRole("combobox", { name: "Agent" }), "agent-a");
    await user.click(screen.getByRole("button", { name: "Review fleet run" }));

    expect(await screen.findByText("Compromised public CA")).toBeInTheDocument();
    expect(screen.getByText("Clean replacement CA")).toBeInTheDocument();
    expect(screen.getByText("payments.example → payments-host")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Start fleet run" }));

    await waitFor(() => expect(onStart).toHaveBeenCalledOnce());
    expect(onStart).toHaveBeenCalledWith(
      expect.objectContaining({
        issuer_id: "issuer-old",
        replacement_authority_id: "authority-new",
        mode: "live",
        cohorts: [
          expect.objectContaining({
            id: "canary",
            ordinal: 1,
            members: [{ identity_id: "identity-a", agent_id: "agent-a", trust_anchor_path: "/etc/trstctl/next-root.pem" }],
          }),
        ],
      }),
    );
  });

  it("keeps the workflow on prerequisite selection when required rosters are empty", async () => {
    vi.spyOn(api, "issuers").mockResolvedValue([]);
    vi.spyOn(api, "caAuthorities").mockResolvedValue({ items: [] });
    vi.spyOn(api, "identities").mockResolvedValue([]);
    vi.spyOn(api, "agents").mockResolvedValue([]);
    const onStart = vi.fn();
    render(
      <IntlProvider initialLocale="en-US" initialTimeZone="UTC">
        <AppQueryProvider>
          <CapabilityFixtureProvider view={runtime(fleetCapability(true))}>
            <FleetReissuanceConfiguration running={false} onStart={onStart} />
          </CapabilityFixtureProvider>
        </AppQueryProvider>
      </IntlProvider>,
    );

    expect(await screen.findByText("Fleet setup is incomplete")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Build migration waves" })).toBeDisabled();
    expect(onStart).not.toHaveBeenCalled();
  });
});
