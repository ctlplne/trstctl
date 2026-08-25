import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { FleetStartAction } from "@/pages/incidents/FleetReissuanceParts";
import { IntlProvider } from "@/i18n/I18nProvider";
import { CapabilityFixtureProvider } from "@/lib/capabilities";
import type { CapabilityView, CapabilityViewItem } from "@/lib/api-types.gen";

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
