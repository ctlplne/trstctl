// SPDX-License-Identifier: BUSL-1.1

import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { IntlProvider } from "@/i18n/I18nProvider";
import { AppQueryProvider } from "@/lib/query";
import { ProviderTemplatesPanel } from "@/pages/provider/ProviderTemplatesPanel";
import { providerApi, type ProviderTemplate, type ProviderTemplateDetail } from "@/lib/providerApi";

const tenants = [
  { id: "alpha", slug: "alpha", name: "Alpha Dental", status: "active" as const, created_at: "2026-01-01T00:00:00Z", updated_at: "2026-01-01T00:00:00Z" },
  { id: "beta", slug: "beta", name: "Beta Law", status: "active" as const, created_at: "2026-01-01T00:00:00Z", updated_at: "2026-01-01T00:00:00Z" },
];

function template(version: number, overrides: Partial<ProviderTemplate> = {}): ProviderTemplate {
  return {
    id: "msp-standard",
    version,
    name: "MSP standard",
    baseline: { profiles: [{ name: "web" }, { name: "mail" }], issuers: [{ name: "msp-ca" }], members: [{ subject: "ops" }] },
    digest: `sha256:${String(version).repeat(64)}`,
    recorded_by: "operator@msp.example",
    recorded_at: `2026-10-0${version}T10:00:00Z`,
    ...overrides,
  };
}

const detail: ProviderTemplateDetail = {
  latest: template(2),
  versions: [template(2), template(1)],
  tenants: [
    { tenant_id: "alpha", template_id: "msp-standard", version: 2, complete: true, results: [], applied_at: "2026-10-03T09:00:00Z" },
    { tenant_id: "beta", template_id: "msp-standard", version: 1, complete: false, results: [], applied_at: "2026-10-02T09:00:00Z" },
  ],
};

function renderPanel() {
  return render(
    <IntlProvider initialLocale="en-US" initialTimeZone="UTC">
      <AppQueryProvider>
        <ProviderTemplatesPanel tenants={tenants} authorityKey={["operator-1"]} onAuthError={vi.fn()} />
      </AppQueryProvider>
    </IntlProvider>,
  );
}

// A186-L1: the provider console shows the tenant templates it records: each
// template's latest version, then on request its baseline's contents, every
// version and the delegated customers bound to it.
describe("Provider tenant templates", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    vi.spyOn(providerApi, "listTemplates").mockResolvedValue([template(2)]);
    vi.spyOn(providerApi, "getTemplate").mockResolvedValue(detail);
  });

  it("lists each template's latest version and shows its versions and customers on request", async () => {
    const user = userEvent.setup();
    renderPanel();
    const table = await screen.findByRole("table", { name: "Tenant templates" });
    const row = within(table).getByRole("row", { name: /MSP standard/ });
    expect(row).toHaveTextContent("2");
    expect(row).toHaveTextContent("222222222222");
    expect(providerApi.getTemplate).not.toHaveBeenCalled();

    await user.click(within(row).getByRole("button", { name: "View MSP standard" }));
    expect(await screen.findByRole("heading", { name: "MSP standard, version 2" })).toBeInTheDocument();
    expect(providerApi.getTemplate).toHaveBeenCalledWith("msp-standard");
    expect(screen.getByText("Profiles: 2")).toBeInTheDocument();
    expect(screen.getByText("CA bindings: 1")).toBeInTheDocument();
    expect(screen.getByText("Member roles: 1")).toBeInTheDocument();
    expect(screen.getByText("Connector targets: 0")).toBeInTheDocument();
    expect(screen.getByText(/Version 1: 111111111111, recorded by operator@msp.example/)).toBeInTheDocument();
    expect(screen.getByText(/Alpha Dental: version 2, applied 2026-10-03 09:00 UTC/)).toBeInTheDocument();
    expect(screen.getByText(/Beta Law: version 1 not fully applied/)).toBeInTheDocument();
  });

  it("says when no template is recorded", async () => {
    vi.spyOn(providerApi, "listTemplates").mockResolvedValue([]);
    renderPanel();
    expect(await screen.findByText("No tenant templates recorded yet.")).toBeInTheDocument();
  });
});
