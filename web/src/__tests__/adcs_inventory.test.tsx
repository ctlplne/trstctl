import { render, screen, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ADCSTemplatePanel } from "@/components/posture/ADCSTemplatePanel";
import { AppQueryProvider } from "@/lib/query";

const { apiMock } = vi.hoisted(() => ({ apiMock: { adcsPosture: vi.fn(), adcsDrift: vi.fn() } }));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

describe("AD CS inventory posture", () => {
  beforeEach(() => {
    apiMock.adcsPosture.mockReset().mockResolvedValue({
      observed: true,
      sources: [
        {
          source_id: "11111111-1111-4111-8111-111111111111",
          name: "corp-adcs",
          schedule_enabled: true,
          monitoring_interval_seconds: 3600,
          last_run_id: "22222222-2222-4222-8222-222222222222",
          last_run_status: "failed",
          last_run_error: "directory_authentication_failed",
          last_run_created_at: "2026-08-11T23:45:00Z",
        },
      ],
      templates: [
        {
          domain: "CORP-CA",
          template: "UserAuth",
          display_name: "User Authentication",
          enrollment_principals: ["S-1-5-11", "S-1-5-21-111-222-333-1001"],
          published_by: ["CORP-CA"],
          worst_severity: "",
          findings: [],
          observed_at: "2026-08-11T23:40:00Z",
          observed_by: "network-relay-1",
        },
      ],
      enrollment_services: [
        {
          domain: "CORP-CA",
          service: "CORP-CA",
          dns_name: "ca01.corp.example",
          enrollment_web_services: ["https://ca01.corp.example/CES/"],
          endpoints: [
            {
              kind: "ndes_admin",
              url: "http://ca01.corp.example/certsrv/mscep_admin/",
              state: "anonymous_access",
              http_status: 200,
              authentication: [],
              tls_verified: false,
              extended_protection: "unobserved",
            },
          ],
          agent_restriction_state: "unobserved",
          agent_restriction_source: "requires_windows_relay",
          worst_severity: "critical",
          findings: [
            {
              id: "ADCS-NDES-ADMIN-ANONYMOUS",
              severity: "critical",
              summary: "The administration endpoint returned content without an authentication challenge.",
              remediation: "Require authenticated access and verified TLS.",
              published: true,
              evidence: [{ attribute: "NDES administration endpoint", observed: "anonymous_access HTTP 200" }],
            },
          ],
          observed_at: "2026-08-11T23:40:00Z",
          observed_by: "network-relay-1",
        },
      ],
      critical: 0,
      high: 0,
      medium: 0,
      guidance: "Enrollment trustees are canonical SIDs; verify effective directory access before changing policy.",
    });
    apiMock.adcsDrift.mockReset().mockResolvedValue({
      items: [
        {
          id: "adcs-drift-aud36",
          run_id: "22222222-2222-4222-8222-222222222222",
          source_id: "11111111-1111-4111-8111-111111111111",
          domain: "CORP-CA",
          agent_id: "33333333-3333-4333-8333-333333333333",
          observed_by: "network-relay-1",
          observed_at: "2026-08-12T00:40:00Z",
          direction: "worse",
          worsened: true,
          changes: [
            {
              template: "UserAuth",
              direction: "worse",
              change: "S-1-5-21-111-222-333-2002 gained enrollment access.",
              attribute: "nTSecurityDescriptor enrollment trustees",
              before: "S-1-5-11, S-1-5-21-111-222-333-1001",
              after: "S-1-5-11, S-1-5-21-111-222-333-1001, S-1-5-21-111-222-333-2002",
            },
          ],
          lifecycle: [
            {
              template: "LegacyAuth",
              lifecycle: "removed",
              was_dangerous: true,
              now_dangerous: false,
            },
          ],
        },
      ],
    });
  });

  it("shows live IIS exposure and honest CA restriction evidence", async () => {
    render(
      <AppQueryProvider>
        <ADCSTemplatePanel />
      </AppQueryProvider>,
    );

    const heading = await screen.findByRole("heading", { name: "Enrollment services and IIS exposure" });
    const section = heading.closest("section");
    expect(section).not.toBeNull();
    expect(within(section!).getByText("requires_windows_relay", { exact: false })).toBeInTheDocument();
    expect(within(section!).getAllByText("anonymous_access", { exact: false }).length).toBeGreaterThan(0);
    expect(within(section!).getByText("ADCS-NDES-ADMIN-ANONYMOUS", { exact: true })).toBeInTheDocument();
    expect(within(section!).getByText(/NDES administration endpoint = anonymous_access HTTP 200/)).toBeInTheDocument();
  });

  it("shows source failure lifecycle and enrollment trustees in the shared data grid", async () => {
    render(
      <AppQueryProvider>
        <ADCSTemplatePanel />
      </AppQueryProvider>,
    );

    expect(await screen.findByRole("list", { name: "Sources" })).toBeInTheDocument();
    expect(screen.getByText("corp-adcs")).toBeInTheDocument();
    expect(screen.getByText("Failed")).toHaveAttribute("data-status-value", "failed");
    expect(screen.getByText("directory_authentication_failed")).toBeInTheDocument();

    const grid = screen.getByRole("table", { name: "AD CS certificate templates" });
    expect(within(grid).getByRole("columnheader", { name: "Principal" })).toBeInTheDocument();
    expect(within(grid).getByText("S-1-5-11, S-1-5-21-111-222-333-1001")).toBeInTheDocument();
    expect(screen.queryByText(/not yet decoded/i)).not.toBeInTheDocument();
  });

  it("shows immutable semantic drift with ACL before and after", async () => {
    render(
      <AppQueryProvider>
        <ADCSTemplatePanel />
      </AppQueryProvider>,
    );

    expect(await screen.findByRole("heading", { name: "Template drift history" })).toBeInTheDocument();
    expect(await screen.findByText("S-1-5-21-111-222-333-2002 gained enrollment access.")).toBeInTheDocument();
    const drift = screen.getByRole("heading", { name: "Template drift history" }).closest("section");
    expect(drift).not.toBeNull();
    expect(within(drift!).getByText("S-1-5-11, S-1-5-21-111-222-333-1001", { exact: true })).toBeInTheDocument();
    expect(within(drift!).getByText("S-1-5-11, S-1-5-21-111-222-333-1001, S-1-5-21-111-222-333-2002", { exact: true })).toBeInTheDocument();
    expect(within(drift!).getByText("11111111-1111-4111-8111-111111111111", { exact: true })).toBeInTheDocument();
    expect(within(drift!).getByText("22222222-2222-4222-8222-222222222222", { exact: true })).toBeInTheDocument();
    expect(within(drift!).getByText("LegacyAuth", { exact: true })).toBeInTheDocument();
    expect(within(drift!).getByText("Dangerous before", { exact: true })).toBeInTheDocument();
    expect(screen.queryByText(/security_descriptor/i)).not.toBeInTheDocument();
  });
});
