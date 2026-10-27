import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ValidityReadinessPanel } from "@/components/certs";
import { AppQueryProvider } from "@/lib/query";
import type { ValidityReadinessReport } from "@/lib/api";

const { apiMock } = vi.hoisted(() => ({
  apiMock: { validityReadiness: vi.fn(), validityReadinessExport: vi.fn() },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

const requirements = {
  name: "CA/Browser Forum Baseline Requirements for the Issuance and Management of Publicly-Trusted TLS Server Certificates",
  version: "2.3.1",
  published: "2026-10-04",
  section: "6.3.2",
  url: "https://cabforum.org/working-groups/server/baseline-requirements/",
};

function step(effective: string, maxDays: number, verdict: "renews" | "at_risk" | "manual", reasons: string[] = []) {
  return { effective, max_days: maxDays, verdict, reasons };
}

const report = {
  requirements,
  generated_at: "2026-10-26T12:00:00Z",
  scheduler: { enabled: true, renew_before: "720h0m0s", renew_before_seconds: 2592000 },
  steps: [
    {
      effective: "2026-03-15",
      should_days: 199,
      max_days: 200,
      in_effect: true,
      renews: 1,
      at_risk: 0,
      manual: 1,
      public_tls: 1,
      public_tls_at_risk: 0,
      public_tls_manual: 1,
      manual_renewals_per_year: 2,
      flagged_profiles: 1,
    },
    {
      effective: "2027-03-15",
      should_days: 99,
      max_days: 100,
      in_effect: false,
      renews: 1,
      at_risk: 0,
      manual: 1,
      public_tls: 1,
      public_tls_at_risk: 0,
      public_tls_manual: 1,
      manual_renewals_per_year: 4,
      flagged_profiles: 1,
    },
    {
      effective: "2029-03-15",
      should_days: 46,
      max_days: 47,
      in_effect: false,
      renews: 0,
      at_risk: 1,
      manual: 1,
      public_tls: 1,
      public_tls_at_risk: 0,
      public_tls_manual: 1,
      manual_renewals_per_year: 8,
      flagged_profiles: 2,
    },
  ],
  profiles: [
    {
      name: "web-public",
      version: 3,
      public_tls: true,
      server_auth: true,
      max_validity: "9528h0m0s",
      requested_days: 398,
      steps: [
        { effective: "2026-03-15", max_days: 200, flagged: true, reason: "requested_validity_exceeds_maximum" },
        { effective: "2027-03-15", max_days: 100, flagged: true, reason: "requested_validity_exceeds_maximum" },
        { effective: "2029-03-15", max_days: 47, flagged: true, reason: "requested_validity_exceeds_maximum" },
      ],
    },
    {
      name: "web-90",
      version: 1,
      public_tls: true,
      server_auth: true,
      max_validity: "2160h0m0s",
      requested_days: 91,
      steps: [
        { effective: "2026-03-15", max_days: 200, flagged: false },
        { effective: "2027-03-15", max_days: 100, flagged: false },
        { effective: "2029-03-15", max_days: 47, flagged: true, reason: "requested_validity_exceeds_maximum" },
      ],
    },
  ],
  certificates: [
    {
      certificate_id: "00000000-0000-4000-8000-000000000001",
      subject: "CN=checkout.example.test",
      issuer: "CN=trstctl Issuing CA",
      not_before: "2026-10-01T00:00:00Z",
      not_after: "2026-10-31T00:00:00Z",
      validity_days: 31,
      scope: "private_tls",
      max_days_at_issuance: 200,
      exceeds_maximum_at_issuance: false,
      automation: "scheduled",
      deployment: "verified",
      renewal_lifetime_days: 30,
      renewal_lead_days: 10,
      steps: [step("2026-03-15", 200, "renews"), step("2027-03-15", 100, "renews"), step("2029-03-15", 47, "at_risk", ["renewal_lifetime_exceeds_maximum"])],
    },
    {
      certificate_id: "00000000-0000-4000-8000-000000000002",
      subject: "CN=www.example.test",
      issuer: "CN=Public CA",
      not_before: "2026-10-01T00:00:00Z",
      not_after: "2026-12-30T00:00:00Z",
      validity_days: 91,
      scope: "public_tls",
      max_days_at_issuance: 200,
      exceeds_maximum_at_issuance: false,
      automation: "none",
      deployment: "not_applicable",
      steps: [
        step("2026-03-15", 200, "manual", ["no_automated_renewal"]),
        step("2027-03-15", 100, "manual", ["no_automated_renewal"]),
        step("2029-03-15", 47, "manual", ["no_automated_renewal"]),
      ],
    },
  ],
  truncated: false,
  limit: 5000,
} as unknown as ValidityReadinessReport;

afterEach(() => {
  vi.restoreAllMocks();
});

function renderPanel() {
  return render(
    <AppQueryProvider>
      <ValidityReadinessPanel />
    </AppQueryProvider>,
  );
}

describe("U1-3 lifetime-reduction readiness", () => {
  it("shows the server's verdicts for each dated step and the public TLS profiles over its maximum", async () => {
    apiMock.validityReadiness.mockResolvedValue(report);
    renderPanel();

    const inEffect = await screen.findByRole("button", { name: "From 2026-03-15: 200 days (in effect)" });
    expect(inEffect).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByText(/Baseline Requirements 2\.3\.1 \(2026-10-04\), section 6\.3\.2/)).toBeInTheDocument();
    const profiles = screen.getByRole("list", { name: "Public TLS profiles over the maximum" });
    expect(within(profiles).getByText("web-public v3")).toBeInTheDocument();
    expect(within(profiles).getByText("Requests 398 days; the maximum is 200")).toBeInTheDocument();
    expect(within(profiles).queryByText("web-90 v1")).not.toBeInTheDocument();
    const work = screen.getByRole("list", { name: "Certificates at risk or renewed by hand" });
    expect(within(work).getByText("CN=www.example.test")).toBeInTheDocument();
    expect(within(work).queryByText("CN=checkout.example.test")).not.toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "From 2029-03-15: 47 days" }));
    expect(screen.getByRole("button", { name: "From 2029-03-15: 47 days" })).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByText("8")).toBeInTheDocument();
    const profiles2029 = screen.getByRole("list", { name: "Public TLS profiles over the maximum" });
    expect(within(profiles2029).getByText("Requests 91 days; the maximum is 47")).toBeInTheDocument();
    const work2029 = screen.getByRole("list", { name: "Certificates at risk or renewed by hand" });
    expect(within(work2029).getByText("CN=checkout.example.test")).toBeInTheDocument();
    expect(within(work2029).getByText("a renewal requests more than the maximum")).toBeInTheDocument();
  });

  it("downloads the server's CSV under the file name that names the BR version", async () => {
    apiMock.validityReadiness.mockResolvedValue(report);
    apiMock.validityReadinessExport.mockResolvedValue({
      filename: "validity-readiness-br-2.3.1-2026-10-26.csv",
      content_type: "text/csv",
      requirements,
      generated_at: "2026-10-26T12:00:00Z",
      truncated: false,
      csv: "record,id\n",
    });
    const createObjectURL = vi.fn(() => "blob:validity");
    const revokeObjectURL = vi.fn();
    Object.assign(URL, { createObjectURL, revokeObjectURL });
    let downloaded = "";
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function (this: HTMLAnchorElement) {
      downloaded = this.download;
    });
    renderPanel();

    await userEvent.click(await screen.findByRole("button", { name: "Download CSV" }));
    expect(apiMock.validityReadinessExport).toHaveBeenCalledTimes(1);
    expect(downloaded).toBe("validity-readiness-br-2.3.1-2026-10-26.csv");
    expect(createObjectURL).toHaveBeenCalledTimes(1);
  });
});
