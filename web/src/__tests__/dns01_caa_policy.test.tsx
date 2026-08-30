import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { ACMEDNS01CAAPolicyEvidence } from "@/lib/api";
import { DNS01CAAPolicyPanel } from "@/pages/protocols/DNS01CAAPolicyPanel";

function policy(overrides: Partial<ACMEDNS01CAAPolicyEvidence>): ACMEDNS01CAAPolicyEvidence {
  return {
    status: "allowed",
    source: "authoritative_live_dns",
    configured_issuer: "trstctl.example",
    governing_name: "example.test",
    wildcard: false,
    relevant_tag: "issue",
    records: [{ flag: 0, tag: "issue", value: "trstctl.example" }],
    allowed_issuers: ["trstctl.example"],
    recommended_records: [],
    recovery_steps: ["No CAA change is required."],
    fail_closed: true,
    ...overrides,
  };
}

describe("DNS-01 CAA policy evidence", () => {
  it("explains that no CAA is allowed but less restrictive and gives an exact guardrail", () => {
    render(
      <DNS01CAAPolicyPanel
        policy={policy({
          status: "unrestricted",
          governing_name: undefined,
          records: [],
          allowed_issuers: [],
          recommended_records: ['api.example.test CAA 0 issue "trstctl.example"'],
          recovery_steps: ["Issuance is allowed.", "Publish the recommended record and check again."],
        })}
      />,
    );

    const panel = screen.getByRole("region", { name: "CAA issuance policy" });
    expect(within(panel).getByRole("heading", { name: "No CAA record limits issuance" })).toBeInTheDocument();
    expect(within(panel).getByText(/DNS currently does not restrict which CA may issue/i)).toBeInTheDocument();
    expect(within(panel).getByText("No governing CAA record found")).toBeInTheDocument();
    expect(within(panel).getByText("No CAA record restricts which issuer may issue.")).toBeInTheDocument();
    expect(within(panel).queryByText("No issuer is allowed by the governing records.")).not.toBeInTheDocument();
    expect(within(panel).getByText('api.example.test CAA 0 issue "trstctl.example"')).toBeInTheDocument();
  });

  it("shows live allowed records and the parsed issuer without suggesting a change", () => {
    render(<DNS01CAAPolicyPanel policy={policy({})} />);

    const panel = screen.getByRole("region", { name: "CAA issuance policy" });
    expect(within(panel).getByRole("heading", { name: "CAA allows this issuer" })).toBeInTheDocument();
    expect(within(panel).getByText('0 issue "trstctl.example"')).toBeInTheDocument();
    expect(within(panel).getAllByText("trstctl.example").length).toBeGreaterThanOrEqual(2);
    expect(within(panel).queryByText("Recommended DNS record")).not.toBeInTheDocument();
  });

  it("makes a DNS lookup failure visibly fail closed and avoids inventing a DNS change", () => {
    render(
      <DNS01CAAPolicyPanel
        policy={policy({
          status: "lookup_failed",
          governing_name: "api.example.test",
          records: [],
          allowed_issuers: [],
          recommended_records: [],
          recovery_steps: ["Repair authoritative DNS reachability.", "Run this preflight again."],
        })}
      />,
    );

    const panel = screen.getByRole("region", { name: "CAA issuance policy" });
    expect(within(panel).getByRole("heading", { name: "CAA could not be verified" })).toBeInTheDocument();
    expect(within(panel).getByText(/blocks issuance instead of guessing/i)).toBeInTheDocument();
    expect(within(panel).getByText("api.example.test")).toBeInTheDocument();
    expect(within(panel).getByText("Issuer authorization is unknown because live DNS could not be verified.")).toBeInTheDocument();
    expect(within(panel).queryByText("No issuer is allowed by the governing records.")).not.toBeInTheDocument();
    expect(within(panel).getByText(/stops before any provider write or certificate issuance/i)).toBeInTheDocument();
    expect(within(panel).queryByText("Recommended DNS record")).not.toBeInTheDocument();
  });

  it("distinguishes missing issuer configuration from a DNS failure", () => {
    render(
      <DNS01CAAPolicyPanel
        policy={policy({
          status: "not_configured",
          configured_issuer: undefined,
          governing_name: undefined,
          records: [],
          allowed_issuers: [],
          recovery_steps: ["Set the CAA issuer domain, then check again."],
        })}
      />,
    );

    const panel = screen.getByRole("region", { name: "CAA issuance policy" });
    expect(within(panel).getByRole("heading", { name: "CAA policy is not configured" })).toBeInTheDocument();
    expect(within(panel).getByText(/Set the issuer domain, then check again/i)).toBeInTheDocument();
    expect(within(panel).getByText("Set an expected issuer before trstctl can compare it with live DNS.")).toBeInTheDocument();
    expect(within(panel).queryByText("No issuer is allowed by the governing records.")).not.toBeInTheDocument();
  });

  it("uses the deny-all explanation only when governing records actually deny every issuer", () => {
    render(
      <DNS01CAAPolicyPanel
        policy={policy({
          status: "denied",
          records: [{ flag: 0, tag: "issue", value: ";" }],
          allowed_issuers: [],
          recommended_records: ['example.test CAA 0 issue "trstctl.example"'],
          recovery_steps: ["Replace the deny-all record only after approval."],
        })}
      />,
    );

    const panel = screen.getByRole("region", { name: "CAA issuance policy" });
    expect(within(panel).getByRole("heading", { name: "CAA blocks this issuer" })).toBeInTheDocument();
    expect(within(panel).getByText("No issuer is allowed by the governing records.")).toBeInTheDocument();
  });
});
