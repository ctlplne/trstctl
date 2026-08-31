import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { AttesterBreakdown, attesterBreakdown, type AttestationFailure } from "@/pages/Workloads";
import { IntlProvider } from "@/i18n/I18nProvider";

function svid(method: string, verifiedAt: string) {
  return {
    subject: "fixture-workload",
    credential_id: `fixture-${method}-${verifiedAt}`,
    not_after: verifiedAt,
    attestation: { id: `att-${method}`, subject: "fixture-workload", selectors: [], method, verified_at: verifiedAt },
  };
}

function failure(method: string, at = "2026-07-26T12:00:00Z"): AttestationFailure {
  return { method, message: "attestation payload rejected", at };
}

// S-C20: the breakdown answers "which attester is actually working", so its
// grouping, its most-recent-verification pick, and its failures-first ordering
// are pinned.
describe("attester breakdown", () => {
  it("uses the same active time zone for verification and unsuccessful-attempt times", () => {
    render(
      <IntlProvider initialLocale="en-US" initialTimeZone="America/New_York">
        <AttesterBreakdown rows={[svid("k8s_sat", "2026-08-31T00:24:48Z")]} failures={[failure("k8s_sat", "2026-08-31T00:25:00Z")]} />
      </IntlProvider>,
    );
    expect(screen.getByText("Aug 30, 2026, 8:24 PM")).toBeInTheDocument();
    expect(screen.getByText("Aug 30, 2026, 8:25 PM")).toBeInTheDocument();
    expect(screen.queryByText(/Aug 31/)).not.toBeInTheDocument();
  });
  it("does not call an infrastructure error a proof refusal or claim it was never verified", () => {
    render(<AttesterBreakdown rows={[]} failures={[{ method: "k8s_sat", message: "internal error", at: "2026-08-30T12:00:00Z" }]} />);
    expect(screen.getByRole("columnheader", { name: "Unsuccessful attempts" })).toBeInTheDocument();
    expect(screen.getByText("1 unsuccessful")).toBeInTheDocument();
    expect(screen.getByText("No issued result")).toBeInTheDocument();
    expect(screen.getByText(/not necessarily proof refusals/i)).toBeInTheDocument();
    expect(screen.queryByText(/refused|^never$/i)).not.toBeInTheDocument();
  });

  it("groups issued SVIDs by attester and keeps the most recent verification", () => {
    const rows = attesterBreakdown([
      svid("k8s_sat", "2026-07-20T00:00:00Z"),
      svid("k8s_sat", "2026-07-25T00:00:00Z"),
      svid("github_oidc", "2026-07-21T00:00:00Z"),
    ]);

    expect(rows).toHaveLength(2);
    const k8s = rows.find((row) => row.method === "k8s_sat");
    expect(k8s?.issued).toBe(2);
    expect(k8s?.lastVerifiedAt).toBe("2026-07-25T00:00:00Z");
  });

  it("orders failing attesters first — they are the ones needing attention", () => {
    const rows = attesterBreakdown([svid("k8s_sat", "2026-07-25T00:00:00Z"), svid("k8s_sat", "2026-07-25T00:00:00Z")], [failure("tpm")]);

    expect(rows[0].method).toBe("tpm");
    expect(rows[0].failures).toBe(1);
    expect(rows[0].issued).toBe(0);
    expect(rows[1].method).toBe("k8s_sat");
  });

  it("counts refusals against an attester that has also issued", () => {
    const rows = attesterBreakdown([svid("k8s_sat", "2026-07-25T00:00:00Z")], [failure("k8s_sat"), failure("k8s_sat")]);

    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ method: "k8s_sat", issued: 1, failures: 2 });
  });

  it("labels a missing method rather than dropping the row", () => {
    const rows = attesterBreakdown([svid("", "2026-07-25T00:00:00Z")]);
    expect(rows[0].method).toBe("unknown");
  });

  it("returns nothing when there is neither an issuance nor a refusal", () => {
    expect(attesterBreakdown([])).toEqual([]);
  });
});
