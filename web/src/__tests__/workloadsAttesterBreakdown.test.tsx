import { describe, expect, it } from "vitest";
import { attesterBreakdown, type AttestationFailure } from "@/pages/Workloads";

function svid(method: string, verifiedAt: string) {
  return { attestation: { method, verified_at: verifiedAt } };
}

function failure(method: string, at = "2026-07-26T12:00:00Z"): AttestationFailure {
  return { method, message: "attestation payload rejected", at };
}

// S-C20: the breakdown answers "which attester is actually working", so its
// grouping, its most-recent-verification pick, and its failures-first ordering
// are pinned.
describe("attester breakdown", () => {
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
