import { describe, expect, it } from "vitest";
import { rankedRiskFactors, riskScoreSegments } from "@/pages/Risk";
import type { CredentialRisk } from "@/lib/api";

function risk(components: Partial<CredentialRisk["components"]>, score = 50): CredentialRisk {
  return {
    credential_id: "cred-1",
    subject: "svc.example",
    kind: "certificate",
    score,
    expires_at: "2026-09-01T00:00:00Z",
    owner_active: true,
    privilege: 1,
    sensitivity: 1,
    exposure: 0,
    components: { age: 0, rotation: 0, privilege: 0, exposure: 0, owner: 0, sensitivity: 0, ...components },
  } as CredentialRisk;
}

// S-C13: the meter and chips are how an operator triages without expanding
// every row, so their magnitude, tone banding, and ranking are pinned.
describe("risk score meter", () => {
  it("fills the meter to the score and leaves the remainder neutral", () => {
    const segments = riskScoreSegments(72);
    expect(segments[0].value).toBe(72);
    expect(segments[1].value).toBe(28);
    expect(segments[1].tone).toBe("neutral");
  });

  it("carries the band's own tone so magnitude reads at a glance", () => {
    expect(riskScoreSegments(95)[0].tone).toBe("critical");
    expect(riskScoreSegments(75)[0].tone).toBe("high");
    expect(riskScoreSegments(50)[0].tone).toBe("medium");
    expect(riskScoreSegments(10)[0].tone).toBe("low");
    expect(riskScoreSegments(0)[0].tone).toBe("neutral");
  });

  it("clamps out-of-range scores instead of overflowing the bar", () => {
    expect(riskScoreSegments(140)[0].value).toBe(100);
    expect(riskScoreSegments(140)[1].value).toBe(0);
    expect(riskScoreSegments(-5)[0].value).toBe(0);
  });
});

describe("risk factor chips", () => {
  it("ranks the contributing factors, biggest first, capped for scannability", () => {
    const ranked = rankedRiskFactors(risk({ age: 0.2, rotation: 0.9, privilege: 0.5 }));
    expect(ranked.map((entry) => entry.factor)).toEqual(["rotation", "privilege"]);
    expect(ranked[0].percent).toBe(90);
  });

  it("omits factors that contribute nothing", () => {
    const ranked = rankedRiskFactors(risk({ rotation: 0.4 }));
    expect(ranked).toHaveLength(1);
    expect(ranked[0].factor).toBe("rotation");
  });

  it("returns nothing when no factor contributes", () => {
    expect(rankedRiskFactors(risk({}))).toEqual([]);
  });

  it("accepts already-percentage components without double-scaling", () => {
    const ranked = rankedRiskFactors(risk({ exposure: 65 }));
    expect(ranked[0].percent).toBe(65);
  });
});
