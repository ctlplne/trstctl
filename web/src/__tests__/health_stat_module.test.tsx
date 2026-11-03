import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { HealthStat } from "@/pages/certificates/HealthStat";
import * as roguePanel from "@/pages/certificates/RogueCertificatePanel";

// The stat tile the Certificates page's revocation-health summary uses lived in
// the rogue-certificate panel's file, beside a formatter only that panel needs.
describe("HealthStat", () => {
  it("is its own module, and the rogue-certificate panel exports only itself", () => {
    expect(Object.keys(roguePanel).sort()).toEqual(["RogueCertificatePanel"]);
    render(<HealthStat label="Expiring in 7 days" value={3} />);
    expect(screen.getByText("Expiring in 7 days")).toBeInTheDocument();
    expect(screen.getByText("3")).toBeInTheDocument();
  });
});
