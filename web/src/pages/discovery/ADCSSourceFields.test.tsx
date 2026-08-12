import { describe, expect, it } from "vitest";
import { parseADCSEnrollmentEndpoints, parseADCSPrivateEgressCIDRs } from "./ADCSSourceFields";

describe("AD CS enrollment endpoint source fields (AUD-37)", () => {
  it("turns operator-scoped lines into the closed relay target vocabulary", () => {
    expect(
      parseADCSEnrollmentEndpoints("CORP-CA | web_enrollment | https://ca.example/certsrv/\nCORP-CA | ndes_admin | https://ca.example/certsrv/mscep_admin/"),
    ).toEqual([
      { enrollment_service: "CORP-CA", kind: "web_enrollment", url: "https://ca.example/certsrv/" },
      { enrollment_service: "CORP-CA", kind: "ndes_admin", url: "https://ca.example/certsrv/mscep_admin/" },
    ]);
  });

  it("rejects a line whose endpoint kind is not understood", () => {
    expect(() => parseADCSEnrollmentEndpoints("CORP-CA | mystery | https://ca.example/")).toThrow(/line 1/);
  });

  it("normalizes the relay's explicit private-network allowlist", () => {
    expect(parseADCSPrivateEgressCIDRs("10.42.8.0/24, 172.20.0.0/16\nfc00:42::/64")).toEqual(["10.42.8.0/24", "172.20.0.0/16", "fc00:42::/64"]);
  });
});
