import { describe, expect, it } from "vitest";
import { edgeCustodyAssuranceLabel } from "@/components/EdgeDelegationsPanel";

describe("edge delegation custody evidence", () => {
  it("does not label PKCS#11 host attestation as hardware-key attestation", () => {
    expect(edgeCustodyAssuranceLabel("hardware_key_attested")).toContain("CSR key attested");
    expect(edgeCustodyAssuranceLabel("host_attested_operator_claim")).toContain("operator-declared");
    expect(edgeCustodyAssuranceLabel("host_attested_operator_claim")).not.toContain("CSR key attested");
  });

  it("names the exportable software lane as an exception", () => {
    expect(edgeCustodyAssuranceLabel("host_attested_software_exception")).toContain("software exception");
  });
});
