import { describe, expect, it } from "vitest";
import { safeCSRExampleName } from "./csrCommand";

describe("copyable CSR example", () => {
  it("keeps an ordinary DNS subject unchanged", () => {
    expect(safeCSRExampleName("payments.svc")).toBe("payments.svc");
    expect(safeCSRExampleName("api-1.example.test")).toBe("api-1.example.test");
  });

  it("does not insert shell syntax or an invalid DNS name into a copyable command", () => {
    for (const name of ["api; touch /tmp/marker", "api$(id).test", "api\nlogout", "*.example.test", "api..test", "-api.test", "api_.test"]) {
      expect(safeCSRExampleName(name)).toBeNull();
    }
  });
});
