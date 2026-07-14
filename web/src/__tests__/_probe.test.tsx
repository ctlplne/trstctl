// Retired scratch probe (sandbox could not unlink during the IA train). Intentionally a no-op.
import { describe, it, expect } from "vitest";
describe("_probe (retired)", () => {
  it("noop", () => expect(true).toBe(true));
});
