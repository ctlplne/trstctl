import { describe, expect, it } from "vitest";

import { hasAnyPermission, hasPermission, wildcardPermission } from "@/lib/access";

// hasPermission used to return true when the permission list was absent, which
// made every gated control visible to a user whose `me` response had not loaded,
// or whose permissions the API omitted for any reason. There is no reading of
// "absent" that means "allowed": /api/v1/me always populates the list, and
// unrestricted access is the "*" wildcard, handled explicitly.
describe("hasPermission", () => {
  it("fails closed when the permission set is unknown", () => {
    expect(hasPermission(null, "certs:issue")).toBe(false);
    expect(hasPermission(undefined, "certs:issue")).toBe(false);
    expect(hasPermission({ permissions: undefined }, "certs:issue")).toBe(false);
  });

  it("denies when the user holds no permissions at all", () => {
    expect(hasPermission({ permissions: [] }, "certs:issue")).toBe(false);
  });

  it("grants only what the user actually holds", () => {
    const user = { permissions: ["certs:read", "audit:read"] };
    expect(hasPermission(user, "certs:read")).toBe(true);
    expect(hasPermission(user, "audit:read")).toBe(true);
    expect(hasPermission(user, "certs:issue")).toBe(false);
    expect(hasPermission(user, "owners:write")).toBe(false);
  });

  it("honours the wildcard, which is how unrestricted access is expressed", () => {
    expect(hasPermission({ permissions: [wildcardPermission] }, "anything:at:all")).toBe(true);
  });
});

describe("hasAnyPermission", () => {
  // The argument here is what a destination REQUIRES, so an empty list means
  // "needs no permission" — a different question from hasPermission's, where an
  // empty set means the user holds nothing.
  it("allows a destination that requires nothing", () => {
    expect(hasAnyPermission({ permissions: [] }, [])).toBe(true);
    expect(hasAnyPermission(null, undefined)).toBe(true);
  });

  it("requires at least one of the listed permissions", () => {
    const user = { permissions: ["certs:read"] };
    expect(hasAnyPermission(user, ["certs:read", "certs:issue"])).toBe(true);
    expect(hasAnyPermission(user, ["owners:write", "certs:issue"])).toBe(false);
  });

  it("hides gated destinations from a user whose permissions have not loaded", () => {
    expect(hasAnyPermission(null, ["audit:read"])).toBe(false);
    expect(hasAnyPermission({ permissions: undefined }, ["audit:read"])).toBe(false);
  });
});
