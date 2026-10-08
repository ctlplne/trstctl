import { beforeEach, describe, expect, it } from "vitest";
import { clearManagedKeyActionIntent, getOrCreateManagedKeyActionIntent } from "./managedKeyActionIntent";

const requester = { tenant_id: "tenant-a", subject: "eval-admin" };

describe("managed-key dual-control action intent", () => {
  beforeEach(() => localStorage.clear());

  it("reuses the exact request key after navigation and a browser reload, then clears only after the effect completes", () => {
    const first = getOrCreateManagedKeyActionIntent(requester, "rotate", "kms/key-1");
    const afterReload = getOrCreateManagedKeyActionIntent({ ...requester }, "rotate", "kms/key-1");
    expect(afterReload).toBe(first);
    expect(getOrCreateManagedKeyActionIntent(requester, "revoke", "kms/key-1")).not.toBe(first);
    expect(getOrCreateManagedKeyActionIntent(requester, "rotate", "kms/key-2")).not.toBe(first);
    expect(getOrCreateManagedKeyActionIntent({ tenant_id: "tenant-b", subject: requester.subject }, "rotate", "kms/key-1")).not.toBe(first);
    expect(getOrCreateManagedKeyActionIntent({ tenant_id: requester.tenant_id, subject: "another-requester" }, "rotate", "kms/key-1")).not.toBe(first);
    clearManagedKeyActionIntent(requester, "rotate", "kms/key-1");
    expect(getOrCreateManagedKeyActionIntent(requester, "rotate", "kms/key-1")).not.toBe(first);
  });

  it("fails closed when saved request state is damaged instead of silently replacing an approval", () => {
    const key = getOrCreateManagedKeyActionIntent(requester, "rotate", "kms/key-1");
    const slot = Array.from({ length: localStorage.length }, (_, index) => localStorage.key(index)).find(
      (name) => name !== null && localStorage.getItem(name) === key,
    );
    expect(slot).toBeDefined();
    localStorage.setItem(slot!, "not a valid request key");
    expect(getOrCreateManagedKeyActionIntent(requester, "rotate", "kms/key-1")).toBeNull();
  });
});
