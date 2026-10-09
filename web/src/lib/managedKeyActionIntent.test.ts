import { describe, expect, it } from "vitest";
import { managedKeyActionIntent } from "./managedKeyActionIntent";

const requester = { tenant_id: "tenant-a", subject: "eval-admin" };

describe("managed-key dual-control action intent", () => {
  it("derives one stable retry key from the exact actor, provider, action, key, and version without browser storage", async () => {
    const first = await managedKeyActionIntent(requester, "rotate", "aws-kms", "kms/key-1", 1);
    expect(first).toMatch(/^mka2-[0-9a-f]{64}$/);
    expect(await managedKeyActionIntent({ ...requester }, "rotate", "aws-kms", "kms/key-1", 1)).toBe(first);
    expect(await managedKeyActionIntent(requester, "rotate", "aws-kms", "kms/key-1", 2)).not.toBe(first);
    expect(await managedKeyActionIntent(requester, "revoke", "aws-kms", "kms/key-1", 1)).not.toBe(first);
    expect(await managedKeyActionIntent(requester, "rotate", "pkcs11", "kms/key-1", 1)).not.toBe(first);
    expect(await managedKeyActionIntent(requester, "rotate", "aws-kms", "kms/key-2", 1)).not.toBe(first);
    expect(await managedKeyActionIntent({ tenant_id: "tenant-b", subject: requester.subject }, "rotate", "aws-kms", "kms/key-1", 1)).not.toBe(first);
    expect(await managedKeyActionIntent({ tenant_id: requester.tenant_id, subject: "another-requester" }, "rotate", "aws-kms", "kms/key-1", 1)).not.toBe(first);
    expect(localStorage.length).toBe(0);
  });

  it("fails closed when the resource version or digest service is unavailable", async () => {
    expect(await managedKeyActionIntent(requester, "rotate", "aws-kms", "kms/key-1", 0)).toBeNull();
    expect(await managedKeyActionIntent(requester, "rotate", "", "kms/key-1", 1)).toBeNull();
  });
});
