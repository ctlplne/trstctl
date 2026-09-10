import { describe, expect, it, vi } from "vitest";
import { readIdentityReceiptPages } from "@/pages/identities/IdentityActivityEvidence";

describe("identity receipt page reads", () => {
  it("refuses a response for another identity", async () => {
    const load = vi.fn().mockResolvedValue({ items: [{ id: "receipt", identity_id: "other" }], next_cursor: "" });
    await expect(readIdentityReceiptPages("selected", 1, load, new AbortController().signal)).rejects.toThrow("selected identity");
  });

  it("refuses a cursor cycle without requesting another page", async () => {
    const load = vi.fn().mockResolvedValue({ items: [], next_cursor: "same" });
    await expect(readIdentityReceiptPages("selected", 3, load, new AbortController().signal)).rejects.toThrow("did not advance");
    expect(load).toHaveBeenCalledTimes(2);
  });

  it("stops a cancelled traversal after its in-flight read", async () => {
    const controller = new AbortController();
    const load = vi.fn().mockImplementation(async () => {
      controller.abort();
      return { items: [], next_cursor: "more" };
    });
    await expect(readIdentityReceiptPages("selected", 2, load, controller.signal)).rejects.toMatchObject({ name: "AbortError" });
    expect(load).toHaveBeenCalledTimes(1);
  });

  it("retains one actual returned record per ID across changing pages", async () => {
    const load = vi
      .fn()
      .mockResolvedValueOnce({ items: [{ id: "same", identity_id: "selected", status: "running" }], next_cursor: "more" })
      .mockResolvedValueOnce({ items: [{ id: "same", identity_id: "selected", status: "succeeded" }], next_cursor: "" });
    const result = await readIdentityReceiptPages("selected", 2, load, new AbortController().signal);
    expect(result).toEqual({ items: [{ id: "same", identity_id: "selected", status: "succeeded" }], next_cursor: "" });
  });
});
