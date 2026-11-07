import { expect, it, vi } from "vitest";
import type { api } from "@/lib/api";
import { createPAMDependentReview } from "./createPAMDependentReview";

it("retries exact opening/page/seal writes after a lost response and returns only the server's sealed intent", async () => {
  const h = "a".repeat(64),
    tail = "b".repeat(64),
    sealDigest = "c".repeat(64),
    intentDigest = "d".repeat(64);
  const id = "58200000-0000-4000-8000-000000000001";
  const host = { binding: { agent_id: "owned-host", enabled: true }, inventory_digest: h, inventory_run_id: "owned-scan", observed_at: "2026-11-07T06:00:00Z" };
  const root = { header: { id, account: { account_id: "owned-account" }, secret_name: "owned/password" }, header_digest: h };
  const intent = { plan: { id, account: root.header.account, secret_name: root.header.secret_name, manifest: { id, digest: sealDigest } } };
  const sealed = {
    ...root,
    page_count: 1,
    host_count: 1,
    entry_count: 0,
    seal: { id, digest: sealDigest, header_digest: h, tail_digest: tail, page_count: 1, host_count: 1, entry_count: 0 },
    intent,
    intent_digest: intentDigest,
  };
  const client = {
    openPAMServiceDependentReview: vi.fn().mockResolvedValue(root),
    appendPAMServiceDependentReviewPage: vi
      .fn()
      .mockRejectedValueOnce(new Error("owned lost reply"))
      .mockImplementation(async (_id, page, input) => ({ ...input, version: 1, id, page_number: page, digest: tail })),
    sealPAMServiceDependentReview: vi.fn().mockResolvedValue(sealed),
    pamServiceDependentReview: vi.fn().mockResolvedValue(sealed),
  };
  const keys = new Map<string, string>();
  const key = (value: unknown) => {
    const json = JSON.stringify(value);
    if (!keys.has(json)) keys.set(json, `owned-${keys.size}`);
    return keys.get(json)!;
  };
  const call = () =>
    createPAMDependentReview(
      client as unknown as typeof api,
      "owned-account",
      { secret_name: "owned/password" },
      [host] as never,
      [],
      key,
      "owned invalid review",
    );
  await expect(call()).rejects.toThrow("owned lost reply");
  expect(client.sealPAMServiceDependentReview).not.toHaveBeenCalled();
  await expect(call()).resolves.toEqual({ intent, intent_digest: intentDigest });
  expect(client.openPAMServiceDependentReview.mock.calls[0]).toEqual(client.openPAMServiceDependentReview.mock.calls[1]);
  expect(client.appendPAMServiceDependentReviewPage.mock.calls[0]).toEqual(client.appendPAMServiceDependentReviewPage.mock.calls[1]);
  expect(client.appendPAMServiceDependentReviewPage.mock.calls[1][2].hosts).toEqual([host]);
});
