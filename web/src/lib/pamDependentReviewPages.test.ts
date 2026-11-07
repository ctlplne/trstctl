import { expect, it } from "vitest";
import type { PAMDependentHostBinding, PAMServiceDependentReviewHost } from "@/lib/api-types.gen";
import { dependentReviewPages, nativeReviewPageBytes } from "./pamDependentReviewPages";

const digest = "a".repeat(64);
const review = { header: { id: "58200000-0000-4000-8000-000000000001" }, header_digest: digest };
function host(id: string): PAMServiceDependentReviewHost {
  return {
    binding: {
      agent_id: id,
      enabled: true,
      revision: 7,
      account: { account_id: "owned-account", dn: "CN=owned<>&\u2028,DC=example", sid: "owned-sid", guid: "owned-guid" },
    } as PAMDependentHostBinding,
    inventory_run_id: "58200000-0000-4000-8000-000000000002",
    inventory_digest: "b".repeat(64),
    observed_at: "2026-11-07T06:00:00Z",
  };
}
it("packs variable UTF-8 native names within both request and canonical page budgets, preserving full order and empty selected hosts", () => {
  const hosts = [host("first"), host("second"), host("selected-empty")];
  const rows = Array.from({ length: 1536 }, (_, i) => ({
    ref: { agent_id: hosts[i % 2].binding.agent_id, family: "tasks" as const, name: `\\owned\\${i}\\${"<>&\u2028🧪".repeat(i % 7 === 0 ? 300 : 30)}` },
    probe: `owned-probe-${i}`,
  }));
  const original = JSON.stringify(rows);
  const pages = [...dependentReviewPages(review, hosts, rows, "owned invalid draft")];
  expect(pages.length).toBeGreaterThan(1);
  expect(pages.flatMap((p) => p.entries ?? []).map((e) => ({ ref: e.ref, probe: e.probe_id }))).toEqual(rows);
  expect(new Set(pages.flatMap((p) => p.hosts ?? []).map((h) => h.binding.agent_id))).toEqual(new Set(hosts.map((h) => h.binding.agent_id)));
  pages.forEach((p, n) => {
    expect(new TextEncoder().encode(JSON.stringify(p)).length).toBeLessThanOrEqual(65536);
    expect(nativeReviewPageBytes(review.header.id, n, p)).toBeLessThanOrEqual(65536);
  });
  expect(JSON.stringify(rows)).toBe(original);
});
it("refuses an unrepresentable single native source and foreign or duplicated host identities", () => {
  const first = host("first");
  expect(() => [...dependentReviewPages(review, [first, first], [], "owned invalid draft")]).toThrow("owned invalid draft");
  expect(() => [
    ...dependentReviewPages(review, [first], [{ ref: { agent_id: "foreign", family: "services", name: "owned" }, probe: "owned" }], "owned invalid draft"),
  ]).toThrow("owned invalid draft");
  const oversized = { ...first, binding: { ...first.binding, account: { ...first.binding.account, dn: "<".repeat(20000) } } };
  expect(() => [...dependentReviewPages(review, [oversized], [], "owned invalid draft")]).toThrow("owned invalid draft");
});
