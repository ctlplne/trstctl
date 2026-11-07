import { beforeEach, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { IntlProvider } from "@/i18n/I18nProvider";
import type { PAMServiceDependentRotationIntent } from "@/lib/api-types.gen";
import { PAMDependentManifestPages } from "@/pages/PAMDependentManifestPages";
const mock = vi.hoisted(() => ({ pamServiceDependentReviewPage: vi.fn(), pamServiceReconciliationReviewPage: vi.fn() }));
vi.mock("@/lib/api", async (original) => ({ ...(await original<typeof import("@/lib/api")>()), api: mock }));
const header = "a".repeat(64),
  first = "b".repeat(64),
  tail = "c".repeat(64),
  digest = "d".repeat(64);
const host = { binding: { agent_id: "owned-host", account: { account_id: "owned-account" } }, inventory_run_id: "owned-scan", inventory_digest: header };
const intent = {
  plan: {
    version: 2,
    id: "owned-review",
    account: { account_id: "owned-account" },
    expires_at: "2099-01-01T00:00:00Z",
    manifest: {
      version: 1,
      id: "owned-review",
      digest,
      header_digest: header,
      tail_digest: tail,
      page_count: 2,
      entry_count: 2,
      host_count: 1,
      expires_at: "2099-01-01T00:00:00Z",
    },
  },
} as PAMServiceDependentRotationIntent;
const pages = [first, tail].map((d, i) => ({
  version: 1,
  id: "owned-review",
  header_digest: header,
  previous_digest: i ? first : header,
  page_number: i,
  digest: d,
  hosts: [host],
  entries: [{ host, ref: { agent_id: "owned-host", family: "services", name: `owned-${i}` }, probe_id: `useful-${i}` }],
}));
beforeEach(() => {
  Object.values(mock).forEach((m) => m.mockReset());
  mock.pamServiceDependentReviewPage.mockImplementation(async (_id, n) => pages[n]);
  mock.pamServiceReconciliationReviewPage.mockImplementation(async (_id, n) => pages[n]);
});
function mount(access: "operator" | "approver", ready: (digest: string | null) => void) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const view = render(
    <QueryClientProvider client={client}>
      <IntlProvider initialLocale="en-US" initialTimeZone="UTC">
        <PAMDependentManifestPages intent={intent} digest={digest} access={access} onReadiness={ready} />
      </IntlProvider>
    </QueryClientProvider>,
  );
  return { client, ...view };
}
it("requires every exact page before readiness and uses only the approver route without retaining previous page bodies", async () => {
  const ready = vi.fn();
  const { client } = mount("approver", ready);
  const user = userEvent.setup();
  await screen.findByText("owned-0", { exact: false });
  expect(ready).not.toHaveBeenLastCalledWith(digest);
  await user.click(screen.getByRole("button", { name: "Next review page" }));
  await screen.findByText("owned-1", { exact: false });
  await waitFor(() => expect(ready).toHaveBeenLastCalledWith(digest));
  expect(mock.pamServiceDependentReviewPage).not.toHaveBeenCalled();
  expect(mock.pamServiceReconciliationReviewPage).toHaveBeenNthCalledWith(2, "owned-review", 1);
  await waitFor(() => expect(client.getQueryData(["pam-dependent-review-page", "approver", "owned-review", digest, 0])).toBeUndefined());
});
it("keeps readiness closed for a failed or substituted later page and recovers only its exact read", async () => {
  const ready = vi.fn();
  mock.pamServiceDependentReviewPage.mockImplementation(async (_id, n) => (n ? { ...pages[1], previous_digest: "e".repeat(64) } : pages[0]));
  mount("operator", ready);
  const user = userEvent.setup();
  await screen.findByText("owned-0", { exact: false });
  await user.click(screen.getByRole("button", { name: "Next review page" }));
  await screen.findByRole("alert");
  expect(ready).not.toHaveBeenLastCalledWith(digest);
  mock.pamServiceDependentReviewPage.mockImplementation(async (_id, n) => pages[n]);
  await user.click(screen.getByRole("button", { name: "Retry read" }));
  await screen.findByText("owned-1", { exact: false });
  await waitFor(() => expect(ready).toHaveBeenLastCalledWith(digest));
});

it("keeps expired or malformed public pages closed without crashing", async () => {
  const ready = vi.fn();
  mock.pamServiceDependentReviewPage.mockResolvedValue({ ...pages[0], hosts: [null] });
  const view = mount("operator", ready);
  await screen.findByRole("alert");
  expect(ready).not.toHaveBeenLastCalledWith(digest);
  view.unmount();
  mock.pamServiceDependentReviewPage.mockImplementation(async (_id, n) => pages[n]);
  const expired = {
    ...intent,
    plan: { ...intent.plan, expires_at: "2000-01-01T00:00:00Z", manifest: { ...intent.plan.manifest!, expires_at: "2000-01-01T00:00:00Z" } },
  };
  const client = new QueryClient();
  render(
    <QueryClientProvider client={client}>
      <IntlProvider initialLocale="en-US" initialTimeZone="UTC">
        <PAMDependentManifestPages intent={expired} digest={digest} onReadiness={ready} />
      </IntlProvider>
    </QueryClientProvider>,
  );
  const user = userEvent.setup();
  await screen.findByText("owned-0", { exact: false });
  await user.click(screen.getByRole("button", { name: "Next review page" }));
  await screen.findByText("owned-1", { exact: false });
  await screen.findByText("This review expired.", { exact: false });
  expect(ready).not.toHaveBeenLastCalledWith(digest);
});

it("requires a fresh page traversal when the exact root or digest changes", async () => {
  const ready = vi.fn();
  const view = mount("operator", ready);
  const user = userEvent.setup();
  await screen.findByText("owned-0", { exact: false });
  await user.click(screen.getByRole("button", { name: "Next review page" }));
  await waitFor(() => expect(ready).toHaveBeenLastCalledWith(digest));
  const nextDigest = "e".repeat(64);
  const nextIntent = { ...intent, plan: { ...intent.plan, id: "other-review", manifest: { ...intent.plan.manifest!, id: "other-review" } } };
  mock.pamServiceDependentReviewPage.mockImplementation(async (id, n) => ({ ...pages[n], id }));
  view.rerender(
    <QueryClientProvider client={view.client}>
      <IntlProvider initialLocale="en-US" initialTimeZone="UTC">
        <PAMDependentManifestPages intent={nextIntent} digest={nextDigest} onReadiness={ready} />
      </IntlProvider>
    </QueryClientProvider>,
  );
  await screen.findByText("owned-0", { exact: false });
  await waitFor(() => expect(ready).toHaveBeenLastCalledWith(null));
  await user.click(screen.getByRole("button", { name: "Next review page" }));
  await waitFor(() => expect(ready).toHaveBeenLastCalledWith(nextDigest));
});
