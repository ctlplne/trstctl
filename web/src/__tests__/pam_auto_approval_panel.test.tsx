import { beforeEach, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import { AppQueryProvider } from "@/lib/query";
import { IntlProvider } from "@/i18n/I18nProvider";
import { PAMAutoApprovalPanel } from "@/pages/PAMAutoApprovalPanel";
const { mocks } = vi.hoisted(() => ({ mocks: { pamAutoApprovalRules: vi.fn(), savePAMAutoApprovalRule: vi.fn(), deletePAMAutoApprovalRule: vi.fn() } }));
vi.mock("@/lib/api", async (original) => {
  const actual = await original<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...mocks } };
});
const rule = {
  id: "11111111-1111-4111-8111-111111111111",
  name: "Routine incidents",
  applies_to: ["session"],
  target_types: ["postgres"],
  target_ids: ["orders"],
  requester_roles: ["oncall"],
  ticket_pattern: "INC-[0-9]+",
  max_ttl_seconds: 120,
  enabled: true,
  revision: 4,
  saved_at: "2026-11-01T00:00:00Z",
  window: { days: ["mon"], start: "09:00", end: "17:00", time_zone: "America/New_York" },
};
beforeEach(() => {
  for (const m of Object.values(mocks)) m.mockReset();
  mocks.pamAutoApprovalRules.mockResolvedValue({ items: [rule] });
  mocks.savePAMAutoApprovalRule.mockResolvedValue({ ...rule, revision: 5 });
  mocks.deletePAMAutoApprovalRule.mockResolvedValue({ deleted: true });
});
function mount(manage = true) {
  return render(
    <AppQueryProvider>
      <IntlProvider initialLocale="en-US" initialTimeZone="UTC">
        <PAMAutoApprovalPanel canManage={manage} />
      </IntlProvider>
    </AppQueryProvider>,
  );
}
it("reviews exact criteria before saving and preserves the read revision", async () => {
  const user = userEvent.setup();
  const view = mount();
  await user.click(await screen.findByRole("button", { name: "Edit rule" }));
  await user.click(screen.getByRole("button", { name: "Review rule" }));
  expect(mocks.savePAMAutoApprovalRule).not.toHaveBeenCalled();
  const review = screen.getByRole("group", { name: "Review automatic approval" });
  expect(review).toHaveTextContent("America/New_York");
  expect(review).toHaveTextContent(rule.id);
  expect(review).toHaveTextContent("Revision read4");
  expect(review).toHaveTextContent("INC-[0-9]+");
  await user.click(screen.getByRole("button", { name: "Save reviewed rule" }));
  await waitFor(() =>
    expect(mocks.savePAMAutoApprovalRule).toHaveBeenCalledWith(
      rule.id,
      expect.objectContaining({
        revision: 4,
        target_types: ["postgres"],
        target_ids: ["orders"],
        requester_roles: ["oncall"],
        ticket_pattern: "INC-[0-9]+",
        window: rule.window,
        max_ttl_seconds: 120,
        enabled: true,
      }),
      expect.any(String),
    ),
  );
  expect(await axe(view.container)).toHaveNoViolations();
});
it("requires target scope and keeps policy conflicts visible without silently changing the revision", async () => {
  const user = userEvent.setup();
  mount();
  await screen.findByText("Routine incidents");
  await user.type(screen.getByRole("textbox", { name: "Rule name" }), "A rule");
  await user.click(screen.getByRole("button", { name: "Review rule" }));
  expect(await screen.findByText("Choose at least one target type, target ID or folder.")).toBeInTheDocument();
  expect(mocks.savePAMAutoApprovalRule).not.toHaveBeenCalled();
  await user.click(screen.getByRole("button", { name: "Edit rule" }));
  await user.click(screen.getByRole("button", { name: "Review rule" }));
  mocks.savePAMAutoApprovalRule.mockRejectedValue(new Error("the rule changed; read it again"));
  await user.click(screen.getByRole("button", { name: "Save reviewed rule" }));
  expect(await screen.findByText("the rule changed; read it again")).toBeInTheDocument();
  expect(mocks.savePAMAutoApprovalRule).toHaveBeenCalledWith(rule.id, expect.objectContaining({ revision: 4 }), expect.any(String));
});
it("reviews deletion and leaves read-only operators unable to change policy", async () => {
  const user = userEvent.setup();
  const view = mount();
  await user.click(await screen.findByRole("button", { name: "Delete rule" }));
  expect(mocks.deletePAMAutoApprovalRule).not.toHaveBeenCalled();
  await user.click(screen.getByRole("button", { name: "Delete reviewed rule" }));
  await waitFor(() => expect(mocks.deletePAMAutoApprovalRule).toHaveBeenCalledWith(rule.id, 4));
  view.unmount();
  mount(false);
  await screen.findByText("Routine incidents");
  expect(screen.queryByRole("button", { name: "Edit rule" })).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Review rule" })).not.toBeInTheDocument();
});
