import { beforeEach, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import { MemoryRouter } from "react-router-dom";
import { AppQueryProvider } from "@/lib/query";
import { IntlProvider } from "@/i18n/I18nProvider";
import { PAMCommandRulesPanel } from "@/pages/PAMCommandRulesPanel";
import { PAMCommandActions } from "@/components/access/PAMCommandActions";

const { mocks } = vi.hoisted(() => ({ mocks: { pamTemplates: vi.fn(), updatePAMTemplate: vi.fn(), pamCommandActions: vi.fn() } }));
vi.mock("@/lib/api", async (original) => {
  const actual = await original<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...mocks } };
});
const template = {
  id: "a2620000-0000-4000-8000-000000000001",
  name: "production",
  reason: "Maintenance",
  required_approvals: 2,
  max_ttl_seconds: 300,
  require_recording: false,
  revision: 7,
  saved_at: "2026-11-05T12:00:00Z",
  command_rules: [],
};
beforeEach(() => {
  for (const mock of Object.values(mocks)) mock.mockReset();
  mocks.pamTemplates.mockResolvedValue({ items: [template] });
  mocks.updatePAMTemplate.mockImplementation(async (id, input) => ({ ...input, id, revision: input.revision + 1 }));
  mocks.pamCommandActions.mockResolvedValue({ items: [] });
});
function mount(children: React.ReactNode) {
  return render(
    <MemoryRouter>
      <AppQueryProvider>
        <IntlProvider initialLocale="en-US" initialTimeZone="UTC">
          {children}
        </IntlProvider>
      </AppQueryProvider>
    </MemoryRouter>,
  );
}

it("reviews the exact revision and bounded human rule before saving any change", async () => {
  const user = userEvent.setup();
  const view = mount(<PAMCommandRulesPanel canManage />);
  await user.click(await screen.findByRole("button", { name: "Add command rule" }));
  const dialog = screen.getByRole("dialog");
  await user.selectOptions(within(dialog).getByRole("combobox", { name: "Access template" }), template.id);
  await user.type(within(dialog).getByRole("textbox", { name: "Rule name" }), "Review destructive maintenance");
  await user.click(within(dialog).getByRole("button", { name: "Next" }));
  await user.selectOptions(await within(dialog).findByRole("listbox", { name: "Operation names" }), ["DROP", "TRUNCATE"]);
  await user.selectOptions(within(dialog).getByRole("combobox", { name: "Rule effect" }), "require_approval");
  expect(await within(dialog).findByRole("spinbutton", { name: "Distinct human reviewers" })).toHaveValue(2);
  expect(within(dialog).getByRole("spinbutton", { name: "Review deadline in seconds" })).toHaveValue(30);
  await user.click(within(dialog).getByRole("button", { name: "Next" }));
  expect(await within(dialog).findByText("Exact template revision and rule")).toBeInTheDocument();
  expect(within(dialog).getByText(/They do not review statement text, arguments or bound values/i)).toBeInTheDocument();
  expect(mocks.updatePAMTemplate).not.toHaveBeenCalled();
  expect(await axe(view.container)).toHaveNoViolations();
  await user.click(within(dialog).getByRole("button", { name: "Save reviewed rule" }));
  await waitFor(() =>
    expect(mocks.updatePAMTemplate).toHaveBeenCalledWith(
      template.id,
      expect.objectContaining({
        revision: 7,
        require_recording: false,
        command_rules: [
          expect.objectContaining({
            id: expect.any(String),
            name: "Review destructive maintenance",
            protocol: "postgres",
            operations: ["DROP", "TRUNCATE"],
            effect: "require_approval",
            required_approvals: 2,
            review_ttl_seconds: 30,
            enabled: true,
          }),
        ],
      }),
      expect.any(String),
    ),
  );
  expect(await screen.findByRole("status")).toHaveTextContent("New sessions use the updated template");
});

it("keeps rule management permission separate from reading saved rules", async () => {
  mount(<PAMCommandRulesPanel canManage={false} />);
  await waitFor(() => expect(mocks.pamTemplates).toHaveBeenCalled());
  expect(screen.queryByRole("button", { name: "Add command rule" })).not.toBeInTheDocument();
});

it("shows a held action deadline and an exact approval link without claiming execution", async () => {
  const id = "a2620000-0000-4000-8000-000000000010";
  mocks.pamCommandActions.mockResolvedValue({
    items: [
      {
        id,
        session_id: "session",
        job_id: 7,
        attempt: 1,
        protocol: "postgres",
        connection_id: "connection",
        ordinal: 1,
        phase: "bind",
        rule_ids: ["rule"],
        message_digest: "message-digest",
        policy_digest: "policy-digest",
        status: "pending",
        effective_status: "pending",
        operations: ["DROP"],
        reason: "review_required",
        observed_at: "2026-11-05T12:00:00Z",
        decided_at: "2026-11-05T12:00:00Z",
        review_expires_at: "2026-11-05T12:00:30Z",
        source_event_id: "source",
        approval_request_id: id,
        approval_intent_digest: "sha256:public-bound-intent",
      },
    ],
  });
  const view = mount(<PAMCommandActions sessionID="session" />);
  expect(await screen.findByText("Waiting for independent review")).toBeInTheDocument();
  expect(screen.getByText(/Review ends at/)).toBeInTheDocument();
  expect(screen.getByRole("link", { name: "Open exact review in a new tab" })).toHaveAttribute("href", `/approvals?request=${id}`);
  expect(screen.getByText(/it does not prove target execution/)).toBeInTheDocument();
  expect(await axe(view.container)).toHaveNoViolations();
});

it("keeps SSH selectors separate and reviews the exact direct-command rule", async () => {
  const user = userEvent.setup();
  mount(<PAMCommandRulesPanel canManage />);
  await user.click(await screen.findByRole("button", { name: "Add command rule" }));
  const dialog = screen.getByRole("dialog");
  await user.selectOptions(within(dialog).getByRole("combobox", { name: "Access template" }), template.id);
  await user.type(within(dialog).getByRole("textbox", { name: "Rule name" }), "Review direct removal");
  await user.selectOptions(within(dialog).getByRole("combobox", { name: "Protocol" }), "ssh");
  await user.click(within(dialog).getByRole("button", { name: "Next" }));
  const selectors = await within(dialog).findByRole("listbox", { name: "Operation names" });
  expect(within(selectors).queryByRole("option", { name: "DROP" })).not.toBeInTheDocument();
  await user.selectOptions(selectors, ["rm"]);
  await user.click(within(dialog).getByRole("button", { name: "Next" }));
  await user.click(await within(dialog).findByRole("button", { name: "Save reviewed rule" }));
  await waitFor(() =>
    expect(mocks.updatePAMTemplate).toHaveBeenCalledWith(
      template.id,
      expect.objectContaining({ command_rules: [expect.objectContaining({ protocol: "ssh", operations: ["rm"], effect: "block" })] }),
      expect.any(String),
    ),
  );
});

it("offers MySQL operation classes with a protocol-bound exact preview", async () => {
  const user = userEvent.setup();
  mount(<PAMCommandRulesPanel canManage />);
  await user.click(await screen.findByRole("button", { name: "Add command rule" }));
  const dialog = screen.getByRole("dialog");
  await user.selectOptions(within(dialog).getByRole("combobox", { name: "Access template" }), template.id);
  await user.type(within(dialog).getByRole("textbox", { name: "Rule name" }), "Review MySQL deletion");
  await user.selectOptions(within(dialog).getByRole("combobox", { name: "Protocol" }), "mysql");
  await user.click(within(dialog).getByRole("button", { name: "Next" }));
  const choices = await within(dialog).findByRole("listbox", { name: "Operation names" });
  expect(within(choices).queryByRole("option", { name: "rm" })).not.toBeInTheDocument();
  expect(within(choices).getByRole("option", { name: "REPLACE" })).toBeInTheDocument();
  await user.deselectOptions(choices, ["DROP"]);
  await user.selectOptions(choices, ["DELETE"]);
  await user.click(within(dialog).getByRole("button", { name: "Next" }));
  await user.click(await within(dialog).findByRole("button", { name: "Save reviewed rule" }));
  await waitFor(() =>
    expect(mocks.updatePAMTemplate).toHaveBeenCalledWith(
      template.id,
      expect.objectContaining({ command_rules: [expect.objectContaining({ protocol: "mysql", operations: ["DELETE"] })] }),
      expect.any(String),
    ),
  );
});

it("reviews a Redis command class with no key or value predicate", async () => {
  const user = userEvent.setup();
  mount(<PAMCommandRulesPanel canManage />);
  await user.click(await screen.findByRole("button", { name: "Add command rule" }));
  const dialog = screen.getByRole("dialog");
  await user.selectOptions(within(dialog).getByRole("combobox", { name: "Access template" }), template.id);
  await user.type(within(dialog).getByRole("textbox", { name: "Rule name" }), "Review Redis deletion");
  await user.selectOptions(within(dialog).getByRole("combobox", { name: "Protocol" }), "redis");
  await user.click(within(dialog).getByRole("button", { name: "Next" }));
  const choices = await within(dialog).findByRole("listbox", { name: "Operation names" });
  expect(within(choices).queryByRole("option", { name: "DROP" })).not.toBeInTheDocument();
  expect((within(choices).getByRole("option", { name: "DEL" }) as HTMLOptionElement).selected).toBe(true);
  await user.click(within(dialog).getByRole("button", { name: "Next" }));
  await user.click(await within(dialog).findByRole("button", { name: "Save reviewed rule" }));
  await waitFor(() =>
    expect(mocks.updatePAMTemplate).toHaveBeenCalledWith(
      template.id,
      expect.objectContaining({ command_rules: [expect.objectContaining({ protocol: "redis", operations: ["DEL"] })] }),
      expect.any(String),
    ),
  );
});

it("reviews a MongoDB command class without document predicates", async () => {
  const user = userEvent.setup();
  mount(<PAMCommandRulesPanel canManage />);
  await user.click(await screen.findByRole("button", { name: "Add command rule" }));
  const dialog = screen.getByRole("dialog");
  await user.selectOptions(within(dialog).getByRole("combobox", { name: "Access template" }), template.id);
  await user.type(within(dialog).getByRole("textbox", { name: "Rule name" }), "Review Mongo document deletion");
  await user.selectOptions(within(dialog).getByRole("combobox", { name: "Protocol" }), "mongodb");
  await user.click(within(dialog).getByRole("button", { name: "Next" }));
  const choices = await within(dialog).findByRole("listbox", { name: "Operation names" });
  expect(within(choices).queryByRole("option", { name: "DELETE" })).not.toBeInTheDocument();
  expect((within(choices).getByRole("option", { name: "delete" }) as HTMLOptionElement).selected).toBe(true);
  await user.click(within(dialog).getByRole("button", { name: "Next" }));
  await user.click(await within(dialog).findByRole("button", { name: "Save reviewed rule" }));
  await waitFor(() =>
    expect(mocks.updatePAMTemplate).toHaveBeenCalledWith(
      template.id,
      expect.objectContaining({ command_rules: [expect.objectContaining({ protocol: "mongodb", operations: ["delete"] })] }),
      expect.any(String),
    ),
  );
});
