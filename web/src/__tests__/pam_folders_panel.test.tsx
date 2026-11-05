import { beforeEach, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import { AppQueryProvider } from "@/lib/query";
import { IntlProvider } from "@/i18n/I18nProvider";
import { PAMFoldersPanel } from "@/pages/PAMFoldersPanel";

const { mocks } = vi.hoisted(() => ({
  mocks: {
    pamFolders: vi.fn(),
    pamTemplates: vi.fn(),
    pamTargets: vi.fn(),
    savePAMFolder: vi.fn(),
    deletePAMFolder: vi.fn(),
    setPAMTargetFolder: vi.fn(),
    updatePAMTemplate: vi.fn(),
  },
}));
vi.mock("@/lib/api", async (original) => {
  const actual = await original<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...mocks } };
});
const template = {
  id: "template-prod",
  name: "production",
  reason: "Incident",
  required_approvals: 3,
  max_ttl_seconds: 60,
  require_recording: true,
  revision: 4,
};
beforeEach(() => {
  for (const mock of Object.values(mocks)) mock.mockReset();
  mocks.pamFolders.mockResolvedValue({ items: [{ name: "prod", template_id: template.id, targets: 1, revision: 2 }] });
  mocks.pamTemplates.mockResolvedValue({ items: [template] });
  mocks.pamTargets.mockResolvedValue({ items: [{ id: "orders", target_type: "postgres", folder: "", source: "tenant", enabled: true }] });
  mocks.savePAMFolder.mockResolvedValue({ name: "stage", template_id: template.id, revision: 1 });
  mocks.setPAMTargetFolder.mockResolvedValue({ id: "orders", folder: "prod" });
  mocks.updatePAMTemplate.mockResolvedValue({ ...template, require_recording: false, revision: 5 });
});
function mount(manage = true) {
  return render(
    <AppQueryProvider>
      <IntlProvider initialLocale="en-US" initialTimeZone="UTC">
        <PAMFoldersPanel canManage={manage} />
      </IntlProvider>
    </AppQueryProvider>,
  );
}
it("saves a folder with a known template, moves an account, and updates the exact recording revision", async () => {
  const user = userEvent.setup();
  const view = mount();
  await screen.findByRole("table", { name: "Account folders" });
  expect(await screen.findByText("Recording required")).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Delete empty folder" })).toBeDisabled();
  await user.type(screen.getByRole("textbox", { name: "Folder name" }), "stage");
  await user.selectOptions(screen.getByRole("combobox", { name: "Access template" }), template.id);
  await user.click(screen.getByRole("button", { name: "Save folder" }));
  await waitFor(() =>
    expect(mocks.savePAMFolder).toHaveBeenCalledWith("stage", { template_id: template.id, revision: 0, description: "" }, expect.any(String)),
  );
  await user.selectOptions(screen.getByRole("combobox", { name: "Folder for orders" }), "prod");
  await user.click(screen.getByRole("button", { name: "Move account" }));
  await waitFor(() => expect(mocks.setPAMTargetFolder).toHaveBeenCalledWith("postgres", "orders", "prod"));
  await user.click(screen.getByRole("button", { name: "Allow unrecorded access" }));
  await waitFor(() => expect(mocks.updatePAMTemplate).toHaveBeenCalledWith(template.id, { ...template, require_recording: false }));
  expect(await axe(view.container)).toHaveNoViolations();
});
it("preserves a revision conflict for the operator and gates configuration by permission", async () => {
  const user = userEvent.setup();
  mocks.savePAMFolder.mockRejectedValue(new Error("the folder changed; read it again"));
  const view = mount();
  await user.click(await screen.findByRole("button", { name: "Edit folder" }));
  await user.click(screen.getByRole("button", { name: "Save folder" }));
  expect(await screen.findByText("the folder changed; read it again")).toBeInTheDocument();
  expect(mocks.savePAMFolder).toHaveBeenCalledWith("prod", expect.objectContaining({ revision: 2 }), expect.any(String));
  view.unmount();
  mount(false);
  await screen.findByText("Recording required");
  expect(screen.queryByRole("button", { name: "Edit folder" })).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Allow unrecorded access" })).not.toBeInTheDocument();
  expect(screen.queryByRole("textbox", { name: "Folder name" })).not.toBeInTheDocument();
});
