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
  // A269: the template's desktop clipboard policy, blocked by default.
  const clipboard = screen.getByRole("combobox", { name: "Desktop clipboard for production" });
  expect(clipboard).toHaveValue("deny");
  await user.selectOptions(clipboard, "both");
  await waitFor(() => expect(mocks.updatePAMTemplate).toHaveBeenCalledWith(template.id, { ...template, desktop_clipboard: "both" }));
  // A277: a template is made high-risk by its fresh sign-in window.
  const freshSignIn = screen.getByRole("combobox", { name: "Fresh sign-in for production" });
  expect(freshSignIn).toHaveValue("0");
  expect(Array.from((freshSignIn as HTMLSelectElement).options).map((o) => o.text)).toEqual(["Not required", "Within 5 min", "Within 15 min", "Within 60 min"]);
  await user.selectOptions(freshSignIn, "300");
  await waitFor(() => expect(mocks.updatePAMTemplate).toHaveBeenCalledWith(template.id, { ...template, reauthenticate_within_seconds: 300 }));
  expect(await axe(view.container)).toHaveNoViolations();
});
it("sets a template's web sign-in for web admin consoles, field names only (A273)", async () => {
  const user = userEvent.setup();
  const view = mount();
  await user.click(await screen.findByRole("button", { name: "Set web sign-in" }));
  const editor = screen.getByRole("group", { name: "Web sign-in for production" });
  await user.selectOptions(screen.getByRole("combobox", { name: "Mode" }), "form");
  const path = screen.getByRole("textbox", { name: "Sign-in page" });
  await user.clear(path);
  await user.type(path, "/ui/login");
  await user.type(screen.getByRole("textbox", { name: "Cookies the browser may hold (comma-separated, optional)" }), "XSRF-TOKEN");
  expect(editor).toHaveTextContent("never a password");
  await user.click(screen.getByRole("button", { name: "Save sign-in" }));
  await waitFor(() =>
    expect(mocks.updatePAMTemplate).toHaveBeenCalledWith(template.id, {
      ...template,
      web_sign_in: { mode: "form", login_path: "/ui/login", username_field: "username", password_field: "password", browser_cookies: ["XSRF-TOKEN"] },
    }),
  );
  expect(await axe(view.container)).toHaveNoViolations();
});
it("sets a single sign-on for a console that signs in through its identity provider (A273-O1)", async () => {
  const user = userEvent.setup();
  mount();
  await user.click(await screen.findByRole("button", { name: "Set web sign-in" }));
  const editor = screen.getByRole("group", { name: "Web sign-in for production" });
  await user.selectOptions(screen.getByRole("combobox", { name: "Mode" }), "sso");
  expect(editor).toHaveTextContent("The browser never reaches the identity provider.");
  const path = screen.getByRole("textbox", { name: "Sign-in page" });
  await user.clear(path);
  await user.type(path, "/oauth/start");
  await user.click(screen.getByRole("button", { name: "Save sign-in" }));
  await waitFor(() =>
    expect(mocks.updatePAMTemplate).toHaveBeenCalledWith(template.id, {
      ...template,
      web_sign_in: { mode: "sso", login_path: "/oauth/start", username_field: "username", password_field: "password", browser_cookies: [] },
    }),
  );
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
