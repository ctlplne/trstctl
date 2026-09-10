import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { expect, it, vi } from "vitest";
import { AuthProvider } from "@/auth/AuthProvider";
import { AppShell } from "@/components/AppShell";
import { AppQueryProvider } from "@/lib/query";

const delayed = vi.hoisted(() => {
  let release!: () => void;
  const pending = new Promise<void>((resolve) => {
    release = resolve;
  });
  return { pending, release, started: false, finished: false };
});
vi.mock("@/components/CommandPalette", async (original) => {
  delayed.started = true;
  await delayed.pending;
  const module = await original();
  delayed.finished = true;
  return module;
});
vi.mock("@/lib/bootstrapApi", async (original) => {
  const module = await original<typeof import("@/lib/bootstrapApi")>();
  return {
    ...module,
    bootstrapApi: {
      ...module.bootstrapApi,
      me: vi.fn().mockResolvedValue({ subject: "overlay-test", tenant_id: "test-tenant", permissions: ["*"] }),
      authMethods: vi.fn().mockResolvedValue({ oidc: true, saml: false, ldap: false }),
      notifications: vi.fn().mockResolvedValue({ items: [] }),
    },
  };
});

it("does not fetch the palette before use or reopen it after Escape during its real module load", async () => {
  const user = userEvent.setup();
  render(
    <AppQueryProvider>
      <AuthProvider>
        <MemoryRouter>
          <AppShell />
        </MemoryRouter>
      </AuthProvider>
    </AppQueryProvider>,
  );
  const opener = (await screen.findAllByRole("button", { name: "Open task search" }))[0];
  expect(delayed.started).toBe(false);
  await user.click(opener);
  await waitFor(() => expect(delayed.started).toBe(true));
  expect(screen.queryByRole("dialog", { name: "What do you need?" })).not.toBeInTheDocument();
  fireEvent.keyDown(document, { key: "Escape" });
  await act(async () => {
    delayed.release();
  });
  await waitFor(() => expect(delayed.finished).toBe(true));
  expect(screen.queryByRole("dialog", { name: "What do you need?" })).not.toBeInTheDocument();
  expect(opener).toHaveFocus();
  await user.click(opener);
  const palette = await screen.findByRole("dialog", { name: "What do you need?" });
  expect(within(palette).getByRole("searchbox", { name: "Search or start a task" })).toHaveFocus();
  await user.keyboard("{Escape}");
  expect(screen.queryByRole("dialog", { name: "What do you need?" })).not.toBeInTheDocument();
  expect(opener).toHaveFocus();
});
