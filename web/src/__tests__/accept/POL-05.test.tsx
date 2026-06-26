import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { ThemeProvider } from "@/components/ThemeProvider";
import { AuthProvider } from "@/auth/AuthProvider";
import { AppRoutes } from "@/App";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    me: vi.fn(),
    owners: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: apiMock };
});

function renderAt(path: string) {
  return render(
    <ThemeProvider>
      <AuthProvider>
        <MemoryRouter initialEntries={[path]}>
          <AppRoutes />
        </MemoryRouter>
      </AuthProvider>
    </ThemeProvider>,
  );
}

describe("POL-05 Owners route polish", () => {
  beforeEach(() => {
    for (const mock of Object.values(apiMock)) mock.mockReset();
    apiMock.me.mockResolvedValue({ subject: "user-1", tenant_id: "t1", email: "u@example.test" });
    apiMock.owners.mockResolvedValue([
      { id: "owner-payments", name: "Payments team", kind: "team", email: "payments@example.test" },
      { id: "owner-platform", name: "Platform service", kind: "workload", email: "platform@example.test" },
    ]);
  });

  it("keeps Owners as a standalone served route with interactive search and filtering", async () => {
    const user = userEvent.setup();
    renderAt("/owners");

    expect(await screen.findByRole("heading", { name: "Owners" })).toBeInTheDocument();

    const search = await screen.findByRole("searchbox", { name: "Search owners" });
    expect(apiMock.owners).toHaveBeenCalledTimes(1);
    await user.type(search, "payments");
    expect(screen.getByRole("row", { name: /Payments team/ })).toBeInTheDocument();
    expect(screen.queryByRole("row", { name: /Platform service/ })).not.toBeInTheDocument();

    await user.clear(search);
    await user.selectOptions(screen.getByLabelText("Owner kind"), "workload");
    expect(screen.getByRole("row", { name: /Platform service/ })).toBeInTheDocument();
    expect(screen.queryByRole("row", { name: /Payments team/ })).not.toBeInTheDocument();
  });
});
