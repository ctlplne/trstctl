import { describe, it, expect, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { BulkActionRunner } from "@/components/bulk/actions";

describe("U8-2 bulk operations across inventories", () => {
  it("fans a bulk renew across selected rows and reports per-row results", async () => {
    const user = userEvent.setup();
    const action = vi.fn((id: string) => (id === "b" ? Promise.reject(new Error("rate limited")) : Promise.resolve({ id })));
    render(
      <BulkActionRunner
        targets={[
          { id: "a", label: "cert-a" },
          { id: "b", label: "cert-b" },
        ]}
        actionLabel="Bulk renew"
        action={action}
      />,
    );

    await user.click(screen.getByRole("button", { name: "Bulk renew (2)" }));
    await waitFor(() => expect(action).toHaveBeenCalledTimes(2));

    const table = await screen.findByRole("table", { name: "Bulk action results" });
    expect(table).toHaveTextContent("cert-a");
    expect(table).toHaveTextContent("applied");
    expect(table).toHaveTextContent("cert-b");
    expect(table).toHaveTextContent(/rate limited/);
  });
});
