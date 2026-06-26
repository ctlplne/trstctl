import { describe, it, expect, vi } from "vitest";
import { render, screen, renderHook, act } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useBulkSelection, runBulk } from "@/lib/bulk";
import { BulkActionBar } from "@/components/bulk";

describe("U0-6 bulk-action primitive", () => {
  it("tracks multi-selection state", () => {
    const { result } = renderHook(() => useBulkSelection());
    act(() => result.current.toggle("a"));
    act(() => result.current.toggle("b"));
    expect(result.current.count).toBe(2);
    expect(result.current.isSelected("a")).toBe(true);
    act(() => result.current.toggle("a"));
    expect(result.current.isSelected("a")).toBe(false);
    act(() => result.current.clear());
    expect(result.current.count).toBe(0);
  });

  it("fans out a bulk action and reports per-row success and failure", async () => {
    const results = await runBulk(["a", "b", "c"], async (id) => {
      if (id === "b") throw new Error("boom");
      return id.toUpperCase();
    });
    expect(results).toEqual([
      { id: "a", ok: true, value: "A" },
      { id: "b", ok: false, error: expect.stringContaining("boom") },
      { id: "c", ok: true, value: "C" },
    ]);
  });

  it("renders the bulk bar only when something is selected and clears on demand", async () => {
    const onClear = vi.fn();
    const { rerender } = render(
      <BulkActionBar count={0} onClear={onClear}>
        <button type="button">Renew</button>
      </BulkActionBar>,
    );
    expect(screen.queryByRole("region", { name: "Bulk actions" })).not.toBeInTheDocument();

    rerender(
      <BulkActionBar count={2} onClear={onClear}>
        <button type="button">Renew</button>
      </BulkActionBar>,
    );
    expect(screen.getByText("2 selected")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Clear selection" }));
    expect(onClear).toHaveBeenCalledTimes(1);
  });
});
