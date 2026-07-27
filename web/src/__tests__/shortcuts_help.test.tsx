import { createRef } from "react";
import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { ShortcutsHelp } from "@/components/ShortcutsHelp";

describe("keyboard shortcuts help", () => {
  it("stays absent while closed", () => {
    const { container } = render(<ShortcutsHelp open={false} onClose={vi.fn()} />);
    expect(container).toBeEmptyDOMElement();
  });

  it("traps focus, closes from keyboard and backdrop, and restores the opener", () => {
    const onClose = vi.fn();
    const openerRef = createRef<HTMLButtonElement>();
    const { container, rerender } = render(
      <>
        <button ref={openerRef}>Open help</button>
        <ShortcutsHelp open onClose={onClose} returnFocusRef={openerRef} />
      </>,
    );

    const dialog = screen.getByRole("dialog", { name: "Keyboard shortcuts" });
    const close = screen.getByRole("button", { name: "Close" });
    expect(dialog).toBeInTheDocument();
    expect(close).toHaveFocus();

    fireEvent.keyDown(document, { key: "Tab", shiftKey: true });
    expect(close).toHaveFocus();
    fireEvent.keyDown(document, { key: "Tab" });
    expect(close).toHaveFocus();
    fireEvent.keyDown(document, { key: "Unrelated" });
    expect(onClose).not.toHaveBeenCalled();

    fireEvent.keyDown(document, { key: "Escape" });
    expect(onClose).toHaveBeenCalledTimes(1);
    fireEvent.click(container.querySelector(".absolute.inset-0") as HTMLElement);
    expect(onClose).toHaveBeenCalledTimes(2);
    fireEvent.click(close);
    expect(onClose).toHaveBeenCalledTimes(3);

    rerender(
      <>
        <button ref={openerRef}>Open help</button>
        <ShortcutsHelp open={false} onClose={onClose} returnFocusRef={openerRef} />
      </>,
    );
    expect(openerRef.current).toHaveFocus();
  });

  it("falls back to the previously focused element when no opener ref is supplied", () => {
    const previous = document.createElement("button");
    document.body.append(previous);
    previous.focus();
    const { rerender } = render(<ShortcutsHelp open onClose={vi.fn()} />);

    expect(screen.getByRole("button", { name: "Close" })).toHaveFocus();
    rerender(<ShortcutsHelp open={false} onClose={vi.fn()} />);
    expect(previous).toHaveFocus();
    previous.remove();
  });
});
