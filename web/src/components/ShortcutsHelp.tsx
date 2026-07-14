import { useEffect, useRef, type RefObject } from "react";
import { X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { translateNow } from "@/i18n/I18nProvider";

export interface ShortcutsHelpProps {
  open: boolean;
  onClose: () => void;
  returnFocusRef?: RefObject<HTMLElement>;
}

const shortcuts = [
  { keys: "Cmd/Ctrl K", label: translateNow("source.open.command.palette.c022b19a38") },
  { keys: "?", label: translateNow("source.show.keyboard.shortcuts.3d0ced5dc6") },
  { keys: "Esc", label: translateNow("source.close.open.overlay.7f51d8d159") },
  { keys: "Tab", label: translateNow("source.move.within.overlay.659fa0eb0e") },
];

function focusableElements(panel: HTMLElement): HTMLElement[] {
  return Array.from(panel.querySelectorAll<HTMLElement>('a[href], button:not([disabled]), textarea, input, select, [tabindex]:not([tabindex="-1"])'));
}

export function ShortcutsHelp({ open, onClose, returnFocusRef }: ShortcutsHelpProps) {
  const panelRef = useRef<HTMLDivElement>(null);
  const closeRef = useRef<HTMLButtonElement>(null);
  const titleId = "shortcuts-help-title";

  useEffect(() => {
    if (!open) return;
    const previous = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const returnTarget = returnFocusRef?.current ?? previous;
    closeRef.current?.focus();
    return () => {
      returnTarget?.focus();
    };
  }, [open, returnFocusRef]);

  useEffect(() => {
    if (!open) return;
    function onKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape") {
        event.preventDefault();
        onClose();
        return;
      }
      if (event.key !== "Tab" || !panelRef.current) return;
      const focusable = focusableElements(panelRef.current);
      if (focusable.length === 0) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    }
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [onClose, open]);

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50">
      <div className="absolute inset-0 bg-foreground/20" aria-hidden="true" onClick={onClose} />
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        className="absolute right-4 top-16 w-[min(24rem,calc(100vw-2rem))] overflow-hidden rounded-panel border border-border bg-background shadow-elevation3"
      >
        <div className="flex items-center justify-between gap-3 border-b border-border p-comfortable">
          <h2 id={titleId} className="text-heading font-semibold">
            {translateNow("source.keyboard.shortcuts.e9bef0b0f3")}</h2>
          <Button ref={closeRef} type="button" size="sm" variant="ghost" onClick={onClose}>
            <X className="h-4 w-4" aria-hidden="true" />
            {translateNow("source.close.7d9eb7acb1")}</Button>
        </div>
        <div className="p-comfortable">
          <dl className="space-y-3">
            {shortcuts.map((shortcut) => (
              <div key={shortcut.label} className="flex items-center justify-between gap-4">
                <dt className="text-sm font-medium">{shortcut.label}</dt>
                <dd className="rounded border border-border bg-muted px-2 py-1 font-mono text-xs text-muted-foreground">{shortcut.keys}</dd>
              </div>
            ))}
          </dl>
        </div>
      </div>
    </div>
  );
}
