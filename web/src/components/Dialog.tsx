import { useEffect, useRef, type ReactNode, type RefObject } from "react";
import { cn } from "@/lib/utils";

const focusableSelector = [
  "a[href]",
  "button:not([disabled])",
  "textarea:not([disabled])",
  "input:not([disabled])",
  "select:not([disabled])",
  '[tabindex]:not([tabindex="-1"])',
].join(",");

export type DialogProps = {
  open: boolean;
  children: ReactNode;
  onClose: () => void;
  titleId: string;
  descriptionId?: string;
  role?: "dialog" | "alertdialog";
  returnFocusRef?: RefObject<HTMLElement>;
  initialFocusRef?: RefObject<HTMLElement>;
  className?: string;
  overlayClassName?: string;
  panelClassName?: string;
  closeOnBackdropClick?: boolean;
  /** Entrance motion for the panel: centered dialog pop, end-edge drawer slide, or none. */
  panelAnimation?: "panel" | "drawer" | "none";
};

export function Dialog({
  children,
  className,
  closeOnBackdropClick = true,
  descriptionId,
  initialFocusRef,
  onClose,
  open,
  overlayClassName = "absolute inset-0 bg-foreground/20",
  panelAnimation = "panel",
  panelClassName,
  returnFocusRef,
  role = "dialog",
  titleId,
}: DialogProps) {
  const rootRef = useRef<HTMLDivElement>(null);
  const panelRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open || !rootRef.current?.parentElement) return;
    const root = rootRef.current;
    const parent = root.parentElement;
    if (!parent) return;
    const siblings = Array.from(parent.children).filter((child) => child !== root) as HTMLElement[];
    const previous = siblings.map((element) => ({
      element,
      ariaHidden: element.getAttribute("aria-hidden"),
      inert: element.inert,
    }));
    for (const element of siblings) {
      element.setAttribute("aria-hidden", "true");
      element.inert = true;
    }
    return () => {
      for (const { element, ariaHidden, inert } of previous) {
        if (ariaHidden === null) element.removeAttribute("aria-hidden");
        else element.setAttribute("aria-hidden", ariaHidden);
        element.inert = inert;
      }
    };
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const previous = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const returnTarget = returnFocusRef?.current ?? previous;
    const focusTarget = initialFocusRef?.current ?? firstFocusable(panelRef.current) ?? panelRef.current;
    focusTarget?.focus();
    return () => {
      if (returnTarget && document.contains(returnTarget)) returnTarget.focus();
    };
  }, [initialFocusRef, open, returnFocusRef]);

  useEffect(() => {
    if (!open) return;
    function onKeyDown(event: KeyboardEvent) {
      const openModals = Array.from(document.querySelectorAll<HTMLElement>('[role="dialog"][aria-modal="true"], [role="alertdialog"][aria-modal="true"]'));
      if (openModals.at(-1) !== panelRef.current) return;
      if (event.key === "Escape") {
        event.preventDefault();
        onClose();
        return;
      }
      if (event.key !== "Tab" || !panelRef.current) return;
      const focusable = focusableElements(panelRef.current);
      if (focusable.length === 0) {
        event.preventDefault();
        panelRef.current.focus();
        return;
      }
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (!focusable.some((element) => element === document.activeElement)) {
        // A heading or panel may own initial focus without being a Tab stop.
        // Enter the modal's tab order instead of escaping behind the overlay.
        event.preventDefault();
        (event.shiftKey ? last : first).focus();
      } else if (event.shiftKey && document.activeElement === first) {
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
    <div ref={rootRef} className={className ?? "fixed inset-0 z-50"} role="presentation">
      <div className={cn(overlayClassName, "motion-safe:animate-overlay-in")} aria-hidden="true" onClick={closeOnBackdropClick ? onClose : undefined} />
      <div
        ref={panelRef}
        role={role}
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={descriptionId}
        className={cn(
          panelClassName,
          panelAnimation === "panel" && "motion-safe:animate-panel-in",
          panelAnimation === "drawer" && "motion-safe:animate-drawer-in",
        )}
        tabIndex={-1}
      >
        {children}
      </div>
    </div>
  );
}

function focusableElements(panel: HTMLElement): HTMLElement[] {
  return Array.from(panel.querySelectorAll<HTMLElement>(focusableSelector)).filter((element) => !element.hasAttribute("disabled"));
}

function firstFocusable(panel: HTMLElement | null): HTMLElement | null {
  if (!panel) return null;
  return focusableElements(panel)[0] ?? null;
}
