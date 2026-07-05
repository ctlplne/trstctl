import { useRef, type ReactNode, type RefObject } from "react";
import { X } from "lucide-react";
import { Dialog } from "@/components/Dialog";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

export type DetailDrawerProps = {
  open: boolean;
  title: ReactNode;
  description?: ReactNode;
  children: ReactNode;
  actions?: ReactNode;
  onClose: () => void;
  returnFocusRef?: RefObject<HTMLElement>;
  className?: string;
};

export function DetailDrawer({ open, title, description, children, actions, onClose, returnFocusRef, className }: DetailDrawerProps) {
  const closeRef = useRef<HTMLButtonElement>(null);
  const titleId = "detail-drawer-title";
  const descriptionId = description ? "detail-drawer-description" : undefined;

  return (
    <Dialog
      open={open}
      onClose={onClose}
      titleId={titleId}
      descriptionId={descriptionId}
      returnFocusRef={returnFocusRef}
      initialFocusRef={closeRef}
      panelAnimation="drawer"
      overlayClassName="absolute inset-0 bg-foreground/20"
      panelClassName={cn("absolute right-0 top-0 flex h-full w-full max-w-xl flex-col border-l border-border bg-background shadow-elevation3", className)}
    >
        <header className="border-b border-border p-comfortable">
          <div className="flex items-start justify-between gap-3">
            <div>
              <h2 id={titleId} className="text-heading font-semibold">
                {title}
              </h2>
              {description && (
                <p id={descriptionId} className="mt-1 text-body text-muted-foreground">
                  {description}
                </p>
              )}
            </div>
            <Button ref={closeRef} type="button" size="sm" variant="ghost" onClick={onClose}>
              <X className="h-4 w-4" aria-hidden="true" />
              Close
            </Button>
          </div>
          {actions && <div className="mt-3 flex flex-wrap gap-2">{actions}</div>}
        </header>
        <div className="min-h-0 flex-1 overflow-y-auto p-comfortable">{children}</div>
    </Dialog>
  );
}
