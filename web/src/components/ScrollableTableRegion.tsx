/* eslint-disable jsx-a11y/no-noninteractive-tabindex -- Wide table regions need focus so keyboard users can scroll clipped columns. */
import type { ReactNode } from "react";

export function ScrollableTableRegion({ children, className = "", label }: { children: ReactNode; className?: string; label: string }) {
  return (
    <div
      aria-label={label}
      className={`${className} min-w-0 max-w-full overflow-x-auto rounded-md border border-border focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus focus-visible:ring-offset-2`}
      role="group"
      tabIndex={0}
    >
      {children}
    </div>
  );
}
