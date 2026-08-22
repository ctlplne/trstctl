/* eslint-disable jsx-a11y/no-noninteractive-tabindex -- Wide table regions need focus so keyboard users can scroll clipped columns. */
import type { ReactNode } from "react";

type ScrollableRegionProps = { children: ReactNode; className?: string; label: string };

/** A named keyboard stop for horizontally clipped content. Native horizontal
 * scrolling is pointer-friendly but otherwise leaves keyboard users unable to
 * reach columns or commands beyond the viewport. */
export function ScrollableRegion({ children, className = "", label }: ScrollableRegionProps) {
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

export { ScrollableRegion as ScrollableTableRegion };
