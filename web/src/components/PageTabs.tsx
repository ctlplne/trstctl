import { useRef, type KeyboardEvent, type ReactNode } from "react";
import { cn } from "@/lib/utils";

export type PageTab = {
  id: string;
  label: ReactNode;
  /** Optional count/status chip rendered after the label. */
  badge?: ReactNode;
};

/** PageTabs is the standard workspace switcher for pages that host several
 * workflows: the page's primary object list stays on the first tab, and every
 * specialist panel moves behind a sibling tab instead of stacking into one
 * endless scroll. Keyboard behavior follows the ARIA tabs pattern (roving
 * tabindex, arrow keys, Home/End). Pair with conditional rendering per tab:
 *
 *   {tab === "inventory" && <section role="tabpanel" …>…</section>}
 */
export function PageTabs({
  tabs,
  active,
  onChange,
  ariaLabel,
  idPrefix,
  className,
}: {
  tabs: PageTab[];
  active: string;
  onChange: (id: string) => void;
  ariaLabel: string;
  /** Prefix for tab/panel DOM ids, e.g. "certs" → certs-tab-inventory. */
  idPrefix: string;
  className?: string;
}) {
  const listRef = useRef<HTMLDivElement>(null);

  function focusTabAt(index: number) {
    const buttons = listRef.current?.querySelectorAll<HTMLButtonElement>("[role='tab']");
    const target = buttons?.[(index + tabs.length) % tabs.length];
    target?.focus();
    const id = target?.dataset.tabId;
    if (id) onChange(id);
  }

  function onKeyDown(event: KeyboardEvent<HTMLButtonElement>, index: number) {
    if (event.key === "ArrowRight") {
      event.preventDefault();
      focusTabAt(index + 1);
    } else if (event.key === "ArrowLeft") {
      event.preventDefault();
      focusTabAt(index - 1);
    } else if (event.key === "Home") {
      event.preventDefault();
      focusTabAt(0);
    } else if (event.key === "End") {
      event.preventDefault();
      focusTabAt(tabs.length - 1);
    }
  }

  return (
    <div ref={listRef} role="tablist" aria-label={ariaLabel} className={cn("mb-5 flex flex-wrap gap-1 border-b border-border", className)}>
      {tabs.map((tab, index) => {
        const selected = tab.id === active;
        return (
          <button
            key={tab.id}
            id={`${idPrefix}-tab-${tab.id}`}
            data-tab-id={tab.id}
            type="button"
            role="tab"
            aria-selected={selected}
            aria-controls={`${idPrefix}-panel-${tab.id}`}
            tabIndex={selected ? 0 : -1}
            onClick={() => onChange(tab.id)}
            onKeyDown={(event) => onKeyDown(event, index)}
            className={cn(
              "-mb-px inline-flex min-h-10 items-center gap-2 border-b-2 px-3 text-sm font-medium transition-colors duration-fast focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-accent",
              selected ? "border-primary text-foreground" : "border-transparent text-muted-foreground hover:border-border hover:text-foreground",
            )}
          >
            {tab.label}
            {tab.badge}
          </button>
        );
      })}
    </div>
  );
}

/** tabPanelProps wires the matching tabpanel attributes for a PageTabs id. */
export function tabPanelProps(idPrefix: string, tabId: string) {
  return {
    id: `${idPrefix}-panel-${tabId}`,
    role: "tabpanel" as const,
    "aria-labelledby": `${idPrefix}-tab-${tabId}`,
  };
}
