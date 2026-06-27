import type { ReactNode } from "react";
import { PageHeader } from "@/components/PageHeader";
import { cn } from "@/lib/utils";

export type ListPageProps = {
  title: string;
  titleId: string;
  description?: string;
  /** Right-aligned header actions (primary CTA, refresh, …). */
  actions?: ReactNode;
  /** Filter/search bar rendered under the header, above the content. */
  toolbar?: ReactNode;
  children: ReactNode;
  className?: string;
};

/**
 * ListPage is the shared frame for trstctl's list/inventory pages (F4: one
 * consistent page template). It composes the standard PageHeader (title +
 * description + right-aligned actions) over an optional toolbar over the page
 * body (typically a DataTable), so every list page has the same shape and pages
 * stop re-implementing the `<section> + PageHeader + filters` boilerplate.
 */
export function ListPage({ title, titleId, description, actions, toolbar, children, className }: ListPageProps) {
  return (
    <section aria-labelledby={titleId} className={cn("space-y-4", className)}>
      <PageHeader title={title} titleId={titleId} description={description} actions={actions} />
      {toolbar}
      {children}
    </section>
  );
}
