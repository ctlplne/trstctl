import type { ReactNode } from "react";
import { Eyebrow } from "@/components/typography";
import { useTranslation } from "@/i18n/I18nProvider";
import { cn } from "@/lib/utils";

/** PageHeader is the standard page title block: an optional accent eyebrow, the
 * page title at the display type scale, an optional muted description, and an
 * optional actions slot (buttons) aligned to the right. It replaces the ad-hoc
 * `<h1 className="text-2xl">` headers so every screen shares one hierarchy. Pass
 * `titleId` to keep `aria-labelledby` wiring on the surrounding <section>. */
export function PageHeader({
  title,
  titleId,
  description,
  technicalDetails,
  eyebrow,
  actions,
  className,
}: {
  title: ReactNode;
  titleId?: string;
  description?: ReactNode;
  /** Exact identifiers, policy facts, commands, and recovery evidence. This
   * stays reachable but is disclosed after the operator-facing answer. */
  technicalDetails?: ReactNode;
  eyebrow?: ReactNode;
  actions?: ReactNode;
  className?: string;
}) {
  const { t } = useTranslation();

  return (
    <div className={cn("mb-7 border-b border-border/90 pb-5", className)}>
      <div className="flex flex-wrap items-start justify-between gap-x-6 gap-y-3">
        <div className="min-w-0 max-w-3xl">
          {eyebrow && (
            <Eyebrow as="p" className="mb-1.5">
              {eyebrow}
            </Eyebrow>
          )}
          <h1 id={titleId} className="text-display font-bold tracking-tight text-foreground">
            {title}
          </h1>
          <div className="mt-2 min-w-0" data-testid="page-depth-answer">
            <span className="sr-only">{t("pageHeader.answer")}</span>
            <p className="max-w-3xl text-body text-muted-foreground">{description ?? t("pageHeader.answerFallback")}</p>
          </div>
        </div>
        {actions && (
          <div
            aria-label={t("pageHeader.operate")}
            className="flex w-full min-w-0 flex-wrap items-center gap-2 sm:w-auto sm:shrink-0"
            role="group"
            data-testid="page-depth-operate"
          >
            <span className="sr-only">{t("pageHeader.operate")}</span>
            {actions}
          </div>
        )}
      </div>
      <details className="group mt-4 min-w-0" data-testid="page-depth-prove">
        <summary className="inline-flex cursor-pointer list-none items-center text-caption text-muted-foreground marker:hidden hover:text-foreground">
          <span className="sr-only">{t("pageHeader.prove")}: </span>
          <span className="font-medium group-open:hidden">{t("pageHeader.openDetails")}</span>
          <span className="hidden font-medium group-open:inline">{t("pageHeader.closeDetails")}</span>
        </summary>
        <div className="mt-2 max-w-3xl border-s-2 border-border ps-3 text-caption leading-relaxed text-muted-foreground">
          {technicalDetails ?? t("pageHeader.proveFallback")}
        </div>
      </details>
    </div>
  );
}
