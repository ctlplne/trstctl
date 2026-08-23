import { Link } from "react-router-dom";
import { buttonVariants } from "@/components/ui/button";
import { useTranslation } from "@/i18n/I18nProvider";
import { cn } from "@/lib/utils";

/** Secondary administration routes stay one quiet disclosure away. They remain
 * keyboard-reachable without competing with the page's one primary action. */
export function AdminHeaderActions() {
  const { t } = useTranslation();
  return (
    <details className="group relative">
      <summary className={cn(buttonVariants({ variant: "outline" }), "cursor-pointer list-none marker:hidden")}>{t("dashboard.moreActions")}</summary>
      <div className="absolute end-0 z-30 mt-2 grid min-w-56 overflow-hidden rounded-panel border border-border bg-card p-1 shadow-elevation2">
        <Link to="/privacy" className="flex items-center gap-2 rounded-control px-3 py-2 text-sm hover:bg-muted/70">
          {t("nav.item.privacy")}
        </Link>
        <Link to="/integrate" className="flex items-center gap-2 rounded-control px-3 py-2 text-sm hover:bg-muted/70">
          {t("nav.item.integrate")}
        </Link>
      </div>
    </details>
  );
}
