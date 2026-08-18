import { Network, ShieldCheck } from "lucide-react";
import { Link } from "react-router-dom";
import { useTranslation } from "@/i18n/I18nProvider";

/** Shared header quick links for the three operational administration pages. */
export function AdminHeaderActions() {
  const { t } = useTranslation();
  return (
    <>
      <Link
        to="/privacy"
        className="inline-flex min-h-10 items-center justify-center gap-2 rounded-md border border-border bg-background px-3 py-2 text-sm font-medium hover:border-brand-accent/40 hover:bg-muted/60"
      >
        <ShieldCheck className="h-4 w-4" aria-hidden="true" />
        {t("nav.item.privacy")}
      </Link>
      <Link
        to="/integrate"
        className="inline-flex min-h-10 items-center justify-center gap-2 rounded-md border border-border bg-background px-3 py-2 text-sm font-medium hover:border-brand-accent/40 hover:bg-muted/60"
      >
        <Network className="h-4 w-4" aria-hidden="true" />
        {t("nav.item.integrate")}
      </Link>
    </>
  );
}
