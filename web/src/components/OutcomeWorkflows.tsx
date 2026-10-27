import { Link } from "react-router-dom";
import { FileSignature, KeyRound, ShieldCheck } from "lucide-react";
import { useTranslation } from "@/i18n/I18nProvider";
import type { MessageKey } from "@/i18n/messages";

interface Outcome {
  id: string;
  to: string;
  titleKey: MessageKey;
  descriptionKey: MessageKey;
  icon: typeof ShieldCheck;
}

/** The three end-to-end outcomes, each starting at the screen where its
 * workflow begins. The docs' outcome pages list every step with its proof. */
const outcomes: Outcome[] = [
  {
    id: "certificates",
    to: "/certificates",
    titleKey: "dashboard.outcomes.certificates.title",
    descriptionKey: "dashboard.outcomes.certificates.description",
    icon: ShieldCheck,
  },
  {
    id: "identity",
    to: "/workloads",
    titleKey: "dashboard.outcomes.identity.title",
    descriptionKey: "dashboard.outcomes.identity.description",
    icon: KeyRound,
  },
  {
    id: "crypto",
    to: "/posture",
    titleKey: "dashboard.outcomes.crypto.title",
    descriptionKey: "dashboard.outcomes.crypto.description",
    icon: FileSignature,
  },
];

/** OutcomeWorkflows routes the console home to the three outcome workflows. */
export function OutcomeWorkflows() {
  const { t } = useTranslation();
  return (
    <section aria-labelledby="dashboard-outcomes-heading" className="space-y-3">
      <div>
        <h2 id="dashboard-outcomes-heading" className="text-heading font-semibold">
          {t("dashboard.outcomes.heading")}
        </h2>
        <p className="mt-1 text-body text-muted-foreground">{t("dashboard.outcomes.help")}</p>
      </div>
      <ul className="grid gap-3 md:grid-cols-3">
        {outcomes.map(({ id, to, titleKey, descriptionKey, icon: Icon }) => (
          <li key={id}>
            <Link
              to={to}
              data-outcome={id}
              className="flex h-full gap-3 rounded-panel border border-border bg-card p-4 transition-colors hover:bg-muted/55 focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-focus"
            >
              <Icon className="mt-0.5 h-5 w-5 shrink-0 text-brand-accent" aria-hidden="true" />
              <span className="min-w-0">
                <span className="block text-body font-semibold">{t(titleKey)}</span>
                <span className="mt-1 block text-caption text-muted-foreground">{t(descriptionKey)}</span>
              </span>
            </Link>
          </li>
        ))}
      </ul>
    </section>
  );
}
