import type { CAAuthority } from "@/lib/api";
import { formatDateTime } from "@/i18n/format";
import { useTranslation } from "@/i18n/I18nProvider";

// A216: the re-key ceremony the CA calendar drafted when this authority
// entered the configured rollover band. Custodians approve it and a person
// executes the re-key with the plan shown; drafting changed nothing.
export function CARolloverDraft({ authority }: { authority: CAAuthority }) {
  const { t } = useTranslation();
  const draft = authority.rollover_draft;
  if (!draft) return null;
  return (
    <section aria-labelledby="ca-rollover-draft-heading" className="grid gap-1 rounded-control border border-border bg-muted/40 p-3 text-sm">
      <h3 id="ca-rollover-draft-heading" className="font-semibold">
        {t("caHierarchy.rollover.heading")}
      </h3>
      {draft.ceremony_id ? (
        <>
          <p>
            {t("caHierarchy.rollover.drafted", {
              band: String(draft.band_months),
              ceremony: draft.ceremony_id,
              status: draft.ceremony_status ?? "",
              approvals: String(draft.approvals),
              threshold: String(draft.threshold),
              when: formatDateTime(draft.drafted_at),
            })}
          </p>
          <p className="break-all text-xs text-muted-foreground">
            {t("caHierarchy.rollover.plan", { reason: draft.reason ?? "", ttl: String(draft.ttl_seconds ?? 0) })}
          </p>
        </>
      ) : (
        <p>{t("caHierarchy.rollover.notDrafted", { band: String(draft.band_months), reason: draft.not_drafted_reason ?? "" })}</p>
      )}
    </section>
  );
}
