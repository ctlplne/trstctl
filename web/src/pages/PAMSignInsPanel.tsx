/* eslint-disable jsx-a11y/no-noninteractive-tabindex -- The named table overflow region needs keyboard focus for horizontal scrolling. */
import { useId, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api, type PAMSignIn } from "@/lib/api";
import { useApiQuery } from "@/lib/query";
import { useTranslation } from "@/i18n/I18nProvider";
import { formatDateTime, type FormatPolicy } from "@/i18n/format";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { ErrorState, LoadingState, UnavailableState } from "@/components/StatePrimitives";

// A274: the sign-ins bypass detection read on providers' targets for their
// managed accounts — metadata only — and what explained each. A sign-in
// nothing explains also raised a compromised-credential finding.

type Filter = { provider: string; unexplained: boolean };
type Explanation = NonNullable<PAMSignIn["explained_by"]>;

export function PAMSignInsPanel() {
  const { locale, timeZone, t } = useTranslation();
  const policy = useMemo<FormatPolicy>(() => ({ locale, timeZone }), [locale, timeZone]);
  const ids = { provider: useId(), unexplained: useId() };
  const [draft, setDraft] = useState<Filter>({ provider: "", unexplained: false });
  const [filter, setFilter] = useState<Filter>({ provider: "", unexplained: false });
  const signIns = useApiQuery(
    ["pam-signins", filter.provider, filter.unexplained],
    ({ signal }) => api.pamSignIns({ providerId: filter.provider || undefined, unexplained: filter.unexplained, signal }),
    { retry: false },
  );
  const items = signIns.data?.items ?? [];

  function explanation(signIn: PAMSignIn): string {
    const by = signIn.explained_by;
    if (!by) return t("admin.access.signins.unexplained");
    const kinds: Record<Explanation["kind"], string> = {
      gateway_session: t("admin.access.signins.kindGatewaySession"),
      session: t("admin.access.signins.kindSession"),
      checkout: t("admin.access.signins.kindCheckout"),
      rotation_check: t("admin.access.signins.kindRotation"),
      health_check: t("admin.access.signins.kindHealthCheck"),
    };
    const kind = kinds[by.kind] ?? by.kind;
    return by.ref ? t("admin.access.signins.explainedWithRef", { kind, ref: by.ref }) : kind;
  }

  function when(signIn: PAMSignIn): string {
    const at = formatDateTime(signIn.at, policy);
    return signIn.earliest ? t("admin.access.signins.between", { earliest: formatDateTime(signIn.earliest, policy), at }) : at;
  }

  return (
    <section aria-labelledby="pam-signins-heading" className="grid gap-3">
      <div>
        <h3 id="pam-signins-heading" className="text-body font-semibold">
          {t("admin.access.signins.heading")}
        </h3>
        <p className="text-sm text-muted-foreground">
          {t("admin.access.signins.description")}{" "}
          <Link to="/discovery?tab=findings" className="underline">
            {t("admin.access.signins.findings")}
          </Link>
        </p>
      </div>
      <form
        className="flex flex-wrap items-end gap-3 text-sm"
        aria-label={t("admin.access.signins.filter")}
        onSubmit={(event) => {
          event.preventDefault();
          setFilter({ provider: draft.provider.trim(), unexplained: draft.unexplained });
        }}
      >
        <div className="grid gap-1">
          <label htmlFor={ids.provider}>{t("admin.access.signins.provider")}</label>
          <Input id={ids.provider} value={draft.provider} onChange={(event) => setDraft({ ...draft, provider: event.target.value })} />
        </div>
        <div className="flex items-center gap-2">
          <Checkbox id={ids.unexplained} checked={draft.unexplained} onChange={(event) => setDraft({ ...draft, unexplained: event.target.checked })} />
          <label htmlFor={ids.unexplained}>{t("admin.access.signins.onlyUnexplained")}</label>
        </div>
        <Button type="submit" size="sm" variant="outline">
          {t("admin.access.signins.show")}
        </Button>
      </form>
      {signIns.loading ? <LoadingState>{t("admin.access.signins.loading")}</LoadingState> : null}
      {signIns.error ? <ErrorState title={t("admin.access.signins.failed")}>{signIns.error}</ErrorState> : null}
      {signIns.data && items.length === 0 ? <UnavailableState title={t("admin.access.signins.none")} /> : null}
      {items.length > 0 ? (
        <div className="overflow-auto" tabIndex={0} role="region" aria-label={t("admin.access.signins.table")}>
          <table className="ui-table">
            <caption className="sr-only">{t("admin.access.signins.table")}</caption>
            <thead>
              <tr>
                <th scope="col">{t("admin.access.signins.when")}</th>
                <th scope="col">{t("admin.access.signins.account")}</th>
                <th scope="col">{t("admin.access.signins.provider")}</th>
                <th scope="col">{t("admin.access.signins.from")}</th>
                <th scope="col">{t("admin.access.signins.how")}</th>
                <th scope="col">{t("admin.access.signins.explainedBy")}</th>
              </tr>
            </thead>
            <tbody>
              {items.map((signIn) => (
                <tr key={`${signIn.provider_id}/${signIn.fingerprint}`}>
                  <td>{when(signIn)}</td>
                  <td className="font-mono text-xs">{signIn.account}</td>
                  <td>{signIn.provider_id}</td>
                  <td>{signIn.source || t("admin.access.signins.noSource")}</td>
                  <td>
                    {signIn.key_id ? t("admin.access.signins.methodWithKey", { method: signIn.method ?? "", key: signIn.key_id }) : (signIn.method ?? "")}
                  </td>
                  <td className={signIn.explained_by ? undefined : "font-medium text-status-danger"}>{explanation(signIn)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
    </section>
  );
}
