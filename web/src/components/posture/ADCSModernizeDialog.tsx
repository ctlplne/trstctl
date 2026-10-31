import { useEffect, useId, useState } from "react";
import { X } from "lucide-react";
import { Dialog } from "@/components/Dialog";
import { ErrorState, LoadingState } from "@/components/StatePrimitives";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useTranslation } from "@/i18n/I18nProvider";
import { api, type ADCSModernizePlan, type ADCSTemplate } from "@/lib/api";
import { apiProblemMessage } from "@/lib/apiProblem";

/**
 * A160: "modernize this template". The server's effect-free preview shows the
 * trstctl profile an inventoried AD CS template becomes and every risky
 * property it leaves behind; Create makes the profile through the normal
 * profile path (dual control when the template required manager approval).
 */
export function ADCSModernizeDialog({ template, onClose }: { template: ADCSTemplate; onClose: () => void }) {
  const { t } = useTranslation();
  const titleId = useId();
  const [dnsSuffix, setDNSSuffix] = useState("");
  const [request, setRequest] = useState(0);
  const [plan, setPlan] = useState<ADCSModernizePlan | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [result, setResult] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    const suffix = dnsSuffix.trim();
    setLoading(true);
    setError(null);
    api
      .previewADCSModernize({ domain: template.domain, template: template.template, ...(suffix ? { dns_suffix: suffix } : {}) })
      .then((next) => {
        if (!cancelled) setPlan(next);
      })
      .catch((err: unknown) => {
        if (!cancelled) setError(apiProblemMessage(err, t("adcs.modernize.previewFailed")));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
    // The suffix is applied only when the operator asks for a new preview.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [template.domain, template.template, request, t]);

  async function create() {
    if (!plan?.ready || saving) return;
    setSaving(true);
    setError(null);
    try {
      const created = await api.modernizeADCSTemplate({
        domain: template.domain,
        template: template.template,
        dns_suffix: plan.dns_suffix,
        profile_name: plan.profile_name,
      });
      setResult(
        created.state === "created"
          ? t("adcs.modernize.created", { name: plan.profile_name })
          : t("adcs.modernize.awaitingApproval", { name: plan.profile_name }),
      );
    } catch (err) {
      setError(apiProblemMessage(err, t("adcs.modernize.failed")));
    } finally {
      setSaving(false);
    }
  }

  return (
    <Dialog
      open
      onClose={onClose}
      titleId={titleId}
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      overlayClassName="absolute inset-0 bg-black/55"
      panelClassName="relative max-h-[calc(100vh-2rem)] w-full max-w-2xl overflow-y-auto rounded-panel border border-border bg-card shadow-elevation2"
    >
      <header className="flex items-start justify-between gap-3 border-b border-border px-5 py-4">
        <div>
          <h2 id={titleId} className="text-title font-semibold">
            {t("adcs.modernize.title", { template: template.template })}
          </h2>
          <p className="mt-1 text-sm text-muted-foreground">{t("adcs.modernize.description")}</p>
        </div>
        <Button type="button" variant="ghost" size="icon" onClick={onClose} aria-label={t("adcs.modernize.close")}>
          <X className="h-4 w-4" aria-hidden="true" />
        </Button>
      </header>
      <div className="grid gap-4 px-5 py-4 text-sm">
        {loading ? <LoadingState>{t("adcs.modernize.previewing")}</LoadingState> : null}
        {error ? <ErrorState title={t("adcs.modernize.failed")}>{error}</ErrorState> : null}
        {plan && !loading ? (
          <>
            <dl className="grid gap-2 sm:grid-cols-2">
              <div>
                <dt className="text-caption text-muted-foreground">{t("adcs.modernize.profileName")}</dt>
                <dd className="font-mono text-xs">{plan.profile_name}</dd>
              </div>
              <div>
                <dt className="text-caption text-muted-foreground">{t("adcs.modernize.dnsSuffix")}</dt>
                <dd className="font-mono text-xs">{plan.dns_suffix || t("adcs.modernize.none")}</dd>
              </div>
            </dl>
            {plan.changes.length > 0 ? (
              <section aria-label={t("adcs.modernize.changes")}>
                <h3 className="font-semibold">{t("adcs.modernize.changes")}</h3>
                <ul className="mt-2 grid list-disc gap-1 ps-5">
                  {plan.changes.map((change) => (
                    <li key={`${change.code}:${change.detail}`}>{change.detail}</li>
                  ))}
                </ul>
              </section>
            ) : null}
            {plan.blockers.length > 0 ? (
              <ErrorState title={t("adcs.modernize.blocked")}>
                <ul className="grid gap-1">
                  {plan.blockers.map((blocker) => (
                    <li key={blocker}>{blocker}</li>
                  ))}
                </ul>
              </ErrorState>
            ) : null}
            <div className="grid gap-1">
              <label className="grid gap-1 font-medium">
                <span>{t("adcs.modernize.dnsSuffixOverride")}</span>
                <Input value={dnsSuffix} onChange={(event) => setDNSSuffix(event.target.value)} autoComplete="off" />
              </label>
              <Button type="button" size="sm" variant="outline" className="justify-self-start" onClick={() => setRequest((n) => n + 1)}>
                {t("adcs.modernize.refresh")}
              </Button>
            </div>
          </>
        ) : null}
        {result ? (
          <p role="status" className="font-medium">
            {result}
          </p>
        ) : null}
      </div>
      <footer className="flex justify-end gap-2 border-t border-border px-5 py-3">
        <Button type="button" variant="outline" onClick={onClose}>
          {t("adcs.modernize.close")}
        </Button>
        <Button type="button" onClick={() => void create()} disabled={!plan?.ready || saving || result !== null}>
          {t("adcs.modernize.create")}
        </Button>
      </footer>
    </Dialog>
  );
}
