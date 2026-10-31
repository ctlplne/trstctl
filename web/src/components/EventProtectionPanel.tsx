import { FormEvent, useState } from "react";
import { api, type EventProtectionPlan, type EventProtectionStatus } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { ErrorState, LoadingState } from "@/components/StatePrimitives";
import { useToast } from "@/components/ToastProvider";
import { useTranslation } from "@/i18n/I18nProvider";

/** Event-field protection (crypto-shred) for this tenant. It loads only when
 * opened: status from the retained source and current key custody, an
 * effect-free preview, then an enable that a bounded worker completes. No
 * control here destroys a key; offboarding does that after the retention
 * window. */
export function EventProtectionPanel() {
  const { t, formatDateTime } = useTranslation();
  const { toast } = useToast();
  const [status, setStatus] = useState<EventProtectionStatus | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [retention, setRetention] = useState("");
  const [plan, setPlan] = useState<EventProtectionPlan | null>(null);
  const [busy, setBusy] = useState<null | "preview" | "enable">(null);

  async function load() {
    setLoading(true);
    setError(null);
    try {
      setStatus(await api.eventProtectionStatus());
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }

  function request() {
    return { registration_identity: status?.registration_identity ?? "", retention: retention.trim() };
  }

  async function preview(event: FormEvent) {
    event.preventDefault();
    setBusy("preview");
    setError(null);
    try {
      setPlan(await api.previewEventProtection(request()));
    } catch (err) {
      setPlan(null);
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(null);
    }
  }

  async function enable() {
    setBusy("enable");
    setError(null);
    try {
      await api.enableEventProtection(request());
      toast({ kind: "success", title: t("privacy.eventProtection.enabledToast") });
      setPlan(null);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(null);
    }
  }

  const stateLabel = (state: string) =>
    state === "active"
      ? t("privacy.eventProtection.state.active")
      : state === "preparing"
        ? t("privacy.eventProtection.state.preparing")
        : t("privacy.eventProtection.state.notEnabled");

  return (
    <details
      className="ui-panel grid gap-3 p-comfortable"
      onToggle={(event) => {
        if (event.currentTarget.open && !status && !loading) void load();
      }}
    >
      <summary className="cursor-pointer text-title font-semibold">{t("privacy.eventProtection.title")}</summary>
      <p className="max-w-3xl text-body text-muted-foreground">{t("privacy.eventProtection.description")}</p>
      {loading ? <LoadingState>{t("privacy.loading")}</LoadingState> : null}
      {error ? <ErrorState title={t("privacy.error.actionFailed")}>{error}</ErrorState> : null}
      {status ? (
        <div className="grid gap-3">
          <dl className="grid gap-2 text-sm sm:grid-cols-2">
            <div>
              <dt className="text-caption text-muted-foreground">{t("privacy.eventProtection.stateLabel")}</dt>
              <dd className="font-medium">{stateLabel(status.state)}</dd>
            </div>
            <div>
              <dt className="text-caption text-muted-foreground">{t("privacy.eventProtection.registrationLabel")}</dt>
              <dd className="break-all font-mono text-caption">{status.registration_identity}</dd>
            </div>
            <div>
              <dt className="text-caption text-muted-foreground">{t("privacy.eventProtection.custodyLabel")}</dt>
              <dd>{status.custody_configured ? t("privacy.eventProtection.custodyConfigured") : t("privacy.eventProtection.custodyMissing")}</dd>
            </div>
            {status.retention ? (
              <div>
                <dt className="text-caption text-muted-foreground">{t("privacy.eventProtection.retentionLabel")}</dt>
                <dd className="font-mono">{status.retention}</dd>
              </div>
            ) : null}
            {status.activated_at ? (
              <div>
                <dt className="text-caption text-muted-foreground">{t("privacy.eventProtection.activatedLabel")}</dt>
                <dd>{formatDateTime(status.activated_at)}</dd>
              </div>
            ) : null}
          </dl>
          <p className="text-sm">{status.next_step}</p>
          <p className="text-caption text-muted-foreground">{t("privacy.eventProtection.legacyNote")}</p>
          {status.state === "not_enabled" ? (
            <form className="grid max-w-md gap-2" onSubmit={(event) => void preview(event)}>
              <label className="grid gap-1 text-sm" htmlFor="event-protection-retention">
                {t("privacy.eventProtection.retentionLabel")}
                <input
                  id="event-protection-retention"
                  className="rounded-control border border-border bg-background px-2 py-1 font-mono"
                  value={retention}
                  onChange={(event) => setRetention(event.target.value)}
                  placeholder={t("privacy.eventProtection.retentionPlaceholder")}
                  aria-describedby="event-protection-retention-hint"
                />
              </label>
              <p id="event-protection-retention-hint" className="text-caption text-muted-foreground">
                {t("privacy.eventProtection.retentionHint")}
              </p>
              <Button type="submit" variant="outline" disabled={busy !== null || retention.trim() === ""}>
                {t("privacy.eventProtection.preview")}
              </Button>
            </form>
          ) : (
            <Button type="button" variant="outline" disabled={loading} onClick={() => void load()}>
              {t("privacy.eventProtection.refresh")}
            </Button>
          )}
          {plan ? (
            <section aria-label={t("privacy.eventProtection.planTitle")} className="grid gap-2 rounded-control border border-border p-3 text-sm">
              <h3 className="font-semibold">{t("privacy.eventProtection.planTitle")}</h3>
              {plan.blockers.length > 0 ? (
                <ul className="list-disc pl-5 text-status-danger">
                  {plan.blockers.map((blocker) => (
                    <li key={blocker}>{blocker}</li>
                  ))}
                </ul>
              ) : null}
              <ul className="list-disc pl-5">
                {[...plan.execute_writes, ...plan.warnings].map((line) => (
                  <li key={line}>{line}</li>
                ))}
              </ul>
              <Button type="button" disabled={!plan.ready || busy !== null} onClick={() => void enable()}>
                {t("privacy.eventProtection.enable")}
              </Button>
            </section>
          ) : null}
        </div>
      ) : null}
    </details>
  );
}
