/* eslint-disable jsx-a11y/no-noninteractive-tabindex -- The named table overflow region needs keyboard focus for horizontal scrolling. */
import { useId, useMemo, useRef, useState } from "react";
import { api, type PAMEmergencyCheckout, type PAMEmergencyGrant } from "@/lib/api";
import { useApiQuery, useQueryClient } from "@/lib/query";
import { useTranslation } from "@/i18n/I18nProvider";
import { formatDateTime, type FormatPolicy } from "@/i18n/format";
import { Button } from "@/components/ui/button";
import { Select } from "@/components/ui/select";
import { Dialog } from "@/components/Dialog";
import { CredentialChip } from "@/components/CredentialChip";
import { ErrorState, LoadingState, UnavailableState } from "@/components/StatePrimitives";

// A272: break-glass identity provider administrators. A named responder
// releases one at once, without review: every approver is notified, the
// password and the current TOTP code (never the seed) are shown once with
// the hardware security key holders, checking it in rotates the password,
// and the grant waits for a post-incident review by someone else (A258).

const LIFETIMES = [300, 900, 1800, 3600];

type Released = { username?: string; password?: string; totp_code?: string; totp_valid_until?: string };

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function parseReleased(credential: string): Released {
  try {
    const parsed: unknown = JSON.parse(credential);
    if (parsed && typeof parsed === "object") return parsed as Released;
  } catch {
    // A credential that is not the JSON account is shown whole.
  }
  return { password: credential };
}

export function PAMBreakGlassPanel({ subject, canRelease, canReview }: { subject: string; canRelease: boolean; canReview: boolean }) {
  const { locale, timeZone, t } = useTranslation();
  const policy = useMemo<FormatPolicy>(() => ({ locale, timeZone }), [locale, timeZone]);
  const queryClient = useQueryClient();
  const ids = { target: useId(), reason: useId(), lifetime: useId(), outcome: useId(), notes: useId() };
  const targets = useApiQuery(["pam-targets"], api.pamTargets, { retry: false });
  const grants = useApiQuery(["pam-emergency-grants"], api.pamEmergencyGrants, { retry: false });
  const [form, setForm] = useState({ target: "", reason: "", lifetime: 300 });
  const [confirming, setConfirming] = useState(false);
  const [released, setReleased] = useState<{ result: PAMEmergencyCheckout; account: Released } | null>(null);
  const [reviewing, setReviewing] = useState<{ grant: PAMEmergencyGrant; outcome: "justified" | "unjustified"; notes: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const keys = useRef({ release: crypto.randomUUID(), checkin: crypto.randomUUID(), review: crypto.randomUUID() });
  const returnFocus = useRef<HTMLButtonElement | null>(null);

  async function act(work: () => Promise<string>) {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      setNotice(await work());
      await Promise.all([["pam-emergency-grants"], ["pam-checkouts"]].map((queryKey) => queryClient.invalidateQueries({ queryKey })));
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }
  const accounts = (targets.data?.items ?? []).filter((target) => target.target_type === "breakglass" && target.enabled);
  const release = (button: HTMLButtonElement) =>
    act(async () => {
      returnFocus.current = button;
      const result = await api.openPAMEmergencyCheckout(
        { request_id: crypto.randomUUID(), target_type: "breakglass", target_id: form.target, reason: form.reason.trim(), ttl_seconds: form.lifetime },
        keys.current.release,
      );
      keys.current.release = crypto.randomUUID();
      setConfirming(false);
      setForm({ target: "", reason: "", lifetime: 300 });
      setReleased({ result, account: parseReleased(result.credential) });
      return t("admin.access.breakglass.releasedNotice", { target: result.checkout.target_id });
    });
  const checkIn = (requestID: string, target: string) =>
    act(async () => {
      await api.checkInPAMCheckout(requestID, keys.current.checkin);
      keys.current.checkin = crypto.randomUUID();
      setReleased(null);
      return t("admin.access.breakglass.checkedInNotice", { target });
    });
  const review = () =>
    act(async () => {
      if (!reviewing) return "";
      await api.reviewPAMEmergencyGrant(reviewing.grant.session_id, { outcome: reviewing.outcome, notes: reviewing.notes.trim() }, keys.current.review);
      keys.current.review = crypto.randomUUID();
      setReviewing(null);
      return t("admin.access.breakglass.reviewedNotice");
    });

  const items = grants.data?.items ?? [];
  return (
    <section aria-labelledby="pam-breakglass-heading" className="grid gap-3">
      <div>
        <h3 id="pam-breakglass-heading" className="text-body font-semibold">
          {t("admin.access.breakglass.heading")}
        </h3>
        <p className="text-sm text-muted-foreground">{t("admin.access.breakglass.description")}</p>
      </div>
      {notice ? (
        <p role="status" className="text-sm text-status-success">
          {notice}
        </p>
      ) : null}
      {error ? <ErrorState title={t("admin.access.breakglass.failed")}>{error}</ErrorState> : null}

      {canRelease ? (
        accounts.length === 0 ? (
          targets.data ? (
            <UnavailableState title={t("admin.access.breakglass.noAccounts")} />
          ) : null
        ) : (
          <form
            className="grid gap-2 rounded-panel border border-border p-3 text-sm"
            onSubmit={(event) => {
              event.preventDefault();
              setConfirming(true);
            }}
          >
            <label htmlFor={ids.target}>{t("admin.access.breakglass.account")}</label>
            <Select id={ids.target} value={form.target} required onChange={(event) => setForm({ ...form, target: event.target.value })}>
              <option value="" disabled>
                {t("admin.access.breakglass.chooseAccount")}
              </option>
              {accounts.map((target) => (
                <option key={target.id} value={target.id}>
                  {target.id}
                </option>
              ))}
            </Select>
            <label htmlFor={ids.reason}>{t("admin.access.breakglass.reason")}</label>
            <textarea
              id={ids.reason}
              className="min-h-16 rounded-md border border-input bg-background p-2"
              required
              value={form.reason}
              onChange={(event) => setForm({ ...form, reason: event.target.value })}
            />
            <label htmlFor={ids.lifetime}>{t("admin.access.breakglass.lifetime")}</label>
            <Select id={ids.lifetime} value={String(form.lifetime)} onChange={(event) => setForm({ ...form, lifetime: Number(event.target.value) })}>
              {LIFETIMES.map((seconds) => (
                <option key={seconds} value={seconds}>
                  {t("admin.access.breakglass.minutes", { count: seconds / 60 })}
                </option>
              ))}
            </Select>
            {confirming ? (
              <div className="grid gap-2" role="alert">
                <p>{t("admin.access.breakglass.confirm", { target: form.target })}</p>
                <div className="flex gap-2">
                  <Button type="button" size="sm" variant="destructive" disabled={busy} onClick={(event) => void release(event.currentTarget)}>
                    {t("admin.access.breakglass.releaseConfirmed")}
                  </Button>
                  <Button type="button" size="sm" variant="ghost" onClick={() => setConfirming(false)}>
                    {t("admin.access.breakglass.cancel")}
                  </Button>
                </div>
              </div>
            ) : (
              <div>
                <Button type="submit" size="sm" disabled={busy || !form.target || !form.reason.trim()}>
                  {t("admin.access.breakglass.release")}
                </Button>
              </div>
            )}
          </form>
        )
      ) : null}

      <h4 className="text-body font-semibold">{t("admin.access.breakglass.grants")}</h4>
      {grants.loading ? <LoadingState>{t("admin.access.breakglass.loading")}</LoadingState> : null}
      {grants.data && items.length === 0 ? <UnavailableState title={t("admin.access.breakglass.noGrants")} /> : null}
      {items.length > 0 ? (
        <div className="overflow-auto" tabIndex={0} role="region" aria-label={t("admin.access.breakglass.grants")}>
          <table className="ui-table">
            <caption className="sr-only">{t("admin.access.breakglass.grants")}</caption>
            <thead>
              <tr>
                <th scope="col">{t("admin.access.breakglass.grantTarget")}</th>
                <th scope="col">{t("admin.access.breakglass.responder")}</th>
                <th scope="col">{t("admin.access.breakglass.reason")}</th>
                <th scope="col">{t("admin.access.breakglass.opened")}</th>
                <th scope="col">{t("admin.access.breakglass.review")}</th>
              </tr>
            </thead>
            <tbody>
              {items.map((grant) => (
                <tr key={grant.session_id}>
                  <td>
                    {grant.target_type}/{grant.target_id}
                  </td>
                  <td>{grant.responder}</td>
                  <td>{grant.reason}</td>
                  <td>{formatDateTime(grant.opened_at, policy)}</td>
                  <td>
                    {grant.review.status === "pending" ? (
                      canReview && grant.responder !== subject ? (
                        <Button
                          type="button"
                          size="sm"
                          variant="outline"
                          disabled={busy}
                          onClick={() => setReviewing({ grant, outcome: "justified", notes: "" })}
                        >
                          {t("admin.access.breakglass.recordReview", { target: grant.target_id })}
                        </Button>
                      ) : (
                        t("admin.access.breakglass.reviewPending")
                      )
                    ) : (
                      t("admin.access.breakglass.reviewed", { outcome: grant.review.outcome ?? "", reviewer: grant.review.reviewer ?? "" })
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}

      {reviewing ? (
        <form
          className="grid gap-2 rounded-panel border border-border p-3 text-sm"
          aria-label={t("admin.access.breakglass.reviewFor", { target: reviewing.grant.target_id })}
          onSubmit={(event) => {
            event.preventDefault();
            void review();
          }}
        >
          <label htmlFor={ids.outcome}>{t("admin.access.breakglass.outcome")}</label>
          <Select
            id={ids.outcome}
            value={reviewing.outcome}
            onChange={(event) => setReviewing({ ...reviewing, outcome: event.target.value as "justified" | "unjustified" })}
          >
            <option value="justified">{t("admin.access.breakglass.justified")}</option>
            <option value="unjustified">{t("admin.access.breakglass.unjustified")}</option>
          </Select>
          <label htmlFor={ids.notes}>{t("admin.access.breakglass.notes")}</label>
          <textarea
            id={ids.notes}
            className="min-h-16 rounded-md border border-input bg-background p-2"
            required
            value={reviewing.notes}
            onChange={(event) => setReviewing({ ...reviewing, notes: event.target.value })}
          />
          <div className="flex gap-2">
            <Button type="submit" size="sm" disabled={busy || !reviewing.notes.trim()}>
              {t("admin.access.breakglass.saveReview")}
            </Button>
            <Button type="button" size="sm" variant="ghost" onClick={() => setReviewing(null)}>
              {t("admin.access.breakglass.cancel")}
            </Button>
          </div>
        </form>
      ) : null}

      {released ? (
        <Dialog
          open
          onClose={() => setReleased(null)}
          titleId="pam-breakglass-release-heading"
          descriptionId="pam-breakglass-release-description"
          returnFocusRef={returnFocus}
          className="fixed inset-0 z-50 flex items-center justify-center p-4"
          overlayClassName="absolute inset-0 bg-black/55"
          panelClassName="relative w-full max-w-lg rounded-panel border border-border bg-card p-5 shadow-elevation2"
        >
          <h2 id="pam-breakglass-release-heading" className="text-title font-semibold">
            {t("admin.access.breakglass.releasedTitle", { target: released.result.checkout.target_id })}
          </h2>
          <p id="pam-breakglass-release-description" className="mt-1 text-sm text-muted-foreground">
            {t("admin.access.breakglass.releasedDescription", { deadline: formatDateTime(released.result.checkout.expires_at, policy) })}
          </p>
          <dl className="mt-3 grid gap-2 text-sm">
            {released.account.username ? (
              <>
                <dt className="font-medium">{t("admin.access.breakglass.username")}</dt>
                <dd>{released.account.username}</dd>
              </>
            ) : null}
            <dt className="font-medium">{t("admin.access.breakglass.password")}</dt>
            <dd>
              <CredentialChip value={released.account.password ?? ""} label={t("admin.access.breakglass.password")} fullValue />
            </dd>
            {released.account.totp_code ? (
              <>
                <dt className="font-medium">{t("admin.access.breakglass.totpCode")}</dt>
                <dd>
                  <CredentialChip value={released.account.totp_code} label={t("admin.access.breakglass.totpCode")} fullValue />
                  {released.account.totp_valid_until ? (
                    <span className="ml-2 text-muted-foreground">
                      {t("admin.access.breakglass.totpValidUntil", { until: formatDateTime(released.account.totp_valid_until, policy) })}
                    </span>
                  ) : null}
                </dd>
              </>
            ) : null}
            {released.result.hardware_key_holders?.length ? (
              <>
                <dt className="font-medium">{t("admin.access.breakglass.keyHolders")}</dt>
                <dd>{released.result.hardware_key_holders.join(", ")}</dd>
              </>
            ) : null}
          </dl>
          <div className="mt-3 flex justify-end gap-2">
            <Button
              type="button"
              variant="outline"
              disabled={busy}
              onClick={() => void checkIn(released.result.checkout.request_id, released.result.checkout.target_id)}
            >
              {t("admin.access.breakglass.checkIn")}
            </Button>
            <Button type="button" onClick={() => setReleased(null)}>
              {t("admin.access.breakglass.close")}
            </Button>
          </div>
        </Dialog>
      ) : null}
    </section>
  );
}
