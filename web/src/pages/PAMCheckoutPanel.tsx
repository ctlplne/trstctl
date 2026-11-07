/* eslint-disable jsx-a11y/no-noninteractive-tabindex -- The named table overflow regions need keyboard focus for horizontal scrolling. */
import { useEffect, useId, useMemo, useRef, useState } from "react";
import { api, type PAMCheckout, type PAMCheckoutReveal, type PAMCheckoutRequest, type PAMCheckoutReview } from "@/lib/api";
import { useApiQuery, useQueryClient } from "@/lib/query";
import { useTranslation } from "@/i18n/I18nProvider";
import { formatDateTime, type FormatPolicy } from "@/i18n/format";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { Dialog } from "@/components/Dialog";
import { CredentialChip } from "@/components/CredentialChip";
import { ErrorState, LoadingState, UnavailableState } from "@/components/StatePrimitives";

// A261: check-outs of vaulted accounts. A check-out is reviewed by others
// before its requester reveals the account's credential, once; checking it
// in, or its deadline passing, rotates the account so the revealed
// credential stops working.

const LIFETIMES = [300, 900, 1800, 3600];

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

export function PAMCheckoutPanel({ subject, canRequest, canCheckInAny }: { subject: string; canRequest: boolean; canCheckInAny: boolean }) {
  const { locale, timeZone, t } = useTranslation();
  const policy = useMemo<FormatPolicy>(() => ({ locale, timeZone }), [locale, timeZone]);
  const queryClient = useQueryClient();
  const ids = { target: useId(), reason: useId(), lifetime: useId() };
  const checkouts = useApiQuery(["pam-checkouts"], api.pamCheckouts, { retry: false });
  const targets = useApiQuery(["pam-targets"], api.pamTargets, { enabled: canRequest, retry: false });
  const [form, setForm] = useState({ target: "", reason: "", lifetime: 900 });
  const [pending, setPending] = useState<{ request: PAMCheckoutRequest; review: PAMCheckoutReview } | null>(null);
  const [revealed, setRevealed] = useState<PAMCheckoutReveal | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const keys = useRef({ request: crypto.randomUUID(), reveal: crypto.randomUUID(), checkin: crypto.randomUUID() });
  const returnFocus = useRef<HTMLButtonElement | null>(null);
  // A revealed check-out past its deadline reads as rotation pending until the
  // expiry worker ends it; the clock is read on mount and every 30 seconds.
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 30_000);
    return () => window.clearInterval(timer);
  }, []);

  async function act(work: () => Promise<string>) {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      setNotice(await work());
      await queryClient.invalidateQueries({ queryKey: ["pam-checkouts"] });
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }
  // A break-glass account is released only through emergency access (A272)
  // and a web console account is never shown (A273): neither is checked out.
  const vaulted = (targets.data?.items ?? []).filter(
    (target) => target.account_secret && target.enabled && target.target_type !== "breakglass" && target.target_type !== "webconsole",
  );
  const requestCheckout = () =>
    act(async () => {
      const [targetType, targetID] = form.target.split("/");
      const request: PAMCheckoutRequest = {
        request_id: crypto.randomUUID(),
        target_type: targetType as PAMCheckoutRequest["target_type"],
        target_id: targetID,
        reason: form.reason.trim(),
        ttl_seconds: form.lifetime,
      };
      const review = await api.requestPAMCheckout(request, keys.current.request);
      keys.current.request = crypto.randomUUID();
      setPending({ request, review });
      return t("admin.access.checkout.requested", { count: review.required_approvals });
    });
  const reveal = (button: HTMLButtonElement) =>
    act(async () => {
      if (!pending) return "";
      returnFocus.current = button;
      const result = await api.revealPAMCheckout(
        pending.request.request_id,
        { approval_request_id: pending.review.approval_request_id, intent_digest: pending.review.intent_digest },
        keys.current.reveal,
      );
      keys.current.reveal = crypto.randomUUID();
      setPending(null);
      setForm({ target: "", reason: "", lifetime: 900 });
      setRevealed(result);
      return "";
    });
  const checkIn = (checkout: PAMCheckout) =>
    act(async () => {
      const ended = await api.checkInPAMCheckout(checkout.request_id, keys.current.checkin);
      keys.current.checkin = crypto.randomUUID();
      return t("admin.access.checkout.checkedInNotice", { target: ended.target_id });
    });
  function state(checkout: PAMCheckout): string {
    if (checkout.status === "checked_in") return t("admin.access.checkout.stateCheckedIn", { actor: checkout.ended_by ?? "" });
    if (checkout.status === "expired") return t("admin.access.checkout.stateExpired");
    if (new Date(checkout.expires_at).getTime() <= now) return t("admin.access.checkout.statePastDeadline");
    return t("admin.access.checkout.stateRevealed", { deadline: formatDateTime(checkout.expires_at, policy) });
  }

  const items = checkouts.data?.items ?? [];
  return (
    <section aria-labelledby="pam-checkout-heading" className="grid gap-3">
      <div>
        <h3 id="pam-checkout-heading" className="text-body font-semibold">
          {t("admin.access.checkout.heading")}
        </h3>
        <p className="text-sm text-muted-foreground">{t("admin.access.checkout.description")}</p>
      </div>
      {notice ? (
        <p role="status" className="text-sm text-status-success">
          {notice}
        </p>
      ) : null}
      {error ? <ErrorState title={t("admin.access.checkout.failed")}>{error}</ErrorState> : null}

      {canRequest ? (
        pending ? (
          <div className="grid gap-2 rounded-panel border border-border p-3 text-sm">
            <p>{t("admin.access.checkout.awaitingReview", { count: pending.review.required_approvals })}</p>
            <p className="break-all font-mono text-xs">{pending.review.approval_request_id}</p>
            <div className="flex gap-2">
              <Button type="button" size="sm" disabled={busy} onClick={(event) => void reveal(event.currentTarget)}>
                {t("admin.access.checkout.reveal")}
              </Button>
              <Button type="button" size="sm" variant="ghost" onClick={() => setPending(null)}>
                {t("admin.access.checkout.cancel")}
              </Button>
            </div>
          </div>
        ) : vaulted.length === 0 ? (
          targets.data ? (
            <UnavailableState title={t("admin.access.checkout.noVaulted")} />
          ) : null
        ) : (
          <form
            className="flex flex-wrap items-end gap-2"
            aria-label={t("admin.access.checkout.requestHeading")}
            onSubmit={(event) => {
              event.preventDefault();
              void requestCheckout();
            }}
          >
            <label htmlFor={ids.target} className="grid gap-1 text-sm">
              {t("admin.access.checkout.account")}
              <Select id={ids.target} value={form.target} onChange={(event) => setForm({ ...form, target: event.target.value })} required>
                <option value="">{t("admin.access.checkout.chooseAccount")}</option>
                {vaulted.map((target) => (
                  <option key={`${target.target_type}/${target.id}`} value={`${target.target_type}/${target.id}`}>
                    {t("admin.access.checkout.accountOption", { target: target.id, kind: target.target_type, account: target.account_secret ?? "" })}
                  </option>
                ))}
              </Select>
            </label>
            <label htmlFor={ids.reason} className="grid gap-1 text-sm">
              {t("admin.access.checkout.reason")}
              <Input id={ids.reason} value={form.reason} onChange={(event) => setForm({ ...form, reason: event.target.value })} required />
            </label>
            <label htmlFor={ids.lifetime} className="grid gap-1 text-sm">
              {t("admin.access.checkout.lifetime")}
              <Select id={ids.lifetime} value={String(form.lifetime)} onChange={(event) => setForm({ ...form, lifetime: Number(event.target.value) })}>
                {LIFETIMES.map((seconds) => (
                  <option key={seconds} value={seconds}>
                    {t("admin.access.checkout.minutes", { minutes: seconds / 60 })}
                  </option>
                ))}
              </Select>
            </label>
            <Button type="submit" size="sm" disabled={busy || !form.target || !form.reason.trim()}>
              {t("admin.access.checkout.requestReview")}
            </Button>
          </form>
        )
      ) : null}

      {checkouts.loading ? <LoadingState>{t("admin.access.checkout.loading")}</LoadingState> : null}
      {checkouts.data && items.length === 0 ? <UnavailableState title={t("admin.access.checkout.none")} /> : null}
      {items.length > 0 ? (
        <div className="overflow-auto" tabIndex={0} role="region" aria-label={t("admin.access.checkout.table")}>
          <table className="ui-table">
            <caption className="sr-only">{t("admin.access.checkout.table")}</caption>
            <thead>
              <tr>
                <th scope="col">{t("admin.access.checkout.account")}</th>
                <th scope="col">{t("admin.access.checkout.requestedBy")}</th>
                <th scope="col">{t("admin.access.checkout.state")}</th>
                <th scope="col">{t("admin.access.checkout.actions")}</th>
              </tr>
            </thead>
            <tbody>
              {items.map((checkout) => (
                <tr key={checkout.request_id}>
                  <td>
                    {checkout.target_id} <span className="text-muted-foreground">({checkout.account_secret})</span>
                  </td>
                  <td>{checkout.requested_by}</td>
                  <td>{state(checkout)}</td>
                  <td>
                    {checkout.status === "revealed" && (canCheckInAny || checkout.requested_by === subject) ? (
                      <Button type="button" size="sm" variant="outline" disabled={busy} onClick={() => void checkIn(checkout)}>
                        {t("admin.access.checkout.checkIn", { target: checkout.target_id })}
                      </Button>
                    ) : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}

      {revealed ? (
        <Dialog
          open
          onClose={() => setRevealed(null)}
          titleId="pam-checkout-reveal-heading"
          descriptionId="pam-checkout-reveal-description"
          returnFocusRef={returnFocus}
          className="fixed inset-0 z-50 flex items-center justify-center p-4"
          overlayClassName="absolute inset-0 bg-black/55"
          panelClassName="relative w-full max-w-lg rounded-panel border border-border bg-card p-5 shadow-elevation2"
        >
          <h2 id="pam-checkout-reveal-heading" className="text-title font-semibold">
            {t("admin.access.checkout.revealTitle", { target: revealed.checkout.target_id })}
          </h2>
          <p id="pam-checkout-reveal-description" className="mt-1 text-sm text-muted-foreground">
            {t("admin.access.checkout.revealDescription", { deadline: formatDateTime(revealed.checkout.expires_at, policy) })}
          </p>
          <div className="mt-3">
            <CredentialChip value={revealed.credential} label={t("admin.access.checkout.credentialLabel")} fullValue />
          </div>
          <div className="mt-3 flex justify-end">
            <Button type="button" onClick={() => setRevealed(null)}>
              {t("admin.access.checkout.close")}
            </Button>
          </div>
        </Dialog>
      ) : null}
    </section>
  );
}
