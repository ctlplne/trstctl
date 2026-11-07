/* eslint-disable jsx-a11y/no-noninteractive-tabindex -- The named table overflow region needs keyboard focus for horizontal scrolling. */
import { useId, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api, type PAMAccountActionReview, type PAMAccountFlag } from "@/lib/api";
import { useApiQuery, useQueryClient } from "@/lib/query";
import { useTranslation } from "@/i18n/I18nProvider";
import { formatDateTime, type FormatPolicy } from "@/i18n/format";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { ErrorState, LoadingState, UnavailableState } from "@/components/StatePrimitives";

// A276: brokered accounts whose owner is gone, or that sat unused past the
// window, are flagged. An action proposed here — reassign the owner, or
// rotate the account's credential and disable it — is approved by two
// people on the approvals page, then applied once and read back.

type Draft = { action: "reassign" | "rotate_disable"; owner: string; oldRef: string; reason: string };
type Pending = { flag: PAMAccountFlag; draft: Draft; requestID: string; review: PAMAccountActionReview };

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

export function PAMAccountFlagsPanel({ canAct }: { canAct: boolean }) {
  const { locale, timeZone, t } = useTranslation();
  const policy = useMemo<FormatPolicy>(() => ({ locale, timeZone }), [locale, timeZone]);
  const queryClient = useQueryClient();
  const ids = { action: useId(), owner: useId(), oldRef: useId(), reason: useId() };
  const flags = useApiQuery(["pam-account-flags"], () => api.pamAccountFlags(), { retry: false });
  const owners = useApiQuery(["owners"], api.owners, { enabled: canAct, retry: false });
  const [editing, setEditing] = useState<PAMAccountFlag | null>(null);
  const [draft, setDraft] = useState<Draft>({ action: "reassign", owner: "", oldRef: "", reason: "" });
  const [pending, setPending] = useState<Pending[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const key = (f: PAMAccountFlag) => `${f.target_type}/${f.target_id}`;
  const ownerName = (id?: string) => (id ? (owners.data?.find((o) => o.id === id)?.name ?? id) : "");

  const reasons = (f: PAMAccountFlag) => f.reasons.map((r) => t(r === "orphaned" ? "admin.access.flags.orphaned" : "admin.access.flags.unused")).join(", ");
  const status = (f: PAMAccountFlag) =>
    t(
      f.status === "open"
        ? "admin.access.flags.statusOpen"
        : f.status === "cleared"
          ? "admin.access.flags.statusCleared"
          : f.action === "reassign"
            ? "admin.access.flags.statusReassigned"
            : "admin.access.flags.statusDisabled",
    );

  async function act(work: () => Promise<string>) {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      setNotice(await work());
      await Promise.all([["pam-account-flags"], ["pam-targets"]].map((queryKey) => queryClient.invalidateQueries({ queryKey })));
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  const body = (d: Draft, requestID: string) => ({
    request_id: requestID,
    action: d.action,
    reason: d.reason.trim(),
    ...(d.action === "reassign" ? { owner_id: d.owner } : {}),
    ...(d.action === "rotate_disable" && d.oldRef.trim() ? { rotation_old_ref: d.oldRef.trim() } : {}),
  });

  function propose() {
    const flag = editing;
    if (!flag) return;
    void act(async () => {
      const requestID = crypto.randomUUID();
      const review = await api.requestPAMAccountAction(flag.target_type, flag.target_id, body(draft, requestID), crypto.randomUUID());
      setPending((current) => [...current.filter((p) => key(p.flag) !== key(flag)), { flag, draft, requestID, review }]);
      setEditing(null);
      return t("admin.access.flags.proposed", { id: flag.target_id, count: review.required_approvals });
    });
  }

  function apply(p: Pending) {
    void act(async () => {
      const flag = await api.applyPAMAccountAction(
        p.flag.target_type,
        p.flag.target_id,
        { ...body(p.draft, p.requestID), approval_request_id: p.review.approval_request_id, intent_digest: p.review.intent_digest },
        crypto.randomUUID(),
      );
      setPending((current) => current.filter((x) => x !== p));
      return t(flag.action === "reassign" ? "admin.access.flags.appliedReassign" : "admin.access.flags.appliedDisable", { id: flag.target_id });
    });
  }

  const items = flags.data?.items ?? [];
  return (
    <section aria-labelledby="pam-account-flags-heading" className="grid gap-3">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h3 id="pam-account-flags-heading" className="text-body font-semibold">
            {t("admin.access.flags.heading")}
          </h3>
          <p className="text-sm text-muted-foreground">{t("admin.access.flags.description")}</p>
        </div>
        {canAct ? (
          <Button
            type="button"
            size="sm"
            variant="outline"
            disabled={busy}
            onClick={() =>
              void act(async () => {
                await api.scanPAMAccountFlags(crypto.randomUUID());
                return t("admin.access.flags.scanned");
              })
            }
          >
            {t("admin.access.flags.scan")}
          </Button>
        ) : null}
      </div>
      {notice ? (
        <p role="status" className="text-sm">
          {notice}
        </p>
      ) : null}
      {error ? <ErrorState title={t("admin.access.flags.failed")}>{error}</ErrorState> : null}
      {flags.loading ? <LoadingState>{t("admin.access.flags.loading")}</LoadingState> : null}
      {flags.data && items.length === 0 ? <UnavailableState title={t("admin.access.flags.none")} /> : null}
      {items.length > 0 ? (
        <div className="overflow-auto" tabIndex={0} role="region" aria-label={t("admin.access.flags.table")}>
          <table className="ui-table">
            <caption className="sr-only">{t("admin.access.flags.table")}</caption>
            <thead>
              <tr>
                <th scope="col">{t("admin.access.flags.account")}</th>
                <th scope="col">{t("admin.access.flags.why")}</th>
                <th scope="col">{t("admin.access.flags.flaggedAt")}</th>
                <th scope="col">{t("admin.access.flags.status")}</th>
                <th scope="col">{t("admin.access.flags.next")}</th>
              </tr>
            </thead>
            <tbody>
              {items.map((f) => {
                const waiting = pending.find((p) => key(p.flag) === key(f));
                return (
                  <tr key={key(f)}>
                    <td className="font-mono text-xs">{key(f)}</td>
                    <td>
                      {reasons(f)}
                      {f.detail ? <span className="block text-caption text-muted-foreground">{f.detail}</span> : null}
                    </td>
                    <td>{formatDateTime(f.flagged_at, policy)}</td>
                    <td>
                      {status(f)}
                      {f.action === "reassign" && f.action_owner_id ? (
                        <span className="block text-caption">{t("admin.access.flags.newOwner", { owner: ownerName(f.action_owner_id) })}</span>
                      ) : null}
                    </td>
                    <td>
                      {f.status === "open" && canAct && !waiting ? (
                        <Button
                          type="button"
                          size="sm"
                          variant="outline"
                          aria-label={t("admin.access.flags.proposeFor", { id: f.target_id })}
                          onClick={() => {
                            setError(null);
                            setDraft({ action: "reassign", owner: "", oldRef: "", reason: "" });
                            setEditing(f);
                          }}
                        >
                          {t("admin.access.flags.propose")}
                        </Button>
                      ) : null}
                      {waiting ? (
                        <div className="grid gap-1">
                          <Link to={`/approvals?request=${encodeURIComponent(waiting.review.approval_request_id)}`} className="underline">
                            {t("admin.access.flags.review", { count: waiting.review.required_approvals })}
                          </Link>
                          <Button type="button" size="sm" disabled={busy} onClick={() => apply(waiting)}>
                            {t("admin.access.flags.apply")}
                          </Button>
                        </div>
                      ) : null}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      ) : null}
      {editing ? (
        <form
          className="grid gap-2 rounded-panel border border-border p-3 text-sm"
          aria-label={t("admin.access.flags.proposeFor", { id: editing.target_id })}
          onSubmit={(event) => {
            event.preventDefault();
            propose();
          }}
        >
          <label htmlFor={ids.action}>{t("admin.access.flags.action")}</label>
          <Select id={ids.action} value={draft.action} onChange={(event) => setDraft({ ...draft, action: event.target.value as Draft["action"] })}>
            <option value="reassign">{t("admin.access.flags.actionReassign")}</option>
            <option value="rotate_disable">{t("admin.access.flags.actionRotateDisable")}</option>
          </Select>
          {draft.action === "reassign" ? (
            <>
              <label htmlFor={ids.owner}>{t("admin.access.flags.owner")}</label>
              <Select id={ids.owner} required value={draft.owner} onChange={(event) => setDraft({ ...draft, owner: event.target.value })}>
                <option value="">{t("admin.access.chooseTargetOwner")}</option>
                {(owners.data ?? []).map((o) => (
                  <option key={o.id} value={o.id}>
                    {o.name}
                  </option>
                ))}
              </Select>
            </>
          ) : (
            <>
              <label htmlFor={ids.oldRef}>{t("admin.access.flags.oldRef")}</label>
              <Input id={ids.oldRef} value={draft.oldRef} onChange={(event) => setDraft({ ...draft, oldRef: event.target.value })} />
            </>
          )}
          <label htmlFor={ids.reason}>{t("admin.access.flags.reason")}</label>
          <Textarea id={ids.reason} required value={draft.reason} onChange={(event) => setDraft({ ...draft, reason: event.target.value })} />
          <div className="flex gap-2">
            <Button type="submit" size="sm" disabled={busy || !draft.reason.trim() || (draft.action === "reassign" && !draft.owner)}>
              {t("admin.access.flags.submit")}
            </Button>
            <Button type="button" size="sm" variant="ghost" onClick={() => setEditing(null)}>
              {t("admin.access.flags.cancel")}
            </Button>
          </div>
        </form>
      ) : null}
    </section>
  );
}
