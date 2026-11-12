import { useState } from "react";
import { useCan } from "@/components/rbac";
import { ErrorState } from "@/components/StatePrimitives";
import { Button } from "@/components/ui/button";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { useTranslation } from "@/i18n/I18nProvider";
import { api, type AccessBundle, type AccessBundleStandingApproval } from "@/lib/api";
import { apiProblemMessage } from "@/lib/apiProblem";
import { useApiQuery } from "@/lib/query";

type Account = { target_type: AccessBundle["access_targets"][number]["target_type"]; target_id: string; role: string };
type Notice = { tone: "status" | "alert"; text: string };

const accountKey = (a: Account) => `${a.target_type}/${a.target_id}:${a.role}`;

// datetime-local wants local wall time without a zone.
function localInput(date: Date): string {
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

/**
 * OD-9: a bundle's standing approvals for its delegated accounts. Never on by
 * default: an administrator who may approve access grants one for one
 * account and role, with an expiry, and the bundle's runs' session requests
 * for it are then approved without a reviewer. Sessions stay recorded and
 * revocable; revoking the approval ends the live sessions it approved.
 */
export function BundleStandingApprovals({ bundle, onChanged }: { bundle: AccessBundle; onChanged: () => void }) {
  const { t, formatDateTime } = useTranslation();
  const canWrite = useCan("access:write");
  const canApprove = useCan("access:approve");
  const approvals = useApiQuery(["access-bundle-standing-approvals", bundle.id], () => api.accessBundleStandingApprovals(bundle.id));
  const accounts: Account[] = bundle.access_targets.flatMap((target) =>
    target.roles.map((role) => ({ target_type: target.target_type, target_id: target.target_id, role })),
  );
  const [account, setAccount] = useState("");
  const [expires, setExpires] = useState(() => localInput(new Date(Date.now() + 7 * 24 * 3600 * 1000)));
  const [reason, setReason] = useState("");
  const [revoking, setRevoking] = useState<string | null>(null);
  const [revokeReason, setRevokeReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<Notice | null>(null);
  const chosen = accounts.find((a) => accountKey(a) === account) ?? accounts[0];
  const accountLabel = (a: { target_type: string; target_id: string; role: string }) =>
    t("agentAccess.standing.accountLabel", { type: a.target_type, id: a.target_id, role: a.role });

  const refresh = () => {
    approvals.refetch();
    onChanged();
  };

  async function grant() {
    if (!chosen) return;
    if (reason.trim() === "") {
      setNotice({ tone: "alert", text: t("agentAccess.standing.reasonRequired") });
      return;
    }
    const at = new Date(expires);
    if (Number.isNaN(at.getTime())) {
      setNotice({ tone: "alert", text: t("agentAccess.standing.expiresInvalid") });
      return;
    }
    setBusy(true);
    setNotice(null);
    try {
      const granted = await api.grantAccessBundleStandingApproval(bundle.id, {
        target_type: chosen.target_type,
        target_id: chosen.target_id,
        role: chosen.role,
        reason: reason.trim(),
        expires_at: at.toISOString(),
      });
      setNotice({
        tone: "status",
        text: t("agentAccess.standing.grantedNotice", { account: accountLabel(granted), expires: formatDateTime(granted.expires_at) }),
      });
      setReason("");
      refresh();
    } catch (err) {
      setNotice({ tone: "alert", text: apiProblemMessage(err, t("agentAccess.standing.grantFailed")) });
    } finally {
      setBusy(false);
    }
  }

  async function revoke(item: AccessBundleStandingApproval) {
    if (revokeReason.trim() === "") {
      setNotice({ tone: "alert", text: t("agentAccess.standing.revokeReasonRequired") });
      return;
    }
    setBusy(true);
    setNotice(null);
    try {
      const revoked = await api.revokeAccessBundleStandingApproval(bundle.id, item.id, revokeReason.trim());
      setNotice({
        tone: "status",
        text: t("agentAccess.standing.revokedNotice", { account: accountLabel(item), sessions: revoked.ended_sessions.length }),
      });
      setRevoking(null);
      setRevokeReason("");
      refresh();
    } catch (err) {
      setNotice({ tone: "alert", text: apiProblemMessage(err, t("agentAccess.standing.revokeFailed")) });
    } finally {
      setBusy(false);
    }
  }

  function status(item: AccessBundleStandingApproval): string {
    if (item.status === "revoked") return t("agentAccess.standing.status.revoked");
    if (item.status === "expired") return t("agentAccess.standing.status.expired");
    return t("agentAccess.standing.status.active");
  }

  const items = approvals.data ?? [];
  return (
    <section className="grid gap-3" aria-labelledby="agent-access-standing">
      <h2 id="agent-access-standing" className="font-medium">
        {t("agentAccess.standing.title", { name: bundle.name })}
      </h2>
      <p className="text-sm text-muted-foreground">{t("agentAccess.standing.description")}</p>
      {approvals.error ? <ErrorState title={t("agentAccess.standing.loadFailed")}>{apiProblemMessage(approvals.error, "")}</ErrorState> : null}
      {notice && (
        <p role={notice.tone} className={notice.tone === "alert" ? "text-sm text-destructive" : "text-sm"}>
          {notice.text}
        </p>
      )}
      {items.length === 0 ? (
        <p className="text-sm text-muted-foreground">{t("agentAccess.standing.none")}</p>
      ) : (
        <table className="ui-table" aria-label={t("agentAccess.standing.tableLabel")}>
          <thead>
            <tr>
              <th scope="col">{t("agentAccess.standing.account")}</th>
              <th scope="col">{t("agentAccess.standing.expires")}</th>
              <th scope="col">{t("agentAccess.standing.approvals")}</th>
              <th scope="col">{t("agentAccess.standing.state")}</th>
              <th scope="col">{t("agentAccess.standing.reason")}</th>
              <th scope="col">
                <span className="sr-only">{t("agentAccess.standing.actions")}</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {items.map((item) => (
              <tr key={item.id} className="align-top">
                <td className="font-mono">{accountLabel(item)}</td>
                <td>{formatDateTime(item.expires_at)}</td>
                <td>
                  {item.last_approved_at
                    ? t("agentAccess.standing.approvalsLast", { count: item.approvals, time: formatDateTime(item.last_approved_at) })
                    : item.approvals}
                </td>
                <td>
                  {status(item)}
                  {item.status === "revoked" && item.revoke_reason ? <span className="block text-xs text-muted-foreground">{item.revoke_reason}</span> : null}
                </td>
                <td>
                  {item.reason}
                  <span className="block text-xs text-muted-foreground">{t("agentAccess.standing.grantedBy", { actor: item.granted_by })}</span>
                </td>
                <td>
                  {item.status === "active" && canWrite ? (
                    revoking === item.id ? (
                      <div className="grid gap-2">
                        <Field label={t("agentAccess.standing.revokeReason")}>
                          {(control) => <Input {...control} value={revokeReason} maxLength={500} onChange={(e) => setRevokeReason(e.target.value)} />}
                        </Field>
                        <div className="flex gap-2">
                          <Button type="button" size="sm" variant="destructive" disabled={busy} onClick={() => void revoke(item)}>
                            {t("agentAccess.standing.confirmRevoke")}
                          </Button>
                          <Button type="button" size="sm" variant="ghost" disabled={busy} onClick={() => setRevoking(null)}>
                            {t("agentAccess.standing.cancelRevoke")}
                          </Button>
                        </div>
                      </div>
                    ) : (
                      <Button
                        type="button"
                        size="sm"
                        variant="outline"
                        disabled={busy}
                        aria-label={t("agentAccess.standing.revokeLabel", { account: accountLabel(item) })}
                        onClick={() => {
                          setRevoking(item.id);
                          setRevokeReason("");
                        }}
                      >
                        {t("agentAccess.standing.revoke")}
                      </Button>
                    )
                  ) : null}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {canWrite && canApprove ? (
        accounts.length === 0 ? (
          <p className="text-sm text-muted-foreground">{t("agentAccess.standing.noAccounts")}</p>
        ) : (
          <div className="grid gap-3 md:grid-cols-4">
            <Field label={t("agentAccess.standing.account")} controlId="standing-account">
              {(control) => (
                <Select {...control} value={chosen ? accountKey(chosen) : ""} onChange={(e) => setAccount(e.target.value)}>
                  {accounts.map((a) => (
                    <option key={accountKey(a)} value={accountKey(a)}>
                      {accountLabel(a)}
                    </option>
                  ))}
                </Select>
              )}
            </Field>
            <Field label={t("agentAccess.standing.expires")} controlId="standing-expires" description={t("agentAccess.standing.expiresHelp")}>
              {(control) => <Input {...control} type="datetime-local" value={expires} onChange={(e) => setExpires(e.target.value)} />}
            </Field>
            <Field label={t("agentAccess.standing.reason")} controlId="standing-reason">
              {(control) => <Input {...control} value={reason} maxLength={500} onChange={(e) => setReason(e.target.value)} />}
            </Field>
            <Button type="button" className="self-end" disabled={busy} onClick={() => void grant()}>
              {t("agentAccess.standing.grant")}
            </Button>
          </div>
        )
      ) : canWrite ? (
        <p className="text-sm text-muted-foreground">{t("agentAccess.standing.needsApprove")}</p>
      ) : null}
    </section>
  );
}
