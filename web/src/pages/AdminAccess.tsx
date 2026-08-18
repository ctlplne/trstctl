import { useEffect, useMemo, useState, type FormEvent, type ReactNode } from "react";
import { KeyRound, Loader2, Plus, RefreshCw, ShieldCheck, UserMinus } from "lucide-react";
import { AdminHeaderActions } from "@/components/AdminHeaderActions";
import { DataGrid, type DataGridColumn } from "@/components/DataGrid";
import { Dialog } from "@/components/Dialog";
import { PageHeader } from "@/components/PageHeader";
import { StatusBadge } from "@/components/StatusBadge";
import { UnavailableState } from "@/components/StatePrimitives";
import { Button } from "@/components/ui/button";
import { useTranslation, translateNow } from "@/i18n/I18nProvider";
import { formatDateTime, type FormatPolicy } from "@/i18n/format";
import { api, type APIToken, type Member, type OIDCMappingStatus, type PAMSession, type PAMSessionRequest, type RoleList } from "@/lib/api";
import { apiProblemMessage } from "@/lib/apiProblem";
import type { StatusTone } from "@/lib/statusVocab";

type PAMSessionFormState = {
  target_type: PAMSessionRequest["target_type"];
  target_id: string;
  role: string;
  method: string;
  payload_base64: string;
  reason: string;
  ttl_seconds: string;
  ssh_principal: string;
  ssh_public_key: string;
};

const defaultPAMSessionForm: PAMSessionFormState = {
  target_type: "postgres",
  target_id: "",
  role: "",
  method: "",
  payload_base64: "",
  reason: "",
  ttl_seconds: "",
  ssh_principal: "",
  ssh_public_key: "",
};

/** /admin/access — the tenant's operational access surface: membership, API
 * tokens, offboarding, and JIT privileged sessions. */
export function AdminAccess() {
  const { locale, timeZone, t } = useTranslation();
  const formatPolicy = useMemo<FormatPolicy>(() => ({ locale, timeZone }), [locale, timeZone]);
  const [roles, setRoles] = useState<RoleList | null>(null);
  const [oidc, setOIDC] = useState<OIDCMappingStatus | null>(null);
  const [members, setMembers] = useState<Member[]>([]);
  const [tokens, setTokens] = useState<APIToken[]>([]);
  const [accessLoading, setAccessLoading] = useState(true);
  const [accessBusy, setAccessBusy] = useState(false);
  const [accessError, setAccessError] = useState<string | null>(null);
  const [accessNotice, setAccessNotice] = useState<string | null>(null);
  const [revealedToken, setRevealedToken] = useState<string | null>(null);
  const [memberSubject, setMemberSubject] = useState("");
  const [memberDisplayName, setMemberDisplayName] = useState("");
  const [memberEmail, setMemberEmail] = useState("");
  const [memberRoles, setMemberRoles] = useState("operator");
  const [tokenSubject, setTokenSubject] = useState("");
  const [tokenScopes, setTokenScopes] = useState("access:read");
  const [offboardSubject, setOffboardSubject] = useState("");
  const [offboardReason, setOffboardReason] = useState("");
  const [pamRows, setPAMRows] = useState<PAMSession[] | null>(null);
  const [pamUnavailable, setPAMUnavailable] = useState<string | null>(null);
  const [pamCursor, setPAMCursor] = useState<string | undefined>(undefined);
  const [pamLoadingMore, setPAMLoadingMore] = useState(false);
  const [pamDetail, setPAMDetail] = useState<PAMSession | null>(null);
  const [pamFormOpen, setPAMFormOpen] = useState(false);
  const [pamForm, setPAMForm] = useState<PAMSessionFormState>(defaultPAMSessionForm);
  const [pamBusy, setPAMBusy] = useState(false);
  const [pamFormError, setPAMFormError] = useState<string | null>(null);
  const [pamCreated, setPAMCreated] = useState<PAMSession | null>(null);
  const [pamCopied, setPAMCopied] = useState(false);
  const roleRows = useMemo(() => roles?.items ?? [], [roles]);
  const pamColumns = useMemo<DataGridColumn<PAMSession>[]>(
    () => [
      { id: "started", header: "Started", cell: (session) => formatOptionalDate(session.started_at, formatPolicy) },
      {
        id: "subject",
        header: "Subject",
        cell: (session) => <span className="break-all font-mono text-xs">{session.subject}</span>,
      },
      { id: "role", header: "Role", cell: (session) => session.role },
      {
        id: "target",
        header: "Target",
        cell: (session) => (
          <div className="grid gap-1">
            <span>{session.target_type}</span>
            <span className="break-all font-mono text-xs text-muted-foreground">{session.target_id}</span>
          </div>
        ),
      },
      {
        id: "status",
        header: "Status",
        cell: (session) => <StatusBadge value={session.status} label={session.status} tone={pamStatusTone(session.status)} />,
      },
      { id: "expires", header: "Expires", cell: (session) => formatOptionalDate(session.expires_at, formatPolicy) },
    ],
    [formatPolicy],
  );

  async function loadAccessAdmin() {
    setAccessLoading(true);
    setAccessError(null);
    try {
      const [roleCatalog, oidcStatus, memberPage, tokenPage] = await Promise.all([
        api.accessRoles(),
        api.oidcMappingStatus(),
        api.members({ includeOffboarded: true, limit: 50 }),
        api.apiTokens({ includeRevoked: true, limit: 50 }),
      ]);
      setRoles(roleCatalog);
      setOIDC(oidcStatus);
      setMembers(memberPage.items ?? []);
      setTokens(tokenPage.items ?? []);
    } catch (err) {
      setAccessError(err instanceof Error ? err.message : String(err));
    } finally {
      setAccessLoading(false);
    }
  }

  useEffect(() => {
    void loadAccessAdmin();
  }, []);

  useEffect(() => {
    let active = true;
    Promise.resolve()
      .then(() => api.pamSessions({ limit: 20 }))
      .then((page) => {
        if (!active) return;
        setPAMUnavailable(null);
        setPAMRows(page.items ?? []);
        setPAMCursor(page.next_cursor);
      })
      .catch((err: unknown) => {
        if (!active) return;
        setPAMUnavailable(apiProblemMessage(err, "Privileged access sessions are unavailable"));
      });
    return () => {
      active = false;
    };
  }, []);

  async function loadMorePAMSessions() {
    if (!pamCursor) return;
    setPAMLoadingMore(true);
    try {
      const page = await api.pamSessions({ limit: 20, cursor: pamCursor });
      setPAMRows((current) => [...(current ?? []), ...(page.items ?? [])]);
      setPAMCursor(page.next_cursor);
    } catch (err) {
      setAccessError(err instanceof Error ? err.message : String(err));
    } finally {
      setPAMLoadingMore(false);
    }
  }

  function closePAMDialog() {
    setPAMFormOpen(false);
    setPAMFormError(null);
    setPAMCreated(null);
    setPAMCopied(false);
  }

  async function openPrivilegedSession(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setPAMBusy(true);
    setPAMFormError(null);
    try {
      const ttl = Number(pamForm.ttl_seconds.trim());
      const input: PAMSessionRequest = {
        method: pamForm.method.trim(),
        payload_base64: pamForm.payload_base64.trim(),
        role: pamForm.role.trim(),
        target_id: pamForm.target_id.trim(),
        target_type: pamForm.target_type,
        ...(pamForm.reason.trim() ? { reason: pamForm.reason.trim() } : {}),
        ...(pamForm.ttl_seconds.trim() && Number.isFinite(ttl) && ttl > 0 ? { ttl_seconds: Math.floor(ttl) } : {}),
        ...(pamForm.target_type === "ssh" && pamForm.ssh_principal.trim() ? { ssh_principal: pamForm.ssh_principal.trim() } : {}),
        ...(pamForm.target_type === "ssh" && pamForm.ssh_public_key.trim() ? { ssh_public_key: pamForm.ssh_public_key.trim() } : {}),
      };
      const created = await api.openPAMSession(input);
      setPAMCreated(created);
      setPAMRows((current) => [created, ...(current ?? []).filter((item) => item.id !== created.id)]);
      setPAMForm(defaultPAMSessionForm);
    } catch (err) {
      setPAMFormError(err instanceof Error ? err.message : String(err));
    } finally {
      setPAMBusy(false);
    }
  }

  async function copyPAMSessionID(id: string) {
    try {
      await navigator.clipboard.writeText(id);
      setPAMCopied(true);
    } catch {
      setPAMCopied(false);
    }
  }

  async function onboardMember(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setAccessBusy(true);
    setAccessError(null);
    setAccessNotice(null);
    try {
      await api.upsertMember(memberSubject.trim(), {
        display_name: memberDisplayName.trim(),
        email: memberEmail.trim(),
        roles: csvList(memberRoles),
        source: "manual",
      });
      setAccessNotice(`Onboarded ${memberSubject.trim()}`);
      setMemberSubject("");
      setMemberDisplayName("");
      setMemberEmail("");
      await loadAccessAdmin();
    } catch (err) {
      setAccessError(err instanceof Error ? err.message : String(err));
    } finally {
      setAccessBusy(false);
    }
  }

  async function mintToken(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setAccessBusy(true);
    setAccessError(null);
    setAccessNotice(null);
    setRevealedToken(null);
    try {
      const created = await api.createAPIToken({ subject: tokenSubject.trim(), scopes: csvList(tokenScopes) });
      setRevealedToken(created.token);
      setAccessNotice(`Minted API token for ${created.subject}`);
      setTokenSubject("");
      await loadAccessAdmin();
    } catch (err) {
      setAccessError(err instanceof Error ? err.message : String(err));
    } finally {
      setAccessBusy(false);
    }
  }

  async function offboardMember(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setAccessBusy(true);
    setAccessError(null);
    setAccessNotice(null);
    setRevealedToken(null);
    try {
      const result = await api.offboardMember(offboardSubject.trim(), { reason: offboardReason.trim() });
      setAccessNotice(`Offboarded ${result.member.subject}; revoked ${result.revoked_token_count} token(s)`);
      setOffboardSubject("");
      setOffboardReason("");
      await loadAccessAdmin();
    } catch (err) {
      setAccessError(err instanceof Error ? err.message : String(err));
    } finally {
      setAccessBusy(false);
    }
  }

  return (
    <section aria-labelledby="admin-access-heading" className="grid gap-6">
      <PageHeader
        titleId="admin-access-heading"
        title={t("platform.tabs.access")}
        description={t("admin.access.description")}
        actions={<AdminHeaderActions />}
      />
      <div className="grid gap-6">
        {/* The page H1 above already says "Access administration" (naming
              parity), so this block only carries the refresh affordance. */}
        <div>
          <div className="mb-3 flex flex-wrap items-center justify-end gap-3">
            <Button type="button" size="sm" variant="outline" onClick={() => void loadAccessAdmin()} disabled={accessLoading}>
              {accessLoading ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <RefreshCw className="h-4 w-4" aria-hidden="true" />}
              {translateNow("source.refresh.0e91610117")}
            </Button>
          </div>
          {accessError && (
            <p role="alert" className="mb-3 rounded-control border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm text-destructive">
              {accessError}
            </p>
          )}
          {accessNotice && (
            <p role="status" className="mb-3 rounded-control border border-status-success/30 bg-status-success/10 px-3 py-2 text-sm text-status-success">
              {accessNotice}
            </p>
          )}
          {revealedToken && (
            <div className="mb-3 rounded-panel border border-status-warning/40 bg-status-warning/10 p-3 text-sm">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <p className="font-medium">{translateNow("source.reveal.once.api.token.8cfd65d574")}</p>
                <Button type="button" size="sm" variant="ghost" onClick={() => setRevealedToken(null)}>
                  {translateNow("source.dismiss.48845bff33")}
                </Button>
              </div>
              <code className="mt-2 block break-all rounded bg-background px-2 py-1 text-xs">{revealedToken}</code>
            </div>
          )}
          <div className="mb-4 grid gap-3 xl:grid-cols-3">
            <form onSubmit={(event) => void onboardMember(event)} className="ui-panel grid gap-3 p-comfortable">
              <div className="flex items-center gap-2">
                <ShieldCheck className="h-4 w-4 text-status-success" aria-hidden="true" />
                <h2 className="text-body font-semibold">{translateNow("source.onboard.member.a6dfe12142")}</h2>
              </div>
              <label className="grid gap-1 text-sm">
                <span className="font-medium text-muted-foreground">{translateNow("source.subject.6897128384")}</span>
                <input className="ui-input" value={memberSubject} onChange={(event) => setMemberSubject(event.target.value)} required />
              </label>
              <label className="grid gap-1 text-sm">
                <span className="font-medium text-muted-foreground">{translateNow("source.display.name.2b7f6a84de")}</span>
                <input className="ui-input" value={memberDisplayName} onChange={(event) => setMemberDisplayName(event.target.value)} />
              </label>
              <label className="grid gap-1 text-sm">
                <span className="font-medium text-muted-foreground">{translateNow("source.email.969ccbd3cf")}</span>
                <input className="ui-input" value={memberEmail} onChange={(event) => setMemberEmail(event.target.value)} />
              </label>
              <label className="grid gap-1 text-sm">
                <span className="font-medium text-muted-foreground">{translateNow("source.roles.c253370554")}</span>
                <input className="ui-input" value={memberRoles} onChange={(event) => setMemberRoles(event.target.value)} required />
              </label>
              <Button type="submit" disabled={accessBusy || !memberSubject.trim()}>
                <Plus className="h-4 w-4" aria-hidden="true" />
                {translateNow("source.save.1509f561f2")}
              </Button>
            </form>
            <form onSubmit={(event) => void mintToken(event)} className="ui-panel grid gap-3 p-comfortable">
              <div className="flex items-center gap-2">
                <KeyRound className="h-4 w-4 text-status-warning" aria-hidden="true" />
                <h2 className="text-body font-semibold">{translateNow("source.mint.api.token.f6cf0efff0")}</h2>
              </div>
              <label className="grid gap-1 text-sm">
                <span className="font-medium text-muted-foreground">{translateNow("source.subject.6897128384")}</span>
                <input className="ui-input" value={tokenSubject} onChange={(event) => setTokenSubject(event.target.value)} required />
              </label>
              <label className="grid gap-1 text-sm">
                <span className="font-medium text-muted-foreground">{translateNow("source.scopes.0d5644ff52")}</span>
                <input className="ui-input" value={tokenScopes} onChange={(event) => setTokenScopes(event.target.value)} required />
              </label>
              <Button type="submit" disabled={accessBusy || !tokenSubject.trim()}>
                <KeyRound className="h-4 w-4" aria-hidden="true" />
                {translateNow("source.mint.ced97cc4a3")}
              </Button>
            </form>
            <form onSubmit={(event) => void offboardMember(event)} className="ui-panel grid gap-3 p-comfortable">
              <div className="flex items-center gap-2">
                <UserMinus className="h-4 w-4 text-destructive" aria-hidden="true" />
                <h2 className="text-body font-semibold">{translateNow("source.offboard.member.8a27787595")}</h2>
              </div>
              <label className="grid gap-1 text-sm">
                <span className="font-medium text-muted-foreground">{translateNow("source.subject.6897128384")}</span>
                {/* Autocomplete from the loaded member roster — no copy-pasting
                  subjects out of the table above. */}
                <input
                  className="ui-input"
                  value={offboardSubject}
                  onChange={(event) => setOffboardSubject(event.target.value)}
                  list="member-subject-options"
                  required
                />
                <datalist id="member-subject-options">
                  {members.map((member) => (
                    <option key={member.subject} value={member.subject}>
                      {member.email ?? member.subject}
                    </option>
                  ))}
                </datalist>
              </label>
              <label className="grid gap-1 text-sm">
                <span className="font-medium text-muted-foreground">{translateNow("source.reason.f81ab834de")}</span>
                <input className="ui-input" value={offboardReason} onChange={(event) => setOffboardReason(event.target.value)} />
              </label>
              <Button type="submit" variant="destructive" loading={accessBusy} disabled={!offboardSubject.trim()}>
                <UserMinus className="h-4 w-4" aria-hidden="true" />
                {translateNow("source.offboard.9053e68ef6")}
              </Button>
            </form>
          </div>
          {pamRows && (
            <div className="ui-panel mb-4 grid gap-3 p-comfortable">
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div>
                  <h2 className="text-body font-semibold">{t("parity.privilegedAccessSessions_368da5")}</h2>
                  <p className="mt-1 text-sm text-muted-foreground">{t("parity.justInTimeOperatorSessionsBrokered_df233f")}</p>
                </div>
                <Button type="button" size="sm" onClick={() => setPAMFormOpen(true)}>
                  <KeyRound className="h-4 w-4" aria-hidden="true" />
                  {t("parity.openSession_73b3ca")}
                </Button>
              </div>
              <DataGrid
                ariaLabel="Privileged access sessions"
                rows={pamRows}
                columns={pamColumns}
                getRowId={(session) => session.id}
                onRowOpen={(session) => setPAMDetail(session)}
                rowActionLabel={() => "Details"}
                pagination={
                  pamCursor ? (
                    <div>
                      <Button type="button" size="sm" variant="outline" disabled={pamLoadingMore} onClick={() => void loadMorePAMSessions()}>
                        {pamLoadingMore ? translateNow("source.loading.more.sessions.25d47273c8") : translateNow("source.load.more.sessions.e04b242241")}
                      </Button>
                    </div>
                  ) : undefined
                }
              />
            </div>
          )}
          {pamUnavailable && (
            <div className="mb-4">
              <UnavailableState title={t("admin.access.pamUnavailableTitle")}>{pamUnavailable}</UnavailableState>
            </div>
          )}
          <div className="mb-4 grid gap-4 xl:grid-cols-2">
            <div className="overflow-x-auto rounded-panel border border-border">
              <table className="ui-table min-w-[34rem]">
                <caption className="sr-only">{translateNow("source.role.catalog.d2bfa0ab0e")}</caption>
                <thead>
                  <tr>
                    <th scope="col">{translateNow("source.role.14736a2eb9")}</th>
                    <th scope="col">{translateNow("source.permissions.abccc78cc9")}</th>
                  </tr>
                </thead>
                <tbody>
                  {roleRows.map((role) => (
                    <tr key={role.name} className="align-top">
                      <td className="font-medium">{role.name}</td>
                      <td className="font-mono text-xs">{role.permissions.join(", ")}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="ui-panel p-comfortable text-sm">
              <h2 className="font-semibold">{translateNow("source.oidc.mapping.status.358515bade")}</h2>
              <dl className="mt-3 grid gap-2">
                <div>
                  <dt className="font-medium text-muted-foreground">{translateNow("source.enabled.92c1cdfdf4")}</dt>
                  <dd>{oidc?.enabled ? translateNow("source.yes.8a798890fe") : translateNow("source.no.9390298f3f")}</dd>
                </div>
                <div>
                  <dt className="font-medium text-muted-foreground">{translateNow("source.claims.1c85c12229")}</dt>
                  <dd>{[oidc?.tenant_claim || "no tenant claim", oidc?.groups_claim || "no groups claim"].join(" · ")}</dd>
                </div>
                <div>
                  <dt className="font-medium text-muted-foreground">{translateNow("source.mappings.f64ec16b0d")}</dt>
                  <dd>
                    {oidc?.tenant_mappings?.length
                      ? oidc.tenant_mappings.map((m) => m.group || m.subject || m.claim).join(", ")
                      : translateNow("source.none.140bedbf9c")}
                  </dd>
                </div>
              </dl>
            </div>
          </div>
          <div className="mb-4 grid gap-4 xl:grid-cols-2">
            <div className="overflow-x-auto rounded-panel border border-border">
              <table className="ui-table min-w-[44rem]">
                <caption className="sr-only">{translateNow("source.tenant.members.7c3b607c20")}</caption>
                <thead>
                  <tr>
                    <th scope="col">{translateNow("source.subject.6897128384")}</th>
                    <th scope="col">{translateNow("source.roles.c253370554")}</th>
                    <th scope="col">{translateNow("source.status.920e413c7d")}</th>
                    <th scope="col">{translateNow("source.updated.3a5ecca188")}</th>
                  </tr>
                </thead>
                <tbody>
                  {members.map((member) => (
                    <tr key={member.subject} className="align-top">
                      <td className="font-medium">{member.subject}</td>
                      <td className="font-mono text-xs">{(member.roles ?? []).join(", ")}</td>
                      <td>{member.status}</td>
                      <td>{formatOptionalDate(member.updated_at, formatPolicy)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="overflow-x-auto rounded-panel border border-border">
              <table className="ui-table min-w-[48rem]">
                <caption className="sr-only">{translateNow("source.api.token.metadata.d3e4dba811")}</caption>
                <thead>
                  <tr>
                    <th scope="col">{translateNow("source.subject.6897128384")}</th>
                    <th scope="col">{translateNow("source.scopes.0d5644ff52")}</th>
                    <th scope="col">{translateNow("source.status.920e413c7d")}</th>
                    <th scope="col">{translateNow("source.created.d70b9e24bc")}</th>
                  </tr>
                </thead>
                <tbody>
                  {tokens.map((token) => (
                    <tr key={token.id} className="align-top">
                      <td className="font-medium">{token.subject}</td>
                      <td className="font-mono text-xs">{token.scopes.join(", ")}</td>
                      <td>{token.revoked_at ? translateNow("source.revoked.4bb47f186d") : translateNow("source.active.9687961165")}</td>
                      <td>{formatOptionalDate(token.created_at, formatPolicy)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        {pamDetail && (
          <Dialog
            open
            onClose={() => setPAMDetail(null)}
            titleId="pam-session-detail-heading"
            descriptionId="pam-session-detail-description"
            className="fixed inset-0 z-50 flex items-center justify-center p-4"
            overlayClassName="absolute inset-0 bg-black/55"
            panelClassName="relative max-h-[calc(100vh-2rem)] w-full max-w-2xl overflow-y-auto rounded-panel border border-border bg-card shadow-elevation2"
          >
            <header className="border-b border-border px-5 py-4">
              <h2 id="pam-session-detail-heading" className="text-title font-semibold">
                {translateNow("source.privileged.session.value1.2958e09fb1", { value1: pamDetail.id })}
              </h2>
              <p id="pam-session-detail-description" className="mt-1 text-sm text-muted-foreground">
                {t("parity.brokerEvidenceForThisJustIn_44ca48")}
              </p>
            </header>
            <dl className="grid gap-2 p-5 text-sm">
              <PlatformDetailRow term="ID" mono>
                {pamDetail.id}
              </PlatformDetailRow>
              <PlatformDetailRow term="Status">
                <StatusBadge value={pamDetail.status} label={pamDetail.status} tone={pamStatusTone(pamDetail.status)} />
              </PlatformDetailRow>
              <PlatformDetailRow term="Subject" mono>
                {pamDetail.subject}
              </PlatformDetailRow>
              <PlatformDetailRow term="Requested by" mono>
                {pamDetail.requested_by}
              </PlatformDetailRow>
              <PlatformDetailRow term="Role">{pamDetail.role}</PlatformDetailRow>
              <PlatformDetailRow term="Target" mono>
                {translateNow("source.value1.value2.7c639bc99b", { value1: pamDetail.target_type, value2: pamDetail.target_id })}
              </PlatformDetailRow>
              <PlatformDetailRow term="Reason">{pamDetail.reason || "-"}</PlatformDetailRow>
              <PlatformDetailRow term="Started">{formatOptionalDate(pamDetail.started_at, formatPolicy)}</PlatformDetailRow>
              <PlatformDetailRow term="Expires">{formatOptionalDate(pamDetail.expires_at, formatPolicy)}</PlatformDetailRow>
              <PlatformDetailRow term="Ended">{formatOptionalDate(pamDetail.ended_at, formatPolicy)}</PlatformDetailRow>
              {pamDetail.attestation ? (
                <PlatformDetailRow term="Attestation">
                  <JSONBlock value={pamDetail.attestation} />
                </PlatformDetailRow>
              ) : null}
              {pamDetail.audit ? (
                <PlatformDetailRow term="Audit">
                  <JSONBlock value={pamDetail.audit} />
                </PlatformDetailRow>
              ) : null}
              {pamDetail.postgres ? (
                <PlatformDetailRow term="PostgreSQL credential">
                  <JSONBlock value={pamDetail.postgres} />
                </PlatformDetailRow>
              ) : null}
              {pamDetail.ssh ? (
                <PlatformDetailRow term="SSH credential">
                  <JSONBlock value={pamDetail.ssh} />
                </PlatformDetailRow>
              ) : null}
            </dl>
            <div className="flex justify-end border-t border-border px-5 py-4">
              <Button type="button" variant="outline" onClick={() => setPAMDetail(null)}>
                {translateNow("source.close.7d9eb7acb1")}
              </Button>
            </div>
          </Dialog>
        )}

        {pamFormOpen && (
          <Dialog
            open
            onClose={closePAMDialog}
            titleId="pam-open-heading"
            descriptionId="pam-open-description"
            className="fixed inset-0 z-50 flex items-center justify-center p-4"
            overlayClassName="absolute inset-0 bg-black/55"
            panelClassName="relative max-h-[calc(100vh-2rem)] w-full max-w-xl overflow-y-auto rounded-panel border border-border bg-card shadow-elevation2"
          >
            <header className="border-b border-border px-5 py-4">
              <h2 id="pam-open-heading" className="text-title font-semibold">
                {t("parity.openPrivilegedSession_78a445")}
              </h2>
              <p id="pam-open-description" className="mt-1 text-sm text-muted-foreground">
                Broker short-lived access to a PostgreSQL role or SSH principal; the session and its evidence land in the audit trail.
              </p>
            </header>
            {pamCreated ? (
              <div className="grid gap-3 p-5 text-sm">
                <p role="status" className="rounded-control border border-status-success/30 bg-status-success/10 px-3 py-2 text-status-success">
                  {t("parity.sessionOpened_368838")}
                </p>
                <dl className="grid gap-2">
                  <PlatformDetailRow term="Session ID">
                    <span className="inline-flex flex-wrap items-center gap-2">
                      <span className="break-all font-mono text-xs">{pamCreated.id}</span>
                      <Button type="button" size="sm" variant="outline" onClick={() => void copyPAMSessionID(pamCreated.id)}>
                        {pamCopied ? translateNow("source.copied.8d525e5f15") : translateNow("source.copy.id.72ac0d580f")}
                      </Button>
                    </span>
                  </PlatformDetailRow>
                  <PlatformDetailRow term="Status">
                    <StatusBadge value={pamCreated.status} label={pamCreated.status} tone={pamStatusTone(pamCreated.status)} />
                  </PlatformDetailRow>
                  <PlatformDetailRow term="Expires">{formatOptionalDate(pamCreated.expires_at, formatPolicy)}</PlatformDetailRow>
                </dl>
                <div className="flex justify-end">
                  <Button type="button" variant="outline" onClick={closePAMDialog}>
                    {translateNow("source.close.7d9eb7acb1")}
                  </Button>
                </div>
              </div>
            ) : (
              <form onSubmit={(event) => void openPrivilegedSession(event)} className="grid gap-3 p-5">
                {pamFormError && (
                  <p role="alert" className="rounded-control border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm text-destructive">
                    {pamFormError}
                  </p>
                )}
                <div className="grid gap-3 md:grid-cols-2">
                  <label className="grid gap-1 text-body font-medium">
                    {t("parity.targetType_a45f80")}
                    <select
                      className="min-h-9 rounded-control border border-border bg-background px-3 py-2 text-body"
                      value={pamForm.target_type}
                      onChange={(event) => setPAMForm({ ...pamForm, target_type: event.target.value as PAMSessionRequest["target_type"] })}
                    >
                      <option value="postgres">{t("parity.postgres_afc848")}</option>
                      <option value="ssh">{t("parity.ssh_e8b9f6")}</option>
                    </select>
                  </label>
                  <label className="grid gap-1 text-body font-medium">
                    {t("parity.targetId_00960a")}
                    <input
                      className="min-h-9 rounded-control border border-border bg-background px-3 py-2 text-body"
                      value={pamForm.target_id}
                      onChange={(event) => setPAMForm({ ...pamForm, target_id: event.target.value })}
                      required
                    />
                  </label>
                  <label className="grid gap-1 text-body font-medium">
                    {translateNow("source.role.14736a2eb9")}
                    <input
                      className="min-h-9 rounded-control border border-border bg-background px-3 py-2 text-body"
                      value={pamForm.role}
                      onChange={(event) => setPAMForm({ ...pamForm, role: event.target.value })}
                      required
                    />
                  </label>
                  <label className="grid gap-1 text-body font-medium">
                    {translateNow("source.method.52a0f9b65b")}
                    <input
                      className="min-h-9 rounded-control border border-border bg-background px-3 py-2 text-body"
                      value={pamForm.method}
                      onChange={(event) => setPAMForm({ ...pamForm, method: event.target.value })}
                      required
                    />
                  </label>
                  {pamForm.target_type === "ssh" && (
                    <label className="grid gap-1 text-body font-medium">
                      {t("parity.sshPrincipal_8d0a6c")}
                      <input
                        className="min-h-9 rounded-control border border-border bg-background px-3 py-2 text-body"
                        value={pamForm.ssh_principal}
                        onChange={(event) => setPAMForm({ ...pamForm, ssh_principal: event.target.value })}
                      />
                    </label>
                  )}
                  <label className="grid gap-1 text-body font-medium">
                    {translateNow("source.reason.f81ab834de")}
                    <input
                      className="min-h-9 rounded-control border border-border bg-background px-3 py-2 text-body"
                      value={pamForm.reason}
                      onChange={(event) => setPAMForm({ ...pamForm, reason: event.target.value })}
                    />
                  </label>
                  <label className="grid gap-1 text-body font-medium">
                    {translateNow("source.ttl.seconds.862d08de5a")}
                    <input
                      className="min-h-9 rounded-control border border-border bg-background px-3 py-2 text-body"
                      type="number"
                      min={1}
                      value={pamForm.ttl_seconds}
                      onChange={(event) => setPAMForm({ ...pamForm, ttl_seconds: event.target.value })}
                      placeholder={translateNow("source.optional.ec91fdd925")}
                    />
                  </label>
                </div>
                {pamForm.target_type === "ssh" && (
                  <label className="grid gap-1 text-body font-medium">
                    {translateNow("source.ssh.public.key.c9be6a369e")}
                    <textarea
                      className="min-h-24 rounded-control border border-border bg-background px-3 py-2 font-mono text-xs"
                      value={pamForm.ssh_public_key}
                      onChange={(event) => setPAMForm({ ...pamForm, ssh_public_key: event.target.value })}
                    />
                  </label>
                )}
                <label className="grid gap-1 text-body font-medium">
                  {t("parity.payloadBase64_738cc4")}
                  <textarea
                    className="min-h-24 rounded-control border border-border bg-background px-3 py-2 font-mono text-xs"
                    value={pamForm.payload_base64}
                    onChange={(event) => setPAMForm({ ...pamForm, payload_base64: event.target.value })}
                    required
                  />
                </label>
                <div className="flex justify-end gap-2">
                  <Button type="button" variant="ghost" onClick={closePAMDialog}>
                    {translateNow("source.cancel.19766ed6cc")}
                  </Button>
                  <Button
                    type="submit"
                    disabled={pamBusy || !pamForm.target_id.trim() || !pamForm.role.trim() || !pamForm.method.trim() || !pamForm.payload_base64.trim()}
                  >
                    {pamBusy ? translateNow("source.opening.b19bb6f448") : translateNow("source.open.session.b205bb47f8")}
                  </Button>
                </div>
              </form>
            )}
          </Dialog>
        )}
      </div>
    </section>
  );
}
function csvList(value: string): string[] {
  return value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function formatOptionalDate(value: string | undefined, policy: FormatPolicy): string {
  if (!value) return "-";
  return formatDateTime(value, policy);
}
function pamStatusTone(status: string): StatusTone {
  if (status === "open" || status === "active") return "success";
  if (status === "expired" || status === "pending") return "warning";
  if (status === "revoked" || status === "failed") return "critical";
  return "neutral";
}
function PlatformDetailRow({ term, children, mono = false }: { term: string; children: ReactNode; mono?: boolean }) {
  return (
    <div className="grid gap-1 sm:grid-cols-[11rem_1fr] sm:gap-2">
      <dt className="font-medium text-muted-foreground">{term}</dt>
      <dd className={mono ? "break-all font-mono text-xs" : "break-words"}>{children}</dd>
    </div>
  );
}

function JSONBlock({ value }: { value: unknown }) {
  let text: string;
  try {
    text = JSON.stringify(value, null, 2);
  } catch {
    text = String(value);
  }
  return <pre className="max-h-48 overflow-auto rounded-control border border-border bg-muted/40 p-2 font-mono text-xs">{text}</pre>;
}
