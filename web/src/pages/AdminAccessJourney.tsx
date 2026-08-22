/* eslint-disable jsx-a11y/no-noninteractive-tabindex -- The four named overflow evidence regions must accept keyboard focus so users can scroll them; Route 040 axe tests enforce the resulting behavior. */
import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent, type ReactNode, type SyntheticEvent } from "react";
import { ChevronDown, History, KeyRound, Loader2, Plus, RefreshCw, ShieldCheck, UserMinus, Users } from "lucide-react";
import { Link } from "react-router-dom";
import { AdminHeaderActions } from "@/components/AdminHeaderActions";
import { DataGrid, type DataGridColumn } from "@/components/DataGrid";
import { Dialog } from "@/components/Dialog";
import { PageHeader } from "@/components/PageHeader";
import { ErrorState, LoadingState, UnavailableState } from "@/components/StatePrimitives";
import { StatusBadge } from "@/components/StatusBadge";
import { Eyebrow, Num } from "@/components/typography";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
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

/** /admin/access — an answer-first access journey. The default page reads only
 * the tenant member roster and served role names. Optional SSO, session, and
 * access-key reads are lazy so an unavailable expert integration cannot turn
 * the first screen into an error wall. */
export function AdminAccess() {
  const { locale, timeZone, t } = useTranslation();
  const tRef = useRef(t);
  useEffect(() => {
    tRef.current = t;
  }, [t]);
  const formatPolicy = useMemo<FormatPolicy>(() => ({ locale, timeZone }), [locale, timeZone]);
  const [roles, setRoles] = useState<RoleList | null>(null);
  const [members, setMembers] = useState<Member[]>([]);
  const [overviewLoading, setOverviewLoading] = useState(true);
  const [overviewError, setOverviewError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const [oidc, setOIDC] = useState<OIDCMappingStatus | null>(null);
  const [ssoLoading, setSSOLoading] = useState(false);
  const [ssoLoaded, setSSOLoaded] = useState(false);
  const [ssoError, setSSOError] = useState<string | null>(null);

  const [tokens, setTokens] = useState<APIToken[]>([]);
  const [pamRows, setPAMRows] = useState<PAMSession[] | null>(null);
  const [pamUnavailable, setPAMUnavailable] = useState<string | null>(null);
  const [pamCursor, setPAMCursor] = useState<string | undefined>(undefined);
  const [sessionDetailsLoading, setSessionDetailsLoading] = useState(false);
  const [sessionDetailsLoaded, setSessionDetailsLoaded] = useState(false);
  const [sessionDetailsError, setSessionDetailsError] = useState<string | null>(null);
  const [pamLoadingMore, setPAMLoadingMore] = useState(false);

  const [addPersonOpen, setAddPersonOpen] = useState(false);
  const [accessKeyOpen, setAccessKeyOpen] = useState(false);
  const [offboardOpen, setOffboardOpen] = useState(false);
  const [offboardConfirmed, setOffboardConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [memberFormError, setMemberFormError] = useState<string | null>(null);
  const [tokenFormError, setTokenFormError] = useState<string | null>(null);
  const [offboardFormError, setOffboardFormError] = useState<string | null>(null);
  const [revealedToken, setRevealedToken] = useState<string | null>(null);
  const [memberSubject, setMemberSubject] = useState("");
  const [memberDisplayName, setMemberDisplayName] = useState("");
  const [memberEmail, setMemberEmail] = useState("");
  const [memberRoles, setMemberRoles] = useState<string[]>(["operator"]);
  const [tokenSubject, setTokenSubject] = useState("");
  const [tokenScopes, setTokenScopes] = useState("access:read");
  const [offboardSubject, setOffboardSubject] = useState("");
  const [offboardReason, setOffboardReason] = useState("");

  const [pamDetail, setPAMDetail] = useState<PAMSession | null>(null);
  const [pamFormOpen, setPAMFormOpen] = useState(false);
  const [pamForm, setPAMForm] = useState<PAMSessionFormState>(defaultPAMSessionForm);
  const [pamBusy, setPAMBusy] = useState(false);
  const [pamFormError, setPAMFormError] = useState<string | null>(null);
  const [pamCreated, setPAMCreated] = useState<PAMSession | null>(null);
  const [pamCopied, setPAMCopied] = useState(false);

  const addPersonTriggerRef = useRef<HTMLButtonElement>(null);
  const accessKeyTriggerRef = useRef<HTMLButtonElement>(null);
  const offboardTriggerRef = useRef<HTMLButtonElement>(null);
  const pamTriggerRef = useRef<HTMLButtonElement>(null);
  const roleRows = useMemo(() => roles?.items ?? [], [roles]);
  const activeMembers = useMemo(() => members.filter((member) => member.status !== "offboarded"), [members]);
  const pamColumns = useMemo<DataGridColumn<PAMSession>[]>(
    () => [
      { id: "started", header: t("admin.access.started"), cell: (session) => formatOptionalDate(session.started_at, formatPolicy) },
      {
        id: "subject",
        header: translateNow("source.subject.6897128384"),
        cell: (session) => <span className="break-all font-mono text-xs">{session.subject}</span>,
      },
      { id: "role", header: translateNow("source.role.14736a2eb9"), cell: (session) => session.role },
      {
        id: "target",
        header: t("admin.access.target"),
        cell: (session) => (
          <div className="grid gap-1">
            <span>{session.target_type}</span>
            <span className="break-all font-mono text-xs text-muted-foreground">{session.target_id}</span>
          </div>
        ),
      },
      {
        id: "status",
        header: translateNow("source.status.920e413c7d"),
        cell: (session) => <StatusBadge value={session.status} label={session.status} tone={pamStatusTone(session.status)} />,
      },
      { id: "expires", header: t("admin.access.expires"), cell: (session) => formatOptionalDate(session.expires_at, formatPolicy) },
    ],
    [formatPolicy, t],
  );

  const loadOverview = useCallback(async () => {
    setOverviewLoading(true);
    setOverviewError(null);
    try {
      const [roleCatalog, memberPage] = await Promise.all([api.accessRoles(), api.members({ includeOffboarded: true, limit: 50 })]);
      setRoles(roleCatalog);
      setMembers(memberPage.items ?? []);
    } catch (err) {
      setOverviewError(apiProblemMessage(err, tRef.current("admin.access.loadFailed")));
    } finally {
      setOverviewLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadOverview();
  }, [loadOverview]);

  async function loadSSODetails(force = false) {
    if (ssoLoading || (ssoLoaded && !force)) return;
    setSSOLoading(true);
    setSSOError(null);
    try {
      setOIDC(await api.oidcMappingStatus());
      setSSOLoaded(true);
    } catch (err) {
      setSSOError(apiProblemMessage(err, t("admin.access.ssoFailed")));
    } finally {
      setSSOLoading(false);
    }
  }

  async function loadSessionDetails(force = false) {
    if (sessionDetailsLoading || (sessionDetailsLoaded && !force)) return;
    setSessionDetailsLoading(true);
    setSessionDetailsError(null);
    setPAMUnavailable(null);
    const [tokenResult, pamResult] = await Promise.allSettled([api.apiTokens({ includeRevoked: true, limit: 50 }), api.pamSessions({ limit: 20 })]);
    if (tokenResult.status === "fulfilled") setTokens(tokenResult.value.items ?? []);
    else setSessionDetailsError(apiProblemMessage(tokenResult.reason, t("admin.access.sessionsFailed")));
    if (pamResult.status === "fulfilled") {
      setPAMRows(pamResult.value.items ?? []);
      setPAMCursor(pamResult.value.next_cursor);
    } else {
      setPAMRows(null);
      setPAMUnavailable(apiProblemMessage(pamResult.reason, t("admin.access.pamUnavailableTitle")));
    }
    setSessionDetailsLoaded(true);
    setSessionDetailsLoading(false);
  }

  function loadSSOWhenOpened(event: SyntheticEvent<HTMLDetailsElement>) {
    if (event.currentTarget.open) void loadSSODetails();
  }

  function loadSessionsWhenOpened(event: SyntheticEvent<HTMLDetailsElement>) {
    if (event.currentTarget.open) void loadSessionDetails();
  }

  async function loadMorePAMSessions() {
    if (!pamCursor) return;
    setPAMLoadingMore(true);
    try {
      const page = await api.pamSessions({ limit: 20, cursor: pamCursor });
      setPAMRows((current) => [...(current ?? []), ...(page.items ?? [])]);
      setPAMCursor(page.next_cursor);
    } catch (err) {
      setPAMUnavailable(apiProblemMessage(err, t("admin.access.pamUnavailableTitle")));
    } finally {
      setPAMLoadingMore(false);
    }
  }

  async function onboardMember(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setMemberFormError(null);
    setNotice(null);
    const subject = memberSubject.trim();
    try {
      await api.upsertMember(subject, {
        display_name: memberDisplayName.trim(),
        email: memberEmail.trim(),
        roles: memberRoles,
        source: "manual",
      });
      await loadOverview();
      setNotice(t("admin.access.addedNotice", { subject }));
      setMemberSubject("");
      setMemberDisplayName("");
      setMemberEmail("");
      setAddPersonOpen(false);
    } catch (err) {
      setMemberFormError(apiProblemMessage(err, t("admin.access.loadFailed")));
    } finally {
      setBusy(false);
    }
  }

  async function mintToken(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setTokenFormError(null);
    setNotice(null);
    setRevealedToken(null);
    try {
      const created = await api.createAPIToken({ subject: tokenSubject.trim(), scopes: csvList(tokenScopes) });
      setRevealedToken(created.token);
      const tokenPage = await api.apiTokens({ includeRevoked: true, limit: 50 });
      setTokens(tokenPage.items ?? []);
      setNotice(t("admin.access.keyCreatedNotice", { subject: created.subject }));
      setTokenSubject("");
    } catch (err) {
      setTokenFormError(apiProblemMessage(err, t("admin.access.sessionsFailed")));
    } finally {
      setBusy(false);
    }
  }

  async function offboardMember(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!offboardConfirmed) return;
    setBusy(true);
    setOffboardFormError(null);
    setNotice(null);
    const subject = offboardSubject.trim();
    try {
      const result = await api.offboardMember(subject, { reason: offboardReason.trim() });
      await loadOverview();
      if (sessionDetailsLoaded) await loadSessionDetails(true);
      setNotice(t("admin.access.offboardedNotice", { subject: result.member.subject, count: result.revoked_token_count }));
      setOffboardSubject("");
      setOffboardReason("");
      setOffboardConfirmed(false);
      setOffboardOpen(false);
    } catch (err) {
      setOffboardFormError(apiProblemMessage(err, t("admin.access.loadFailed")));
    } finally {
      setBusy(false);
    }
  }

  function closeAddPersonDialog() {
    setAddPersonOpen(false);
    setMemberFormError(null);
  }

  function openAddPersonDialog() {
    const available = new Set(roleRows.map((role) => role.name));
    setMemberRoles((current) => {
      const stillAvailable = current.filter((role) => available.has(role));
      if (stillAvailable.length) return stillAvailable;
      const firstChoice = roleRows.find((role) => role.name === "operator") ?? roleRows[0];
      return firstChoice ? [firstChoice.name] : [];
    });
    setAddPersonOpen(true);
  }

  function closeAccessKeyDialog() {
    setAccessKeyOpen(false);
    setTokenFormError(null);
    setRevealedToken(null);
  }

  function closeOffboardDialog() {
    setOffboardOpen(false);
    setOffboardFormError(null);
    setOffboardConfirmed(false);
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
      setPAMFormError(apiProblemMessage(err, t("admin.access.pamUnavailableTitle")));
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

  return (
    <section aria-labelledby="admin-access-heading" className="grid gap-4">
      <PageHeader
        titleId="admin-access-heading"
        title={t("platform.tabs.access")}
        description={t("admin.access.description")}
        technicalDetails={t("admin.access.technical")}
        actions={<AdminHeaderActions />}
      />

      <section aria-labelledby="access-overview-heading" className="ui-panel grid gap-4 p-comfortable">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="max-w-3xl">
            <Eyebrow as="p">{t("admin.access.overviewLabel")}</Eyebrow>
            <h2 id="access-overview-heading" className="mt-1 text-title font-semibold">
              {t("admin.access.overviewTitle")}
            </h2>
            <p className="mt-2 text-sm text-muted-foreground">{t("admin.access.overviewBody")}</p>
          </div>
          <Button ref={addPersonTriggerRef} type="button" onClick={openAddPersonDialog}>
            <Plus className="h-4 w-4" aria-hidden="true" />
            {t("admin.access.addPerson")}
          </Button>
        </div>

        {overviewLoading ? <LoadingState>{t("admin.access.loadingOverview")}</LoadingState> : null}
        {overviewError ? (
          <ErrorState title={t("admin.access.loadFailed")}>
            <p>{overviewError}</p>
            <Button type="button" size="sm" variant="outline" className="mt-2" onClick={() => void loadOverview()}>
              {t("admin.access.retry")}
            </Button>
          </ErrorState>
        ) : null}
        {!overviewLoading && !overviewError ? (
          <dl className="grid gap-3 sm:grid-cols-3">
            <OverviewFact
              icon={<Users className="h-4 w-4" aria-hidden="true" />}
              label={t("admin.access.people")}
              value={<Num>{members.length}</Num>}
              detail={t("admin.access.activePeople", { count: activeMembers.length })}
            />
            <OverviewFact
              icon={<ShieldCheck className="h-4 w-4" aria-hidden="true" />}
              label={t("admin.access.roles")}
              value={<Num>{roleRows.length}</Num>}
              detail={
                roleRows
                  .slice(0, 3)
                  .map((role) => role.name)
                  .join(", ") || "—"
              }
            />
            <OverviewFact
              icon={<KeyRound className="h-4 w-4" aria-hidden="true" />}
              label={t("admin.access.tenantBoundary")}
              value={t("admin.access.currentTenantOnly")}
              detail={t("admin.access.boundaryTechnical")}
            />
          </dl>
        ) : null}
        {!overviewLoading && !overviewError && members.length === 0 ? <UnavailableState title={t("admin.access.noPeople")} /> : null}
        {notice ? (
          <p role="status" className="rounded-control border border-status-success/30 bg-status-success/10 px-3 py-2 text-sm text-status-success">
            {notice}
          </p>
        ) : null}
        <div>
          <Button type="button" size="sm" variant="ghost" onClick={() => void loadOverview()} disabled={overviewLoading}>
            <RefreshCw className={`h-4 w-4 ${overviewLoading ? "animate-spin" : ""}`} aria-hidden="true" />
            {t("admin.access.refresh")}
          </Button>
        </div>
      </section>

      <div className="grid gap-3">
        <AccessDisclosure title={t("admin.access.ssoSummary")} description={t("admin.access.ssoBody")} onToggle={loadSSOWhenOpened}>
          {ssoLoading ? <LoadingState>{t("admin.access.ssoLoading")}</LoadingState> : null}
          {ssoError ? (
            <ErrorState title={t("admin.access.ssoFailed")}>
              <p>{ssoError}</p>
              <Button type="button" size="sm" variant="outline" className="mt-2" onClick={() => void loadSSODetails(true)}>
                {t("admin.access.retry")}
              </Button>
            </ErrorState>
          ) : null}
          {oidc ? (
            <div className="grid gap-4">
              <dl className="grid gap-3 sm:grid-cols-3">
                <OverviewFact label={t("admin.access.ssoStatus")} value={oidc.enabled ? t("admin.access.enabled") : t("admin.access.disabled")} />
                <OverviewFact label={t("admin.access.tenantClaim")} value={oidc.tenant_claim || t("admin.access.notConfigured")} />
                <OverviewFact label={t("admin.access.groupsClaim")} value={oidc.groups_claim || t("admin.access.notConfigured")} />
              </dl>
              <section aria-labelledby="sso-mappings-heading" className="grid gap-2">
                <h3 id="sso-mappings-heading" className="text-body font-semibold">
                  {t("admin.access.groupMappings")}
                </h3>
                {oidc.tenant_mappings?.length ? (
                  <ul className="grid gap-2 sm:grid-cols-2">
                    {oidc.tenant_mappings.map((mapping, index) => (
                      <li
                        key={`${mapping.tenant_id}-${mapping.group ?? mapping.subject ?? mapping.claim ?? index}`}
                        className="rounded-control border border-border bg-background p-3 text-sm"
                      >
                        <p className="font-medium">{mapping.group || mapping.subject || mapping.claim}</p>
                        <p className="mt-1 text-muted-foreground">
                          {(mapping.roles ?? []).join(", ") || "—"} · <span className="font-mono text-xs">{mapping.tenant_id}</span>
                        </p>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <UnavailableState title={t("admin.access.noGroupMappings")} />
                )}
              </section>
            </div>
          ) : null}

          <section aria-labelledby="role-catalog-heading" className="grid gap-2">
            <h3 id="role-catalog-heading" className="text-body font-semibold">
              {t("admin.access.roleCatalog")}
            </h3>
            {/* A named horizontal overflow region needs a keyboard entry point; axe enforces this behavior. */}
            <div
              role="region"
              aria-label={t("admin.access.rolePermissionsRegion")}
              tabIndex={0}
              className="max-w-full overflow-x-auto rounded-panel border border-border focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            >
              <table className="ui-table min-w-[44rem]">
                <thead>
                  <tr>
                    <th scope="col">{translateNow("source.role.14736a2eb9")}</th>
                    <th scope="col">{t("admin.access.exactPermissions")}</th>
                  </tr>
                </thead>
                <tbody>
                  {roleRows.map((role) => (
                    <tr key={role.name} className="align-top">
                      <td className="font-medium">{role.name}</td>
                      <td>
                        <ul className="flex max-w-4xl flex-wrap gap-1.5">
                          {role.permissions.map((permission) => (
                            <li key={permission}>
                              <code className="rounded bg-muted px-1.5 py-0.5 text-xs">{permission}</code>
                            </li>
                          ))}
                        </ul>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>

          <section aria-labelledby="member-roster-heading" className="grid gap-2">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <h3 id="member-roster-heading" className="text-body font-semibold">
                {t("admin.access.memberRoster")}
              </h3>
              <Button
                ref={offboardTriggerRef}
                type="button"
                size="sm"
                variant="outline"
                onClick={() => setOffboardOpen(true)}
                disabled={activeMembers.length === 0}
              >
                <UserMinus className="h-4 w-4" aria-hidden="true" />
                {t("admin.access.offboardPerson")}
              </Button>
            </div>
            {/* A named horizontal overflow region needs a keyboard entry point; axe enforces this behavior. */}
            <div
              role="region"
              aria-label={t("admin.access.memberRosterRegion")}
              tabIndex={0}
              className="max-w-full overflow-x-auto rounded-panel border border-border focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            >
              <table className="ui-table min-w-[44rem]">
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
                      <td>
                        <span className="font-medium">{member.display_name || member.subject}</span>
                        {member.display_name ? <span className="mt-1 block break-all font-mono text-xs text-muted-foreground">{member.subject}</span> : null}
                      </td>
                      <td className="font-mono text-xs">{(member.roles ?? []).join(", ") || "—"}</td>
                      <td>{member.status}</td>
                      <td>{formatOptionalDate(member.updated_at, formatPolicy)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        </AccessDisclosure>

        <AccessDisclosure title={t("admin.access.sessionsSummary")} description={t("admin.access.sessionsBody")} onToggle={loadSessionsWhenOpened}>
          {sessionDetailsLoading ? <LoadingState>{t("admin.access.sessionsLoading")}</LoadingState> : null}
          {sessionDetailsError ? (
            <ErrorState title={t("admin.access.sessionsFailed")}>
              <p>{sessionDetailsError}</p>
              <Button type="button" size="sm" variant="outline" className="mt-2" onClick={() => void loadSessionDetails(true)}>
                {t("admin.access.retry")}
              </Button>
            </ErrorState>
          ) : null}
          {sessionDetailsLoaded ? (
            <div className="grid gap-5">
              <section aria-labelledby="access-keys-heading" className="grid gap-2">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <h3 id="access-keys-heading" className="text-body font-semibold">
                    {t("admin.access.accessKeys")}
                  </h3>
                  <Button ref={accessKeyTriggerRef} type="button" size="sm" variant="outline" onClick={() => setAccessKeyOpen(true)}>
                    <KeyRound className="h-4 w-4" aria-hidden="true" />
                    {t("admin.access.createAccessKey")}
                  </Button>
                </div>
                {tokens.length ? (
                  <>
                    {/* A named horizontal overflow region needs a keyboard entry point; axe enforces this behavior. */}
                    <div
                      role="region"
                      aria-label={t("admin.access.accessKeysRegion")}
                      tabIndex={0}
                      className="max-w-full overflow-x-auto rounded-panel border border-border focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                    >
                      <table className="ui-table min-w-[48rem]">
                        <thead>
                          <tr>
                            <th scope="col">{t("admin.access.keyId")}</th>
                            <th scope="col">{translateNow("source.subject.6897128384")}</th>
                            <th scope="col">{translateNow("source.scopes.0d5644ff52")}</th>
                            <th scope="col">{translateNow("source.status.920e413c7d")}</th>
                            <th scope="col">{translateNow("source.created.d70b9e24bc")}</th>
                          </tr>
                        </thead>
                        <tbody>
                          {tokens.map((token) => (
                            <tr key={token.id} className="align-top">
                              <td className="font-mono text-xs">{token.id}</td>
                              <td>{token.subject}</td>
                              <td className="font-mono text-xs">{token.scopes.join(", ")}</td>
                              <td>{token.revoked_at ? translateNow("source.revoked.4bb47f186d") : translateNow("source.active.9687961165")}</td>
                              <td>{formatOptionalDate(token.created_at, formatPolicy)}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </>
                ) : (
                  <UnavailableState title={t("admin.access.noAccessKeys")} />
                )}
              </section>

              <section aria-labelledby="privileged-sessions-heading" className="grid gap-2">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <h3 id="privileged-sessions-heading" className="text-body font-semibold">
                    {t("admin.access.privilegedSessions")}
                  </h3>
                  {pamRows ? (
                    <Button ref={pamTriggerRef} type="button" size="sm" variant="outline" onClick={() => setPAMFormOpen(true)}>
                      <KeyRound className="h-4 w-4" aria-hidden="true" />
                      {t("admin.access.openSession")}
                    </Button>
                  ) : null}
                </div>
                {pamRows?.length ? (
                  <DataGrid
                    ariaLabel={t("admin.access.privilegedSessions")}
                    rows={pamRows}
                    columns={pamColumns}
                    getRowId={(session) => session.id}
                    onRowOpen={(session) => setPAMDetail(session)}
                    rowActionLabel={() => t("admin.access.details")}
                    pagination={
                      pamCursor ? (
                        <Button type="button" size="sm" variant="outline" disabled={pamLoadingMore} onClick={() => void loadMorePAMSessions()}>
                          {pamLoadingMore ? translateNow("source.loading.more.sessions.25d47273c8") : translateNow("source.load.more.sessions.e04b242241")}
                        </Button>
                      ) : undefined
                    }
                  />
                ) : null}
                {pamRows && pamRows.length === 0 ? <UnavailableState title={t("admin.access.noSessions")} /> : null}
                {pamUnavailable ? <UnavailableState title={t("admin.access.pamUnavailableTitle")}>{pamUnavailable}</UnavailableState> : null}
              </section>
            </div>
          ) : null}
        </AccessDisclosure>

        <AccessDisclosure title={t("admin.access.certificationSummary")} description={t("admin.access.certificationBody")}>
          <div className="grid gap-3 sm:grid-cols-2">
            <Link
              to="/policy"
              className="inline-flex min-h-10 items-center justify-center gap-2 rounded-control border border-border bg-background px-3 py-2 text-sm font-medium hover:bg-muted/60"
            >
              <ShieldCheck className="h-4 w-4" aria-hidden="true" />
              {t("admin.access.openAccessReviews")}
            </Link>
            <Link
              to="/audit"
              className="inline-flex min-h-10 items-center justify-center gap-2 rounded-control border border-border bg-background px-3 py-2 text-sm font-medium hover:bg-muted/60"
            >
              <History className="h-4 w-4" aria-hidden="true" />
              {t("admin.access.openChangeHistory")}
            </Link>
          </div>
        </AccessDisclosure>
      </div>

      {addPersonOpen ? (
        <Dialog
          open
          onClose={closeAddPersonDialog}
          titleId="add-person-heading"
          descriptionId="add-person-description"
          returnFocusRef={addPersonTriggerRef}
          className="fixed inset-0 z-50 flex items-center justify-center p-4"
          overlayClassName="absolute inset-0 bg-black/55"
          panelClassName="relative max-h-[calc(100vh-2rem)] w-full max-w-lg overflow-y-auto rounded-panel border border-border bg-card shadow-elevation2"
        >
          <header className="border-b border-border px-5 py-4">
            <h2 id="add-person-heading" className="text-title font-semibold">
              {t("admin.access.addPerson")}
            </h2>
            <p id="add-person-description" className="mt-1 text-sm text-muted-foreground">
              {t("admin.access.addPersonDescription")}
            </p>
          </header>
          <form onSubmit={(event) => void onboardMember(event)} className="grid gap-3 p-5">
            {memberFormError ? <ErrorState title={t("admin.access.loadFailed")}>{memberFormError}</ErrorState> : null}
            <FormField label={translateNow("source.subject.6897128384")}>
              <Input value={memberSubject} onChange={(event) => setMemberSubject(event.target.value)} required />
            </FormField>
            <FormField label={translateNow("source.display.name.2b7f6a84de")}>
              <Input value={memberDisplayName} onChange={(event) => setMemberDisplayName(event.target.value)} />
            </FormField>
            <FormField label={translateNow("source.email.969ccbd3cf")}>
              <Input type="email" value={memberEmail} onChange={(event) => setMemberEmail(event.target.value)} />
            </FormField>
            <fieldset className="grid gap-2 rounded-control border border-border p-3">
              <legend className="px-1 text-sm font-medium text-muted-foreground">{translateNow("source.roles.c253370554")}</legend>
              <p className="text-xs text-muted-foreground">{t("admin.access.rolesHint")}</p>
              {roleRows.length ? (
                <div className="grid gap-2 sm:grid-cols-2">
                  {roleRows.map((role) => (
                    <label key={role.name} className="flex items-center gap-2 rounded-control border border-border bg-background px-3 py-2 text-sm">
                      <Checkbox
                        checked={memberRoles.includes(role.name)}
                        onChange={(event) =>
                          setMemberRoles((current) => (event.target.checked ? [...current, role.name] : current.filter((candidate) => candidate !== role.name)))
                        }
                      />
                      <span>{role.name}</span>
                    </label>
                  ))}
                </div>
              ) : (
                <p role="status" className="text-sm text-muted-foreground">
                  {t("admin.access.noRolesAvailable")}
                </p>
              )}
            </fieldset>
            <div className="flex justify-end gap-2 pt-2">
              <Button type="button" variant="ghost" onClick={closeAddPersonDialog}>
                {translateNow("source.cancel.19766ed6cc")}
              </Button>
              <Button type="submit" disabled={busy || !memberSubject.trim() || memberRoles.length === 0}>
                {busy ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <Plus className="h-4 w-4" aria-hidden="true" />}
                {t("admin.access.addPerson")}
              </Button>
            </div>
          </form>
        </Dialog>
      ) : null}

      {accessKeyOpen ? (
        <Dialog
          open
          onClose={closeAccessKeyDialog}
          titleId="create-key-heading"
          descriptionId="create-key-description"
          returnFocusRef={accessKeyTriggerRef}
          className="fixed inset-0 z-50 flex items-center justify-center p-4"
          overlayClassName="absolute inset-0 bg-black/55"
          panelClassName="relative max-h-[calc(100vh-2rem)] w-full max-w-lg overflow-y-auto rounded-panel border border-border bg-card shadow-elevation2"
        >
          <header className="border-b border-border px-5 py-4">
            <h2 id="create-key-heading" className="text-title font-semibold">
              {t("admin.access.createAccessKey")}
            </h2>
            <p id="create-key-description" className="mt-1 text-sm text-muted-foreground">
              {t("admin.access.createKeyDescription")}
            </p>
          </header>
          {revealedToken ? (
            <div className="grid gap-3 p-5">
              <p role="status" className="font-medium">
                {t("admin.access.revealOnce")}
              </p>
              <code className="break-all rounded-control border border-status-warning/40 bg-status-warning/10 p-3 text-xs">{revealedToken}</code>
              <div className="flex justify-end">
                <Button type="button" variant="outline" onClick={closeAccessKeyDialog}>
                  {translateNow("source.close.7d9eb7acb1")}
                </Button>
              </div>
            </div>
          ) : (
            <form onSubmit={(event) => void mintToken(event)} className="grid gap-3 p-5">
              {tokenFormError ? <ErrorState title={t("admin.access.sessionsFailed")}>{tokenFormError}</ErrorState> : null}
              <FormField label={translateNow("source.subject.6897128384")}>
                <Input value={tokenSubject} onChange={(event) => setTokenSubject(event.target.value)} required />
              </FormField>
              <FormField label={translateNow("source.scopes.0d5644ff52")}>
                <Input value={tokenScopes} onChange={(event) => setTokenScopes(event.target.value)} required />
              </FormField>
              <div className="flex justify-end gap-2 pt-2">
                <Button type="button" variant="ghost" onClick={closeAccessKeyDialog}>
                  {translateNow("source.cancel.19766ed6cc")}
                </Button>
                <Button type="submit" disabled={busy || !tokenSubject.trim()}>
                  {busy ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <KeyRound className="h-4 w-4" aria-hidden="true" />}
                  {t("admin.access.createAccessKey")}
                </Button>
              </div>
            </form>
          )}
        </Dialog>
      ) : null}

      {offboardOpen ? (
        <Dialog
          open
          role="alertdialog"
          closeOnBackdropClick={false}
          onClose={closeOffboardDialog}
          titleId="offboard-person-heading"
          descriptionId="offboard-person-description"
          returnFocusRef={offboardTriggerRef}
          className="fixed inset-0 z-50 flex items-center justify-center p-4"
          overlayClassName="absolute inset-0 bg-black/55"
          panelClassName="relative max-h-[calc(100vh-2rem)] w-full max-w-lg overflow-y-auto rounded-panel border border-border bg-card shadow-elevation2"
        >
          <header className="border-b border-border px-5 py-4">
            <h2 id="offboard-person-heading" className="text-title font-semibold">
              {t("admin.access.offboardTitle")}
            </h2>
            <p id="offboard-person-description" className="mt-1 text-sm text-muted-foreground">
              {t("admin.access.offboardDescription")}
            </p>
          </header>
          <form onSubmit={(event) => void offboardMember(event)} className="grid gap-3 p-5">
            {offboardFormError ? <ErrorState title={t("admin.access.loadFailed")}>{offboardFormError}</ErrorState> : null}
            <FormField label={t("admin.access.person")}>
              <Select value={offboardSubject} onChange={(event) => setOffboardSubject(event.target.value)} required>
                <option value="">{t("admin.access.person")}</option>
                {activeMembers.map((member) => (
                  <option key={member.subject} value={member.subject}>
                    {member.display_name || member.email || member.subject}
                  </option>
                ))}
              </Select>
            </FormField>
            {activeMembers.length === 0 ? <UnavailableState title={t("admin.access.noEligiblePeople")} /> : null}
            <FormField label={translateNow("source.reason.f81ab834de")}>
              <Input value={offboardReason} onChange={(event) => setOffboardReason(event.target.value)} />
            </FormField>
            <label className="flex items-start gap-2 rounded-control border border-destructive/30 bg-destructive/10 p-3 text-sm">
              <Checkbox className="mt-0.5" checked={offboardConfirmed} onChange={(event) => setOffboardConfirmed(event.target.checked)} />
              <span>{t("admin.access.offboardConfirm")}</span>
            </label>
            <div className="flex justify-end gap-2 pt-2">
              <Button type="button" variant="ghost" onClick={closeOffboardDialog}>
                {translateNow("source.cancel.19766ed6cc")}
              </Button>
              <Button type="submit" variant="destructive" disabled={busy || !offboardSubject || !offboardConfirmed}>
                {busy ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <UserMinus className="h-4 w-4" aria-hidden="true" />}
                {t("admin.access.offboardPerson")}
              </Button>
            </div>
          </form>
        </Dialog>
      ) : null}

      {pamDetail ? <PAMDetailDialog session={pamDetail} formatPolicy={formatPolicy} onClose={() => setPAMDetail(null)} /> : null}
      {pamFormOpen ? (
        <PAMFormDialog
          form={pamForm}
          setForm={setPAMForm}
          busy={pamBusy}
          error={pamFormError}
          created={pamCreated}
          copied={pamCopied}
          returnFocusRef={pamTriggerRef}
          onClose={closePAMDialog}
          onSubmit={openPrivilegedSession}
          onCopy={copyPAMSessionID}
          formatPolicy={formatPolicy}
        />
      ) : null}
    </section>
  );
}

function AccessDisclosure({
  title,
  description,
  children,
  onToggle,
}: {
  title: string;
  description: string;
  children: ReactNode;
  onToggle?: (event: SyntheticEvent<HTMLDetailsElement>) => void;
}) {
  return (
    <details className="group rounded-panel border border-border bg-card" onToggle={onToggle}>
      <summary className="flex cursor-pointer list-none items-start justify-between gap-4 p-comfortable marker:hidden">
        <span>
          <span className="block text-body font-semibold">{title}</span>
          <span className="mt-1 block max-w-3xl text-sm text-muted-foreground">{description}</span>
        </span>
        <ChevronDown className="mt-1 h-4 w-4 shrink-0 text-muted-foreground transition-transform group-open:rotate-180" aria-hidden="true" />
      </summary>
      <div className="grid gap-5 border-t border-border p-comfortable">{children}</div>
    </details>
  );
}

function OverviewFact({ icon, label, value, detail }: { icon?: ReactNode; label: ReactNode; value: ReactNode; detail?: ReactNode }) {
  return (
    <div className="min-w-0 rounded-control border border-border bg-background p-3">
      <dt className="flex items-center gap-2 text-caption font-semibold text-muted-foreground">
        {icon}
        {label}
      </dt>
      <dd className="mt-1 break-words text-body font-semibold">{value}</dd>
      {detail ? <dd className="mt-1 break-words text-xs text-muted-foreground">{detail}</dd> : null}
    </div>
  );
}

function FormField({ label, hint, children }: { label: ReactNode; hint?: ReactNode; children: ReactNode }) {
  return (
    <label className="grid gap-1 text-sm">
      <span className="font-medium text-muted-foreground">{label}</span>
      {children}
      {hint ? <span className="text-xs text-muted-foreground">{hint}</span> : null}
    </label>
  );
}

function PAMDetailDialog({ session, formatPolicy, onClose }: { session: PAMSession; formatPolicy: FormatPolicy; onClose: () => void }) {
  const { t } = useTranslation();
  return (
    <Dialog
      open
      onClose={onClose}
      titleId="pam-session-detail-heading"
      descriptionId="pam-session-detail-description"
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      overlayClassName="absolute inset-0 bg-black/55"
      panelClassName="relative max-h-[calc(100vh-2rem)] w-full max-w-2xl overflow-y-auto rounded-panel border border-border bg-card shadow-elevation2"
    >
      <header className="border-b border-border px-5 py-4">
        <h2 id="pam-session-detail-heading" className="text-title font-semibold">
          {translateNow("source.privileged.session.value1.2958e09fb1", { value1: session.id })}
        </h2>
        <p id="pam-session-detail-description" className="mt-1 text-sm text-muted-foreground">
          {t("admin.access.sessionEvidence")}
        </p>
      </header>
      <dl className="grid gap-2 p-5 text-sm">
        <DetailRow term={t("admin.access.id")} mono>
          {session.id}
        </DetailRow>
        <DetailRow term={translateNow("source.status.920e413c7d")}>
          <StatusBadge value={session.status} label={session.status} tone={pamStatusTone(session.status)} />
        </DetailRow>
        <DetailRow term={translateNow("source.subject.6897128384")} mono>
          {session.subject}
        </DetailRow>
        <DetailRow term={translateNow("source.role.14736a2eb9")}>{session.role}</DetailRow>
        <DetailRow term={t("admin.access.target")} mono>
          {session.target_type}:{session.target_id}
        </DetailRow>
        <DetailRow term={translateNow("source.reason.f81ab834de")}>{session.reason || "—"}</DetailRow>
        <DetailRow term={t("admin.access.started")}>{formatOptionalDate(session.started_at, formatPolicy)}</DetailRow>
        <DetailRow term={t("admin.access.expires")}>{formatOptionalDate(session.expires_at, formatPolicy)}</DetailRow>
        {session.attestation ? (
          <DetailRow term={t("admin.access.attestation")}>
            <JSONBlock value={session.attestation} />
          </DetailRow>
        ) : null}
        {session.audit ? (
          <DetailRow term={t("admin.access.audit")}>
            <JSONBlock value={session.audit} />
          </DetailRow>
        ) : null}
      </dl>
      <div className="flex justify-end border-t border-border px-5 py-4">
        <Button type="button" variant="outline" onClick={onClose}>
          {translateNow("source.close.7d9eb7acb1")}
        </Button>
      </div>
    </Dialog>
  );
}

function PAMFormDialog({
  form,
  setForm,
  busy,
  error,
  created,
  copied,
  returnFocusRef,
  onClose,
  onSubmit,
  onCopy,
  formatPolicy,
}: {
  form: PAMSessionFormState;
  setForm: (form: PAMSessionFormState) => void;
  busy: boolean;
  error: string | null;
  created: PAMSession | null;
  copied: boolean;
  returnFocusRef: React.RefObject<HTMLButtonElement>;
  onClose: () => void;
  onSubmit: (event: FormEvent<HTMLFormElement>) => Promise<void>;
  onCopy: (id: string) => Promise<void>;
  formatPolicy: FormatPolicy;
}) {
  const { t } = useTranslation();
  return (
    <Dialog
      open
      onClose={onClose}
      titleId="pam-open-heading"
      descriptionId="pam-open-description"
      returnFocusRef={returnFocusRef}
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      overlayClassName="absolute inset-0 bg-black/55"
      panelClassName="relative max-h-[calc(100vh-2rem)] w-full max-w-xl overflow-y-auto rounded-panel border border-border bg-card shadow-elevation2"
    >
      <header className="border-b border-border px-5 py-4">
        <h2 id="pam-open-heading" className="text-title font-semibold">
          {t("admin.access.openSession")}
        </h2>
        <p id="pam-open-description" className="mt-1 text-sm text-muted-foreground">
          {t("admin.access.sessionDescription")}
        </p>
      </header>
      {created ? (
        <div className="grid gap-3 p-5 text-sm">
          <p role="status" className="rounded-control border border-status-success/30 bg-status-success/10 px-3 py-2 text-status-success">
            {t("admin.access.sessionOpened")}
          </p>
          <DetailRow term={t("admin.access.sessionId")}>
            <span className="inline-flex flex-wrap items-center gap-2">
              <span className="break-all font-mono text-xs">{created.id}</span>
              <Button type="button" size="sm" variant="outline" onClick={() => void onCopy(created.id)}>
                {copied ? translateNow("source.copied.8d525e5f15") : translateNow("source.copy.id.72ac0d580f")}
              </Button>
            </span>
          </DetailRow>
          <DetailRow term={t("admin.access.expires")}>{formatOptionalDate(created.expires_at, formatPolicy)}</DetailRow>
          <div className="flex justify-end">
            <Button type="button" variant="outline" onClick={onClose}>
              {translateNow("source.close.7d9eb7acb1")}
            </Button>
          </div>
        </div>
      ) : (
        <form onSubmit={(event) => void onSubmit(event)} className="grid gap-3 p-5">
          {error ? <ErrorState title={t("admin.access.sessionOpenFailed")}>{error}</ErrorState> : null}
          <div className="grid gap-3 md:grid-cols-2">
            <FormField label={t("admin.access.targetType")}>
              <Select value={form.target_type} onChange={(event) => setForm({ ...form, target_type: event.target.value as PAMSessionRequest["target_type"] })}>
                <option value="postgres">{t("admin.access.postgresql")}</option>
                <option value="ssh">{t("admin.access.ssh")}</option>
              </Select>
            </FormField>
            <FormField label={t("admin.access.targetId")}>
              <Input value={form.target_id} onChange={(event) => setForm({ ...form, target_id: event.target.value })} required />
            </FormField>
            <FormField label={translateNow("source.role.14736a2eb9")}>
              <Input value={form.role} onChange={(event) => setForm({ ...form, role: event.target.value })} required />
            </FormField>
            <FormField label={translateNow("source.method.52a0f9b65b")}>
              <Input value={form.method} onChange={(event) => setForm({ ...form, method: event.target.value })} required />
            </FormField>
            <FormField label={translateNow("source.reason.f81ab834de")}>
              <Input value={form.reason} onChange={(event) => setForm({ ...form, reason: event.target.value })} />
            </FormField>
            <FormField label={translateNow("source.ttl.seconds.862d08de5a")}>
              <Input type="number" min={1} value={form.ttl_seconds} onChange={(event) => setForm({ ...form, ttl_seconds: event.target.value })} />
            </FormField>
          </div>
          {form.target_type === "ssh" ? (
            <>
              <FormField label={t("admin.access.sshPrincipal")}>
                <Input value={form.ssh_principal} onChange={(event) => setForm({ ...form, ssh_principal: event.target.value })} />
              </FormField>
              <FormField label={translateNow("source.ssh.public.key.c9be6a369e")}>
                <Textarea
                  className="min-h-24 font-mono text-xs"
                  value={form.ssh_public_key}
                  onChange={(event) => setForm({ ...form, ssh_public_key: event.target.value })}
                />
              </FormField>
            </>
          ) : null}
          <FormField label={t("admin.access.payloadBase64")}>
            <Textarea
              className="min-h-24 font-mono text-xs"
              value={form.payload_base64}
              onChange={(event) => setForm({ ...form, payload_base64: event.target.value })}
              required
            />
          </FormField>
          <div className="flex justify-end gap-2">
            <Button type="button" variant="ghost" onClick={onClose}>
              {translateNow("source.cancel.19766ed6cc")}
            </Button>
            <Button type="submit" disabled={busy || !form.target_id.trim() || !form.role.trim() || !form.method.trim() || !form.payload_base64.trim()}>
              {busy ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : null}
              {t("admin.access.openSessionSubmit")}
            </Button>
          </div>
        </form>
      )}
    </Dialog>
  );
}

function DetailRow({ term, children, mono = false }: { term: string; children: ReactNode; mono?: boolean }) {
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
  return (
    <>
      {/* Exact JSON can overflow both axes; keyboard users need a focusable scroll entry point. */}
      <pre className="max-h-48 overflow-auto rounded-control border border-border bg-muted/40 p-2 font-mono text-xs" tabIndex={0}>
        {text}
      </pre>
    </>
  );
}

function csvList(value: string): string[] {
  return value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function formatOptionalDate(value: string | undefined, policy: FormatPolicy): string {
  return value ? formatDateTime(value, policy) : "—";
}

function pamStatusTone(status: string): StatusTone {
  if (status === "open" || status === "active") return "success";
  if (status === "expired" || status === "pending") return "warning";
  if (status === "revoked" || status === "failed") return "critical";
  return "neutral";
}
