import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { ErrorState } from "@/components/StatePrimitives";
import { useTranslation } from "@/i18n/I18nProvider";
import type { MessageKey } from "@/i18n/messages";
import { api, type AccessActivityFilter, type AccessAuthority, type AccessRun, type AccessRunIssued } from "@/lib/api";
import { useApiQuery } from "@/lib/query";

// A251: agent access bundles. A bundle is a reusable set of permissions for
// custom agents, CI jobs and private MCP servers; a grant gives it to a user or
// a machine; a run's credential holds only what its grants give at each
// request. The page shows effective authority after every grant change.

const audiences = ["custom_agent", "ci", "mcp_server"] as const;
type Audience = (typeof audiences)[number];

const list = (value: string) =>
  value
    .split(",")
    .map((part) => part.trim())
    .filter(Boolean);

const runStatusKey: Record<string, MessageKey> = {
  active: "agentAccess.run.status.active",
  no_authority: "agentAccess.run.status.noAuthority",
  expired: "agentAccess.run.status.expired",
  revoked: "agentAccess.run.status.revoked",
};

const activityKey: Record<string, MessageKey> = {
  saved: "agentAccess.activity.action.saved",
  deleted: "agentAccess.activity.action.deleted",
  granted: "agentAccess.activity.action.granted",
  ungranted: "agentAccess.activity.action.ungranted",
  run_issued: "agentAccess.activity.action.runIssued",
  run_revoked: "agentAccess.activity.action.runRevoked",
  run_used: "agentAccess.activity.action.runUsed",
};

const audienceKey: Record<Audience, MessageKey> = {
  custom_agent: "agentAccess.audience.customAgent",
  ci: "agentAccess.audience.ci",
  mcp_server: "agentAccess.audience.mcpServer",
};

/** download hands the browser a JSON document to save. */
function download(name: string, value: unknown) {
  if (typeof URL.createObjectURL !== "function") return;
  const url = URL.createObjectURL(new Blob([JSON.stringify(value, null, 2)], { type: "application/json" }));
  const link = document.createElement("a");
  link.href = url;
  link.download = name;
  link.click();
  URL.revokeObjectURL(url);
}

export function AgentAccess() {
  const { t, formatDateTime } = useTranslation();
  const bundles = useApiQuery(["access-bundles"], () => api.accessBundles());
  const [selected, setSelected] = useState("");
  const detail = useApiQuery(["access-bundle", selected], () => api.accessBundle(selected), { enabled: Boolean(selected) });
  const runs = useApiQuery(["access-runs"], () => api.accessRuns({ limit: 50 }));
  const [applied, setApplied] = useState<AccessActivityFilter & { cursor?: string }>({});
  const activity = useApiQuery(["access-activity", applied], () => api.accessActivity({ ...applied, limit: 20 }));

  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [authority, setAuthority] = useState<AccessAuthority | null>(null);
  const [issued, setIssued] = useState<AccessRunIssued | null>(null);
  const [confirmDelete, setConfirmDelete] = useState("");
  const [draft, setDraft] = useState({
    name: "",
    description: "",
    permissions: "",
    ttlMinutes: "15",
    audiences: { ci: true } as Partial<Record<Audience, boolean>>,
  });
  const [grant, setGrant] = useState({ principal_type: "machine", principal: "", expires_at: "" });
  const [lookup, setLookup] = useState("");
  const [run, setRun] = useState({ ttlMinutes: "15", label: "" });
  const [filter, setFilter] = useState({ principal: "", q: "" });

  const act = async (work: () => Promise<void>) => {
    setBusy(true);
    setMessage("");
    try {
      await work();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : String(error));
    } finally {
      setBusy(false);
    }
  };
  const refresh = () => {
    bundles.refetch();
    runs.refetch();
    activity.refetch();
    if (selected) detail.refetch();
  };

  const createBundle = () =>
    act(async () => {
      const created = await api.createAccessBundle({
        name: draft.name.trim(),
        description: draft.description.trim(),
        permissions: list(draft.permissions),
        audiences: audiences.filter((a) => draft.audiences[a]),
        max_run_ttl_seconds: Math.round(Number(draft.ttlMinutes) * 60),
      });
      setDraft({ ...draft, name: "", description: "", permissions: "" });
      setSelected(created.id);
      refresh();
    });
  const deleteBundle = (id: string) =>
    act(async () => {
      await api.deleteAccessBundle(id);
      setConfirmDelete("");
      if (selected === id) setSelected("");
      refresh();
    });
  const giveGrant = () =>
    act(async () => {
      const change = await api.grantAccessBundle(selected, {
        principal_type: grant.principal_type as "user" | "machine",
        principal: grant.principal.trim(),
        ...(grant.expires_at ? { expires_at: new Date(grant.expires_at).toISOString() } : {}),
      });
      setAuthority(change.authority);
      setGrant({ ...grant, principal: "", expires_at: "" });
      refresh();
    });
  const removeGrant = (grantID: string) =>
    act(async () => {
      const change = await api.ungrantAccessBundle(selected, grantID, t("agentAccess.grants.removedReason"));
      setAuthority(change.authority);
      refresh();
    });
  const showAuthority = () =>
    act(async () => {
      setAuthority(await api.accessAuthority(lookup.trim()));
    });
  const startRun = () =>
    act(async () => {
      setIssued(
        await api.issueAccessRun({
          bundle_ids: [selected],
          ttl_seconds: Math.round(Number(run.ttlMinutes) * 60),
          ...(run.label.trim() ? { label: run.label.trim() } : {}),
        }),
      );
      refresh();
    });
  const revoke = (target: AccessRun) =>
    act(async () => {
      await api.revokeAccessRun(target.id);
      refresh();
    });
  const exportActivity = () =>
    act(async () => {
      download("access-activity.json", await api.exportAccessActivity({ principal: applied.principal, q: applied.q, bundle: applied.bundle }));
    });

  const bundle = detail.data;
  return (
    <div className="space-y-6">
      <header className="space-y-2">
        <h1 className="text-2xl font-semibold">{t("agentAccess.page.title")}</h1>
        <p className="text-muted-foreground max-w-3xl">{t("agentAccess.page.intro")}</p>
      </header>

      {message ? <ErrorState title={message} /> : null}

      <Card>
        <CardHeader>
          <CardTitle>{t("agentAccess.bundles.title")}</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {bundles.error ? <ErrorState title={bundles.error} /> : null}
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left">
                <th>{t("agentAccess.bundles.col.name")}</th>
                <th>{t("agentAccess.bundles.col.permissions")}</th>
                <th>{t("agentAccess.bundles.col.ceiling")}</th>
                <th>{t("agentAccess.bundles.col.use")}</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {(bundles.data?.items ?? []).map((b) => (
                <tr key={b.id} className="align-top">
                  <td>
                    <Button type="button" variant="ghost" onClick={() => setSelected(b.id)}>
                      {b.name}
                    </Button>
                  </td>
                  <td>{b.permissions.join(", ")}</td>
                  <td>{t("agentAccess.bundles.ceiling", { minutes: Math.round(b.max_run_ttl_seconds / 60) })}</td>
                  <td>{t("agentAccess.bundles.use", { grants: b.live_grants, runs: b.active_runs })}</td>
                  <td>
                    {confirmDelete === b.id ? (
                      <Button type="button" variant="destructive" disabled={busy} onClick={() => void deleteBundle(b.id)}>
                        {t("agentAccess.bundles.confirmDelete", { name: b.name })}
                      </Button>
                    ) : (
                      <Button type="button" variant="outline" disabled={busy} onClick={() => setConfirmDelete(b.id)}>
                        {t("agentAccess.bundles.delete")}
                      </Button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {bundles.data && bundles.data.items.length === 0 ? <p className="text-muted-foreground text-sm">{t("agentAccess.bundles.empty")}</p> : null}

          <section className="grid gap-3 md:grid-cols-2" aria-labelledby="agent-access-new">
            <h2 id="agent-access-new" className="font-medium md:col-span-2">
              {t("agentAccess.bundles.new")}
            </h2>
            <Field label={t("agentAccess.bundles.name")} controlId="bundle-name">
              {(control) => <Input {...control} value={draft.name} onChange={(e) => setDraft({ ...draft, name: e.target.value })} />}
            </Field>
            <Field label={t("agentAccess.bundles.permissions")} controlId="bundle-permissions">
              {(control) => <Input {...control} value={draft.permissions} onChange={(e) => setDraft({ ...draft, permissions: e.target.value })} />}
            </Field>
            <Field label={t("agentAccess.bundles.description")} controlId="bundle-description">
              {(control) => <Input {...control} value={draft.description} onChange={(e) => setDraft({ ...draft, description: e.target.value })} />}
            </Field>
            <Field label={t("agentAccess.bundles.ttl")} controlId="bundle-ttl">
              {(control) => (
                <Input
                  {...control}
                  type="number"
                  min={1}
                  max={1440}
                  value={draft.ttlMinutes}
                  onChange={(e) => setDraft({ ...draft, ttlMinutes: e.target.value })}
                />
              )}
            </Field>
            <fieldset className="flex flex-wrap gap-4 md:col-span-2">
              <legend className="text-sm">{t("agentAccess.bundles.audiences")}</legend>
              {audiences.map((a) => (
                <label key={a} className="flex items-center gap-2 text-sm">
                  <input
                    type="checkbox"
                    checked={Boolean(draft.audiences[a])}
                    onChange={(e) => setDraft({ ...draft, audiences: { ...draft.audiences, [a]: e.target.checked } })}
                  />
                  {t(audienceKey[a])}
                </label>
              ))}
            </fieldset>
            <div>
              <Button type="button" disabled={busy || !draft.name.trim() || list(draft.permissions).length === 0} onClick={() => void createBundle()}>
                {t("agentAccess.bundles.create")}
              </Button>
            </div>
          </section>
        </CardContent>
      </Card>

      {bundle ? (
        <Card>
          <CardHeader>
            <CardTitle>{t("agentAccess.grants.title", { name: bundle.name })}</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left">
                  <th>{t("agentAccess.grants.col.principal")}</th>
                  <th>{t("agentAccess.grants.col.until")}</th>
                  <th>{t("agentAccess.grants.col.state")}</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {(bundle.grants ?? []).map((g) => (
                  <tr key={g.id}>
                    <td>{t("agentAccess.grants.principal", { type: g.principal_type, principal: g.principal })}</td>
                    <td>{g.expires_at ? formatDateTime(g.expires_at) : t("agentAccess.grants.noExpiry")}</td>
                    <td>{g.removed_at ? t("agentAccess.grants.removed") : g.live ? t("agentAccess.grants.live") : t("agentAccess.grants.notLive")}</td>
                    <td>
                      {g.removed_at ? null : (
                        <Button type="button" variant="outline" disabled={busy} onClick={() => void removeGrant(g.id)}>
                          {t("agentAccess.grants.remove", { principal: g.principal })}
                        </Button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            <div className="grid gap-3 md:grid-cols-4">
              <Field label={t("agentAccess.grants.type")} controlId="grant-type">
                {(control) => (
                  <Select {...control} value={grant.principal_type} onChange={(e) => setGrant({ ...grant, principal_type: e.target.value })}>
                    <option value="machine">{t("agentAccess.grants.type.machine")}</option>
                    <option value="user">{t("agentAccess.grants.type.user")}</option>
                  </Select>
                )}
              </Field>
              <Field label={t("agentAccess.grants.principalLabel")} controlId="grant-principal">
                {(control) => <Input {...control} value={grant.principal} onChange={(e) => setGrant({ ...grant, principal: e.target.value })} />}
              </Field>
              <Field label={t("agentAccess.grants.expires")} controlId="grant-expires">
                {(control) => (
                  <Input {...control} type="datetime-local" value={grant.expires_at} onChange={(e) => setGrant({ ...grant, expires_at: e.target.value })} />
                )}
              </Field>
              <Button type="button" className="self-end" disabled={busy || !grant.principal.trim()} onClick={() => void giveGrant()}>
                {t("agentAccess.grants.give")}
              </Button>
            </div>

            <section className="grid gap-3 md:grid-cols-3" aria-labelledby="agent-access-run">
              <h2 id="agent-access-run" className="font-medium md:col-span-3">
                {t("agentAccess.run.title")}
              </h2>
              <Field label={t("agentAccess.run.ttl")} controlId="run-ttl">
                {(control) => (
                  <Input {...control} type="number" min={1} value={run.ttlMinutes} onChange={(e) => setRun({ ...run, ttlMinutes: e.target.value })} />
                )}
              </Field>
              <Field label={t("agentAccess.run.label")} controlId="run-label">
                {(control) => <Input {...control} value={run.label} onChange={(e) => setRun({ ...run, label: e.target.value })} />}
              </Field>
              <Button type="button" className="self-end" disabled={busy} onClick={() => void startRun()}>
                {t("agentAccess.run.start")}
              </Button>
            </section>
          </CardContent>
        </Card>
      ) : null}

      {issued ? (
        <Card>
          <CardHeader>
            <CardTitle>{t("agentAccess.issued.title")}</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3 text-sm">
            <p>{t("agentAccess.issued.once", { expires: formatDateTime(issued.run.expires_at) })}</p>
            <Field label={t("agentAccess.issued.token")} controlId="issued-token">
              {(control) => <Input {...control} readOnly value={issued.token} />}
            </Field>
            <dl className="space-y-2">
              <dt className="font-medium">{t("agentAccess.issued.customAgent")}</dt>
              <dd>
                <code>{issued.launch.custom_agent}</code>
              </dd>
              <dt className="font-medium">{t("agentAccess.issued.ci")}</dt>
              <dd>{issued.launch.ci}</dd>
              <dt className="font-medium">{t("agentAccess.issued.mcp")}</dt>
              <dd>
                <code>{issued.launch.mcp_server}</code>
              </dd>
            </dl>
            <Button type="button" variant="outline" onClick={() => setIssued(null)}>
              {t("agentAccess.issued.done")}
            </Button>
          </CardContent>
        </Card>
      ) : null}

      <Card>
        <CardHeader>
          <CardTitle>{t("agentAccess.authority.title")}</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3 text-sm">
          <div className="flex flex-wrap items-end gap-3">
            <Field label={t("agentAccess.authority.principal")} controlId="authority-principal">
              {(control) => <Input {...control} value={lookup} onChange={(e) => setLookup(e.target.value)} />}
            </Field>
            <Button type="button" disabled={busy || !lookup.trim()} onClick={() => void showAuthority()}>
              {t("agentAccess.authority.show")}
            </Button>
          </div>
          {authority ? (
            <div className="space-y-2" aria-live="polite">
              <h2 className="font-medium">{t("agentAccess.authority.for", { principal: authority.principal })}</h2>
              {authority.permissions.length === 0 ? (
                <p>{t("agentAccess.authority.none")}</p>
              ) : (
                <ul>
                  {authority.permissions.map((p) => (
                    <li key={p.permission}>
                      {t("agentAccess.authority.via", { permission: p.permission, bundles: p.via.map((v) => v.bundle_name).join(", ") })}
                    </li>
                  ))}
                </ul>
              )}
              {authority.runs.map((r) => (
                <p key={r.id}>
                  {t("agentAccess.authority.run", {
                    id: r.id,
                    chain: r.chain.map((link) => (link.actor ? `${link.step} (${link.actor})` : link.step)).join(" → "),
                  })}
                </p>
              ))}
              <p className="text-muted-foreground">{authority.bounds.revocation}</p>
              <p className="text-muted-foreground">{authority.bounds.outage}</p>
              <p className="text-muted-foreground">{authority.bounds.lasting}</p>
            </div>
          ) : null}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>{t("agentAccess.runs.title")}</CardTitle>
        </CardHeader>
        <CardContent>
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left">
                <th>{t("agentAccess.runs.col.principal")}</th>
                <th>{t("agentAccess.runs.col.bundles")}</th>
                <th>{t("agentAccess.runs.col.now")}</th>
                <th>{t("agentAccess.runs.col.status")}</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {(runs.data?.items ?? []).map((r) => (
                <tr key={r.id} className="align-top">
                  <td>{r.label ? t("agentAccess.runs.labeled", { principal: r.principal, label: r.label }) : r.principal}</td>
                  <td>{r.bundle_names.join(", ")}</td>
                  <td>{r.effective.length ? r.effective.join(", ") : t("agentAccess.runs.nothing")}</td>
                  <td>{t(runStatusKey[r.status] ?? "agentAccess.run.status.active")}</td>
                  <td>
                    {r.status === "active" || r.status === "no_authority" ? (
                      <Button type="button" variant="outline" disabled={busy} onClick={() => void revoke(r)}>
                        {t("agentAccess.runs.revoke", { principal: r.principal })}
                      </Button>
                    ) : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>{t("agentAccess.activity.title")}</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3 text-sm">
          <p className="text-muted-foreground">{t("agentAccess.activity.help")}</p>
          <div className="flex flex-wrap items-end gap-3">
            <Field label={t("agentAccess.activity.principal")} controlId="activity-principal">
              {(control) => <Input {...control} value={filter.principal} onChange={(e) => setFilter({ ...filter, principal: e.target.value })} />}
            </Field>
            <Field label={t("agentAccess.activity.search")} controlId="activity-q">
              {(control) => <Input {...control} value={filter.q} onChange={(e) => setFilter({ ...filter, q: e.target.value })} />}
            </Field>
            <Button type="button" onClick={() => setApplied({ principal: filter.principal.trim() || undefined, q: filter.q.trim() || undefined })}>
              {t("agentAccess.activity.apply")}
            </Button>
            <Button type="button" variant="outline" disabled={busy} onClick={() => void exportActivity()}>
              {t("agentAccess.activity.export")}
            </Button>
          </div>
          <table className="w-full">
            <thead>
              <tr className="text-left">
                <th>{t("agentAccess.activity.col.when")}</th>
                <th>{t("agentAccess.activity.col.what")}</th>
                <th>{t("agentAccess.activity.col.who")}</th>
                <th>{t("agentAccess.activity.col.detail")}</th>
              </tr>
            </thead>
            <tbody>
              {(activity.data?.items ?? []).map((row, i) => (
                <tr key={`${row.at}-${row.action}-${i}`} className="align-top">
                  <td>{formatDateTime(row.at)}</td>
                  <td>{t(activityKey[row.action] ?? "agentAccess.activity.action.saved", { bundles: row.bundle_names.join(", ") })}</td>
                  <td>{row.principal ? t("agentAccess.activity.who", { principal: row.principal, actor: row.actor ?? "" }) : row.actor}</td>
                  <td>{row.detail}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <div className="flex gap-2">
            {applied.cursor ? (
              <Button type="button" variant="outline" onClick={() => setApplied({ ...applied, cursor: undefined })}>
                {t("agentAccess.activity.newest")}
              </Button>
            ) : null}
            {activity.data?.next_cursor ? (
              <Button type="button" variant="outline" onClick={() => setApplied({ ...applied, cursor: activity.data?.next_cursor })}>
                {t("agentAccess.activity.older")}
              </Button>
            ) : null}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
