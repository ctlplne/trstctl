import { useEffect, useState, type FormEvent } from "react";
import { Button } from "@/components/ui/button";
import { Field } from "@/components/ui/field";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { ErrorState } from "@/components/StatePrimitives";
import { useTranslation } from "@/i18n/I18nProvider";
import { api, type SecretMigration, type SecretMigrationRequest, type SecretProject } from "@/lib/api";
import { apiProblemMessage } from "@/lib/apiProblem";

// A243: migrate an export (dotenv, JSON or YAML per environment and folder)
// into this project. Assessment is value-free; staging sends the same export
// with the assessment's digest, and the export's system stays each secret's
// writer until cutover. The export's text stays in this form only while it
// is open.

type Format = "dotenv" | "json" | "yaml";
type SourceRow = { environment: string; folder: string; format: Format; content: string };

// The value-free plan the server returns (secretmigrate.Assessment).
interface MigrationPlan {
  counts: { import: number; reissue: number; blocked: number; unsupported: number; permissions_translated: number; permissions_held: number };
  environments: { name: string; open: boolean; open_accepted: boolean }[];
  objects: { name: string; action: string; reason?: string; existing_version: number; references?: string[]; description?: string }[];
  unsupported: { location: string; reason: string }[];
  permissions: { subject: string; access: string; environment: string; folder?: string; status: string; role?: string; reason?: string }[];
}

function planOf(run: SecretMigration): MigrationPlan {
  return run.plan as unknown as MigrationPlan;
}

function parseList(text: string): unknown[] | undefined {
  if (!text.trim()) return undefined;
  const parsed: unknown = JSON.parse(text);
  if (!Array.isArray(parsed)) throw new Error("not a JSON list");
  return parsed;
}

export function SecretProjectMigrations({ project }: { project: SecretProject }) {
  const { t } = useTranslation();
  const envs = (project.environments ?? []).map((env) => env.slug);
  const [sources, setSources] = useState<SourceRow[]>([{ environment: envs[0] ?? "", folder: "", format: "dotenv", content: "" }]);
  const [permissions, setPermissions] = useState("");
  const [consumers, setConsumers] = useState("");
  const [acceptOpen, setAcceptOpen] = useState<string[]>([]);
  const [run, setRun] = useState<SecretMigration | null>(null);
  const [runs, setRuns] = useState<SecretMigration[]>([]);
  const [noConsumers, setNoConsumers] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let cancelled = false;
    api
      .listSecretMigrations()
      .then((list) => {
        if (!cancelled) setRuns((list.items ?? []).filter((item) => item.project === project.slug));
      })
      .catch(() => undefined);
    return () => {
      cancelled = true;
    };
  }, [project.slug, run?.state]);

  function request(): SecretMigrationRequest {
    return {
      project: project.slug,
      sources: sources.map((s) => ({ environment: s.environment, folder: s.folder.trim() || undefined, format: s.format, content: s.content })),
      permissions: parseList(permissions) as SecretMigrationRequest["permissions"],
      consumers: parseList(consumers) as SecretMigrationRequest["consumers"],
      accept_open_environments: acceptOpen.length > 0 ? acceptOpen : undefined,
    };
  }

  async function act(work: () => Promise<SecretMigration>, failed: string) {
    setBusy(true);
    try {
      setRun(await work());
      setError(null);
    } catch (cause) {
      setError(apiProblemMessage(cause, failed));
    } finally {
      setBusy(false);
    }
  }

  function assess(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void act(
      () => api.assessSecretMigration({ ...request(), migration_id: run && run.state !== "rolled-back" ? run.id : undefined }),
      t("secrets.migrate.assessFailed"),
    );
  }

  const plan = run ? planOf(run) : null;
  const reissue = plan?.objects.filter((o) => o.action === "reissue" && !run?.objects.some((w) => w.name === o.name && w.outcome === "reissued")) ?? [];
  const setSource = (i: number, patch: Partial<SourceRow>) => setSources((rows) => rows.map((row, j) => (j === i ? { ...row, ...patch } : row)));

  return (
    <section className="grid gap-4 rounded-panel border border-border p-4" aria-label={t("secrets.migrate.title")}>
      <div>
        <h3 className="text-sm font-semibold">{t("secrets.migrate.title")}</h3>
        <p className="mt-1 max-w-3xl text-caption text-muted-foreground">{t("secrets.migrate.help")}</p>
      </div>
      <form className="grid gap-3" onSubmit={assess}>
        {sources.map((source, i) => (
          <fieldset key={i} className="grid gap-2 rounded-control border border-border p-3 md:grid-cols-3">
            <Field label={t("secrets.migrate.environment")}>
              {(control) => (
                <Select {...control} value={source.environment} onChange={(event) => setSource(i, { environment: event.target.value })}>
                  {envs.map((env) => (
                    <option key={env} value={env}>
                      {env}
                    </option>
                  ))}
                </Select>
              )}
            </Field>
            <Field label={t("secrets.migrate.folder")}>
              {(control) => <Input {...control} value={source.folder} onChange={(event) => setSource(i, { folder: event.target.value })} />}
            </Field>
            <Field label={t("secrets.migrate.format")}>
              {(control) => (
                <Select {...control} value={source.format} onChange={(event) => setSource(i, { format: event.target.value as Format })}>
                  <option value="dotenv">{t("secrets.migrate.formatDotenv")}</option>
                  <option value="json">{t("secrets.migrate.formatJSON")}</option>
                  <option value="yaml">{t("secrets.migrate.formatYAML")}</option>
                </Select>
              )}
            </Field>
            <Field label={t("secrets.migrate.content")} className="md:col-span-3">
              {(control) => (
                <Textarea
                  {...control}
                  className="min-h-24 font-mono text-xs"
                  spellCheck={false}
                  autoComplete="off"
                  value={source.content}
                  onChange={(event) => setSource(i, { content: event.target.value })}
                />
              )}
            </Field>
          </fieldset>
        ))}
        <div className="flex flex-wrap gap-2">
          <Button
            type="button"
            variant="outline"
            onClick={() => setSources((rows) => [...rows, { environment: envs[0] ?? "", folder: "", format: "dotenv", content: "" }])}
          >
            {t("secrets.migrate.addSource")}
          </Button>
        </div>
        <Field label={t("secrets.migrate.permissions")} description={t("secrets.migrate.permissionsHelp")}>
          {(control) => (
            <Textarea {...control} className="min-h-16 font-mono text-xs" value={permissions} onChange={(event) => setPermissions(event.target.value)} />
          )}
        </Field>
        <Field label={t("secrets.migrate.consumers")} description={t("secrets.migrate.consumersHelp")}>
          {(control) => (
            <Textarea {...control} className="min-h-16 font-mono text-xs" value={consumers} onChange={(event) => setConsumers(event.target.value)} />
          )}
        </Field>
        {plan?.environments.some((env) => env.open) ? (
          <div className="grid gap-1 text-sm">
            {plan.environments
              .filter((env) => env.open)
              .map((env) => (
                <label key={env.name} className="flex items-center gap-2">
                  <Checkbox
                    checked={acceptOpen.includes(env.name)}
                    onChange={(event) => setAcceptOpen((list) => (event.target.checked ? [...list, env.name] : list.filter((name) => name !== env.name)))}
                  />
                  {t("secrets.migrate.acceptOpen", { environment: env.name })}
                </label>
              ))}
          </div>
        ) : null}
        <Button type="submit" disabled={busy || sources.some((s) => !s.environment || !s.content.trim())}>
          {run ? t("secrets.migrate.reassess") : t("secrets.migrate.assess")}
        </Button>
      </form>
      {error ? <ErrorState title={t("secrets.migrate.failedTitle")}>{error}</ErrorState> : null}
      {run && plan ? (
        <div className="grid gap-3" aria-label={t("secrets.migrate.planLabel")}>
          <p className="text-sm">
            {t("secrets.migrate.summary", {
              state: run.state,
              import: plan.counts.import,
              reissue: plan.counts.reissue,
              blocked: plan.counts.blocked,
              unsupported: plan.counts.unsupported,
              held: plan.counts.permissions_held,
            })}
          </p>
          <table className="ui-table text-xs">
            <caption className="sr-only">{t("secrets.migrate.objects")}</caption>
            <thead>
              <tr>
                <th scope="col">{t("secrets.migrate.name")}</th>
                <th scope="col">{t("secrets.migrate.action")}</th>
                <th scope="col">{t("secrets.migrate.writer")}</th>
                <th scope="col">{t("secrets.migrate.reason")}</th>
              </tr>
            </thead>
            <tbody>
              {plan.objects.map((o) => {
                const written = run.objects.find((w) => w.name === o.name);
                return (
                  <tr key={o.name}>
                    <td className="font-mono">{o.name}</td>
                    <td>{written?.rollback ? written.rollback : (written?.outcome ?? o.action)}</td>
                    <td>{written ? t("secrets.migrate.writerVersion", { writer: written.writer, version: written.version }) : null}</td>
                    <td className="text-muted-foreground">{o.reason ?? o.description ?? ""}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          {plan.unsupported.length > 0 ? (
            <ul className="text-xs text-muted-foreground">
              {plan.unsupported.map((u) => (
                <li key={u.location}>
                  {u.location}: {u.reason}
                </li>
              ))}
            </ul>
          ) : null}
          {plan.permissions.length > 0 ? (
            <ul className="text-xs" aria-label={t("secrets.migrate.permissions")}>
              {plan.permissions.map((p, i) => (
                <li key={i}>
                  {t("secrets.migrate.permissionLine", {
                    subject: p.subject,
                    access: p.access,
                    scope: p.folder ? `${p.environment}/${p.folder}` : p.environment,
                    status: p.status,
                  })}
                  {p.role ? <span className="ml-1">{t("secrets.migrate.permissionRole", { role: p.role })}</span> : null}
                  {p.reason ? <span className="ml-1 text-muted-foreground">{p.reason}</span> : null}
                </li>
              ))}
            </ul>
          ) : null}
          {run.consumers.length > 0 ? (
            <ul className="text-xs" aria-label={t("secrets.migrate.consumers")}>
              {run.consumers.map((c) => (
                <li key={c.name}>{t("secrets.migrate.consumerStatus", { name: c.name, read: c.read.length, total: c.secrets.length })}</li>
              ))}
            </ul>
          ) : null}
          <div className="flex flex-wrap items-center gap-2">
            {run.state === "assessed" || run.state === "staged" ? (
              <Button
                type="button"
                disabled={busy}
                onClick={() => void act(() => api.stageSecretMigration(run.id, { ...request(), plan_digest: run.digest }), t("secrets.migrate.stageFailed"))}
              >
                {t("secrets.migrate.stage")}
              </Button>
            ) : null}
            {run.state !== "rolled-back" && plan.counts.permissions_translated > 0 ? (
              <Button
                type="button"
                variant="outline"
                disabled={busy}
                onClick={() => void act(() => api.applySecretMigrationPermissions(run.id), t("secrets.migrate.permissionsFailed"))}
              >
                {t("secrets.migrate.applyPermissions")}
              </Button>
            ) : null}
            {run.state === "staged" ? (
              <>
                {run.consumers.length === 0 ? (
                  <label className="flex items-center gap-2 text-sm">
                    <Checkbox checked={noConsumers} onChange={(event) => setNoConsumers(event.target.checked)} />
                    {t("secrets.migrate.noConsumers")}
                  </label>
                ) : null}
                <Button
                  type="button"
                  disabled={busy}
                  onClick={() => void act(() => api.cutOverSecretMigration(run.id, noConsumers), t("secrets.migrate.cutoverFailed"))}
                >
                  {t("secrets.migrate.cutover")}
                </Button>
              </>
            ) : null}
            {reissue.length > 0 && run.state !== "rolled-back" ? (
              <Button
                type="button"
                variant="outline"
                disabled={busy}
                onClick={() =>
                  void act(
                    () =>
                      api.reissueSecretMigrationCredentials(
                        run.id,
                        reissue.map((o) => o.name),
                      ),
                    t("secrets.migrate.reissueFailed"),
                  )
                }
              >
                {t("secrets.migrate.reissue", { count: reissue.length })}
              </Button>
            ) : null}
            {run.state === "staged" || run.state === "cut-over" ? (
              <Button
                type="button"
                variant="ghost"
                disabled={busy}
                onClick={() => void act(() => api.rollBackSecretMigration(run.id), t("secrets.migrate.rollbackFailed"))}
              >
                {t("secrets.migrate.rollback")}
              </Button>
            ) : null}
          </div>
        </div>
      ) : null}
      {runs.length > 0 ? (
        <ul className="text-xs text-muted-foreground" aria-label={t("secrets.migrate.runs")}>
          {runs.map((item) => (
            <li key={item.id}>
              <button type="button" className="underline" onClick={() => void api.getSecretMigration(item.id).then(setRun)}>
                {item.id}
              </button>{" "}
              · {item.state}
            </li>
          ))}
        </ul>
      ) : null}
    </section>
  );
}
