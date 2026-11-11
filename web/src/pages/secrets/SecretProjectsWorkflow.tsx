import { useCallback, useEffect, useState, type FormEvent } from "react";
import { Button } from "@/components/ui/button";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { ErrorState } from "@/components/StatePrimitives";
import { useCan } from "@/components/rbac";
import { formatDateTime } from "@/i18n/format";
import { useTranslation } from "@/i18n/I18nProvider";
import { api, type SecretProject } from "@/lib/api";
import { apiProblemMessage } from "@/lib/apiProblem";
import { SecretProjectMigrations } from "./SecretProjectMigrations";
import { SecretProjectTransfers } from "./SecretProjectTransfers";

// A235: the secrets workspace. A project groups an application's secrets by
// environment over the same native store (a secret belongs to it by its name,
// "<project>/<environment>/…"). A restricted environment is open only to the
// members granted it, so the server leaves its names out for everyone else and
// this view says so. Owners are named, or shown as unknown — never guessed.
// Nothing here reads a secret value. Changing projects needs access:write;
// members change under access:write or, within its own grant, by the
// project's admin holding secrets:write (A235-L1), as the server says in
// can_manage_members.

type Role = "viewer" | "developer" | "admin";

// canManageMember reports whether the caller may revoke a member: the server
// says it may manage members, and a project admin restricted to some
// environments manages only members inside them (A235-L1).
function canManageMember(project: SecretProject, environments: string[]): boolean {
  if (!project.can_manage_members) return false;
  const own = project.manageable_environments ?? [];
  if (own.length === 0) return true;
  return environments.length > 0 && environments.every((env) => own.includes(env));
}

function slugs(value: string): string[] {
  return value
    .split(",")
    .map((part) => part.trim())
    .filter(Boolean);
}

export function SecretProjectsWorkflow() {
  const { t } = useTranslation();
  const canManage = useCan("access:write");
  const canWrite = useCan("secrets:write");
  const [projects, setProjects] = useState<SecretProject[]>([]);
  const [selected, setSelected] = useState<SecretProject | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [slug, setSlug] = useState("");
  const [name, setName] = useState("");
  const [environments, setEnvironments] = useState("dev, stage");
  const [restricted, setRestricted] = useState("stage");
  const [memberSubject, setMemberSubject] = useState("");
  const [memberRole, setMemberRole] = useState<Role>("developer");
  const [memberEnvironments, setMemberEnvironments] = useState("");
  // A235-L3: renaming the project (environment "") or one environment.
  const [renaming, setRenaming] = useState<{ environment: string } | null>(null);
  const [newName, setNewName] = useState("");

  const refresh = useCallback(async () => {
    try {
      setProjects((await api.listSecretProjects()).items);
      setError(null);
    } catch (cause) {
      setError(apiProblemMessage(cause, t("secrets.projects.readFailed")));
    }
  }, [t]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  async function open(project: string) {
    try {
      setSelected(await api.getSecretProject(project));
      setError(null);
    } catch (cause) {
      setError(apiProblemMessage(cause, t("secrets.projects.readFailed")));
    }
  }

  async function create(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const closed = new Set(slugs(restricted));
    setBusy(true);
    try {
      const project = await api.createSecretProject({
        slug: slug.trim(),
        name: name.trim(),
        environments: slugs(environments).map((env) => ({ slug: env, restricted: closed.has(env) })),
      });
      setSlug("");
      setName("");
      setSelected(project);
      setError(null);
      await refresh();
    } catch (cause) {
      setError(apiProblemMessage(cause, t("secrets.projects.createFailed")));
    } finally {
      setBusy(false);
    }
  }

  async function grant(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selected) return;
    setBusy(true);
    try {
      setSelected(await api.putSecretProjectMember(selected.slug, memberSubject.trim(), { role: memberRole, environments: slugs(memberEnvironments) }));
      setMemberSubject("");
      setMemberEnvironments("");
      setError(null);
    } catch (cause) {
      setError(apiProblemMessage(cause, t("secrets.projects.grantFailed")));
    } finally {
      setBusy(false);
    }
  }

  function startRename(environment: string, current: string) {
    setRenaming({ environment });
    setNewName(current);
  }

  async function rename(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selected || !renaming) return;
    setBusy(true);
    try {
      const input = { name: newName.trim() };
      setSelected(
        renaming.environment
          ? await api.renameSecretProjectEnvironment(selected.slug, renaming.environment, input)
          : await api.renameSecretProject(selected.slug, input),
      );
      setRenaming(null);
      setNewName("");
      setError(null);
      await refresh();
    } catch (cause) {
      setError(apiProblemMessage(cause, t("secrets.projects.renameFailed")));
    } finally {
      setBusy(false);
    }
  }

  async function revoke(subject: string) {
    if (!selected) return;
    setBusy(true);
    try {
      setSelected(await api.deleteSecretProjectMember(selected.slug, subject));
      setError(null);
    } catch (cause) {
      setError(apiProblemMessage(cause, t("secrets.projects.revokeFailed")));
    } finally {
      setBusy(false);
    }
  }

  const ownerLabel = (owner: string) => (owner === "unknown" ? t("secrets.projects.ownerUnknown") : owner);
  const healthLabel: Record<string, string> = {
    ok: t("secrets.projects.health.ok"),
    expiring: t("secrets.projects.health.expiring"),
    expired: t("secrets.projects.health.expired"),
  };
  const accessLabel: Record<string, string> = {
    open: t("secrets.projects.access.open"),
    member: t("secrets.projects.access.member"),
    restricted: t("secrets.projects.access.restricted"),
  };

  return (
    <section aria-labelledby="secret-projects-heading" className="grid gap-4 border-y border-border py-4">
      <div>
        <h2 id="secret-projects-heading" tabIndex={-1} className="text-title font-semibold">
          {t("secrets.projects.heading")}
        </h2>
        <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{t("secrets.projects.description")}</p>
      </div>
      {error ? <ErrorState title={t("secrets.projects.error")}>{error}</ErrorState> : null}

      {projects.length === 0 ? (
        <p className="text-sm text-muted-foreground">{t("secrets.projects.empty")}</p>
      ) : (
        <ul className="grid gap-2" aria-label={t("secrets.projects.listLabel")}>
          {projects.map((project) => (
            <li key={project.slug} className="flex flex-wrap items-center justify-between gap-2 rounded-control border border-border p-3 text-sm">
              <span>
                <strong>{project.name || project.slug}</strong> <span className="font-mono text-xs text-muted-foreground">{project.slug}</span>
              </span>
              <span className={project.owner === "unknown" ? "font-semibold text-risk-high" : "text-muted-foreground"}>{ownerLabel(project.owner)}</span>
              <Button type="button" variant="outline" onClick={() => void open(project.slug)}>
                {t("secrets.projects.open")}
              </Button>
            </li>
          ))}
        </ul>
      )}

      {selected ? (
        <article aria-labelledby="secret-project-detail" className="ui-panel grid gap-4 p-comfortable text-sm">
          <div className="flex flex-wrap items-center gap-2">
            <h3 id="secret-project-detail" className="font-semibold">
              {selected.name || selected.slug}
            </h3>
            {canManage ? (
              <Button type="button" variant="outline" onClick={() => startRename("", selected.name || selected.slug)} disabled={busy}>
                {t("secrets.projects.rename")}
              </Button>
            ) : null}
          </div>
          {renaming ? (
            <form
              onSubmit={(event) => void rename(event)}
              className="grid max-w-xl gap-3"
              aria-label={
                renaming.environment
                  ? t("secrets.projects.renameEnvironmentLabel", { environment: renaming.environment })
                  : t("secrets.projects.renameProjectLabel")
              }
            >
              <Field label={t("secrets.projects.newName")}>
                {(control) => <Input {...control} value={newName} maxLength={128} onChange={(event) => setNewName(event.target.value)} />}
              </Field>
              <p className="text-muted-foreground">{t("secrets.projects.renameKeepsSlug", { slug: renaming.environment || selected.slug })}</p>
              <div className="flex flex-wrap gap-2">
                <Button type="submit" disabled={busy || !newName.trim()}>
                  {t("secrets.projects.renameSave")}
                </Button>
                <Button type="button" variant="outline" onClick={() => setRenaming(null)} disabled={busy}>
                  {t("secrets.projects.renameCancel")}
                </Button>
              </div>
            </form>
          ) : null}
          <p>
            {t("secrets.projects.owner")}:{" "}
            <span className={selected.owner === "unknown" ? "font-semibold text-risk-high" : ""}>{ownerLabel(selected.owner)}</span>
          </p>
          {selected.owner_resources ? (
            <div className="grid gap-1" aria-label={t("secrets.projects.applicationLabel")}>
              <p>
                {t("secrets.projects.application", {
                  certificates: String(selected.owner_resources.certificates),
                  identities: String(selected.owner_resources.identities),
                  attention: String(selected.owner_resources.certificates_needing_work),
                })}
              </p>
              <ul className="grid gap-1">
                {[...selected.owner_resources.soonest_certificates, ...selected.owner_resources.soonest_identities].map((item) => (
                  <li key={`${item.kind}:${item.id}`} className="flex flex-wrap gap-2">
                    <span className="font-mono text-xs">{item.kind}</span>
                    <span>{item.name}</span>
                    <span className={item.health === "ok" ? "text-muted-foreground" : "font-semibold text-risk-high"}>
                      {healthLabel[item.health] ?? item.health}
                    </span>
                    {item.not_after ? <span className="text-muted-foreground">{formatDateTime(item.not_after)}</span> : null}
                  </li>
                ))}
              </ul>
            </div>
          ) : (
            <p className="text-muted-foreground">{t("secrets.projects.applicationUnknown")}</p>
          )}

          {(selected.environments ?? []).map((env) => (
            <div key={env.slug} className="grid gap-2 border-t border-border pt-3">
              <p className="flex flex-wrap items-center gap-2">
                <strong>{env.name || env.slug}</strong>
                <span className="rounded-control border border-border px-2 py-0.5 text-xs">{accessLabel[env.access] ?? env.access}</span>
                {canManage ? (
                  <Button
                    type="button"
                    variant="outline"
                    aria-label={t("secrets.projects.renameEnvironmentLabel", { environment: env.slug })}
                    onClick={() => startRename(env.slug, env.name || env.slug)}
                    disabled={busy}
                  >
                    {t("secrets.projects.rename")}
                  </Button>
                ) : null}
              </p>
              {env.access === "restricted" ? (
                <p className="text-muted-foreground">{t("secrets.projects.restrictedHidden")}</p>
              ) : env.secrets.length === 0 ? (
                <p className="text-muted-foreground">{t("secrets.projects.noSecrets")}</p>
              ) : (
                <ul className="grid gap-1">
                  {env.secrets.map((secret) => (
                    <li key={secret.name} className="flex flex-wrap gap-2">
                      <span className="font-mono text-xs">{secret.key}</span>
                      <span className="text-muted-foreground">v{secret.version}</span>
                      <span className={secret.owner === "unknown" ? "font-semibold text-risk-high" : "text-muted-foreground"}>{ownerLabel(secret.owner)}</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          ))}

          <div className="grid gap-2 border-t border-border pt-3">
            <strong>{t("secrets.projects.members")}</strong>
            {(selected.members ?? []).length === 0 ? (
              <p className="text-muted-foreground">{t("secrets.projects.noMembers")}</p>
            ) : (
              <ul className="grid gap-1">
                {(selected.members ?? []).map((member) => (
                  <li key={member.subject} className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-xs">{member.subject}</span>
                    <span>{member.role}</span>
                    <span className="text-muted-foreground">
                      {member.environments.length === 0 ? t("secrets.projects.allEnvironments") : member.environments.join(", ")}
                    </span>
                    {canManageMember(selected, member.environments) ? (
                      <Button type="button" variant="outline" onClick={() => void revoke(member.subject)} disabled={busy}>
                        {t("secrets.projects.revoke")}
                      </Button>
                    ) : null}
                  </li>
                ))}
              </ul>
            )}
            {selected.can_manage_members ? (
              <form onSubmit={(event) => void grant(event)} className="grid max-w-xl gap-3" aria-label={t("secrets.projects.grantLabel")}>
                {selected.manageable_environments?.length ? (
                  <p className="text-sm text-muted-foreground">
                    {t("secrets.projects.manageableEnvironments", { environments: selected.manageable_environments.join(", ") })}
                  </p>
                ) : null}
                <Field label={t("secrets.projects.memberSubject")}>
                  {(control) => (
                    <Input {...control} value={memberSubject} maxLength={256} required onChange={(event) => setMemberSubject(event.target.value)} />
                  )}
                </Field>
                <Field label={t("secrets.projects.memberRole")}>
                  {(control) => (
                    <Select {...control} value={memberRole} onChange={(event) => setMemberRole(event.target.value as Role)}>
                      <option value="viewer">{t("secrets.projects.role.viewer")}</option>
                      <option value="developer">{t("secrets.projects.role.developer")}</option>
                      <option value="admin">{t("secrets.projects.role.admin")}</option>
                    </Select>
                  )}
                </Field>
                <Field label={t("secrets.projects.memberEnvironments")} description={t("secrets.projects.memberEnvironmentsHelp")}>
                  {(control) => <Input {...control} value={memberEnvironments} onChange={(event) => setMemberEnvironments(event.target.value)} />}
                </Field>
                <Button type="submit" disabled={busy || !memberSubject.trim()}>
                  {t("secrets.projects.grant")}
                </Button>
              </form>
            ) : null}
          </div>
          {canWrite ? <SecretProjectTransfers project={selected} onApplied={() => void open(selected.slug)} /> : null}
          {canWrite ? <SecretProjectMigrations project={selected} /> : null}
        </article>
      ) : null}

      {canManage ? (
        <form onSubmit={(event) => void create(event)} className="grid max-w-xl gap-3" aria-label={t("secrets.projects.createLabel")}>
          <Field label={t("secrets.projects.slug")} description={t("secrets.projects.slugHelp")}>
            {(control) => <Input {...control} value={slug} maxLength={63} required onChange={(event) => setSlug(event.target.value)} />}
          </Field>
          <Field label={t("secrets.projects.name")}>
            {(control) => <Input {...control} value={name} maxLength={128} onChange={(event) => setName(event.target.value)} />}
          </Field>
          <Field label={t("secrets.projects.environments")} description={t("secrets.projects.environmentsHelp")}>
            {(control) => <Input {...control} value={environments} required onChange={(event) => setEnvironments(event.target.value)} />}
          </Field>
          <Field label={t("secrets.projects.restricted")} description={t("secrets.projects.restrictedHelp")}>
            {(control) => <Input {...control} value={restricted} onChange={(event) => setRestricted(event.target.value)} />}
          </Field>
          <Button type="submit" disabled={busy || !slug.trim() || slugs(environments).length === 0}>
            {t("secrets.projects.create")}
          </Button>
        </form>
      ) : null}
    </section>
  );
}
