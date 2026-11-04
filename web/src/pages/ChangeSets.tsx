import { useEffect, useMemo, useState } from "react";
import { useFieldArray, useForm, useWatch } from "react-hook-form";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { ErrorState } from "@/components/StatePrimitives";
import { useTranslation } from "@/i18n/I18nProvider";
import { ApiError } from "@/lib/apiTransport";
import { api, type ChangeApplication, type ChangePlan, type ChangeSet } from "@/lib/api";
import { useApiQuery } from "@/lib/query";

// A248: the console form is one more author of the same typed change set the
// API, a GitOps file and an AI draft produce. It builds the set, plans it,
// shows exactly what applying would do, and applies only the plan reviewed.

export type ChangeSetForm = {
  name: string;
  description: string;
  owners: { key: string; kind: string; name: string; application_id: string; service: string; environment: string; escalation_chain: string }[];
  profiles: { name: string; spec: string }[];
  members: { subject: string; roles: string }[];
  targets: { key: string; name: string; connector: string; config: string; enabled: boolean }[];
};

const blank: ChangeSetForm = { name: "", description: "", owners: [], profiles: [], members: [], targets: [] };

export const changeSetTemplates: Record<string, ChangeSetForm> = {
  blank,
  onboard: {
    ...blank,
    name: "onboard an application",
    owners: [{ key: "", kind: "team", name: "", application_id: "", service: "", environment: "", escalation_chain: "" }],
    profiles: [{ name: "", spec: '{"allowed_key_algorithms":["ECDSA"],"allowed_protocols":["acme"],"max_validity":"720h"}' }],
    members: [{ subject: "", roles: "viewer" }],
  },
  grant: { ...blank, name: "grant a member roles", members: [{ subject: "", roles: "viewer" }] },
  target: { ...blank, name: "add a connector target", targets: [{ key: "", name: "", connector: "", config: "{}", enabled: false }] },
};

const list = (value: string) =>
  value
    .split(",")
    .map((part) => part.trim())
    .filter(Boolean);

/** changeSetFromForm builds the typed set the API plans: rows left empty are
 * dropped, comma lists split, and JSON fields parsed. */
export function changeSetFromForm(form: ChangeSetForm, invalid: (field: string) => string): { set: ChangeSet } | { error: string } {
  const set: ChangeSet = { name: form.name.trim() };
  if (form.description.trim()) set.description = form.description.trim();
  const owners = form.owners
    .filter((o) => o.key.trim() || o.name.trim())
    .map((o) => {
      const owner: NonNullable<ChangeSet["owners"]>[number] = { key: o.key.trim(), kind: o.kind.trim(), name: o.name.trim() };
      if (o.application_id.trim()) owner.application_id = o.application_id.trim();
      if (o.service.trim()) owner.service = o.service.trim();
      if (o.environment.trim()) owner.environment = o.environment.trim();
      if (list(o.escalation_chain).length) owner.escalation_chain = list(o.escalation_chain);
      return owner;
    });
  if (owners.length) set.owners = owners;
  const profiles: NonNullable<ChangeSet["profiles"]> = [];
  for (const p of form.profiles.filter((p) => p.name.trim())) {
    try {
      profiles.push({ name: p.name.trim(), spec: JSON.parse(p.spec) });
    } catch {
      return { error: invalid(p.name.trim()) };
    }
  }
  if (profiles.length) set.profiles = profiles;
  const members = form.members.filter((m) => m.subject.trim()).map((m) => ({ subject: m.subject.trim(), roles: list(m.roles) }));
  if (members.length) set.members = members;
  const targets: NonNullable<ChangeSet["deployment_targets"]> = [];
  for (const target of form.targets.filter((x) => x.key.trim())) {
    try {
      targets.push({
        key: target.key.trim(),
        name: target.name.trim(),
        connector: target.connector.trim(),
        config: JSON.parse(target.config),
        enabled: target.enabled,
      });
    } catch {
      return { error: invalid(target.key.trim()) };
    }
  }
  if (targets.length) set.deployment_targets = targets;
  return { set };
}

type Reviewed = { set: ChangeSet; plan: ChangePlan; fingerprint: string };

export function ChangeSets() {
  const { t } = useTranslation();
  const form = useForm<ChangeSetForm>({ defaultValues: changeSetTemplates.onboard });
  const owners = useFieldArray({ control: form.control, name: "owners" });
  const profiles = useFieldArray({ control: form.control, name: "profiles" });
  const members = useFieldArray({ control: form.control, name: "members" });
  const targets = useFieldArray({ control: form.control, name: "targets" });
  const values = useWatch({ control: form.control });
  const [mode, setMode] = useState<"form" | "json">("form");
  const [json, setJSON] = useState("");
  const [reviewed, setReviewed] = useState<Reviewed | null>(null);
  const [applied, setApplied] = useState<ChangeApplication | null>(null);
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const [draftRequest, setDraftRequest] = useState("");
  const ai = useApiQuery(["ai-status"], () => api.aiStatus(), { retry: false });

  const invalid = (field: string) => t("changes.error.json", { field });
  const current = useMemo((): { set: ChangeSet } | { error: string } => {
    if (mode === "form") return changeSetFromForm({ ...blank, ...(values as ChangeSetForm) }, invalid);
    try {
      return { set: JSON.parse(json) as ChangeSet };
    } catch {
      return { error: invalid(t("changes.json.label")) };
    }
    // invalid closes over t; values and json are the inputs.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [mode, values, json]);
  const fingerprint = "set" in current ? JSON.stringify(current.set) : "";
  const stale = reviewed !== null && reviewed.fingerprint !== fingerprint;

  useEffect(() => {
    if (stale) setApplied(null);
  }, [stale]);

  const loadTemplate = (name: string) => {
    form.reset(changeSetTemplates[name] ?? blank);
    setReviewed(null);
    setApplied(null);
    setMessage("");
  };
  const toJSON = () => {
    if ("set" in current) setJSON(JSON.stringify(current.set, null, 2));
    setMode("json");
  };
  const plan = async (set: ChangeSet) => {
    setBusy(true);
    setMessage("");
    setApplied(null);
    try {
      const planned = await api.planChangeSet(set);
      setReviewed({ set, plan: planned, fingerprint: JSON.stringify(set) });
    } catch (error) {
      setReviewed(null);
      setMessage(error instanceof Error ? error.message : String(error));
    } finally {
      setBusy(false);
    }
  };
  const apply = async () => {
    if (!reviewed || stale) return;
    setBusy(true);
    setMessage("");
    try {
      setApplied(await api.applyChangeSet({ change_set: reviewed.set, plan_digest: reviewed.plan.plan_digest }));
    } catch (error) {
      setMessage(error instanceof ApiError && error.status === 409 ? t("changes.apply.conflict") : error instanceof Error ? error.message : String(error));
    } finally {
      setBusy(false);
    }
  };
  const draft = async () => {
    setBusy(true);
    setMessage("");
    try {
      const drafted = await api.draftChangeSet({ request: draftRequest });
      setJSON(JSON.stringify(drafted.change_set, null, 2));
      setMode("json");
      if (drafted.plan) {
        setReviewed({ set: drafted.change_set, plan: drafted.plan, fingerprint: JSON.stringify(drafted.change_set) });
      } else {
        setReviewed(null);
        setMessage(t("changes.draft.refused", { reason: drafted.refused ?? "" }));
      }
    } catch (error) {
      setMessage(error instanceof Error ? error.message : String(error));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-6">
      <header className="space-y-2">
        <h1 className="text-2xl font-semibold">{t("changes.page.title")}</h1>
        <p className="text-muted-foreground max-w-3xl">{t("changes.page.intro")}</p>
      </header>

      <Card>
        <CardContent className="space-y-4 pt-6">
          <div className="flex flex-wrap items-end gap-4">
            <Field label={t("changes.template.label")} controlId="change-template">
              {(control) => (
                <Select {...control} defaultValue="onboard" onChange={(event) => loadTemplate(event.target.value)}>
                  <option value="blank">{t("changes.template.blank")}</option>
                  <option value="onboard">{t("changes.template.onboard")}</option>
                  <option value="grant">{t("changes.template.grant")}</option>
                  <option value="target">{t("changes.template.target")}</option>
                </Select>
              )}
            </Field>
            <div className="flex gap-2" role="group" aria-label={t("changes.page.title")}>
              <Button type="button" variant={mode === "form" ? "default" : "outline"} onClick={() => setMode("form")}>
                {t("changes.mode.form")}
              </Button>
              <Button type="button" variant={mode === "json" ? "default" : "outline"} onClick={toJSON}>
                {t("changes.mode.json")}
              </Button>
            </div>
          </div>

          {mode === "form" ? (
            <div className="space-y-6">
              <div className="grid gap-4 md:grid-cols-2">
                <Field label={t("changes.field.name")} controlId="change-name">
                  {(control) => <Input {...control} {...form.register("name")} />}
                </Field>
                <Field label={t("changes.field.description")} controlId="change-description">
                  {(control) => <Input {...control} {...form.register("description")} />}
                </Field>
              </div>

              <section className="space-y-3" aria-labelledby="change-owners">
                <h2 id="change-owners" className="font-medium">
                  {t("changes.section.owners")}
                </h2>
                {owners.fields.map((row, i) => (
                  <div key={row.id} className="grid gap-3 md:grid-cols-4">
                    <Field label={t("changes.owner.key")} controlId={`owner-key-${i}`}>
                      {(control) => <Input {...control} {...form.register(`owners.${i}.key`)} />}
                    </Field>
                    <Field label={t("changes.owner.kind")} controlId={`owner-kind-${i}`}>
                      {(control) => (
                        <Select {...control} {...form.register(`owners.${i}.kind`)}>
                          {["team", "user", "service", "workload", "vendor"].map((kind) => (
                            <option key={kind} value={kind}>
                              {kind}
                            </option>
                          ))}
                        </Select>
                      )}
                    </Field>
                    <Field label={t("changes.owner.name")} controlId={`owner-name-${i}`}>
                      {(control) => <Input {...control} {...form.register(`owners.${i}.name`)} />}
                    </Field>
                    <Field label={t("changes.owner.applicationId")} controlId={`owner-app-${i}`}>
                      {(control) => <Input {...control} {...form.register(`owners.${i}.application_id`)} />}
                    </Field>
                    <Field label={t("changes.owner.service")} controlId={`owner-service-${i}`}>
                      {(control) => <Input {...control} {...form.register(`owners.${i}.service`)} />}
                    </Field>
                    <Field label={t("changes.owner.environment")} controlId={`owner-env-${i}`}>
                      {(control) => <Input {...control} {...form.register(`owners.${i}.environment`)} />}
                    </Field>
                    <Field label={t("changes.owner.escalation")} controlId={`owner-esc-${i}`}>
                      {(control) => <Input {...control} {...form.register(`owners.${i}.escalation_chain`)} />}
                    </Field>
                    <Button type="button" variant="outline" className="self-end" onClick={() => owners.remove(i)}>
                      {t("changes.action.remove")}
                    </Button>
                  </div>
                ))}
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => owners.append({ key: "", kind: "team", name: "", application_id: "", service: "", environment: "", escalation_chain: "" })}
                >
                  {t("changes.action.add")}
                </Button>
              </section>

              <section className="space-y-3" aria-labelledby="change-profiles">
                <h2 id="change-profiles" className="font-medium">
                  {t("changes.section.profiles")}
                </h2>
                {profiles.fields.map((row, i) => (
                  <div key={row.id} className="grid gap-3 md:grid-cols-[1fr_2fr_auto]">
                    <Field label={t("changes.profile.name")} controlId={`profile-name-${i}`}>
                      {(control) => <Input {...control} {...form.register(`profiles.${i}.name`)} />}
                    </Field>
                    <Field label={t("changes.profile.spec")} controlId={`profile-spec-${i}`}>
                      {(control) => <Textarea {...control} rows={3} {...form.register(`profiles.${i}.spec`)} />}
                    </Field>
                    <Button type="button" variant="outline" className="self-end" onClick={() => profiles.remove(i)}>
                      {t("changes.action.remove")}
                    </Button>
                  </div>
                ))}
                <Button type="button" variant="outline" onClick={() => profiles.append({ name: "", spec: "{}" })}>
                  {t("changes.action.add")}
                </Button>
              </section>

              <section className="space-y-3" aria-labelledby="change-members">
                <h2 id="change-members" className="font-medium">
                  {t("changes.section.members")}
                </h2>
                {members.fields.map((row, i) => (
                  <div key={row.id} className="grid gap-3 md:grid-cols-[1fr_1fr_auto]">
                    <Field label={t("changes.member.subject")} controlId={`member-subject-${i}`}>
                      {(control) => <Input {...control} {...form.register(`members.${i}.subject`)} />}
                    </Field>
                    <Field label={t("changes.member.roles")} controlId={`member-roles-${i}`}>
                      {(control) => <Input {...control} {...form.register(`members.${i}.roles`)} />}
                    </Field>
                    <Button type="button" variant="outline" className="self-end" onClick={() => members.remove(i)}>
                      {t("changes.action.remove")}
                    </Button>
                  </div>
                ))}
                <Button type="button" variant="outline" onClick={() => members.append({ subject: "", roles: "" })}>
                  {t("changes.action.add")}
                </Button>
              </section>

              <section className="space-y-3" aria-labelledby="change-targets">
                <h2 id="change-targets" className="font-medium">
                  {t("changes.section.targets")}
                </h2>
                {targets.fields.map((row, i) => (
                  <div key={row.id} className="grid gap-3 md:grid-cols-4">
                    <Field label={t("changes.target.key")} controlId={`target-key-${i}`}>
                      {(control) => <Input {...control} {...form.register(`targets.${i}.key`)} />}
                    </Field>
                    <Field label={t("changes.target.name")} controlId={`target-name-${i}`}>
                      {(control) => <Input {...control} {...form.register(`targets.${i}.name`)} />}
                    </Field>
                    <Field label={t("changes.target.connector")} controlId={`target-connector-${i}`}>
                      {(control) => <Input {...control} {...form.register(`targets.${i}.connector`)} />}
                    </Field>
                    <Field label={t("changes.target.enabled")} controlId={`target-enabled-${i}`}>
                      {(control) => <input {...control} type="checkbox" {...form.register(`targets.${i}.enabled`)} />}
                    </Field>
                    <Field label={t("changes.target.config")} controlId={`target-config-${i}`}>
                      {(control) => <Textarea {...control} rows={3} {...form.register(`targets.${i}.config`)} />}
                    </Field>
                    <Button type="button" variant="outline" className="self-end" onClick={() => targets.remove(i)}>
                      {t("changes.action.remove")}
                    </Button>
                  </div>
                ))}
                <Button type="button" variant="outline" onClick={() => targets.append({ key: "", name: "", connector: "", config: "{}", enabled: false })}>
                  {t("changes.action.add")}
                </Button>
              </section>
            </div>
          ) : (
            <Field label={t("changes.json.label")} controlId="change-json">
              {(control) => <Textarea {...control} rows={16} value={json} onChange={(event) => setJSON(event.target.value)} />}
            </Field>
          )}

          {"error" in current ? <p className="text-destructive text-sm">{current.error}</p> : null}
          <div className="flex flex-wrap gap-2">
            <Button type="button" disabled={busy || "error" in current} onClick={() => "set" in current && void plan(current.set)}>
              {t("changes.action.plan")}
            </Button>
            <Button type="button" variant="outline" disabled={busy || !reviewed || stale} onClick={() => void apply()}>
              {t("changes.action.apply")}
            </Button>
          </div>
        </CardContent>
      </Card>

      {ai.data?.model_configured ? (
        <Card>
          <CardHeader>
            <CardTitle>{t("changes.action.draft")}</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <p className="text-muted-foreground text-sm">{t("changes.draft.help")}</p>
            <Field label={t("changes.draft.request")} controlId="change-draft">
              {(control) => <Textarea {...control} rows={3} value={draftRequest} onChange={(event) => setDraftRequest(event.target.value)} />}
            </Field>
            <Button type="button" disabled={busy || !draftRequest.trim()} onClick={() => void draft()}>
              {t("changes.action.draft")}
            </Button>
          </CardContent>
        </Card>
      ) : null}

      {message ? <ErrorState title={message} /> : null}

      {reviewed ? (
        <Card>
          <CardHeader>
            <CardTitle>{t("changes.plan.title")}</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {stale ? <p className="text-destructive text-sm">{t("changes.plan.stale")}</p> : null}
            <p className="text-sm">
              {t("changes.plan.summary", {
                changes: reviewed.plan.changes,
                total: reviewed.plan.items.length,
                plan: reviewed.plan.plan_digest,
                intent: reviewed.plan.change_set_digest,
              })}
            </p>
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left">
                  <th>{t("changes.plan.col.object")}</th>
                  <th>{t("changes.plan.col.action")}</th>
                  <th>{t("changes.plan.col.involves")}</th>
                  <th>{t("changes.plan.col.effects")}</th>
                  <th>{t("changes.plan.col.verification")}</th>
                </tr>
              </thead>
              <tbody>
                {reviewed.plan.items.map((item) => (
                  <tr key={`${item.kind}/${item.key}`} className="align-top">
                    <td>
                      {item.kind} {item.key}
                    </td>
                    <td>{item.action}</td>
                    <td>
                      <ul>
                        {[...item.identities, ...item.credentials, ...item.grants, ...item.destinations, ...item.approvals].map((line) => (
                          <li key={line}>{line}</li>
                        ))}
                      </ul>
                    </td>
                    <td>{item.effects.join(", ")}</td>
                    <td>{item.verification}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </CardContent>
        </Card>
      ) : null}

      {applied ? (
        <Card>
          <CardContent className="space-y-3 pt-6">
            <p className="text-sm">{applied.complete ? t("changes.apply.complete") : t("changes.apply.incomplete")}</p>
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left">
                  <th>{t("changes.plan.col.object")}</th>
                  <th>{t("changes.apply.col.outcome")}</th>
                  <th>{t("changes.apply.col.verified")}</th>
                </tr>
              </thead>
              <tbody>
                {applied.results.map((result) => (
                  <tr key={`${result.kind}/${result.key}`}>
                    <td>
                      {result.kind} {result.key}
                    </td>
                    <td>{result.error ? t("changes.apply.outcomeWithError", { outcome: result.outcome, error: result.error }) : result.outcome}</td>
                    <td>{result.verified ? t("changes.apply.verified.yes") : t("changes.apply.verified.no")}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </CardContent>
        </Card>
      ) : null}
    </div>
  );
}
