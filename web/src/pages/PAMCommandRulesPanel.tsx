import { useState } from "react";
import { zodResolver } from "@hookform/resolvers/zod";
import { useForm, useWatch } from "react-hook-form";
import { z } from "zod";
import { DataGrid } from "@/components/DataGrid";
import { Dialog } from "@/components/Dialog";
import { ErrorState } from "@/components/StatePrimitives";
import { StepShell } from "@/components/wizard/StepShell";
import { Button } from "@/components/ui/button";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { useTranslation } from "@/i18n/I18nProvider";
import { api, type PAMAccessTemplate, type PAMCommandRule } from "@/lib/api";
import { useApiQuery, useQueryClient } from "@/lib/query";

// Operation names are public configuration, never arbitrary shell/SQL tokens.
const postgresOperations = [
  "ALTER",
  "ANALYZE",
  "BEGIN",
  "CALL",
  "CLUSTER",
  "COMMENT",
  "COMMIT",
  "COPY",
  "CREATE",
  "DELETE",
  "DISCARD",
  "DO",
  "DROP",
  "EXPLAIN",
  "GRANT",
  "INSERT",
  "LOCK",
  "MERGE",
  "REFRESH",
  "REINDEX",
  "RESET",
  "REVOKE",
  "ROLLBACK",
  "SELECT",
  "SET",
  "TRUNCATE",
  "UPDATE",
  "VACUUM",
  "WITH",
] as const;
const sshOperations = [
  "bash",
  "chmod",
  "chown",
  "chpasswd",
  "command",
  "dd",
  "env",
  "exec",
  "iptables",
  "kill",
  "mkfs",
  "mount",
  "nft",
  "node",
  "passwd",
  "perl",
  "python",
  "python3",
  "reboot",
  "rm",
  "rmdir",
  "ruby",
  "scp",
  "sftp",
  "sh",
  "ssh",
  "su",
  "sudo",
  "systemctl",
  "umount",
  "useradd",
  "userdel",
] as const;
const mysqlOperations = [
  "ALTER",
  "ANALYZE",
  "BEGIN",
  "CALL",
  "COMMIT",
  "CREATE",
  "DELETE",
  "DO",
  "DROP",
  "EXPLAIN",
  "FLUSH",
  "GRANT",
  "INSERT",
  "KILL",
  "LOCK",
  "OPTIMIZE",
  "RENAME",
  "REPAIR",
  "REPLACE",
  "RESET",
  "REVOKE",
  "ROLLBACK",
  "SELECT",
  "SET",
  "SHOW",
  "START",
  "TRUNCATE",
  "UNLOCK",
  "UPDATE",
  "USE",
] as const;
const redisOperations = [
  "APPEND",
  "DECR",
  "DECRBY",
  "DEL",
  "EVAL",
  "EVALSHA",
  "EXPIRE",
  "FCALL",
  "FCALL_RO",
  "GET",
  "GETDEL",
  "HDEL",
  "HGET",
  "HMGET",
  "HMSET",
  "HSET",
  "INCR",
  "INCRBY",
  "LPOP",
  "LPUSH",
  "MGET",
  "MSET",
  "PERSIST",
  "PEXPIRE",
  "RENAME",
  "RENAMENX",
  "RPOP",
  "RPUSH",
  "SADD",
  "SET",
  "SREM",
  "SISMEMBER",
  "SMEMBERS",
  "TTL",
  "UNLINK",
  "ZADD",
  "ZREM",
] as const;
const mongoOperations = [
  "aggregate",
  "atlasversion",
  "buildinfo",
  "bulkwrite",
  "collmod",
  "collstats",
  "connectionstatus",
  "count",
  "create",
  "createindexes",
  "dbstats",
  "delete",
  "distinct",
  "drop",
  "dropdatabase",
  "dropindexes",
  "endsessions",
  "explain",
  "find",
  "findandmodify",
  "getmore",
  "getparameter",
  "insert",
  "killcursors",
  "listcollections",
  "listdatabases",
  "listindexes",
  "ping",
  "renamecollection",
  "rolesinfo",
  "serverstatus",
  "update",
  "usersinfo",
  "validate",
  "whatsmyuri",
] as const;
const clickhouseOperations = [
  "ALTER",
  "ATTACH",
  "BACKUP",
  "CHECK",
  "CREATE",
  "DELETE",
  "DESCRIBE",
  "DETACH",
  "DROP",
  "EXCHANGE",
  "EXISTS",
  "EXPLAIN",
  "GRANT",
  "INSERT",
  "KILL",
  "MOVE",
  "OPTIMIZE",
  "RENAME",
  "RESTORE",
  "REVOKE",
  "SELECT",
  "SET",
  "SHOW",
  "SYSTEM",
  "TRUNCATE",
  "UNDROP",
  "UPDATE",
  "USE",
  "WITH",
] as const;
// Network device command verbs (A270); an abbreviation names every verb it starts.
const netdeviceOperations = [
  "bash",
  "clear",
  "commit",
  "configure",
  "copy",
  "create",
  "debug",
  "delete",
  "diagnose",
  "erase",
  "execute",
  "format",
  "load",
  "modify",
  "no",
  "reload",
  "request",
  "restart",
  "rollback",
  "run",
  "save",
  "set",
  "start",
  "write",
] as const;
const operationChoices = {
  postgres: postgresOperations,
  ssh: sshOperations,
  mysql: mysqlOperations,
  redis: redisOperations,
  mongodb: mongoOperations,
  clickhouse: clickhouseOperations,
  netdevice: netdeviceOperations,
};
const operations = [
  ...postgresOperations,
  ...sshOperations,
  ...mysqlOperations,
  ...redisOperations,
  ...mongoOperations,
  ...clickhouseOperations,
  ...netdeviceOperations,
] as const;
const schema = z
  .object({
    protocol: z.enum(["postgres", "ssh", "mysql", "redis", "mongodb", "clickhouse", "netdevice"]),
    templateID: z.string().uuid(),
    name: z.string().trim().min(1).max(80),
    operations: z.array(z.enum(operations)).min(1).max(32),
    effect: z.enum(["block", "require_approval", "alert"]),
    severity: z.enum(["warning", "critical"]),
    enabled: z.boolean(),
    quorum: z.coerce.number().int().min(1).max(3),
    ttl: z.coerce.number().int().min(5).max(45),
  })
  .refine((v) => v.operations.every((op) => (operationChoices[v.protocol] as readonly string[]).includes(op)), {
    path: ["operations"],
  });
type Form = z.input<typeof schema>;
type Values = z.output<typeof schema>;
type Saved = { template: PAMAccessTemplate; rule: PAMCommandRule };
const defaults: Form = {
  protocol: "postgres",
  templateID: "",
  name: "",
  operations: ["DROP"],
  effect: "block",
  severity: "warning",
  enabled: true,
  quorum: 2,
  ttl: 30,
};

/** A template edit affects new sessions. Existing sessions keep their reviewed snapshot. */
export function PAMCommandRulesPanel({ canManage }: { canManage: boolean }) {
  const { t } = useTranslation();
  const cache = useQueryClient();
  const templates = useApiQuery(["pam-templates"], api.pamTemplates, { retry: false });
  const [open, setOpen] = useState(false);
  const [step, setStep] = useState(0);
  const [base, setBase] = useState<PAMAccessTemplate | null>(null);
  const [editing, setEditing] = useState<string | null>(null);
  const [ruleID, setRuleID] = useState<string>(() => crypto.randomUUID());
  const [saveKey, setSaveKey] = useState<string>(() => crypto.randomUUID());
  const [review, setReview] = useState<PAMCommandRule | null>(null);
  const [removing, setRemoving] = useState<Saved | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const {
    register,
    setValue,
    reset,
    trigger,
    getValues,
    control,
    formState: { errors },
  } = useForm<Form, unknown, Values>({ resolver: zodResolver(schema), defaultValues: defaults });
  const protocol = useWatch({ control, name: "protocol" });
  const effect = useWatch({ control, name: "effect" });
  const rows: Saved[] = (templates.data?.items ?? []).flatMap((template) => (template.command_rules ?? []).map((rule) => ({ template, rule })));
  const begin = (row?: Saved) => {
    setError(null);
    setNotice(null);
    setStep(0);
    setReview(null);
    setEditing(row?.rule.id ?? null);
    setRuleID(row?.rule.id ?? crypto.randomUUID());
    setSaveKey(crypto.randomUUID());
    setBase(row?.template ?? null);
    reset(
      row
        ? {
            protocol: row.rule.protocol,
            templateID: row.template.id,
            name: row.rule.name,
            operations: row.rule.operations as Values["operations"],
            effect: row.rule.effect,
            severity: row.rule.severity ?? "warning",
            enabled: row.rule.enabled,
            quorum: row.rule.required_approvals ?? 2,
            ttl: row.rule.review_ttl_seconds ?? 30,
          }
        : defaults,
    );
    setOpen(true);
  };
  const next = async () => {
    if (step === 0) {
      if (!(await trigger(["templateID", "name"]))) return;
      const selected = templates.data?.items.find((item) => item.id === getValues("templateID"));
      if (!selected) return;
      setBase(selected);
      setStep(1);
      return;
    }
    const result = schema.safeParse(getValues());
    if (!result.success) {
      await trigger();
      return;
    }
    const v = result.data;
    setReview({
      id: ruleID,
      name: v.name,
      enabled: v.enabled,
      protocol: v.protocol,
      operations: v.operations,
      effect: v.effect,
      ...(v.effect === "require_approval" ? { required_approvals: v.quorum, review_ttl_seconds: v.ttl } : {}),
      ...(v.effect === "alert" ? { severity: v.severity } : {}),
    });
    setStep(2);
  };
  const replace = async (template: PAMAccessTemplate, rules: PAMCommandRule[]) => {
    const updated = await api.updatePAMTemplate(template.id, { ...template, command_rules: rules }, saveKey);
    cache.setQueryData<{ items: PAMAccessTemplate[] }>(["pam-templates"], (current) => ({
      items: (current?.items ?? []).map((item) => (item.id === updated.id ? updated : item)),
    }));
    await cache.invalidateQueries({ queryKey: ["pam-templates"] });
  };
  const save = async () => {
    if (!base || !review) return;
    setBusy(true);
    setError(null);
    try {
      const rules = base.command_rules ?? [];
      await replace(base, editing ? rules.map((rule) => (rule.id === editing ? review : rule)) : [...rules, review]);
      setOpen(false);
      setNotice(t("admin.access.rules.saved"));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };
  const remove = async () => {
    if (!removing) return;
    setBusy(true);
    setError(null);
    try {
      await replace(
        removing.template,
        (removing.template.command_rules ?? []).filter((rule) => rule.id !== removing.rule.id),
      );
      setRemoving(null);
      setNotice(t("admin.access.rules.saved"));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };
  const invalid = t("admin.access.rules.invalid");
  return (
    <section className="grid gap-4" aria-labelledby="pam-command-rules-heading">
      <h3 id="pam-command-rules-heading" className="text-body font-semibold">
        {t("admin.access.rules.heading")}
      </h3>
      <p className="text-caption text-muted-foreground">{t("admin.access.rules.help")}</p>
      {error && !open && !removing ? (
        <ErrorState title={t("admin.access.rules.failed")}>
          <p>{error}</p>
        </ErrorState>
      ) : null}
      {notice ? <p role="status">{notice}</p> : null}
      <DataGrid<Saved>
        ariaLabel={t("admin.access.rules.savedRules")}
        rows={rows}
        getRowId={(r) => r.template.id + ":" + r.rule.id}
        state={templates.error ? "error" : templates.loading ? "loading" : "ready"}
        columns={[
          { id: "template", header: t("admin.access.folders.template"), cell: (r) => r.template.name },
          { id: "name", header: t("admin.access.rules.name"), cell: (r) => r.rule.name },
          { id: "protocol", header: t("admin.access.rules.protocol"), cell: (r) => r.rule.protocol },
          { id: "operations", header: t("admin.access.rules.operations"), cell: (r) => r.rule.operations.join(", ") },
          {
            id: "effect",
            header: t("admin.access.rules.effect"),
            cell: (r) => (
              <span>
                {t(
                  r.rule.enabled
                    ? r.rule.effect === "block"
                      ? "admin.access.rules.block"
                      : r.rule.effect === "alert"
                        ? "admin.access.rules.alert"
                        : "admin.access.rules.requireReview"
                    : "admin.access.rules.disabled",
                )}
                {r.rule.effect === "alert" ? t(r.rule.severity === "critical" ? "admin.access.rules.alertCritical" : "admin.access.rules.alertWarning") : null}
                {r.rule.effect === "require_approval"
                  ? t("admin.access.rules.reviewLimits", { count: r.rule.required_approvals ?? 0, seconds: r.rule.review_ttl_seconds ?? 0 })
                  : null}
              </span>
            ),
          },
          {
            id: "actions",
            header: t("admin.access.targetAction"),
            cell: (r) =>
              canManage ? (
                <div className="flex gap-2">
                  <Button type="button" variant="outline" size="sm" onClick={() => begin(r)}>
                    {t("admin.access.folders.edit")}
                  </Button>
                  <Button
                    type="button"
                    variant="destructive-outline"
                    size="sm"
                    onClick={() => {
                      setRemoving(r);
                      setError(null);
                      setSaveKey(crypto.randomUUID());
                    }}
                  >
                    {t("admin.access.folders.delete")}
                  </Button>
                </div>
              ) : null,
          },
        ]}
      />
      {canManage ? (
        <Button type="button" className="w-fit" disabled={templates.loading || !!templates.error || !templates.data?.items.length} onClick={() => begin()}>
          {t("admin.access.rules.add")}
        </Button>
      ) : null}
      <Dialog
        open={open}
        onClose={() => {
          if (!busy) setOpen(false);
        }}
        titleId="pam-command-edit-heading"
      >
        <h3 id="pam-command-edit-heading" className="text-title">
          {t("admin.access.rules.heading")}
        </h3>
        {error ? (
          <ErrorState title={t("admin.access.rules.failed")}>
            <p>{error}</p>
          </ErrorState>
        ) : null}
        <StepShell
          currentIndex={step}
          steps={[
            { id: "scope", label: t("admin.access.rules.scopeStep"), description: t("admin.access.rules.scopeHelp") },
            { id: "rule", label: t("admin.access.rules.ruleStep"), description: t("admin.access.rules.ruleHelp") },
            { id: "review", label: t("admin.access.rules.reviewStep"), description: t("admin.access.rules.reviewHelp") },
          ]}
          onPrevious={step > 0 ? () => setStep(step - 1) : undefined}
          onNext={step < 2 ? () => void next() : undefined}
        >
          {step === 0 ? (
            <div className="grid gap-3">
              <Field label={t("admin.access.folders.template")} required error={errors.templateID ? invalid : undefined}>
                {(control) => (
                  <Select {...control} {...register("templateID")} disabled={editing !== null}>
                    <option value="" disabled>
                      {t("admin.access.folders.selectTemplate")}
                    </option>
                    {templates.data?.items.map((item) => (
                      <option key={item.id} value={item.id}>
                        {item.name}
                      </option>
                    ))}
                  </Select>
                )}
              </Field>
              <Field label={t("admin.access.rules.name")} required error={errors.name ? invalid : undefined}>
                {(control) => <Input {...control} {...register("name")} />}
              </Field>
              <Field label={t("admin.access.rules.protocol")}>
                {(control) => (
                  <Select
                    {...control}
                    {...register("protocol", {
                      onChange: (event) =>
                        setValue("operations", [
                          event.target.value === "ssh"
                            ? "rm"
                            : event.target.value === "redis"
                              ? "DEL"
                              : event.target.value === "mongodb"
                                ? "delete"
                                : event.target.value === "netdevice"
                                  ? "write"
                                  : "DROP",
                        ]),
                    })}
                  >
                    <option value="postgres">{t("admin.access.postgresql")}</option>
                    <option value="ssh">{t("admin.access.ssh")}</option>
                    <option value="mysql">{t("admin.access.rules.mysql")}</option>
                    <option value="redis">{t("admin.access.rules.redis")}</option>
                    <option value="mongodb">{t("admin.access.rules.mongodb")}</option>
                    <option value="clickhouse">{t("admin.access.rules.clickhouse")}</option>
                    <option value="netdevice">{t("admin.access.rules.netdevice")}</option>
                  </Select>
                )}
              </Field>
              <p>{t("admin.access.rules.protocolHelp")}</p>
            </div>
          ) : step === 1 ? (
            <div className="grid gap-3">
              <Field
                label={t("admin.access.rules.operations")}
                required
                description={t("admin.access.rules.operationsHelp")}
                error={errors.operations ? invalid : undefined}
              >
                {(control) => (
                  <Select {...control} multiple {...register("operations")}>
                    {operationChoices[protocol].map((op) => (
                      <option key={op} value={op}>
                        {op}
                      </option>
                    ))}
                  </Select>
                )}
              </Field>
              <Field label={t("admin.access.rules.effect")} required>
                {(control) => (
                  <Select
                    {...control}
                    {...register("effect", {
                      onChange: (event) => {
                        if (event.target.value === "block") {
                          setValue("quorum", 2);
                          setValue("ttl", 30);
                        }
                      },
                    })}
                  >
                    <option value="block">{t("admin.access.rules.block")}</option>
                    <option value="require_approval">{t("admin.access.rules.requireReview")}</option>
                    <option value="alert">{t("admin.access.rules.alert")}</option>
                  </Select>
                )}
              </Field>
              {effect === "alert" ? (
                <Field label={t("admin.access.rules.severity")} description={t("admin.access.rules.alertHelp")} required>
                  {(control) => (
                    <Select {...control} {...register("severity")}>
                      <option value="warning">{t("admin.access.rules.severityWarning")}</option>
                      <option value="critical">{t("admin.access.rules.severityCritical")}</option>
                    </Select>
                  )}
                </Field>
              ) : null}
              <Field label={t("admin.access.rules.enabled")}>{(control) => <Input {...control} type="checkbox" {...register("enabled")} />}</Field>
              {effect === "require_approval" ? (
                <>
                  <Field label={t("admin.access.rules.quorum")} description={t("admin.access.rules.quorumHelp")} error={errors.quorum ? invalid : undefined}>
                    {(control) => <Input {...control} type="number" min={1} max={3} {...register("quorum")} />}
                  </Field>
                  <Field
                    label={t("admin.access.rules.reviewSeconds")}
                    description={t("admin.access.rules.secondsHelp")}
                    error={errors.ttl ? invalid : undefined}
                  >
                    {(control) => <Input {...control} type="number" min={5} max={45} {...register("ttl")} />}
                  </Field>
                </>
              ) : null}
            </div>
          ) : (
            <div className="grid gap-3">
              <p>{t("admin.access.rules.newSessions")}</p>
              <p>{t("admin.access.rules.privacy")}</p>
              <p>{t("admin.access.rules.bypass")}</p>
              <details open>
                <summary>{t("admin.access.rules.exactEdit")}</summary>
                <pre className="whitespace-pre-wrap break-all text-caption">
                  {JSON.stringify({ template_id: base?.id, revision: base?.revision, rule: review }, null, 2)}
                </pre>
              </details>
              <Button type="button" loading={busy} onClick={() => void save()}>
                {t("admin.access.rules.save")}
              </Button>
            </div>
          )}
        </StepShell>
      </Dialog>
      <Dialog
        open={removing !== null}
        onClose={() => {
          if (!busy) setRemoving(null);
        }}
        titleId="pam-command-remove-heading"
      >
        <h3 id="pam-command-remove-heading" className="text-title">
          {t("admin.access.rules.removeHeading")}
        </h3>
        <p>{t("admin.access.rules.removeHelp", { name: removing?.rule.name ?? "" })}</p>
        {error ? (
          <ErrorState title={t("admin.access.rules.failed")}>
            <p>{error}</p>
          </ErrorState>
        ) : null}
        <Button type="button" variant="destructive" loading={busy} onClick={() => void remove()}>
          {t("admin.access.folders.delete")}
        </Button>
      </Dialog>
    </section>
  );
}
