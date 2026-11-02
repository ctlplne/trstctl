import { useCallback, useEffect, useState, type FormEvent } from "react";
import { Button } from "@/components/ui/button";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { ErrorState } from "@/components/StatePrimitives";
import { useCan } from "@/components/rbac";
import { formatDateTime } from "@/i18n/format";
import { useTranslation } from "@/i18n/I18nProvider";
import { api, type SecretScopedSync, type SecretScopedSyncPlan } from "@/lib/api";
import { apiProblemMessage } from "@/lib/apiProblem";

// A237: scoped secret sync. A definition keeps every secret under a source
// prefix in step with a KV v2 destination. The plan is value-free: each
// destination key with its action. Keys the sync didn't write are never
// touched unless the reviewed delete scope includes them. Auto definitions are
// applied by the control plane when their sources change; manual ones wait for
// a reviewed apply here.

type DeleteScope = "none" | "managed" | "prefix";

export function ScopedSyncsWorkflow({ targets }: { targets: string[] }) {
  const { t } = useTranslation();
  const canWrite = useCan("secrets:write");
  const [syncs, setSyncs] = useState<SecretScopedSync[]>([]);
  const [selected, setSelected] = useState<SecretScopedSync | null>(null);
  const [plan, setPlan] = useState<SecretScopedSyncPlan | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [name, setName] = useState("");
  const [source, setSource] = useState("");
  const [target, setTarget] = useState(targets[0] ?? "");
  const [destination, setDestination] = useState("");
  const [deleteScope, setDeleteScope] = useState<DeleteScope>("none");
  const [auto, setAuto] = useState(false);

  const refresh = useCallback(async () => {
    try {
      setSyncs((await api.listSecretScopedSyncs()).items);
      setError(null);
    } catch (cause) {
      setError(apiProblemMessage(cause, t("secrets.scopedSyncs.readFailed")));
    }
  }, [t]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  useEffect(() => {
    if (!target && targets[0]) setTarget(targets[0]);
  }, [target, targets]);

  async function open(id: string) {
    try {
      setSelected(await api.getSecretScopedSync(id));
      setPlan(null);
      setMessage(null);
      setError(null);
    } catch (cause) {
      setError(apiProblemMessage(cause, t("secrets.scopedSyncs.readFailed")));
    }
  }

  async function define(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    try {
      const created = await api.defineSecretScopedSync({
        name: name.trim(),
        source_prefix: source.trim(),
        target,
        destination_prefix: destination.trim() || undefined,
        delete_scope: deleteScope,
        mode: auto ? "auto" : "manual",
      });
      setName("");
      setSource("");
      setDestination("");
      setSelected(created);
      setPlan(null);
      setError(null);
      await refresh();
    } catch (cause) {
      setError(apiProblemMessage(cause, t("secrets.scopedSyncs.defineFailed")));
    } finally {
      setBusy(false);
    }
  }

  async function preview() {
    if (!selected) return;
    setBusy(true);
    try {
      setPlan(await api.previewSecretScopedSync(selected.id));
      setMessage(null);
      setError(null);
    } catch (cause) {
      setError(apiProblemMessage(cause, t("secrets.scopedSyncs.previewFailed")));
    } finally {
      setBusy(false);
    }
  }

  async function apply() {
    if (!selected || !plan) return;
    setBusy(true);
    try {
      const receipt = await api.applySecretScopedSync(selected.id, { plan_digest: plan.plan_digest });
      setMessage(t("secrets.scopedSyncs.applied", { writes: String(receipt.writes.length), deletes: String(receipt.deletes.length) }));
      setPlan(null);
      setError(null);
      setSelected(await api.getSecretScopedSync(selected.id));
    } catch (cause) {
      const reason = apiProblemMessage(cause, t("secrets.scopedSyncs.applyFailed"));
      await preview();
      setError(reason);
    } finally {
      setBusy(false);
    }
  }

  async function switchMode() {
    if (!selected) return;
    setBusy(true);
    try {
      setSelected(await api.setSecretScopedSyncMode(selected.id, { mode: selected.mode === "auto" ? "manual" : "auto" }));
      setError(null);
      await refresh();
    } catch (cause) {
      setError(apiProblemMessage(cause, t("secrets.scopedSyncs.modeFailed")));
    } finally {
      setBusy(false);
    }
  }

  const actionLabel: Record<string, string> = {
    create: t("secrets.scopedSyncs.action.create"),
    update: t("secrets.scopedSyncs.action.update"),
    unchanged: t("secrets.scopedSyncs.action.unchanged"),
    delete: t("secrets.scopedSyncs.action.delete"),
    deleting: t("secrets.scopedSyncs.action.deleting"),
    orphaned: t("secrets.scopedSyncs.action.orphaned"),
    unmanaged: t("secrets.scopedSyncs.action.unmanaged"),
    blocked: t("secrets.scopedSyncs.action.blocked"),
  };
  const modeLabel = (mode: string) => (mode === "auto" ? t("secrets.scopedSyncs.mode.auto") : t("secrets.scopedSyncs.mode.manual"));

  return (
    <section aria-labelledby="scoped-syncs-heading" className="grid gap-4 border-t border-border pt-4">
      <div>
        <h3 id="scoped-syncs-heading" className="font-semibold">
          {t("secrets.scopedSyncs.heading")}
        </h3>
        <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{t("secrets.scopedSyncs.description")}</p>
      </div>
      {error ? <ErrorState title={t("secrets.scopedSyncs.error")}>{error}</ErrorState> : null}
      {message ? <p role="status">{message}</p> : null}
      {syncs.length === 0 ? (
        <p className="text-sm text-muted-foreground">{t("secrets.scopedSyncs.empty")}</p>
      ) : (
        <ul className="grid gap-2" aria-label={t("secrets.scopedSyncs.listLabel")}>
          {syncs.map((sync) => (
            <li key={sync.id} className="flex flex-wrap items-center justify-between gap-2 rounded-control border border-border p-3 text-sm">
              <span>
                <strong>{sync.name}</strong>{" "}
                <span className="font-mono text-xs text-muted-foreground">
                  {t("secrets.scopedSyncs.route", { source: sync.source_prefix, target: sync.target, destination: sync.destination_prefix ?? "" })}
                </span>
              </span>
              <span className="rounded-control border border-border px-2 py-0.5 text-xs">{modeLabel(sync.mode)}</span>
              <Button type="button" variant="outline" onClick={() => void open(sync.id)}>
                {t("secrets.scopedSyncs.open")}
              </Button>
            </li>
          ))}
        </ul>
      )}

      {selected ? (
        <article aria-labelledby="scoped-sync-detail" className="ui-panel grid gap-3 p-comfortable text-sm">
          <h4 id="scoped-sync-detail" className="font-semibold">
            {selected.name}
          </h4>
          <p>{t("secrets.scopedSyncs.modeIs", { mode: modeLabel(selected.mode) })}</p>
          {selected.reconcile_status ? (
            <p
              className={
                selected.reconcile_status === "blocked" || selected.reconcile_status === "failed" ? "font-semibold text-risk-high" : "text-muted-foreground"
              }
            >
              {t("secrets.scopedSyncs.lastReconcile", {
                status: selected.reconcile_status,
                reason: selected.reconcile_reason ?? "",
                at: selected.last_reconcile_at ? formatDateTime(selected.last_reconcile_at) : "",
              })}
            </p>
          ) : null}
          {(selected.keys ?? []).length > 0 ? (
            <ul className="grid gap-1" aria-label={t("secrets.scopedSyncs.keysLabel")}>
              {(selected.keys ?? []).map((key) => (
                <li key={key.key} className="flex flex-wrap gap-2">
                  <span className="font-mono text-xs">{key.key}</span>
                  <span className="text-muted-foreground">{key.job_status ?? key.state}</span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-muted-foreground">{t("secrets.scopedSyncs.noKeys")}</p>
          )}
          <div className="flex flex-wrap gap-2">
            <Button type="button" variant="outline" onClick={() => void preview()} disabled={busy}>
              {t("secrets.scopedSyncs.preview")}
            </Button>
            {canWrite ? (
              <Button type="button" variant="outline" onClick={() => void switchMode()} disabled={busy}>
                {selected.mode === "auto" ? t("secrets.scopedSyncs.toManual") : t("secrets.scopedSyncs.toAuto")}
              </Button>
            ) : null}
          </div>
          {plan ? (
            <div className="grid gap-2">
              <p>{t("secrets.scopedSyncs.summary", { changes: String(plan.changes), blocked: String(plan.blocked) })}</p>
              <ul className="grid gap-1" aria-label={t("secrets.scopedSyncs.planLabel")}>
                {plan.items.map((item) => (
                  <li key={item.key} className="flex flex-wrap gap-2">
                    <span className="font-mono text-xs">{item.key}</span>
                    <span className={item.action === "blocked" ? "font-semibold text-risk-high" : ""}>{actionLabel[item.action] ?? item.action}</span>
                    {item.reason ? <span className="text-muted-foreground">{item.reason}</span> : null}
                  </li>
                ))}
              </ul>
              {canWrite ? (
                <Button type="button" onClick={() => void apply()} disabled={busy || plan.blocked > 0 || plan.changes === 0}>
                  {t("secrets.scopedSyncs.apply")}
                </Button>
              ) : null}
            </div>
          ) : null}
        </article>
      ) : null}

      {canWrite ? (
        <form onSubmit={(event) => void define(event)} className="grid max-w-xl gap-3" aria-label={t("secrets.scopedSyncs.defineLabel")}>
          <Field label={t("secrets.scopedSyncs.name")}>
            {(control) => <Input {...control} value={name} maxLength={63} required onChange={(event) => setName(event.target.value)} />}
          </Field>
          <Field label={t("secrets.scopedSyncs.source")} description={t("secrets.scopedSyncs.sourceHelp")}>
            {(control) => <Input {...control} value={source} required onChange={(event) => setSource(event.target.value)} />}
          </Field>
          <Field label={t("secrets.scopedSyncs.target")}>
            {(control) => (
              <Select {...control} value={target} required onChange={(event) => setTarget(event.target.value)}>
                {targets.map((id) => (
                  <option key={id} value={id}>
                    {id}
                  </option>
                ))}
              </Select>
            )}
          </Field>
          <Field label={t("secrets.scopedSyncs.destination")}>
            {(control) => <Input {...control} value={destination} onChange={(event) => setDestination(event.target.value)} />}
          </Field>
          <Field label={t("secrets.scopedSyncs.deleteScope")} description={t("secrets.scopedSyncs.deleteScopeHelp")}>
            {(control) => (
              <Select {...control} value={deleteScope} onChange={(event) => setDeleteScope(event.target.value as DeleteScope)}>
                <option value="none">{t("secrets.scopedSyncs.scope.none")}</option>
                <option value="managed">{t("secrets.scopedSyncs.scope.managed")}</option>
                <option value="prefix">{t("secrets.scopedSyncs.scope.prefix")}</option>
              </Select>
            )}
          </Field>
          <label className="flex items-center gap-2">
            <input type="checkbox" checked={auto} onChange={(event) => setAuto(event.target.checked)} />
            {t("secrets.scopedSyncs.autoLabel")}
          </label>
          <Button type="submit" disabled={busy || !name.trim() || !source.trim() || !target}>
            {t("secrets.scopedSyncs.define")}
          </Button>
        </form>
      ) : null}
    </section>
  );
}
