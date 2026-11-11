import { useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { ErrorState } from "@/components/StatePrimitives";
import { useTranslation } from "@/i18n/I18nProvider";
import { api, type SecretProject, type SecretPromotionPlan, type SecretRestorePlan } from "@/lib/api";
import { apiProblemMessage } from "@/lib/apiProblem";

// A236: promote an environment (or a folder) into another, or restore one to a
// point in time. Both preview a value-free plan first and apply it by its
// digest; a blocked item blocks the whole batch, and a plan that went stale
// is previewed again before anything is written. A promotion into a restricted
// environment waits for its approvers (A236-L1): the panel names the request
// and keeps the reviewed plan to apply again once it is approved.

type Mode = "promote" | "restore";

export function SecretProjectTransfers({ project, onApplied }: { project: SecretProject; onApplied: () => void }) {
  const { t } = useTranslation();
  const envs = (project.environments ?? []).map((env) => env.slug);
  const [mode, setMode] = useState<Mode>("promote");
  const [from, setFrom] = useState(envs[0] ?? "");
  const [to, setTo] = useState(envs[1] ?? envs[0] ?? "");
  const [folder, setFolder] = useState("");
  const [at, setAt] = useState("");
  const [promotion, setPromotion] = useState<SecretPromotionPlan | null>(null);
  const [restore, setRestore] = useState<SecretRestorePlan | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [awaiting, setAwaiting] = useState<string | null>(null);

  const atISO = () => (at ? new Date(at).toISOString() : "");

  async function preview(event?: FormEvent<HTMLFormElement>) {
    event?.preventDefault();
    setAwaiting(null);
    setBusy(true);
    setMessage(null);
    try {
      if (mode === "promote") {
        setPromotion(await api.previewSecretPromotion(project.slug, { from, to, folder: folder.trim() || undefined }));
      } else {
        setRestore(await api.previewSecretRestore(project.slug, { environment: from, folder: folder.trim() || undefined, at: atISO() }));
      }
      setError(null);
    } catch (cause) {
      setError(apiProblemMessage(cause, t("secrets.transfers.previewFailed")));
    } finally {
      setBusy(false);
    }
  }

  async function apply() {
    setBusy(true);
    try {
      const receipt =
        mode === "promote" && promotion
          ? await api.applySecretPromotion(project.slug, { from, to, folder: folder.trim() || undefined, plan_digest: promotion.plan_digest })
          : restore
            ? await api.applySecretRestore(project.slug, {
                environment: from,
                folder: folder.trim() || undefined,
                at: atISO(),
                plan_digest: restore.plan_digest,
              })
            : null;
      setMessage(receipt ? t("secrets.transfers.applied", { count: String(receipt.items.length) }) : null);
      setAwaiting(null);
      setPromotion(null);
      setRestore(null);
      setError(null);
      onApplied();
    } catch (cause) {
      // A stale or blocked plan: preview again so the operator reviews what
      // would happen now, and keep the reason nothing was applied in view.
      const reason = apiProblemMessage(cause, t("secrets.transfers.applyFailed"));
      const pending = /approval_required:\S+ request_id=([0-9a-f-]{36})/.exec(reason);
      if (pending) {
        setError(null);
        setAwaiting(pending[1]);
        return;
      }
      await preview();
      setError(reason);
    } finally {
      setBusy(false);
    }
  }

  const plan = mode === "promote" ? promotion : restore;
  const modeLabel: Record<Mode, string> = { promote: t("secrets.transfers.mode.promote"), restore: t("secrets.transfers.mode.restore") };
  const actionLabel: Record<string, string> = {
    create: t("secrets.transfers.action.create"),
    update: t("secrets.transfers.action.update"),
    restore: t("secrets.transfers.action.restore"),
    unchanged: t("secrets.transfers.action.unchanged"),
    created_since: t("secrets.transfers.action.createdSince"),
    blocked: t("secrets.transfers.action.blocked"),
  };

  return (
    <section aria-labelledby="secret-transfers-heading" className="grid gap-3 border-t border-border pt-3">
      <h4 id="secret-transfers-heading" className="font-semibold">
        {t("secrets.transfers.heading")}
      </h4>
      <div role="group" aria-label={t("secrets.transfers.modeLabel")} className="flex gap-2">
        {(["promote", "restore"] as const).map((value) => (
          <Button
            key={value}
            type="button"
            variant={mode === value ? "default" : "outline"}
            aria-pressed={mode === value}
            onClick={() => {
              setMode(value);
              setPromotion(null);
              setRestore(null);
            }}
          >
            {modeLabel[value]}
          </Button>
        ))}
      </div>
      <form onSubmit={(event) => void preview(event)} className="grid max-w-xl gap-3">
        <Field label={mode === "promote" ? t("secrets.transfers.from") : t("secrets.transfers.environment")}>
          {(control) => (
            <Select {...control} value={from} onChange={(event) => setFrom(event.target.value)}>
              {envs.map((env) => (
                <option key={env} value={env}>
                  {env}
                </option>
              ))}
            </Select>
          )}
        </Field>
        {mode === "promote" ? (
          <Field label={t("secrets.transfers.to")}>
            {(control) => (
              <Select {...control} value={to} onChange={(event) => setTo(event.target.value)}>
                {envs.map((env) => (
                  <option key={env} value={env}>
                    {env}
                  </option>
                ))}
              </Select>
            )}
          </Field>
        ) : (
          <Field label={t("secrets.transfers.at")} description={t("secrets.transfers.atHelp")}>
            {(control) => <Input {...control} type="datetime-local" step="1" value={at} required onChange={(event) => setAt(event.target.value)} />}
          </Field>
        )}
        <Field label={t("secrets.transfers.folder")} description={t("secrets.transfers.folderHelp")}>
          {(control) => <Input {...control} value={folder} maxLength={256} onChange={(event) => setFolder(event.target.value)} />}
        </Field>
        <Button type="submit" variant="outline" disabled={busy || !from || (mode === "promote" ? !to || to === from : !at)}>
          {t("secrets.transfers.preview")}
        </Button>
      </form>
      {error ? <ErrorState title={t("secrets.transfers.error")}>{error}</ErrorState> : null}
      {awaiting ? (
        <p role="status" className="rounded-control border border-border p-3">
          {t("secrets.transfers.awaitingApproval", { request: awaiting })}{" "}
          <Link to="/approvals" className="text-primary underline">
            {t("secrets.transfers.openApprovals")}
          </Link>
        </p>
      ) : null}
      {message ? <p role="status">{message}</p> : null}
      {plan ? (
        <div className="grid gap-2">
          <p>{t("secrets.transfers.summary", { changes: String(plan.changes), blocked: String(plan.blocked) })}</p>
          <ul className="grid gap-1" aria-label={t("secrets.transfers.planLabel")}>
            {mode === "promote" && promotion
              ? promotion.items.map((item) => (
                  <li key={item.key} className="flex flex-wrap gap-2">
                    <span className="font-mono text-xs">{item.key}</span>
                    <span className={item.action === "blocked" ? "font-semibold text-risk-high" : ""}>{actionLabel[item.action] ?? item.action}</span>
                    <span className="text-muted-foreground">
                      {t("secrets.transfers.promoteVersions", {
                        source: String(item.source_version),
                        target: item.target_version ? t("secrets.transfers.version", { version: String(item.target_version) }) : t("secrets.transfers.new"),
                      })}
                    </span>
                    {item.owner_name ? <span>{t("secrets.transfers.takesOwner", { owner: item.owner_name })}</span> : null}
                    {item.reason ? <span className="text-risk-high">{item.reason}</span> : null}
                  </li>
                ))
              : (restore?.items ?? []).map((item) => (
                  <li key={item.name} className="flex flex-wrap gap-2">
                    <span className="font-mono text-xs">{item.name}</span>
                    <span className={item.action === "blocked" ? "font-semibold text-risk-high" : ""}>{actionLabel[item.action] ?? item.action}</span>
                    <span className="text-muted-foreground">
                      {item.restore_version
                        ? t("secrets.transfers.restoreVersions", { current: String(item.current_version), restore: String(item.restore_version) })
                        : t("secrets.transfers.version", { version: String(item.current_version) })}
                    </span>
                    {item.reason ? <span className="text-risk-high">{item.reason}</span> : null}
                  </li>
                ))}
          </ul>
          {mode === "promote" && promotion && promotion.kept.length > 0 ? (
            <p className="text-muted-foreground">{t("secrets.transfers.kept", { names: promotion.kept.join(", ") })}</p>
          ) : null}
          <Button type="button" onClick={() => void apply()} disabled={busy || plan.blocked > 0 || plan.changes === 0}>
            {mode === "promote" ? t("secrets.transfers.applyPromote") : t("secrets.transfers.applyRestore")}
          </Button>
        </div>
      ) : null}
    </section>
  );
}
