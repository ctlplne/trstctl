import { useRef, useState } from "react";
import { useForm, useWatch } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { api, type PAMServiceDependentRotationView } from "@/lib/api";
import { useApiQuery, useQueryClient } from "@/lib/query";
import { useTranslation } from "@/i18n/I18nProvider";
import { Dialog } from "@/components/Dialog";
import { CredentialChip } from "@/components/CredentialChip";
import { Button } from "@/components/ui/button";
import { Field } from "@/components/ui/field";
import { Textarea } from "@/components/ui/textarea";
import { ErrorState, LoadingState } from "@/components/StatePrimitives";

export function PAMDependentRecovery({ id, stepID, intentDigest }: { id: string; stepID: string; intentDigest: string }) {
  const { t } = useTranslation();
  const client = useQueryClient();
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const keys = useRef(new Map<string, string>());
  const review = useApiQuery(["pam-dependent-recovery", id, stepID], () => api.previewPAMServiceDependentRecovery(id, stepID), { enabled: open, retry: false });
  const schema = z.object({
    reason: z.string().trim().min(1, t("admin.access.rotation.required")).max(4096),
    acknowledge: z.boolean().refine((v) => v, t("admin.access.rotation.required")),
  });
  const form = useForm<z.infer<typeof schema>>({ resolver: zodResolver(schema), defaultValues: { reason: "", acknowledge: false } });
  const reason = useWatch({ control: form.control, name: "reason" });
  const acknowledged = useWatch({ control: form.control, name: "acknowledge" });
  const value = review.data;
  const exact = !!value && value.previous_step.step_id === stepID && value.intent_digest === intentDigest && value.previous_step.direction === "inverse";
  async function queue(values: z.infer<typeof schema>) {
    if (!value || !exact || review.fetching || review.error || busy) return;
    const input = {
      step_id: stepID,
      intent_digest: value.intent_digest,
      recovery_digest: value.recovery_digest,
      reason: values.reason,
      acknowledge_original_outcome: values.acknowledge,
    };
    const serialized = JSON.stringify(input);
    if (!keys.current.has(serialized)) keys.current.set(serialized, crypto.randomUUID());
    setBusy(true);
    setError(null);
    try {
      await api.queuePAMServiceDependentRecovery(id, input, keys.current.get(serialized)!);
      client.setQueryData<PAMServiceDependentRotationView>(["pam-dependent-rotation", id], (old) => (old ? { ...old, recovery_step_id: undefined } : old));
      await Promise.all([
        client.invalidateQueries({ queryKey: ["pam-dependent-rotation", id] }),
        client.invalidateQueries({ queryKey: ["pam-dependent-steps", id] }),
      ]);
      setOpen(false);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }
  return (
    <>
      <Button
        type="button"
        variant="outline"
        onClick={() => {
          form.reset();
          setError(null);
          setOpen(true);
        }}
      >
        {t("admin.access.rotation.recovery.open")}
      </Button>
      <Dialog
        open={open}
        onClose={() => {
          if (!busy) setOpen(false);
        }}
        titleId="dependent-recovery-title"
        descriptionId="dependent-recovery-help"
        panelClassName="relative mx-auto mt-8 max-h-[85vh] max-w-3xl overflow-auto rounded-lg border border-border bg-card p-6 shadow-lg"
      >
        <h3 id="dependent-recovery-title" className="text-title font-semibold">
          {t("admin.access.rotation.recovery.open")}
        </h3>
        <p id="dependent-recovery-help">{t("admin.access.rotation.recovery.help")}</p>
        {review.loading ? <LoadingState>{t("admin.access.dependents.loading")}</LoadingState> : null}
        {review.error ? (
          <ErrorState title={review.error}>
            <Button type="button" onClick={review.refetch}>
              {t("admin.access.dependents.retry")}
            </Button>
          </ErrorState>
        ) : null}
        {value && !exact ? <ErrorState title={t("admin.access.rotation.recovery.changed")} /> : null}
        {error ? <ErrorState title={error} /> : null}
        {value && exact ? (
          <div className="my-4 grid gap-3">
            <p>
              {t("admin.access.rotation.recovery.effect", {
                direction: value.previous_step.direction,
                action: value.previous_step.action,
                family: value.previous_step.ref.family,
                name: value.previous_step.ref.name,
                agent: value.previous_step.ref.agent_id,
                status: value.previous_status,
              })}
            </p>
            <CredentialChip value={value.previous_step.account_sid} fullValue />
            <p>{t("admin.access.rotation.recovery.versions", { current: value.current_vault_version, retained: value.retained_generation_version })}</p>
            <CredentialChip value={value.recovery_digest} fullValue />
            <details open>
              <summary>{t("admin.access.rotation.recovery.exact")}</summary>
              <pre className="overflow-auto whitespace-pre-wrap text-xs">{JSON.stringify(value, null, 2)}</pre>
            </details>
            <form onSubmit={(event) => void form.handleSubmit(queue)(event)} className="grid gap-3">
              <Field label={t("admin.access.rotation.recovery.reason")} required error={form.formState.errors.reason?.message}>
                {(control) => <Textarea {...control} {...form.register("reason")} disabled={busy} />}
              </Field>
              <label className="flex items-start gap-2">
                <input type="checkbox" {...form.register("acknowledge")} disabled={busy} />
                <span>{t("admin.access.rotation.recovery.ack")}</span>
              </label>
              <Button
                type="submit"
                loading={busy}
                disabled={busy || review.fetching || !!review.error || !acknowledged || !reason.trim() || reason.trim().length > 4096}
              >
                {t("admin.access.rotation.recovery.queue")}
              </Button>
            </form>
          </div>
        ) : null}
        <Button type="button" variant="outline" disabled={busy} onClick={() => setOpen(false)}>
          {t("admin.access.rotation.recovery.close")}
        </Button>
      </Dialog>
    </>
  );
}
