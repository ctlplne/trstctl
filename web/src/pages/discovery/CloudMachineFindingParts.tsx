import { CloudChangeIntent } from "./CloudChangeIntent";
import { useRef, useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { useForm, useWatch } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { CredentialChip } from "@/components/CredentialChip";
import { ErrorState, LoadingState } from "@/components/StatePrimitives";
import { Button } from "@/components/ui/button";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { StepShell } from "@/components/wizard/StepShell";
import { useTranslation } from "@/i18n/I18nProvider";
import type { DiscoveryFinding } from "@/lib/api";
import type { CloudMachineChange, CloudMachineChangeRequest } from "@/lib/api-types.gen";
import { newIdempotencyKey } from "@/lib/apiTransport";
import { cloudChangesKey, executeCloudMachineChange, listCloudMachineChanges, proposeCloudMachineChange } from "@/lib/cloudMachineApi";
import { useApiQuery, useQueryClient } from "@/lib/query";

const metadataSchema = z.object({
  version: z.literal(1),
  collected_at: z.string(),
  source_origin: z.string().optional(),
  identity: z.object({ native_id: z.string().optional(), principal: z.object({ arn: z.string() }) }),
  keys: z
    .array(
      z.object({
        key: z.object({ id: z.string(), status: z.string(), created_at: z.string(), last_used_at: z.string().optional(), last_use_coverage: z.string() }),
        long_lived: z.boolean(),
        stale: z.boolean(),
      }),
    )
    .nullable(),
  evaluations: z.array(
    z.object({
      check: z.object({ action: z.string(), resource: z.string() }),
      result: z.object({ decision: z.string(), reasons: z.array(z.object({ source: z.string(), detail: z.string() })) }),
      unused_in_covered_window: z.boolean(),
      activity_coverage: z.string(),
      observed_uses: z.number(),
      resource_unbound_uses: z.number(),
    }),
  ),
  self_escalation_candidates: z.array(z.object({ action: z.string(), resource: z.string(), reason: z.string(), confidence: z.string() })).nullable(),
  limitations: z.array(z.string()).nullable(),
});
type Captured = z.infer<typeof metadataSchema>;
const formSchema = z.object({
  target: z.string().min(1),
  writer: z
    .string()
    .trim()
    .regex(/^env:[A-Za-z_][A-Za-z0-9_]*$/),
  reason: z.string().trim().min(1).max(500),
  required: z.coerce.number().int().min(1).max(5),
});
type FormValues = z.input<typeof formSchema>;

export function CloudMachineFindingParts({ finding }: { finding: DiscoveryFinding }) {
  const { t } = useTranslation();
  if (finding.kind !== "cloud_machine_entitlement") return null;
  const parsed = metadataSchema.safeParse(finding.metadata);
  if (!parsed.success) return <ErrorState title={t("discovery.machine.evidenceUnavailable")}>{t("discovery.machine.rescan")}</ErrorState>;
  return <CloudMachineFinding key={finding.id} finding={finding} value={parsed.data} />;
}
function CloudMachineFinding({ finding, value }: { finding: DiscoveryFinding; value: Captured }) {
  const { t } = useTranslation();
  return (
    <Card>
      <CardHeader>
        <CardTitle>{t("discovery.machine.findingHeading")}</CardTitle>
      </CardHeader>
      <CardContent className="grid gap-4">
        <CredentialChip value={value.identity.principal.arn} fullValue />
        <p className="text-sm text-muted-foreground">{t("discovery.machine.snapshot", { at: value.collected_at })}</p>
        <p className="text-sm text-muted-foreground">{t("discovery.machine.modelLimit")}</p>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr>
                <th>{t("discovery.machine.action")}</th>
                <th>{t("discovery.machine.resource")}</th>
                <th>{t("discovery.machine.decision")}</th>
                <th>{t("discovery.machine.activity")}</th>
              </tr>
            </thead>
            <tbody>
              {value.evaluations.map((item, index) => (
                <tr key={index}>
                  <td>{item.check.action}</td>
                  <td className="break-all">{item.check.resource}</td>
                  <td>
                    {item.result.decision}
                    <ul>
                      {item.result.reasons.map((reason, i) => (
                        <li key={i}>
                          {reason.source}: {reason.detail}
                        </li>
                      ))}
                    </ul>
                  </td>
                  <td>
                    {t("discovery.machine.activityResult", {
                      coverage: item.activity_coverage,
                      uses: item.observed_uses,
                      unbound: item.resource_unbound_uses,
                      unused: String(item.unused_in_covered_window),
                    })}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {(value.keys ?? []).map(({ key, long_lived, stale }) => (
          <div key={key.id} className="grid gap-1 border-t pt-3 text-sm">
            <CredentialChip value={key.id} fullValue />
            <p>
              {t("discovery.machine.keyResult", {
                status: key.status,
                created: key.created_at,
                used: key.last_used_at ?? key.last_use_coverage,
                long: String(long_lived),
                stale: String(stale),
              })}
            </p>
          </div>
        ))}
        {(value.self_escalation_candidates ?? []).map((item, i) => (
          <p key={i} className="text-sm">
            {t("discovery.machine.escalation", { action: item.action, resource: item.resource, reason: item.reason, confidence: item.confidence })}
          </p>
        ))}
        {(value.limitations ?? []).length > 0 && (
          <ul className="list-disc pl-5 text-sm text-muted-foreground">
            {value.limitations?.map((item, i) => (
              <li key={i}>{item}</li>
            ))}
          </ul>
        )}
        {value.source_origin && value.identity.native_id ? <CloudChangeControls finding={finding} value={value} /> : <p>{t("discovery.machine.rescan")}</p>}
      </CardContent>
    </Card>
  );
}
function CloudChangeControls({ finding, value }: { finding: DiscoveryFinding; value: Captured }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const key = cloudChangesKey(finding.id);
  const changes = useApiQuery(key, ({ signal }) => listCloudMachineChanges(finding.id, signal), { live: { intervalMs: 5000 } });
  const [step, setStep] = useState(0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const keys = useRef(new Map<string, string>());
  const form = useForm<FormValues, unknown, z.output<typeof formSchema>>({
    resolver: zodResolver(formSchema),
    defaultValues: { target: "", writer: "", reason: "", required: 2 },
  });
  const fields = useWatch({ control: form.control });
  const selected = (fields.target ?? "").split(":");
  const request: CloudMachineChangeRequest = {
    finding_id: finding.id,
    action: selected[0] === "key" ? "revoke_key" : "tighten_policy",
    ...(selected[0] === "key" ? { access_key_id: selected[1] } : { evaluation_index: Number(selected[1]) }),
    writer_session_file_ref: fields.writer ?? "",
    reason: fields.reason ?? "",
    required_approvals: Number(fields.required ?? 2),
  };
  function mutationKey(value: string) {
    let existing = keys.current.get(value);
    if (!existing) {
      existing = newIdempotencyKey();
      keys.current.set(value, existing);
    }
    return existing;
  }
  async function update(work: () => Promise<CloudMachineChange>) {
    setBusy(true);
    setError(null);
    try {
      const result = await work();
      queryClient.setQueryData(key, (before: { items: CloudMachineChange[]; next_cursor: string } | undefined) => ({
        items: [...(before?.items ?? []).filter((item) => item.id !== result.id), result],
        next_cursor: before?.next_cursor ?? "",
      }));
      await queryClient.invalidateQueries({ queryKey: key });
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setBusy(false);
    }
  }
  const submit = (event: FormEvent<HTMLFormElement>) => {
    void form.handleSubmit(async () => {
      if (step === 2) await update(() => proposeCloudMachineChange(request, mutationKey(JSON.stringify(request))));
    })(event);
  };
  return (
    <section className="grid gap-4 border-t pt-4">
      <h4 className="text-title font-semibold">{t("discovery.machine.reviewChange")}</h4>
      <p className="text-sm text-muted-foreground">{t("discovery.machine.changeHelp")}</p>
      <form onSubmit={submit}>
        <StepShell
          currentIndex={step}
          steps={[
            { id: "target", label: t("discovery.machine.selectChange"), description: t("discovery.machine.selectHelp") },
            { id: "authority", label: t("discovery.machine.reviewBinding"), description: t("discovery.machine.writerHelp") },
            { id: "review", label: t("discovery.machine.reviewChange"), description: t("discovery.machine.effectHelp") },
          ]}
          onPrevious={() => setStep(Math.max(0, step - 1))}
          onNext={
            step < 2
              ? async () => {
                  if (await form.trigger(step === 0 ? ["target"] : ["writer", "reason", "required"])) setStep(step + 1);
                }
              : undefined
          }
        >
          {step === 0 && (
            <Field label={t("discovery.machine.selectChange")} error={form.formState.errors.target ? t("discovery.machine.invalidChange") : undefined} required>
              {(control) => (
                <Select {...control} {...form.register("target")}>
                  <option value="">{t("discovery.machine.choose")}</option>
                  {(value.keys ?? []).map((item) => (
                    <option key={item.key.id} value={`key:${item.key.id}`}>
                      {t("discovery.machine.revokeOption", { id: item.key.id })}
                    </option>
                  ))}
                  {value.evaluations.map((item, index) =>
                    item.unused_in_covered_window &&
                    item.result.decision === "allowed" &&
                    item.activity_coverage === "complete" &&
                    item.check.resource.startsWith("arn:") &&
                    !/[*?]/.test(item.check.action + item.check.resource) ? (
                      <option key={index} value={`policy:${index}`}>
                        {t("discovery.machine.tightenOption", { action: item.check.action, resource: item.check.resource })}
                      </option>
                    ) : null,
                  )}
                </Select>
              )}
            </Field>
          )}
          {step === 1 && (
            <div className="grid gap-4">
              <Field
                label={t("discovery.machine.writer")}
                description={t("discovery.machine.writerHelp")}
                error={form.formState.errors.writer ? t("discovery.machine.invalidBinding") : undefined}
                required
              >
                {(control) => <Input {...control} {...form.register("writer")} placeholder={t("discovery.machine.writerExample")} />}
              </Field>
              <Field label={t("discovery.machine.reason")} error={form.formState.errors.reason ? t("discovery.machine.invalidChange") : undefined} required>
                {(control) => <Textarea {...control} {...form.register("reason")} />}
              </Field>
              <Field label={t("discovery.machine.required")} error={form.formState.errors.required ? t("discovery.machine.invalidChange") : undefined} required>
                {(control) => <Input {...control} {...form.register("required")} type="number" min={1} max={5} />}
              </Field>
            </div>
          )}
          {step === 2 && (
            <div className="grid gap-3">
              <p>{t("discovery.machine.effectHelp")}</p>
              <pre className="overflow-x-auto whitespace-pre-wrap break-all text-xs">{JSON.stringify(request, null, 2)}</pre>
              <Button type="submit" variant="destructive" loading={busy}>
                {t("discovery.machine.propose")}
              </Button>
            </div>
          )}
        </StepShell>
      </form>
      {error && <ErrorState title={t("discovery.machine.changeError")}>{error}</ErrorState>}
      <Link className="text-sm text-primary underline" to="/approvals">
        {t("discovery.machine.openApprovals")}
      </Link>
      {changes.loading && <LoadingState>{t("discovery.machine.loadingChanges")}</LoadingState>}
      {changes.error && <ErrorState title={t("discovery.machine.changeError")}>{changes.error}</ErrorState>}
      {(changes.data?.items ?? []).map((plan) => (
        <article key={plan.id} className="grid gap-2 border-t pt-3 text-sm">
          <CredentialChip value={plan.id} fullValue />
          <p>{t("discovery.machine.changeState", { action: plan.intent.action, state: plan.state, expires: plan.expires_at })}</p>
          <CloudChangeIntent plan={plan} />
          {plan.state === "preparing_replacement" && <p>{t("discovery.machine.preparingReplacement")}</p>}
          {plan.state === "waiting_adoption" && (
            <p>
              {t("discovery.machine.waitingAdoption", {
                consumer: plan.intent.consumer ?? "",
                subject: plan.intent.consumer_subject ?? "",
                version: plan.result?.replacement_version ?? 0,
              })}
            </p>
          )}
          {plan.adoption && (
            <p>{t("discovery.machine.adoptionReceipt", { subject: plan.adoption.subject, version: plan.adoption.version, event: plan.adoption.event_id })}</p>
          )}

          {plan.result?.effect_uncertain && <p className="text-risk-high">{t("discovery.machine.uncertain")}</p>}
          {plan.result && (
            <p>
              {t("discovery.machine.nativeResult", {
                postcondition: plan.result.postcondition ?? "",
                checked: plan.result.checked_at,
                error: plan.result.error ?? "",
              })}
            </p>
          )}
          {plan.state === "awaiting_approval" && (
            <Button
              type="button"
              variant="destructive-outline"
              loading={busy}
              onClick={() => void update(() => executeCloudMachineChange(plan.id, mutationKey(`execute:${plan.id}`)))}
            >
              {t("discovery.machine.execute")}
            </Button>
          )}
        </article>
      ))}
      {changes.data?.next_cursor && <p>{t("discovery.machine.moreChanges")}</p>}
    </section>
  );
}
