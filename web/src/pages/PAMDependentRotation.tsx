import { Link } from "react-router-dom";
import { useRef, useState } from "react";
import { useFieldArray, useForm, useWatch } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { api, type PAMServiceDependentRotationPreview, type PAMServiceReconciliationPendingReview } from "@/lib/api";
import type { PAMDependentRef, PAMServiceDependentRotationStep } from "@/lib/api-types.gen";
import { useApiQuery, useQueryClient } from "@/lib/query";
import { useTranslation } from "@/i18n/I18nProvider";
import { StepShell } from "@/components/wizard/StepShell";
import { DataGrid } from "@/components/DataGrid";
import { CredentialChip } from "@/components/CredentialChip";
import { Num } from "@/components/typography";
import { Button } from "@/components/ui/button";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { PAMDependentRecovery } from "./PAMDependentRecovery";
import { PAMReconciliationIntent } from "./PAMReconciliationIntent";
import { ErrorState, LoadingState } from "@/components/StatePrimitives";

// Read every selected host page. Only the served preview can authorize a reset;
// these native references populate review controls, never completion claims.
async function inventory(accountID: string, incomplete: string) {
  const refs: PAMDependentRef[] = [];
  const seen = new Set<string>();
  let after = "";
  do {
    const page = await api.pamServiceDependentHosts(accountID, after);
    for (const host of page.items) {
      if (!host.binding.enabled) continue;
      if (!host.latest_scan?.current || host.latest_scan.status !== "complete") throw new Error(incomplete);
      const scan = await api.pamServiceDependentScan(host.latest_scan.id);
      if (!scan.report || scan.status !== "complete") throw new Error(incomplete);
      const base = { agent_id: host.binding.agent_id };
      for (const s of scan.report.services ?? []) refs.push({ ...base, family: "services", name: s.name });
      for (const t of scan.report.tasks ?? []) refs.push({ ...base, family: "tasks", name: t.path });
      for (const p of scan.report.pools ?? []) refs.push({ ...base, family: "iis", name: p.name });
    }
    after = page.next_cursor ?? "";
    if (after && seen.has(after)) throw new Error(incomplete);
    seen.add(after);
  } while (after);
  if (!refs.length) throw new Error(incomplete);
  return refs;
}
async function passwordReferences() {
  const names: string[] = [];
  const seen = new Set<string>();
  let cursor = "";
  do {
    const page = await api.secretPage({ limit: 100, cursor });
    names.push(...page.items.map((s) => s.name));
    cursor = page.next_cursor ?? "";
    if (cursor && seen.has(cursor)) throw new Error("secret reference cursor repeated");
    seen.add(cursor);
  } while (cursor);
  return names;
}
const rowID = (ref: PAMDependentRef) => JSON.stringify([ref.agent_id, ref.family, ref.name]);

export function PAMDependentRotation({
  accountID,
  canManage,
  rotationID,
  onRotationID,
  reviewID,
  approvalID,
  onReviewID,
}: {
  accountID: string;
  canManage: boolean;
  rotationID?: string;
  onRotationID: (id: string) => void;
  reviewID?: string;
  approvalID?: string;
  onReviewID?: (review: string, approval: string) => void;
}) {
  const { t } = useTranslation();
  const client = useQueryClient();
  const [activeID, setActiveID] = useState(rotationID ?? "");
  const activeRotation = rotationID || activeID;
  const [localReview, setLocalReview] = useState({ reviewID: "", approvalID: "" });
  const savedReview = reviewID || localReview.reviewID;
  const savedApproval = approvalID || localReview.approvalID;
  const pendingKey = ["pam-reconcile-pending", accountID, savedReview, savedApproval];
  const pending = useApiQuery(pendingKey, () => api.pamServiceReconciliationPendingReview(accountID, savedReview, savedApproval), {
    enabled: !!reviewID && !!approvalID && !activeRotation,
    retry: false,
  });
  const id = activeRotation || pending.data?.rotation_id || "";
  const [stage, setStage] = useState(0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [localPreview, setPreview] = useState<PAMServiceDependentRotationPreview | null>(null);
  const preview = pending.data ? { intent: pending.data.intent, intent_digest: pending.data.intent_digest } : localPreview;
  const reviewing = !!preview;
  const reconcile = preview?.intent.mode === "reconcile";
  const approval = pending.data?.approval;
  const mayQueue = !reconcile || (!pending.error && !pending.fetching && (approval?.status === "approved" || pending.data?.queue_pending === true));
  const [after, setAfter] = useState("");
  const [history, setHistory] = useState<string[]>([]);
  const requestKeys = useRef(new Map<string, string>());
  const names = useApiQuery(["pam-dependent-password-references"], passwordReferences, { enabled: canManage && !id, retry: false });
  const progress = useApiQuery(["pam-dependent-rotation", id], () => api.pamServiceDependentRotation(id), {
    enabled: !!id,
    retry: false,
    live: { intervalMs: 3000 },
  });
  const steps = useApiQuery(["pam-dependent-steps", id, after], () => api.pamServiceDependentRotationSteps(id, after), {
    enabled: !!id,
    retry: false,
    live: { intervalMs: 3000 },
  });
  const schema = z
    .object({
      secretName: z.string().trim().min(1, t("admin.access.rotation.required")),
      dependents: z.array(
        z.object({
          ref: z.object({ agent_id: z.string(), family: z.enum(["services", "tasks", "iis"]), name: z.string() }),
          probe: z.string().trim().min(1, t("admin.access.rotation.required")),
        }),
      ),
      acknowledge: z.boolean(),
      mode: z.enum(["rotate", "reconcile"]),
      reason: z.string().trim().max(4096),
    })
    .superRefine((v, c) => {
      if (v.mode === "reconcile" && !v.reason) c.addIssue({ code: "custom", path: ["reason"], message: t("admin.access.rotation.required") });
    });
  const form = useForm<z.infer<typeof schema>>({
    resolver: zodResolver(schema),
    defaultValues: { secretName: "", dependents: [], acknowledge: false, mode: "rotate", reason: "" },
  });
  const fields = useFieldArray({ control: form.control, name: "dependents" });
  const mode = useWatch({ control: form.control, name: "mode" });
  const acknowledged = useWatch({ control: form.control, name: "acknowledge" });
  async function act(work: () => Promise<void>) {
    setBusy(true);
    setError(null);
    try {
      await work();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }
  function requestKey(input: unknown) {
    const value = JSON.stringify(input);
    if (!requestKeys.current.has(value)) requestKeys.current.set(value, crypto.randomUUID());
    return requestKeys.current.get(value)!;
  }
  async function loadDependents() {
    if (!(await form.trigger(["secretName", "mode", "reason"]))) return;
    await act(async () => {
      const refs = await client.fetchQuery({
        queryKey: ["pam-dependent-review-inputs", accountID],
        queryFn: () => inventory(accountID, t("admin.access.rotation.incomplete")),
        staleTime: 0,
      });
      fields.replace(refs.map((ref) => ({ ref, probe: "" })));
      setStage(1);
    });
  }
  async function review() {
    await form.handleSubmit(async (values) =>
      act(async () => {
        const input = {
          ...(values.mode === "reconcile" ? { mode: "reconcile" as const } : {}),
          secret_name: values.secretName,
          order: values.dependents.map((d) => d.ref),
          probes: values.dependents.map((d) => ({ ref: d.ref, probe_id: d.probe })),
        };
        setPreview(await api.previewPAMServiceDependentRotation(accountID, input, requestKey(input)));
        form.setValue("acknowledge", false);
        setStage(2);
      }),
    )();
  }
  async function queue() {
    if (!preview || !acknowledged || !mayQueue) return;
    await act(async () => {
      const input = {
        ...preview,
        acknowledge_single_phase: true,
        ...(reconcile && approval ? { approval_request_id: approval.approval_request_id, approval_intent_digest: approval.approval_intent_digest } : {}),
      };
      const value = await api.queuePAMServiceDependentRotation(accountID, input, requestKey(input));
      client.setQueryData(["pam-dependent-rotation", value.rotation.id], value);
      setActiveID(value.rotation.id);
      onRotationID(value.rotation.id);
      await client.invalidateQueries({ queryKey: ["pam-dependent-rotation", value.rotation.id] });
    });
  }
  async function requestApproval() {
    if (!preview || !reconcile || approval) return;
    await act(async () => {
      const input = { ...preview, reason: form.getValues("reason").trim() };
      const grant = await api.requestPAMServiceReconciliationApproval(accountID, input, requestKey(input));
      const key = ["pam-reconcile-pending", accountID, preview.intent.plan.id, grant.approval_request_id];
      const value: PAMServiceReconciliationPendingReview = { ...preview, created_at: preview.intent.plan.created_at, approval: grant, reason: input.reason };
      client.setQueryData(key, value);
      setLocalReview({ reviewID: preview.intent.plan.id, approvalID: grant.approval_request_id });
      onReviewID?.(preview.intent.plan.id, grant.approval_request_id);
      await client.invalidateQueries({ queryKey: ["approval-requests"] });
    });
  }
  const wizard = [
    { id: "password", label: t("admin.access.rotation.password"), description: t("admin.access.rotation.passwordHelp") },
    { id: "dependents", label: t("admin.access.rotation.order"), description: t("admin.access.rotation.orderHelp") },
    { id: "review", label: t("admin.access.rotation.review"), description: t("admin.access.rotation.reviewHelp") },
  ];
  const value = progress.data;
  const foreign = value && value.rotation.intent.plan.account.account_id !== accountID;
  return (
    <section className="mt-4 border-t border-border pt-4" aria-label={t("admin.access.rotation.title")}>
      <h3 className="text-title font-semibold">{t("admin.access.rotation.title")}</h3>
      {error ? <ErrorState title={error} /> : null}
      {pending.error ? (
        <ErrorState title={pending.error}>
          <Button type="button" onClick={pending.refetch}>
            {t("admin.access.dependents.retry")}
          </Button>
        </ErrorState>
      ) : null}
      {!!reviewID && pending.loading ? <LoadingState>{t("admin.access.dependents.loading")}</LoadingState> : null}
      {!id && canManage && (!reviewID || !!pending.data) ? (
        <StepShell
          steps={wizard}
          currentIndex={reviewing ? 2 : stage}
          onPrevious={
            stage && !savedReview
              ? () => {
                  setPreview(null);
                  setStage(stage - 1);
                }
              : undefined
          }
          onNext={reviewing ? undefined : stage === 0 ? () => void loadDependents() : stage === 1 ? () => void review() : undefined}
          nextLabel={stage === 0 ? t("admin.access.rotation.reviewDependents") : t("admin.access.rotation.preview")}
          nextDisabled={busy || names.loading || !!names.error}
        >
          {!reviewing && stage === 0 ? (
            <>
              {names.error ? (
                <ErrorState title={names.error}>
                  <Button type="button" variant="outline" onClick={names.refetch}>
                    {t("admin.access.dependents.retry")}
                  </Button>
                </ErrorState>
              ) : null}
              <Field label={t("admin.access.rotation.operation")}>
                {(control) => (
                  <Select {...control} {...form.register("mode")} disabled={busy}>
                    <option value="rotate">{t("admin.access.rotation.normal")}</option>
                    <option value="reconcile">{t("admin.access.rotation.reconcile")}</option>
                  </Select>
                )}
              </Field>
              {mode === "reconcile" ? (
                <Field label={t("admin.access.rotation.reason")} required error={form.formState.errors.reason?.message}>
                  {(control) => <Textarea {...control} {...form.register("reason")} disabled={busy} />}
                </Field>
              ) : null}
              <Field label={t("admin.access.rotation.password")} error={form.formState.errors.secretName?.message} required>
                {(control) => (
                  <Select {...control} {...form.register("secretName")} disabled={busy || names.loading}>
                    <option value="">{t("admin.access.rotation.choosePassword")}</option>
                    {names.data?.map((name) => (
                      <option key={name} value={name}>
                        {name}
                      </option>
                    ))}
                  </Select>
                )}
              </Field>
            </>
          ) : !reviewing && stage === 1 ? (
            <ol className="grid gap-3">
              {fields.fields.map((dependent, index) => (
                <li key={dependent.id} className="border-b border-border pb-3">
                  <p>
                    <Num>{index + 1}</Num> {dependent.ref.family}: {dependent.ref.name}
                  </p>
                  <CredentialChip value={dependent.ref.agent_id} />
                  <Field
                    label={t("admin.access.rotation.probe", { name: dependent.ref.name })}
                    description={t("admin.access.rotation.probeHelp")}
                    error={form.formState.errors.dependents?.[index]?.probe?.message}
                    required
                  >
                    {(control) => <Input {...control} {...form.register(`dependents.${index}.probe`)} disabled={busy} />}
                  </Field>
                  <div className="mt-2 flex gap-2">
                    <Button type="button" variant="outline" disabled={busy || index === 0} onClick={() => fields.move(index, index - 1)}>
                      {t("admin.access.rotation.earlier", { name: dependent.ref.name })}
                    </Button>
                    <Button type="button" variant="outline" disabled={busy || index === fields.fields.length - 1} onClick={() => fields.move(index, index + 1)}>
                      {t("admin.access.rotation.later", { name: dependent.ref.name })}
                    </Button>
                  </div>
                </li>
              ))}
            </ol>
          ) : preview ? (
            <div className="grid gap-3">
              <p>
                {t("admin.access.rotation.reviewVersion", {
                  name: preview.intent.plan.secret_name,
                  version: preview.intent.expected_version,
                  expires: preview.intent.plan.expires_at,
                })}
              </p>
              <CredentialChip value={preview.intent_digest} fullValue />
              <ol>
                {preview.intent.plan.order.map((ref) => (
                  <li key={rowID(ref)}>
                    {ref.family}: {ref.name} <CredentialChip value={ref.agent_id} />
                  </li>
                ))}
              </ol>
              <details>
                <summary>{t("admin.access.rotation.exactReview")}</summary>
                <pre className="overflow-auto whitespace-pre-wrap text-xs">{JSON.stringify(preview, null, 2)}</pre>
              </details>
              {reconcile ? (
                <>
                  <PAMReconciliationIntent intent={preview.intent} digest={preview.intent_digest} />
                  {approval ? (
                    <>
                      <p>{pending.data?.reason}</p>
                      <p role="status">
                        {t("admin.access.rotation.approvalState", {
                          status: approval.status,
                          count: approval.approval_count,
                          required: approval.required_approvals,
                        })}
                      </p>
                      <Link className="text-brand-accent underline" to={"/approvals?request=" + encodeURIComponent(approval.approval_request_id)}>
                        {t("admin.access.rotation.openApproval")}
                      </Link>
                      <Button type="button" variant="outline" disabled={pending.fetching} onClick={pending.refetch}>
                        {t("admin.access.rotation.refreshApproval")}
                      </Button>
                      {pending.data?.queue_pending ? <p>{t("admin.access.rotation.queuePending")}</p> : null}
                    </>
                  ) : (
                    <Button type="button" disabled={busy} onClick={() => void requestApproval()}>
                      {t("admin.access.rotation.requestApproval")}
                    </Button>
                  )}
                </>
              ) : null}
              <label className="flex items-start gap-2">
                <input type="checkbox" {...form.register("acknowledge")} disabled={busy} />
                <span>{t("admin.access.rotation.acknowledge")}</span>
              </label>
              <Button type="button" disabled={busy || !acknowledged || !mayQueue} loading={busy} onClick={() => void queue()}>
                {t("admin.access.rotation.execute")}
              </Button>
            </div>
          ) : null}
        </StepShell>
      ) : null}
      {id ? (
        <>
          <CredentialChip value={id} fullValue />
          {progress.loading ? <LoadingState>{t("admin.access.dependents.loading")}</LoadingState> : null}
          {progress.error ? (
            <ErrorState title={progress.error}>
              <Button type="button" variant="outline" onClick={progress.refetch}>
                {t("admin.access.dependents.retry")}
              </Button>
            </ErrorState>
          ) : null}
          {foreign ? <ErrorState title={t("admin.access.rotation.foreign")} /> : null}
          {value && !foreign ? (
            <>
              <p role="status">{t("admin.access.rotation.progress", { phase: value.command.phase, direction: value.rotation.direction })}</p>
              <p>
                {t("admin.access.rotation.restored", {
                  value: value.rotation.directory_restored ? t("admin.access.rotation.yes") : t("admin.access.rotation.no"),
                })}
              </p>
              {value.rotation.failure ? <p>{value.rotation.failure}</p> : null}
              {value.command.error ? <p>{value.command.error}</p> : null}
              {value.command.phase === "completed" ? (
                <p>{t("admin.access.rotation.complete")}</p>
              ) : (
                <p className="text-sm text-muted-foreground">{t("admin.access.rotation.pendingHelp")}</p>
              )}
              {canManage && value.recovery_step_id ? (
                <PAMDependentRecovery
                  key={id + ":" + value.recovery_step_id}
                  id={id}
                  stepID={value.recovery_step_id}
                  intentDigest={value.rotation.intent_digest}
                />
              ) : null}
              <DataGrid<PAMServiceDependentRotationStep>
                ariaLabel={t("admin.access.rotation.steps")}
                rows={steps.data?.items ?? []}
                getRowId={(s) => s.intent.step_id}
                state={steps.loading ? "loading" : steps.error ? "error" : undefined}
                stateMessage={steps.error ?? undefined}
                columns={[
                  {
                    id: "native",
                    header: t("admin.access.rotation.native"),
                    cell: (s) => (
                      <>
                        <p>
                          {s.intent.ref.family}: {s.intent.ref.name}
                        </p>
                        <CredentialChip value={s.intent.ref.agent_id} />
                        <p>
                          {s.intent.direction}: {s.intent.action}
                        </p>
                      </>
                    ),
                  },
                  {
                    id: "evidence",
                    header: t("admin.access.rotation.evidence"),
                    cell: (s) => (
                      <>
                        <p>{s.status}</p>
                        {s.intent.recovery ? <p>{t("admin.access.rotation.recovery.history", { previous: s.intent.recovery.previous_step_id })}</p> : null}
                        {s.report?.failure ? <p>{s.report.failure}</p> : null}
                        <details>
                          <summary>{t("admin.access.rotation.exactEvidence")}</summary>
                          <pre className="overflow-auto whitespace-pre-wrap text-xs">{JSON.stringify(s, null, 2)}</pre>
                        </details>
                      </>
                    ),
                  },
                  {
                    id: "delivery",
                    header: t("admin.access.rotation.delivery"),
                    cell: (s) => <span>{t("admin.access.dependents.delivery", { status: s.delivery_status ?? t("admin.access.rotation.unknown") })}</span>,
                  },
                ]}
                pagination={
                  <div className="flex gap-2">
                    {history.length ? (
                      <Button
                        type="button"
                        variant="outline"
                        onClick={() => {
                          setAfter(history[history.length - 1]);
                          setHistory((h) => h.slice(0, -1));
                        }}
                      >
                        {t("admin.access.rotation.previousSteps")}
                      </Button>
                    ) : null}
                    {steps.data?.next_cursor ? (
                      <Button
                        type="button"
                        variant="outline"
                        onClick={() => {
                          setHistory((h) => [...h, after]);
                          setAfter(steps.data!.next_cursor!);
                        }}
                      >
                        {t("admin.access.rotation.nextSteps")}
                      </Button>
                    ) : null}
                  </div>
                }
              />
            </>
          ) : null}
        </>
      ) : null}
    </section>
  );
}
