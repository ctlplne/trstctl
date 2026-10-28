import { useState } from "react";
import { Link } from "react-router-dom";
import { useForm, useWatch } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { useInfiniteQuery } from "@tanstack/react-query";
import { z } from "zod";
import { DataGrid, type DataGridColumn } from "@/components/DataGrid";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Button } from "@/components/ui/button";
import { StepShell } from "@/components/wizard/StepShell";
import { Num } from "@/components/typography";
import { api, ApiError, type Agent, type SSHTrustFleetPreview, type SSHTrustFleetApproval, type SSHTrustFleetRollout } from "@/lib/api";
import { newIdempotencyKey } from "@/lib/apiTransport";
import { apiProblemMessage } from "@/lib/apiProblem";
import { formatDateTime } from "@/i18n/format";
import { translateNow as t } from "@/i18n/I18nProvider";
import type { MessageKey } from "@/i18n/messages";

const skipLabels: Record<string, MessageKey> = {
  disabled: "sshTrust.fleetChange.skip.disabled",
  unconfirmed: "sshTrust.fleetChange.skip.unconfirmed",
  misconfigured: "sshTrust.fleetChange.skip.misconfigured",
  not_reported: "sshTrust.fleetChange.skip.notReported",
  stale: "sshTrust.fleetChange.skip.stale",
  not_host_role: "sshTrust.fleetChange.skip.notHost",
  ca_not_staged: "sshTrust.fleetChange.skip.caNotStaged",
  claims_paused: "sshTrust.fleetChange.skip.claimsPaused",
};
export function fleetSkipLabel(code?: string) {
  return t(skipLabels[code ?? ""] ?? "sshTrust.fleetChange.skip.notReported");
}

function schema() {
  const invalid = t("sshTrust.fleetChange.invalid");
  return z.object({
    name: z.string().trim().min(1, invalid).max(128, invalid),
    reason: z.string().trim().min(1, invalid).max(1024, invalid),
    public_ca_key: z
      .string()
      .trim()
      .min(1, invalid)
      .max(32768, invalid)
      .refine((value) => !/[\r\n]/.test(value), invalid),
    agent_ids: z.array(z.string().uuid(invalid)).min(1, t("sshTrust.fleetChange.selectHost")).max(100, t("sshTrust.fleetChange.hostLimit")),
  });
}
type FormValues = z.infer<ReturnType<typeof schema>>;
type Review = { preview: SSHTrustFleetPreview; approvalKey: string; startKey: string };

export function SSHTrustFleetWizard({
  publicKey,
  onCancel,
  onStarted,
}: {
  publicKey: string;
  onCancel: () => void;
  onStarted: (rollout: SSHTrustFleetRollout) => void;
}) {
  const form = useForm<FormValues>({
    resolver: zodResolver(schema()),
    defaultValues: { name: "", reason: "", public_ca_key: publicKey.trim(), agent_ids: [] },
  });
  const selected = useWatch({ control: form.control, name: "agent_ids" }) ?? [];
  const agents = useInfiniteQuery({
    queryKey: ["ssh-trust-fleet-agents"],
    initialPageParam: "",
    queryFn: ({ pageParam }) => api.agentPage({ limit: 100, ...(pageParam ? { cursor: pageParam } : {}) }),
    getNextPageParam: (page) => page.next_cursor || undefined,
  });
  const rows = agents.data?.pages.flatMap((page) => page.agents ?? []) ?? [];
  const names = new Map(rows.map((agent) => [agent.id, agent.name]));
  const [step, setStep] = useState(0);
  const [review, setReview] = useState<Review | null>(null);
  const [approval, setApproval] = useState<SSHTrustFleetApproval | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const steps = [
    { id: "scope", label: t("sshTrust.fleetChange.scopeStep"), description: t("sshTrust.fleetChange.scopeHelp") },
    { id: "review", label: t("sshTrust.fleetChange.reviewStep"), description: t("sshTrust.fleetChange.reviewHelp") },
    { id: "approval", label: t("sshTrust.fleetChange.approvalStep"), description: t("sshTrust.fleetChange.approvalHelp") },
  ];
  const columns: DataGridColumn<Agent>[] = [
    { id: "name", header: t("sshTrust.fleetChange.host"), cell: (agent) => agent.name },
    { id: "roles", header: t("sshTrust.fleetChange.roles"), cell: (agent) => (agent.roles ?? []).join(", ") },
    {
      id: "local",
      header: t("sshTrust.fleetChange.localOptIn"),
      cell: (agent) =>
        t(
          !agent.reported_ssh_trust_readiness
            ? "sshTrust.fleetChange.skip.notReported"
            : agent.reported_ssh_trust_readiness.enabled
              ? "sshTrust.fleetChange.localEnabled"
              : "sshTrust.fleetChange.skip.disabled",
        ),
    },
  ];
  async function preview(values: FormValues) {
    setBusy(true);
    setError(null);
    try {
      const result = await api.previewSSHTrustFleet(values);
      setReview({ preview: result, approvalKey: newIdempotencyKey(), startKey: newIdempotencyKey() });
      setApproval(null);
      setStep(1);
    } catch (err) {
      setError(apiProblemMessage(err, t("sshTrust.fleetChange.previewFailed")));
    } finally {
      setBusy(false);
    }
  }
  async function requestApproval() {
    if (!review) return;
    setBusy(true);
    setError(null);
    try {
      const result = await api.requestSSHTrustFleetApproval({ plan: review.preview.plan, plan_digest: review.preview.plan_digest }, review.approvalKey);
      setApproval(result);
      setStep(2);
    } catch (err) {
      setError(apiProblemMessage(err, t("sshTrust.fleetChange.approvalFailed")));
    } finally {
      setBusy(false);
    }
  }
  async function start() {
    if (!review || !approval) return;
    setBusy(true);
    setError(null);
    try {
      const result = await api.startSSHTrustFleet(
        {
          plan: review.preview.plan,
          plan_digest: review.preview.plan_digest,
          approval_request_id: approval.approval_request_id,
          approval_intent_digest: approval.approval_intent_digest,
        },
        review.startKey,
      );
      onStarted(result);
    } catch (err) {
      setError(apiProblemMessage(err, t("sshTrust.fleetChange.startFailed")));
      if (err instanceof ApiError && err.status === 409) setReview({ ...review, startKey: newIdempotencyKey() });
    } finally {
      setBusy(false);
    }
  }
  return (
    <StepShell
      steps={steps}
      currentIndex={step}
      progressLabel={t("sshTrust.fleetChange.setupProgress")}
      nextDisabled={busy || (step === 1 && (!review?.preview.ready_hosts || !review.preview.job_kind_enabled))}
      nextLabel={t(step === 0 ? "sshTrust.fleetChange.preview" : step === 1 ? "sshTrust.fleetChange.requestApproval" : "sshTrust.fleetChange.start")}
      onNext={() => {
        if (step === 0) void form.handleSubmit(preview)();
        else if (step === 1) void requestApproval();
        else void start();
      }}
      onPrevious={
        step > 0 && !busy
          ? () => {
              setStep(0);
              setReview(null);
              setApproval(null);
              setError(null);
            }
          : undefined
      }
    >
      <div className="space-y-3">
        {error ? (
          <p role="alert" className="text-risk-critical">
            {error}
          </p>
        ) : null}
        {step === 0 ? (
          <form className="space-y-3" onSubmit={form.handleSubmit(preview)}>
            <Field label={t("sshTrust.fleetChange.name")} controlId="ssh-fleet-name" error={form.formState.errors.name?.message}>
              {(control) => <Input {...control} {...form.register("name")} />}
            </Field>
            <Field label={t("sshTrust.fleetChange.reason")} controlId="ssh-fleet-reason" error={form.formState.errors.reason?.message}>
              {(control) => <Textarea {...control} {...form.register("reason")} />}
            </Field>
            <Field label={t("sshTrust.fleetChange.publicKey")} controlId="ssh-fleet-key" error={form.formState.errors.public_ca_key?.message}>
              {(control) => <Textarea {...control} {...form.register("public_ca_key")} />}
            </Field>
            {form.formState.errors.agent_ids?.message ? <p role="alert">{form.formState.errors.agent_ids.message}</p> : null}
            <DataGrid
              ariaLabel={t("sshTrust.fleetChange.selectHosts")}
              rows={rows}
              columns={columns}
              getRowId={(agent) => agent.id}
              state={agents.isPending ? "loading" : agents.isError ? "error" : rows.length ? "ready" : "empty"}
              stateMessage={agents.isError ? apiProblemMessage(agents.error, t("sshTrust.fleetChange.agentsFailed")) : t("sshTrust.fleetChange.noAgents")}
              selection={{
                selectedIds: new Set(selected),
                onSelectedIdsChange: (ids) => form.setValue("agent_ids", [...ids], { shouldValidate: true }),
                getRowLabel: (agent) => agent.name,
              }}
              pagination={
                agents.hasNextPage ? (
                  <Button type="button" variant="outline" loading={agents.isFetchingNextPage} onClick={() => void agents.fetchNextPage()}>
                    {t("sshTrust.fleetChange.moreAgents")}
                  </Button>
                ) : undefined
              }
            />
          </form>
        ) : null}
        {review && step >= 1 ? (
          <section className="space-y-2" aria-label={t("sshTrust.fleetChange.reviewSummary")}>
            <p>{t("sshTrust.fleetChange.effectSummary", { ready: review.preview.ready_hosts, skipped: review.preview.skipped_hosts })}</p>
            <p>
              {t("sshTrust.fleetChange.caFingerprint")}: <Num>{review.preview.plan.ca_fingerprint}</Num>
            </p>
            <p>
              {t("sshTrust.fleetChange.expires")}: <Num>{formatDateTime(review.preview.plan.expires_at)}</Num>
            </p>
            <p>
              {t("sshTrust.fleetChange.planDigest")}: <Num>{review.preview.plan_digest}</Num>
            </p>
            {!review.preview.job_kind_enabled ? <p role="alert">{t("sshTrust.fleetChange.enableJobKind")}</p> : null}
            <DataGrid
              ariaLabel={t("sshTrust.fleetChange.reviewHosts")}
              rows={review.preview.plan.hosts}
              getRowId={(host) => host.agent_id}
              columns={[
                { id: "host", header: t("sshTrust.fleetChange.host"), cell: (host) => names.get(host.agent_id) ?? host.agent_id },
                {
                  id: "decision",
                  header: t("sshTrust.fleetChange.decision"),
                  cell: (host) => (host.state === "ready" ? t("sshTrust.fleetChange.ready") : fleetSkipLabel(host.reason)),
                },
              ]}
            />
          </section>
        ) : null}
        {approval && step === 2 ? (
          <section className="space-y-2" aria-label={t("sshTrust.fleetChange.approvalSummary")}>
            <p>{t("sshTrust.fleetChange.reviewersNeeded", { count: approval.required_approvals })}</p>
            <p>
              <Num>{approval.approval_request_id}</Num>
            </p>
            <p>{t("sshTrust.fleetChange.approvalNext")}</p>
            <Link className="text-primary underline" to="/approvals">
              {t("sshTrust.fleetChange.openApprovals")}
            </Link>
          </section>
        ) : null}
        <Button type="button" variant="outline" disabled={busy} onClick={onCancel}>
          {t("sshTrust.fleetChange.cancel")}
        </Button>
      </div>
    </StepShell>
  );
}
