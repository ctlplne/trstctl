import { useMemo, useState } from "react";
import { zodResolver } from "@hookform/resolvers/zod";
import { useForm } from "react-hook-form";
import { z } from "zod";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { EmptyState } from "@/components/EmptyState";
import { ErrorState, LoadingState } from "@/components/StatePrimitives";
import { StatusBadge } from "@/components/StatusBadge";
import { useTranslation } from "@/i18n/I18nProvider";
import { api, type CBOMAsset, type PQCMigrationCampaignClosure, type PQCMigrationCampaignFinding } from "@/lib/api";
import { useApiQuery, useQueryClient } from "@/lib/query";

const createSchema = z.object({
  name: z.string().trim().min(1, "Campaign name is required."),
  owner: z.string().trim().min(1, "Owner is required."),
  deadline: z.string().min(1, "Deadline is required."),
  wave: z.string().trim().min(1, "Wave is required."),
  readinessCriteria: z.string().trim().min(1, "At least one readiness criterion is required."),
  findingIds: z.array(z.string()).min(1, "Select at least one CBOM finding."),
});
type CreateValues = z.infer<typeof createSchema>;

const readinessSchema = z.object({
  status: z.enum(["pending", "passed", "blocked"]),
  evidenceRefs: z.string().trim(),
});
type ReadinessValues = z.infer<typeof readinessSchema>;

const dispositionSchema = z.object({
  disposition: z.enum(["remediated", "excepted"]),
  method: z.string().trim().min(1, "Method is required."),
  reason: z.string().trim().min(1, "Reason is required."),
  evidenceRefs: z.string().trim(),
  evidenceDigests: z
    .string()
    .trim()
    .refine((value) => lines(value).length > 0, "At least one SHA-256 evidence digest is required.")
    .refine((value) => lines(value).every((digest) => /^sha256:[0-9a-f]{64}$/.test(digest)), "Use sha256 followed by 64 lowercase hex characters."),
});
type DispositionValues = z.infer<typeof dispositionSchema>;

export function PQCCampaigns({ assets }: { assets: CBOMAsset[] }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const campaigns = useApiQuery(["pqc-campaigns"], () => api.pqcCampaigns({ limit: 100 }));
  const [selectedID, setSelectedID] = useState<string | null>(null);
  const selected = useApiQuery(["pqc-campaign", selectedID], () => api.pqcCampaign(selectedID as string), { enabled: selectedID !== null });
  const [busy, setBusy] = useState<string | null>(null);
  const [operationError, setOperationError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [closure, setClosure] = useState<PQCMigrationCampaignClosure | null>(null);
  const vulnerableAssets = useMemo(() => assets.filter((asset) => asset.quantum_vulnerable || asset.out_of_policy), [assets]);

  const createForm = useForm<CreateValues>({
    resolver: zodResolver(createSchema),
    mode: "onTouched",
    defaultValues: { name: "", owner: "", deadline: "", wave: "wave-1", readinessCriteria: "", findingIds: [] },
  });
  const readinessForm = useForm<ReadinessValues>({
    resolver: zodResolver(readinessSchema),
    defaultValues: { status: "passed", evidenceRefs: "" },
  });

  async function refresh(campaignID?: string) {
    await queryClient.invalidateQueries({ queryKey: ["pqc-campaigns"] });
    if (campaignID) await queryClient.invalidateQueries({ queryKey: ["pqc-campaign", campaignID] });
  }

  const createCampaign = createForm.handleSubmit(async (values) => {
    setBusy("create");
    setOperationError(null);
    setNotice(null);
    try {
      const campaign = await api.createCryptoReadinessAction({
        name: values.name,
        owner: values.owner,
        deadline: new Date(values.deadline).toISOString(),
        wave: values.wave,
        readiness_criteria: lines(values.readinessCriteria),
        finding_ids: values.findingIds,
      });
      createForm.reset();
      setSelectedID(campaign.id);
      setNotice(t("posture.pqcCampaign.created", { name: campaign.name }));
      await refresh(campaign.id);
    } catch (error) {
      setOperationError(errorMessage(error, t("posture.pqcCampaign.error")));
    } finally {
      setBusy(null);
    }
  });

  const recordReadiness = readinessForm.handleSubmit(async (values) => {
    if (!selectedID) return;
    setBusy("readiness");
    setOperationError(null);
    setNotice(null);
    try {
      await api.setPQCCampaignReadiness(selectedID, {
        status: values.status,
        evidence_refs: lines(values.evidenceRefs),
      });
      setNotice(t("posture.pqcCampaign.readinessRecorded"));
      await refresh(selectedID);
    } catch (error) {
      setOperationError(errorMessage(error, t("posture.pqcCampaign.error")));
    } finally {
      setBusy(null);
    }
  });

  async function recordDisposition(finding: PQCMigrationCampaignFinding, values: DispositionValues): Promise<boolean> {
    if (!selectedID) return false;
    setBusy(`finding:${finding.finding_id}`);
    setOperationError(null);
    setNotice(null);
    try {
      await api.dispositionPQCCampaignFinding(selectedID, finding.finding_id, {
        disposition: values.disposition,
        method: values.method,
        reason: values.reason,
        evidence_refs: lines(values.evidenceRefs),
        evidence_digests: lines(values.evidenceDigests),
      });
      setNotice(t("posture.pqcCampaign.dispositionRecorded"));
      await refresh(selectedID);
      return true;
    } catch (error) {
      setOperationError(errorMessage(error, t("posture.pqcCampaign.error")));
      return false;
    } finally {
      setBusy(null);
    }
  }

  async function closeCampaign() {
    if (!selectedID) return;
    setBusy("close");
    setOperationError(null);
    setNotice(null);
    try {
      const campaign = await api.closePQCCampaign(selectedID);
      setNotice(t("posture.pqcCampaign.closed", { name: campaign.name }));
      await refresh(selectedID);
    } catch (error) {
      setOperationError(errorMessage(error, t("posture.pqcCampaign.error")));
    } finally {
      setBusy(null);
    }
  }

  async function exportEvidence() {
    if (!selectedID) return;
    setBusy("evidence");
    setOperationError(null);
    setNotice(null);
    try {
      setClosure(await api.pqcCampaignEvidence(selectedID));
      setNotice(t("posture.pqcCampaign.evidenceLoaded"));
    } catch (error) {
      setOperationError(errorMessage(error, t("posture.pqcCampaign.error")));
    } finally {
      setBusy(null);
    }
  }

  return (
    <section className="grid gap-4 rounded-panel border border-border p-comfortable" aria-labelledby="pqc-campaigns-heading">
      <div>
        <h3 id="pqc-campaigns-heading" className="font-semibold">
          {t("posture.pqcCampaign.heading")}
        </h3>
        <p className="mt-1 text-sm text-muted-foreground">{t("posture.pqcCampaign.description")}</p>
      </div>

      <div className="rounded-control border border-border bg-muted/30 p-3" role="note">
        <p className="font-medium">{t("posture.pqcCampaign.communityHeading")}</p>
        <p className="mt-1 text-sm text-muted-foreground">{t("posture.pqcCampaign.communityBody")}</p>
      </div>

      <form className="grid gap-3 rounded-control border border-border p-3" onSubmit={createCampaign}>
        <h4 className="font-medium">{t("posture.pqcCampaign.createHeading")}</h4>
        <div className="grid gap-3 md:grid-cols-2">
          <Field label={t("posture.pqcCampaign.name")} error={createForm.formState.errors.name?.message} required>
            {(control) => <Input {...control} {...createForm.register("name")} />}
          </Field>
          <Field label={t("posture.pqcCampaign.owner")} error={createForm.formState.errors.owner?.message} required>
            {(control) => <Input {...control} {...createForm.register("owner")} placeholder="team:payments" />}
          </Field>
          <Field label={t("posture.pqcCampaign.deadline")} error={createForm.formState.errors.deadline?.message} required>
            {(control) => <Input {...control} {...createForm.register("deadline")} type="datetime-local" />}
          </Field>
          <Field label={t("posture.pqcCampaign.wave")} error={createForm.formState.errors.wave?.message} required>
            {(control) => <Input {...control} {...createForm.register("wave")} />}
          </Field>
        </div>
        <Field
          label={t("posture.pqcCampaign.criteria")}
          description={t("posture.pqcCampaign.linesHint")}
          error={createForm.formState.errors.readinessCriteria?.message}
          required
        >
          {(control) => <Textarea {...control} {...createForm.register("readinessCriteria")} className="min-h-20" />}
        </Field>
        <fieldset className="grid gap-2">
          <legend className="text-sm font-medium">{t("posture.pqcCampaign.findings")}</legend>
          {vulnerableAssets.map((asset) => (
            <label
              key={asset.id}
              htmlFor={`pqc-campaign-finding-${asset.id}`}
              className="flex items-start gap-2 rounded-control border border-border p-2 text-sm"
            >
              <Checkbox id={`pqc-campaign-finding-${asset.id}`} value={asset.id} {...createForm.register("findingIds")} />
              <span>
                <span className="block font-medium">{asset.location}</span>
                <span className="text-xs text-muted-foreground">{asset.algorithm || asset.protocol || asset.kind}</span>
              </span>
            </label>
          ))}
          {createForm.formState.errors.findingIds?.message ? (
            <p className="text-caption font-medium text-risk-critical">{createForm.formState.errors.findingIds.message}</p>
          ) : null}
          {vulnerableAssets.length === 0 ? <p className="text-sm text-muted-foreground">{t("posture.pqcCampaign.noFindings")}</p> : null}
        </fieldset>
        <Button type="submit" disabled={busy !== null || vulnerableAssets.length === 0}>
          {busy === "create" ? t("posture.pqcCampaign.creating") : t("posture.pqcCampaign.create")}
        </Button>
      </form>

      <section className="grid gap-3" aria-labelledby="pqc-campaign-list-heading">
        <h4 id="pqc-campaign-list-heading" className="font-medium">
          {t("posture.pqcCampaign.listHeading")}
        </h4>
        {campaigns.loading ? <LoadingState>{t("posture.pqcCampaign.loading")}</LoadingState> : null}
        {campaigns.error ? <ErrorState title={t("posture.pqcCampaign.error")}>{campaigns.error}</ErrorState> : null}
        {!campaigns.loading && !campaigns.error && (campaigns.data?.items ?? []).length === 0 ? (
          <EmptyState title={t("posture.pqcCampaign.empty")}>{t("posture.pqcCampaign.emptyBody")}</EmptyState>
        ) : null}
        <div className="grid gap-2">
          {(campaigns.data?.items ?? []).map((campaign) => (
            <button
              key={campaign.id}
              type="button"
              className="grid gap-1 rounded-control border border-border p-3 text-left hover:bg-muted/30"
              onClick={() => {
                setSelectedID(campaign.id);
                setClosure(null);
              }}
            >
              <span className="flex flex-wrap items-center justify-between gap-2">
                <span className="font-medium">{campaign.name}</span>
                <StatusBadge
                  value={campaign.status}
                  label={campaign.status}
                  tone={campaign.status === "closed" ? "success" : "warning"}
                  vocabulary="lifecycle"
                />
              </span>
              <span className="text-xs text-muted-foreground">
                {campaign.owner} · {campaign.wave} · {campaign.pending_count} {t("posture.pqcCampaign.pending")}
              </span>
            </button>
          ))}
        </div>
      </section>

      {selectedID ? (
        <section className="grid gap-3 rounded-control border border-border p-3" aria-labelledby="pqc-campaign-detail-heading">
          <h4 id="pqc-campaign-detail-heading" className="font-medium">
            {selected.data?.name ?? t("posture.pqcCampaign.detail")}
          </h4>
          {selected.loading ? <LoadingState>{t("posture.pqcCampaign.loadingDetail")}</LoadingState> : null}
          {selected.error ? <ErrorState title={t("posture.pqcCampaign.error")}>{selected.error}</ErrorState> : null}
          {selected.data ? (
            <>
              <dl className="grid gap-2 text-sm sm:grid-cols-4">
                <Metric label={t("posture.pqcCampaign.owner")} value={selected.data.owner} />
                <Metric label={t("posture.pqcCampaign.wave")} value={selected.data.wave} />
                <Metric label={t("posture.pqcCampaign.readiness")} value={selected.data.readiness_status} />
                <Metric label={t("posture.pqcCampaign.remaining")} value={String(selected.data.pending_count)} />
              </dl>

              {selected.data.status === "open" ? (
                <form className="grid gap-2 border-t border-border pt-3" onSubmit={recordReadiness}>
                  <h5 className="font-medium">{t("posture.pqcCampaign.readinessHeading")}</h5>
                  <div className="grid gap-2 md:grid-cols-2">
                    <Field label={t("posture.pqcCampaign.status")}>
                      {(control) => (
                        <Select {...control} {...readinessForm.register("status")}>
                          <option value="pending">{t("posture.pqcCampaign.readinessPending")}</option>
                          <option value="passed">{t("posture.pqcCampaign.readinessPassed")}</option>
                          <option value="blocked">{t("posture.pqcCampaign.readinessBlocked")}</option>
                        </Select>
                      )}
                    </Field>
                    <Field label={t("posture.pqcCampaign.evidenceRefs")} description={t("posture.pqcCampaign.linesHint")}>
                      {(control) => <Textarea {...control} {...readinessForm.register("evidenceRefs")} className="min-h-16" />}
                    </Field>
                  </div>
                  <Button type="submit" variant="outline" disabled={busy !== null}>
                    {t("posture.pqcCampaign.recordReadiness")}
                  </Button>
                </form>
              ) : null}

              <div className="grid gap-3 border-t border-border pt-3">
                <h5 className="font-medium">{t("posture.pqcCampaign.findingsHeading")}</h5>
                {selected.data.findings?.map((finding) => (
                  <section key={finding.finding_id} className="grid gap-2 rounded-control border border-border p-3">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <span className="font-medium">{finding.location}</span>
                      <StatusBadge
                        value={finding.disposition}
                        label={finding.disposition}
                        tone={finding.disposition === "pending" ? "warning" : "success"}
                        vocabulary="lifecycle"
                      />
                    </div>
                    <p className="font-mono text-xs text-muted-foreground">{finding.finding_digest}</p>
                    {finding.disposition === "pending" && selected.data?.status === "open" ? (
                      <FindingDispositionForm finding={finding} busy={busy !== null} onSubmit={recordDisposition} />
                    ) : null}
                  </section>
                ))}
              </div>

              <div className="flex flex-wrap gap-2 border-t border-border pt-3">
                {selected.data.status === "open" ? (
                  <Button
                    type="button"
                    onClick={() => void closeCampaign()}
                    disabled={busy !== null || selected.data.readiness_status !== "passed" || selected.data.pending_count !== 0}
                  >
                    {t("posture.pqcCampaign.close")}
                  </Button>
                ) : (
                  <Button type="button" variant="outline" onClick={() => void exportEvidence()} disabled={busy !== null}>
                    {t("posture.pqcCampaign.exportEvidence")}
                  </Button>
                )}
              </div>
              {closure ? (
                <Textarea
                  readOnly
                  aria-label={t("posture.pqcCampaign.signedEvidence")}
                  className="min-h-40 font-mono text-xs"
                  value={JSON.stringify(closure, null, 2)}
                />
              ) : null}
            </>
          ) : null}
        </section>
      ) : null}

      {notice ? <p role="status">{notice}</p> : null}
      {operationError ? (
        <p role="alert" className="text-sm font-medium text-destructive">
          {operationError}
        </p>
      ) : null}
    </section>
  );
}

function lines(value: string): string[] {
  return value
    .split(/\r?\n|,/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function errorMessage(error: unknown, fallback: string): string {
  return error instanceof Error ? error.message : fallback;
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd className="font-medium">{value}</dd>
    </div>
  );
}

function FindingDispositionForm({
  finding,
  busy,
  onSubmit,
}: {
  finding: PQCMigrationCampaignFinding;
  busy: boolean;
  onSubmit: (finding: PQCMigrationCampaignFinding, values: DispositionValues) => Promise<boolean>;
}) {
  const { t } = useTranslation();
  const form = useForm<DispositionValues>({
    resolver: zodResolver(dispositionSchema),
    defaultValues: { disposition: "remediated", method: "manual", reason: "", evidenceRefs: "", evidenceDigests: "" },
  });
  const submit = form.handleSubmit(async (values) => {
    if (await onSubmit(finding, values)) {
      form.reset({ disposition: "remediated", method: "manual", reason: "", evidenceRefs: "", evidenceDigests: "" });
    }
  });

  return (
    <form className="grid gap-2" onSubmit={submit}>
      <div className="grid gap-2 md:grid-cols-2">
        <Field label={t("posture.pqcCampaign.disposition")}>
          {(control) => (
            <Select {...control} {...form.register("disposition")}>
              <option value="remediated">{t("posture.pqcCampaign.remediated")}</option>
              <option value="excepted">{t("posture.pqcCampaign.excepted")}</option>
            </Select>
          )}
        </Field>
        <Field label={t("posture.pqcCampaign.method")} error={form.formState.errors.method?.message}>
          {(control) => <Input {...control} {...form.register("method")} />}
        </Field>
        <Field label={t("posture.pqcCampaign.reason")} error={form.formState.errors.reason?.message}>
          {(control) => <Textarea {...control} {...form.register("reason")} className="min-h-16" />}
        </Field>
        <Field label={t("posture.pqcCampaign.evidenceRefs")} description={t("posture.pqcCampaign.linesHint")}>
          {(control) => <Textarea {...control} {...form.register("evidenceRefs")} className="min-h-16" />}
        </Field>
        <Field
          label={t("posture.pqcCampaign.evidenceDigests")}
          description={t("posture.pqcCampaign.digestHint")}
          error={form.formState.errors.evidenceDigests?.message}
          required
          className="md:col-span-2"
        >
          {(control) => <Textarea {...control} {...form.register("evidenceDigests")} className="min-h-16 font-mono text-xs" />}
        </Field>
      </div>
      <Button type="submit" variant="outline" disabled={busy}>
        {t("posture.pqcCampaign.recordDisposition")}
      </Button>
    </form>
  );
}
