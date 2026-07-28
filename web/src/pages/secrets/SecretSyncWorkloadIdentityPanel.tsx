import { useMemo, useState } from "react";
import { zodResolver } from "@hookform/resolvers/zod";
import { useForm } from "react-hook-form";
import { z } from "zod";
import { DataGrid, type DataGridColumn, type DataGridState } from "@/components/DataGrid";
import { useCan } from "@/components/rbac";
import { StatusBadge } from "@/components/StatusBadge";
import { Button } from "@/components/ui/button";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { formatDateTime } from "@/i18n/format";
import { useTranslation } from "@/i18n/I18nProvider";
import { api, type SecretSyncWorkloadIdentitySource, type SecretSyncWorkloadIdentitySourceRequest } from "@/lib/api";
import { useApiQuery, useQueryClient } from "@/lib/query";
import { apiProblemMessage } from "./SecretsPageParts";

type ValidationMessage =
  | "secrets.wif.nameRequired"
  | "secrets.wif.roleArnInvalid"
  | "secrets.wif.serviceAccountInvalid"
  | "secrets.wif.audienceRequired"
  | "secrets.wif.subjectRequired"
  | "secrets.wif.targetRequired"
  | "secrets.wif.proofRefInvalid"
  | "secrets.wif.trustSourceRequired";

function buildSourceSchema(translate: (id: ValidationMessage) => string) {
  return z
    .object({
      name: z.string().trim().min(1, translate("secrets.wif.nameRequired")),
      provider: z.enum(["aws", "gcp"]),
      roleArn: z.string().trim(),
      serviceAccount: z.string().trim(),
      audience: z.string().trim().min(1, translate("secrets.wif.audienceRequired")),
      subject: z.string().trim().min(1, translate("secrets.wif.subjectRequired")),
      targetId: z.string().trim().min(1, translate("secrets.wif.targetRequired")),
      prefixes: z.string(),
      proofRef: z
        .string()
        .trim()
        .regex(/^(file:.+|secret:\/\/.+)$/, translate("secrets.wif.proofRefInvalid")),
      trustSourceId: z.string().uuid(translate("secrets.wif.trustSourceRequired")),
      enabled: z.boolean(),
    })
    .superRefine((value, context) => {
      if (value.provider === "aws" && !/^arn:aws:iam::[0-9]{12}:role\/.+$/.test(value.roleArn)) {
        context.addIssue({ code: "custom", path: ["roleArn"], message: translate("secrets.wif.roleArnInvalid") });
      }
      if (
        value.provider === "gcp" &&
        value.serviceAccount !== "" &&
        !/^[^\s@]+@[^\s@]+\.iam\.gserviceaccount\.com$/.test(value.serviceAccount)
      ) {
        context.addIssue({ code: "custom", path: ["serviceAccount"], message: translate("secrets.wif.serviceAccountInvalid") });
      }
    });
}
type SourceValues = z.infer<ReturnType<typeof buildSourceSchema>>;

const wizardFields: Record<number, Array<keyof SourceValues>> = {
  1: ["name", "provider", "roleArn", "serviceAccount", "audience", "subject"],
  2: ["targetId", "prefixes"],
  3: ["proofRef", "trustSourceId", "enabled"],
};

export function SecretSyncWorkloadIdentityPanel() {
  const { t } = useTranslation();
  const canRead = useCan("secrets:read");
  const canWrite = useCan("secrets:write");
  const queryClient = useQueryClient();
  const sources = useApiQuery(["secret-sync-workload-identities"], api.secretSyncWorkloadIdentitySources, { enabled: canRead });
  const trustSources = useApiQuery(["workload-attester-trust-sources"], api.workloadAttesterTrustSources, { enabled: canRead });
  const targets = useApiQuery(["secret-sync-targets"], api.secretSyncTargets, { enabled: canRead });
  const [step, setStep] = useState(1);
  const [editingID, setEditingID] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [operationError, setOperationError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const sourceSchema = useMemo(() => buildSourceSchema(t), [t]);
  const form = useForm<SourceValues>({
    resolver: zodResolver(sourceSchema),
    mode: "onTouched",
    defaultValues: {
      name: "",
      provider: "aws",
      roleArn: "",
      serviceAccount: "",
      audience: "",
      subject: "",
      targetId: "",
      prefixes: "",
      proofRef: "",
      trustSourceId: "",
      enabled: true,
    },
  });
  const selectedProvider = form.watch("provider");

  const providerTargets = useMemo(
    () =>
      (targets.data?.targets ?? []).filter(
        (target) =>
          target.configured &&
          (target.id.toLowerCase().includes(selectedProvider) || target.platform.toLowerCase().includes(selectedProvider)),
      ),
    [selectedProvider, targets.data],
  );
  const oidcTrustSources = useMemo(
    () =>
      (trustSources.data?.items ?? []).filter(
        (source) => source.enabled && !source.revoked_at && ["k8s_sat", "gcp_iit", "github_oidc"].includes(source.method),
      ),
    [trustSources.data],
  );

  async function refresh() {
    await queryClient.invalidateQueries({ queryKey: ["secret-sync-workload-identities"] });
  }

  function resetForm() {
    form.reset();
    setEditingID(null);
    setStep(1);
  }

  function editSource(source: SecretSyncWorkloadIdentitySource) {
    form.reset({
      name: source.name,
      provider: source.provider,
      roleArn: source.role_arn,
      serviceAccount: source.service_account,
      audience: source.audience,
      subject: source.subject,
      targetId: source.target_id,
      prefixes: source.allowed_remote_key_prefixes.join("\n"),
      proofRef: source.workload_proof_ref,
      trustSourceId: source.trust_source_id,
      enabled: source.enabled,
    });
    setEditingID(source.id);
    setStep(1);
    setOperationError(null);
    setNotice(null);
  }

  async function nextStep() {
    if (await form.trigger(wizardFields[step])) setStep((current) => Math.min(3, current + 1));
  }

  const save = form.handleSubmit(async (values) => {
    setBusy("save");
    setOperationError(null);
    setNotice(null);
    const input: SecretSyncWorkloadIdentitySourceRequest = {
      name: values.name.trim(),
      provider: values.provider,
      role_arn: values.provider === "aws" ? values.roleArn.trim() : "",
      ...(values.provider === "gcp" ? { service_account: values.serviceAccount.trim() } : {}),
      audience: values.audience.trim(),
      subject: values.subject.trim(),
      target_id: values.targetId.trim(),
      allowed_remote_key_prefixes: lines(values.prefixes),
      workload_proof_ref: values.proofRef.trim(),
      trust_source_id: values.trustSourceId,
      enabled: values.enabled,
    };
    try {
      if (editingID) {
        await api.updateSecretSyncWorkloadIdentitySource(editingID, input);
        setNotice(t("secrets.wif.updated"));
      } else {
        await api.createSecretSyncWorkloadIdentitySource(input);
        setNotice(t("secrets.wif.created"));
      }
      resetForm();
      await refresh();
    } catch (error) {
      setOperationError(apiProblemMessage(error, t("secrets.wif.mutationFailed")));
    } finally {
      setBusy(null);
    }
  });

  async function deleteSource(source: SecretSyncWorkloadIdentitySource) {
    setBusy(`delete:${source.id}`);
    setOperationError(null);
    setNotice(null);
    try {
      await api.deleteSecretSyncWorkloadIdentitySource(source.id);
      if (editingID === source.id) resetForm();
      setNotice(t("secrets.wif.deleted"));
      await refresh();
    } catch (error) {
      setOperationError(apiProblemMessage(error, t("secrets.wif.mutationFailed")));
    } finally {
      setBusy(null);
    }
  }

  const columns = useMemo<Array<DataGridColumn<SecretSyncWorkloadIdentitySource>>>(() => {
    const allColumns: Array<DataGridColumn<SecretSyncWorkloadIdentitySource>> = [
      {
        id: "name",
        header: t("secrets.wif.name"),
        cell: (source) => (
          <span>
            <span className="block font-medium">{source.name}</span>
            <span className="block font-mono text-xs uppercase text-muted-foreground">{source.provider}</span>
            <span className="block font-mono text-xs text-muted-foreground">{source.target_id}</span>
          </span>
        ),
      },
      {
        id: "binding",
        header: t("secrets.wif.binding"),
        cell: (source) => (
          <span>
            <span className="block break-all font-mono text-xs">{source.subject}</span>
            <span className="block text-xs text-muted-foreground">{source.audience}</span>
          </span>
        ),
      },
      {
        id: "status",
        header: t("secrets.wif.status"),
        cell: (source) => (
          <span className="grid gap-1">
            <StatusBadge value={source.status} label={source.status.replaceAll("_", " ")} tone={statusTone(source.status)} vocabulary="lifecycle" />
            <span className="text-xs text-muted-foreground">{source.status_reason}</span>
          </span>
        ),
      },
      {
        id: "expiry",
        header: t("secrets.wif.expiry"),
        cell: (source) => (source.token_expires_at ? formatDateTime(source.token_expires_at) : t("secrets.wif.noCredential")),
      },
      {
        id: "actions",
        header: t("secrets.wif.actions"),
        cell: (source) => (
          <span className="flex flex-wrap gap-2">
            <Button type="button" size="sm" variant="outline" onClick={() => editSource(source)}>
              {t("secrets.wif.edit")}
            </Button>
            <Button type="button" size="sm" variant="destructive" disabled={busy !== null} onClick={() => void deleteSource(source)}>
              {busy === `delete:${source.id}` ? t("secrets.wif.deleting") : t("secrets.wif.delete")}
            </Button>
          </span>
        ),
      },
    ];
    return allColumns.filter((column) => canWrite || column.id !== "actions");
  }, [busy, canWrite, t]);

  let gridState: DataGridState = "ready";
  let stateTitle: string | undefined;
  let stateMessage: string | undefined;
  if (!canRead) {
    gridState = "permission-denied";
    stateTitle = t("secrets.wif.permissionDenied");
  } else if (typeof api.secretSyncWorkloadIdentitySources !== "function") {
    gridState = "unavailable";
    stateTitle = t("secrets.wif.unavailable");
  } else if (sources.loading) {
    gridState = "loading";
    stateMessage = t("secrets.wif.loading");
  } else if (sources.error) {
    gridState = "error";
    stateTitle = t("secrets.wif.loadFailed");
    stateMessage = sources.error;
  } else if ((sources.data?.items.length ?? 0) === 0) {
    gridState = "empty";
    stateTitle = t("secrets.wif.empty");
    stateMessage = t("secrets.wif.emptyBody");
  }

  return (
    <section className="grid gap-4 rounded-panel border border-border p-comfortable" aria-labelledby="secret-sync-wif-heading">
      <div>
        <h3 id="secret-sync-wif-heading" className="font-semibold">
          {t("secrets.wif.heading")}
        </h3>
        <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{t("secrets.wif.description")}</p>
      </div>

      <DataGrid
        ariaLabel={t("secrets.wif.listLabel")}
        rows={sources.data?.items ?? []}
        columns={columns}
        getRowId={(source) => source.id}
        state={gridState}
        stateTitle={stateTitle}
        stateMessage={stateMessage}
        virtualization={false}
      />

      {canWrite ? (
        <form className="grid gap-4 rounded-control border border-border p-3" onSubmit={save}>
          <div className="flex flex-wrap items-center justify-between gap-2">
            <h4 className="font-medium">{editingID ? t("secrets.wif.editHeading") : t("secrets.wif.createHeading")}</h4>
            <span className="text-xs text-muted-foreground">{t("secrets.wif.step", { step, total: 3 })}</span>
          </div>

          {step === 1 ? (
            <div className="grid gap-3 md:grid-cols-2">
              <Field label={t("secrets.wif.name")} error={form.formState.errors.name?.message} required>
                {(control) => <Input {...control} {...form.register("name")} />}
              </Field>
              <Field label={t("secrets.wif.provider")} required>
                {(control) => (
                  <Select
                    {...control}
                    {...form.register("provider", {
                      onChange: () => {
                        form.setValue("targetId", "");
                        form.clearErrors(["roleArn", "serviceAccount", "targetId"]);
                      },
                    })}
                  >
                    <option value="aws">{t("secrets.wif.providerAWS")}</option>
                    <option value="gcp">{t("secrets.wif.providerGCP")}</option>
                  </Select>
                )}
              </Field>
              {selectedProvider === "aws" ? (
                <Field label={t("secrets.wif.roleArn")} error={form.formState.errors.roleArn?.message} required>
                  {(control) => <Input {...control} {...form.register("roleArn")} placeholder={t("secrets.wif.roleArnPlaceholder")} />}
                </Field>
              ) : (
                <Field
                  label={t("secrets.wif.serviceAccount")}
                  description={t("secrets.wif.serviceAccountHint")}
                  error={form.formState.errors.serviceAccount?.message}
                >
                  {(control) => (
                    <Input
                      {...control}
                      {...form.register("serviceAccount")}
                      placeholder={t("secrets.wif.serviceAccountPlaceholder")}
                    />
                  )}
                </Field>
              )}
              <Field label={t("secrets.wif.audience")} error={form.formState.errors.audience?.message} required>
                {(control) => <Input {...control} {...form.register("audience")} />}
              </Field>
              <Field label={t("secrets.wif.subject")} error={form.formState.errors.subject?.message} required>
                {(control) => <Input {...control} {...form.register("subject")} />}
              </Field>
            </div>
          ) : null}

          {step === 2 ? (
            <div className="grid gap-3 md:grid-cols-2">
              <Field label={t("secrets.wif.target")} error={form.formState.errors.targetId?.message} required>
                {(control) => (
                  <Select {...control} {...form.register("targetId")}>
                    <option value="">{t("secrets.wif.selectTarget")}</option>
                    {providerTargets.map((target) => (
                      <option key={target.id} value={target.id}>
                        {target.name} ({target.id})
                      </option>
                    ))}
                  </Select>
                )}
              </Field>
              <Field label={t("secrets.wif.prefixes")} description={t("secrets.wif.prefixesHint")} error={form.formState.errors.prefixes?.message}>
                {(control) => <Textarea {...control} {...form.register("prefixes")} className="min-h-24 font-mono text-xs" />}
              </Field>
            </div>
          ) : null}

          {step === 3 ? (
            <div className="grid gap-3 md:grid-cols-2">
              <Field label={t("secrets.wif.proofRef")} description={t("secrets.wif.proofRefHint")} error={form.formState.errors.proofRef?.message} required>
                {(control) => <Input {...control} {...form.register("proofRef")} placeholder={t("secrets.wif.proofRefPlaceholder")} />}
              </Field>
              <Field label={t("secrets.wif.trustSource")} error={form.formState.errors.trustSourceId?.message} required>
                {(control) => (
                  <Select {...control} {...form.register("trustSourceId")}>
                    <option value="">{t("secrets.wif.selectTrustSource")}</option>
                    {oidcTrustSources.map((source) => (
                      <option key={source.id} value={source.id}>
                        {source.name} ({source.method})
                      </option>
                    ))}
                  </Select>
                )}
              </Field>
              <label className="flex items-center gap-2 text-sm font-medium">
                <input type="checkbox" {...form.register("enabled")} />
                {t("secrets.wif.enabled")}
              </label>
              <p className="rounded-control border border-border bg-muted/30 p-3 text-sm text-muted-foreground" role="note">
                {t("secrets.wif.offlineNote")}
              </p>
            </div>
          ) : null}

          <div className="flex flex-wrap justify-between gap-2">
            <span className="flex gap-2">
              {step > 1 ? (
                <Button type="button" variant="outline" onClick={() => setStep((current) => current - 1)}>
                  {t("secrets.wif.back")}
                </Button>
              ) : null}
              {editingID ? (
                <Button type="button" variant="ghost" onClick={resetForm}>
                  {t("secrets.wif.cancel")}
                </Button>
              ) : null}
            </span>
            {step < 3 ? (
              <Button type="button" onClick={() => void nextStep()}>
                {t("secrets.wif.next")}
              </Button>
            ) : (
              <Button type="submit" disabled={busy !== null || oidcTrustSources.length === 0 || providerTargets.length === 0}>
                {busy === "save" ? t("secrets.wif.saving") : t("secrets.wif.save")}
              </Button>
            )}
          </div>
          {notice ? <p role="status">{notice}</p> : null}
          {operationError ? (
            <p role="alert" className="text-sm font-medium text-destructive">
              {operationError}
            </p>
          ) : null}
        </form>
      ) : null}
    </section>
  );
}

function lines(value: string): string[] {
  return value
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
}

function statusTone(status: SecretSyncWorkloadIdentitySource["status"]) {
  switch (status) {
    case "active":
      return "success" as const;
    case "ready":
      return "info" as const;
    case "disabled":
    case "offline_disabled":
      return "warning" as const;
    case "exchange_failed":
      return "critical" as const;
  }
}
