import { useMemo, useState } from "react";
import { zodResolver } from "@hookform/resolvers/zod";
import { RotateCcw, ShieldCheck } from "lucide-react";
import { useForm, useWatch } from "react-hook-form";
import { z } from "zod";
import { CredentialChip } from "@/components/CredentialChip";
import { ErrorState, UnavailableState } from "@/components/StatePrimitives";
import { StatusBadge } from "@/components/StatusBadge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { StepShell } from "@/components/wizard/StepShell";
import { useTranslation } from "@/i18n/I18nProvider";
import { ApiError, api, type CodeSigningKeylessRequest, type CodeSigningPreview, type CodeSigningRequest, type CodeSigningSignature } from "@/lib/api";
import { apiProblemMessage } from "@/lib/apiProblem";
import { useCapabilities, useCapabilityAction } from "@/lib/capabilities";

type Mode = "key" | "keyless";

type CodeSigningForm = {
  mode: Mode;
  artifactType: string;
  digest: string;
  keyId: string;
  identityMethod: string;
  identityPayload: string;
};

type Review =
  | { inputKey: string; mode: "key"; request: CodeSigningRequest; plan: CodeSigningPreview }
  | { inputKey: string; mode: "keyless"; request: CodeSigningKeylessRequest; plan: CodeSigningPreview };

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function encodeSHA256Digest(input: string, invalidMessage: string): string {
  const trimmed = input.trim();
  const hex = trimmed.toLowerCase().startsWith("sha256:") ? trimmed.slice(7) : trimmed;
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) throw new Error(invalidMessage);
  const bytes = new Uint8Array(32);
  for (let index = 0; index < bytes.length; index += 1) bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  return bytesToBase64(bytes);
}

function encodeIdentityPayload(input: string): string {
  return bytesToBase64(new TextEncoder().encode(input.trim()));
}

function normalizedInputKey(values: CodeSigningForm): string {
  return JSON.stringify({
    mode: values.mode,
    artifact_type: values.artifactType.trim(),
    digest: values.digest
      .trim()
      .toLowerCase()
      .replace(/^sha256:/, ""),
    key_id: values.mode === "key" ? values.keyId.trim() : "",
    identity_method: values.mode === "keyless" ? values.identityMethod.trim() : "",
    identity_payload: values.mode === "keyless" ? values.identityPayload.trim() : "",
  });
}

function newCodeSigningIdempotencyKey(): string {
  if (typeof globalThis.crypto?.randomUUID === "function") return `codesign-${globalThis.crypto.randomUUID()}`;
  return `codesign-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function actionIsRunnable(enabled: boolean, state: string): boolean {
  return !enabled || state === "allowed" || state === "scoped";
}

function PlanList({ title, items }: { title: string; items: string[] }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>{title}</CardTitle>
      </CardHeader>
      <CardContent>
        <ul className="list-disc space-y-1 ps-5 text-sm text-muted-foreground">
          {items.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
      </CardContent>
    </Card>
  );
}

/** Preview is the safety contract: it binds the exact caller, digest, mode,
 * signer configuration, and (for keyless) identity proof without performing an
 * attestation, signing, persistence, or network call. Retry keeps one immutable
 * command and one idempotency key, so an uncertain response cannot double-sign. */
export function CodeSigningWorkflow() {
  const { t } = useTranslation();
  const capabilities = useCapabilities();
  const previewKey = useCapabilityAction("F50", "previewCodeArtifact");
  const previewKeyless = useCapabilityAction("F50", "previewCodeArtifactKeyless");
  const executeKey = useCapabilityAction("F50", "signCodeArtifact");
  const executeKeyless = useCapabilityAction("F50", "signCodeArtifactKeyless");
  const [step, setStep] = useState(0);
  const [review, setReview] = useState<Review | null>(null);
  const [idempotencyKey, setIdempotencyKey] = useState<string | null>(null);
  const [previewBusy, setPreviewBusy] = useState(false);
  const [executeBusy, setExecuteBusy] = useState(false);
  const [retryable, setRetryable] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [signature, setSignature] = useState<CodeSigningSignature | null>(null);

  const schema = useMemo(
    () =>
      z
        .object({
          mode: z.enum(["key", "keyless"]),
          artifactType: z.string().trim().min(1, t("codesign.workflow.required")),
          digest: z
            .string()
            .trim()
            .regex(/^(?:sha256:)?[0-9a-fA-F]{64}$/, t("codesign.workflow.digestError")),
          keyId: z.string(),
          identityMethod: z.string(),
          identityPayload: z.string(),
        })
        .superRefine((value, context) => {
          if (value.mode === "key" && !value.keyId.trim()) {
            context.addIssue({ code: "custom", path: ["keyId"], message: t("codesign.workflow.required") });
          }
          if (value.mode === "keyless" && !value.identityMethod.trim()) {
            context.addIssue({ code: "custom", path: ["identityMethod"], message: t("codesign.workflow.required") });
          }
          if (value.mode === "keyless" && !value.identityPayload.trim()) {
            context.addIssue({ code: "custom", path: ["identityPayload"], message: t("codesign.workflow.required") });
          }
        }),
    [t],
  );
  const form = useForm<CodeSigningForm>({
    resolver: zodResolver(schema),
    mode: "onTouched",
    defaultValues: { mode: "key", artifactType: "container", digest: "", keyId: "", identityMethod: "github_oidc", identityPayload: "" },
  });
  const values: CodeSigningForm = {
    mode: useWatch({ control: form.control, name: "mode" }) ?? "key",
    artifactType: useWatch({ control: form.control, name: "artifactType" }) ?? "",
    digest: useWatch({ control: form.control, name: "digest" }) ?? "",
    keyId: useWatch({ control: form.control, name: "keyId" }) ?? "",
    identityMethod: useWatch({ control: form.control, name: "identityMethod" }) ?? "",
    identityPayload: useWatch({ control: form.control, name: "identityPayload" }) ?? "",
  };
  const inputKey = normalizedInputKey(values);
  const currentReview = review?.inputKey === inputKey ? review : null;
  const previewAction = values.mode === "key" ? previewKey : previewKeyless;
  const executeAction = values.mode === "key" ? executeKey : executeKeyless;
  const previewRunnable = actionIsRunnable(capabilities.enabled, previewAction.state);
  const executeRunnable = actionIsRunnable(capabilities.enabled, executeAction.state);
  const configureReady =
    /^(?:sha256:)?[0-9a-fA-F]{64}$/.test(values.digest.trim()) &&
    Boolean(values.artifactType.trim()) &&
    (values.mode === "key" ? Boolean(values.keyId.trim()) : Boolean(values.identityMethod.trim() && values.identityPayload.trim()));

  function invalidateReview() {
    setReview(null);
    setIdempotencyKey(null);
    setRetryable(false);
    setSignature(null);
    setError(null);
    setStep(0);
  }

  function setMode(mode: Mode) {
    invalidateReview();
    form.setValue("mode", mode, { shouldDirty: true, shouldValidate: true });
  }

  async function reviewPlan(next: CodeSigningForm) {
    setPreviewBusy(true);
    setError(null);
    setSignature(null);
    setRetryable(false);
    try {
      const digest = encodeSHA256Digest(next.digest, t("codesign.workflow.digestError"));
      const nextInputKey = normalizedInputKey(next);
      if (next.mode === "key") {
        const request: CodeSigningRequest = { artifact_type: next.artifactType.trim(), digest, key_id: next.keyId.trim() };
        const plan = await api.previewCode(request);
        acceptPlan({ inputKey: nextInputKey, mode: "key", request, plan });
      } else {
        const request: CodeSigningKeylessRequest = {
          artifact_type: next.artifactType.trim(),
          digest,
          identity_method: next.identityMethod.trim(),
          identity_payload: encodeIdentityPayload(next.identityPayload),
        };
        const plan = await api.previewCodeKeyless(request);
        acceptPlan({ inputKey: nextInputKey, mode: "keyless", request, plan });
      }
    } catch (failure) {
      setReview(null);
      setIdempotencyKey(null);
      setError(apiProblemMessage(failure, t("codesign.workflow.previewFailed")));
    } finally {
      setPreviewBusy(false);
    }
  }

  function acceptPlan(next: Review) {
    if (!next.plan.effect_free || next.plan.preview_writes.length > 0 || next.plan.preview_external_effects.length > 0) {
      throw new Error(t("codesign.workflow.previewUnsafe"));
    }
    if (next.plan.ready && !next.plan.request_fingerprint) throw new Error(t("codesign.workflow.previewMissingFingerprint"));
    setReview(next);
    setIdempotencyKey(next.plan.ready ? newCodeSigningIdempotencyKey() : null);
    setStep(1);
  }

  async function executeReviewed() {
    if (!currentReview?.plan.ready || !currentReview.plan.request_fingerprint || !idempotencyKey) {
      setError(t("codesign.workflow.reviewRequired"));
      return;
    }
    setExecuteBusy(true);
    setError(null);
    try {
      const result =
        currentReview.mode === "key"
          ? await api.signCode({ ...currentReview.request, preview_fingerprint: currentReview.plan.request_fingerprint }, idempotencyKey)
          : await api.signCodeKeyless({ ...currentReview.request, preview_fingerprint: currentReview.plan.request_fingerprint }, idempotencyKey);
      setSignature(result);
      setRetryable(false);
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 409) {
        invalidateReview();
        setError(t("codesign.workflow.previewStale"));
      } else {
        setRetryable(!(failure instanceof ApiError) || failure.status >= 500);
        setError(apiProblemMessage(failure, t("codesign.workflow.executeFailed")));
      }
    } finally {
      setExecuteBusy(false);
    }
  }

  const steps = [
    {
      id: "configure",
      label: t("codesign.workflow.configureStep"),
      description: t("codesign.workflow.configureHelp"),
      progressState: configureReady ? ("done" as const) : ("pending" as const),
    },
    {
      id: "review",
      label: t("codesign.workflow.reviewStep"),
      description: t("codesign.workflow.reviewHelp"),
      progressState: currentReview?.plan.ready ? ("done" as const) : currentReview ? ("blocked" as const) : ("pending" as const),
    },
  ];

  return (
    <form
      aria-label={t("codesign.workflow.formLabel")}
      className="grid gap-4"
      onSubmit={(event) => {
        event.preventDefault();
        if (step === 0) void form.handleSubmit(reviewPlan)();
        else void executeReviewed();
      }}
    >
      {!previewRunnable || !executeRunnable ? (
        <UnavailableState title={t("codesign.workflow.permissionBlocked")}>
          {previewAction.unavailable?.detail ?? executeAction.unavailable?.detail ?? t("codesign.workflow.permissionHelp")}
        </UnavailableState>
      ) : null}
      <StepShell
        steps={steps}
        currentIndex={step}
        nextDisabled={!configureReady || previewBusy || !previewRunnable}
        nextLabel={previewBusy ? t("codesign.workflow.reviewing") : t("codesign.workflow.reviewAction")}
        onNext={step === 0 ? () => void form.handleSubmit(reviewPlan)() : undefined}
        onPrevious={step === 1 ? () => setStep(0) : undefined}
        progressLabel={t("codesign.workflow.progress")}
      >
        {step === 0 ? (
          <div className="grid gap-5">
            <fieldset className="grid gap-2">
              <legend className="text-sm font-medium">{t("codesign.workflow.mode")}</legend>
              <div className="flex flex-wrap gap-2">
                <Button
                  type="button"
                  variant={values.mode === "key" ? "default" : "outline"}
                  aria-pressed={values.mode === "key"}
                  onClick={() => setMode("key")}
                >
                  {t("codesign.workflow.managedMode")}
                </Button>
                <Button
                  type="button"
                  variant={values.mode === "keyless" ? "default" : "outline"}
                  aria-pressed={values.mode === "keyless"}
                  onClick={() => setMode("keyless")}
                >
                  {t("codesign.workflow.keylessMode")}
                </Button>
              </div>
            </fieldset>
            <div className="grid gap-4 md:grid-cols-2">
              <Field
                label={t("codesign.workflow.artifactType")}
                description={t("codesign.workflow.artifactTypeHelp")}
                error={form.formState.errors.artifactType?.message}
                required
              >
                {(field) => (
                  <Select {...field} {...form.register("artifactType", { onChange: invalidateReview })} required>
                    <option value="container">{t("codesign.workflow.artifactContainer")}</option>
                    <option value="oci-image">{t("codesign.workflow.artifactOCI")}</option>
                    <option value="sbom">{t("codesign.workflow.artifactSBOM")}</option>
                    <option value="blob">{t("codesign.workflow.artifactBlob")}</option>
                  </Select>
                )}
              </Field>
              <Field
                label={t("codesign.workflow.digest")}
                description={t("codesign.workflow.digestHelp")}
                error={form.formState.errors.digest?.message}
                required
              >
                {(field) => (
                  <Input
                    {...field}
                    {...form.register("digest", { onChange: invalidateReview })}
                    placeholder={t("codesign.workflow.digestPlaceholder")}
                    className="font-mono text-xs"
                    required
                  />
                )}
              </Field>
              {values.mode === "key" ? (
                <Field
                  label={t("codesign.workflow.keyId")}
                  description={t("codesign.workflow.keyIdHelp")}
                  error={form.formState.errors.keyId?.message}
                  required
                >
                  {(field) => (
                    <Input
                      {...field}
                      {...form.register("keyId", { onChange: invalidateReview })}
                      placeholder={t("codesign.workflow.keyIdPlaceholder")}
                      required
                    />
                  )}
                </Field>
              ) : (
                <>
                  <Field
                    label={t("codesign.workflow.identityMethod")}
                    description={t("codesign.workflow.identityMethodHelp")}
                    error={form.formState.errors.identityMethod?.message}
                    required
                  >
                    {(field) => <Input {...field} {...form.register("identityMethod", { onChange: invalidateReview })} required />}
                  </Field>
                  <Field
                    className="md:col-span-2"
                    label={t("codesign.workflow.identityProof")}
                    description={t("codesign.workflow.identityProofHelp")}
                    error={form.formState.errors.identityPayload?.message}
                    required
                  >
                    {(field) => (
                      <Textarea
                        {...field}
                        {...form.register("identityPayload", { onChange: invalidateReview })}
                        className="min-h-24 font-mono text-xs"
                        autoComplete="off"
                        required
                      />
                    )}
                  </Field>
                </>
              )}
            </div>
          </div>
        ) : currentReview ? (
          <div className="grid gap-5">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div>
                <h3 className="font-semibold">{currentReview.plan.ready ? t("codesign.workflow.previewReady") : t("codesign.workflow.previewBlocked")}</h3>
                <p className="mt-1 text-sm text-muted-foreground">{t("codesign.workflow.previewNoEffects")}</p>
              </div>
              <StatusBadge
                value={currentReview.plan.ready ? "ready" : "blocked"}
                label={currentReview.plan.ready ? t("codesign.workflow.ready") : t("codesign.workflow.blocked")}
                tone={currentReview.plan.ready ? "success" : "warning"}
              />
            </div>
            <dl className="grid gap-3 text-sm sm:grid-cols-2 lg:grid-cols-4">
              <div>
                <dt className="text-muted-foreground">{t("codesign.workflow.mode")}</dt>
                <dd>{currentReview.plan.mode === "key" ? t("codesign.workflow.managedMode") : t("codesign.workflow.keylessMode")}</dd>
              </div>
              <div>
                <dt className="text-muted-foreground">{t("codesign.workflow.artifactType")}</dt>
                <dd>{currentReview.plan.artifact_type}</dd>
              </div>
              <div>
                <dt className="text-muted-foreground">{t("codesign.workflow.digest")}</dt>
                <dd className="break-all font-mono text-xs">{currentReview.plan.digest_sha256}</dd>
              </div>
              <div>
                <dt className="text-muted-foreground">{t("codesign.workflow.signer")}</dt>
                <dd className="break-all font-mono text-xs">{currentReview.plan.key_id ?? currentReview.plan.identity_method}</dd>
              </div>
              <div>
                <dt className="text-muted-foreground">{t("codesign.workflow.algorithm")}</dt>
                <dd>{currentReview.plan.signing_algorithm ?? t("codesign.workflow.runtimeSelected")}</dd>
              </div>
              <div>
                <dt className="text-muted-foreground">{t("codesign.workflow.transparency")}</dt>
                <dd>{currentReview.plan.transparency_destination ?? t("codesign.workflow.notConfigured")}</dd>
              </div>
              <div>
                <dt className="text-muted-foreground">{t("codesign.workflow.approval")}</dt>
                <dd>{currentReview.plan.approval_required ? t("codesign.workflow.approvalRequired") : t("codesign.workflow.policyAtExecution")}</dd>
              </div>
              <div>
                <dt className="text-muted-foreground">{t("codesign.workflow.permission")}</dt>
                <dd className="font-mono text-xs">{currentReview.plan.required_permission}</dd>
              </div>
            </dl>
            {currentReview.plan.blockers.length > 0 ? (
              <ErrorState title={t("codesign.workflow.previewBlocked")}>
                <ul className="list-disc space-y-1 ps-5">
                  {currentReview.plan.blockers.map((blocker) => (
                    <li key={blocker}>{blocker}</li>
                  ))}
                </ul>
              </ErrorState>
            ) : null}
            <div className="grid gap-4 lg:grid-cols-3">
              <PlanList title={t("codesign.workflow.effects")} items={[...currentReview.plan.execute_writes, ...currentReview.plan.execute_external_effects]} />
              <PlanList title={t("codesign.workflow.recovery")} items={currentReview.plan.recovery_steps} />
              <PlanList title={t("codesign.workflow.verification")} items={currentReview.plan.verification_steps} />
            </div>
            <p className="text-sm text-muted-foreground">{currentReview.plan.secret_data_handling}</p>
            <details>
              <summary className="cursor-pointer text-sm font-medium text-primary">{t("codesign.workflow.exactEvidence")}</summary>
              <div className="mt-2 grid gap-2">
                <CredentialChip value={currentReview.plan.request_fingerprint} label={t("codesign.workflow.requestFingerprint")} fullValue />
                <CredentialChip value={currentReview.plan.configuration_fingerprint} label={t("codesign.workflow.configurationFingerprint")} fullValue />
              </div>
            </details>
          </div>
        ) : (
          <ErrorState title={t("codesign.workflow.previewFailed")}>{t("codesign.workflow.reviewRequired")}</ErrorState>
        )}
      </StepShell>
      {error ? <ErrorState title={step === 0 ? t("codesign.workflow.previewFailed") : t("codesign.workflow.executeFailed")}>{error}</ErrorState> : null}
      {step === 1 && currentReview?.plan.ready ? (
        <div className="flex flex-wrap justify-end gap-2">
          {retryable ? (
            <Button type="button" variant="outline" onClick={() => setStep(0)}>
              <RotateCcw className="h-4 w-4" aria-hidden="true" />
              {t("codesign.workflow.newReview")}
            </Button>
          ) : null}
          <Button type="submit" disabled={executeBusy || !executeRunnable} loading={executeBusy}>
            <ShieldCheck className="h-4 w-4" aria-hidden="true" />
            {retryable ? t("codesign.workflow.retryReviewed") : t("codesign.workflow.executeReviewed")}
          </Button>
        </div>
      ) : null}
      {signature ? <SignatureReceipt signature={signature} /> : null}
    </form>
  );
}

function SignatureReceipt({ signature }: { signature: CodeSigningSignature }) {
  const { t } = useTranslation();
  return (
    <Card aria-live="polite">
      <CardHeader>
        <CardTitle>{t("codesign.workflow.receiptTitle")}</CardTitle>
      </CardHeader>
      <CardContent>
        <dl className="grid gap-3 text-sm sm:grid-cols-2">
          <div>
            <dt className="text-muted-foreground">{t("codesign.workflow.algorithm")}</dt>
            <dd>{signature.algorithm}</dd>
          </div>
          <div>
            <dt className="text-muted-foreground">{t("codesign.workflow.artifactType")}</dt>
            <dd>{signature.artifact_type}</dd>
          </div>
          {signature.key_id ? (
            <div>
              <dt className="text-muted-foreground">{t("codesign.workflow.signer")}</dt>
              <dd className="font-mono text-xs">{signature.key_id}</dd>
            </div>
          ) : null}
          {signature.fulcio_issuer ? (
            <div>
              <dt className="text-muted-foreground">{t("codesign.workflow.fulcioIssuer")}</dt>
              <dd className="break-all font-mono text-xs">{signature.fulcio_issuer}</dd>
            </div>
          ) : null}
          {signature.fulcio_san ? (
            <div>
              <dt className="text-muted-foreground">{t("codesign.receipt.fulcioSAN")}</dt>
              <dd className="break-all font-mono text-xs">{signature.fulcio_san}</dd>
            </div>
          ) : null}
          {signature.transparency_destination ? (
            <div>
              <dt className="text-muted-foreground">{t("codesign.receipt.transparencyDestination")}</dt>
              <dd className="font-mono text-xs">{signature.transparency_destination}</dd>
            </div>
          ) : null}
          <div className="sm:col-span-2">
            <dt className="text-muted-foreground">{t("codesign.receipt.signatureBase64")}</dt>
            <dd className="break-all font-mono text-xs">{signature.signature}</dd>
            <a
              href={`data:application/octet-stream;base64,${signature.signature}`}
              download="artifact.sig"
              className="mt-2 inline-flex text-xs font-medium text-primary underline"
            >
              {t("codesign.receipt.downloadSignature")}
            </a>
          </div>
          <div className="sm:col-span-2">
            <dt className="text-muted-foreground">{t("codesign.workflow.publicKey")}</dt>
            <dd className="break-all font-mono text-xs">{signature.public_key_der}</dd>
          </div>
        </dl>
      </CardContent>
    </Card>
  );
}
