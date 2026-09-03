import { useState, type FormEvent } from "react";
import { zodResolver } from "@hookform/resolvers/zod";
import { useForm } from "react-hook-form";
import { z } from "zod";
import { Eye, Loader2, RotateCcw, ScanSearch } from "lucide-react";
import { Link } from "react-router-dom";
import { ErrorState, UnavailableState } from "@/components/StatePrimitives";
import { StepShell } from "@/components/wizard/StepShell";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { useTranslation, translateNow } from "@/i18n/I18nProvider";
import {
  ApiError,
  api,
  type SecretRepositoryScanPosture,
  type SecretScan,
  type SecretScanPreview,
  type SecretScanRequest,
  type ThirdPartySecretScanPosture,
  type ThirdPartySecretScanReceipt,
} from "@/lib/api";
import { apiProblemMessage } from "@/lib/apiProblem";
import { RepositoryScanPosture, ThirdPartyScanPosture, defaultThirdPartyProviders } from "./SecretsPageParts";

const scanDefaults = { path: "", mode: "workspace" as "workspace" | "git_history", customRulesPath: "" };
type ScanFormValues = typeof scanDefaults;

function newScanIdempotencyKey(): string {
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) return crypto.randomUUID();
  return `secret-scan-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

export function SecretScanningWorkflow({
  repoPosture,
  thirdPartyPosture,
  loadingBlocked,
}: {
  repoPosture: SecretRepositoryScanPosture | null;
  thirdPartyPosture: ThirdPartySecretScanPosture | null;
  loadingBlocked: boolean;
}) {
  const { t } = useTranslation();
  const [step, setStep] = useState(0);
  const [plan, setPlan] = useState<SecretScanPreview | null>(null);
  const [result, setResult] = useState<SecretScan | null>(null);
  const [idempotencyKey, setIdempotencyKey] = useState<string | null>(null);
  const [previewBusy, setPreviewBusy] = useState(false);
  const [runBusy, setRunBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [retryable, setRetryable] = useState(false);
  const [thirdPartyProvider, setThirdPartyProvider] = useState("cicd_log");
  const [thirdPartySource, setThirdPartySource] = useState("");
  const [thirdPartyArtifactPath, setThirdPartyArtifactPath] = useState("");
  const [thirdPartyEvent, setThirdPartyEvent] = useState("");
  const [thirdPartyBusy, setThirdPartyBusy] = useState(false);
  const [thirdPartyError, setThirdPartyError] = useState<string | null>(null);
  const [thirdPartyReceipt, setThirdPartyReceipt] = useState<ThirdPartySecretScanReceipt | null>(null);
  const required = t("secrets.scan.required");
  const schema = z.object({
    path: z.string().trim().min(1, required),
    mode: z.enum(["workspace", "git_history"]),
    customRulesPath: z.string().trim(),
  });
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<ScanFormValues>({ resolver: zodResolver(schema), defaultValues: scanDefaults });

  async function review(values: ScanFormValues) {
    setPreviewBusy(true);
    setError(null);
    setRetryable(false);
    setResult(null);
    try {
      const request: SecretScanRequest = {
        path: values.path.trim(),
        mode: values.mode,
        ...(values.customRulesPath.trim() ? { custom_rules_path: values.customRulesPath.trim() } : {}),
      };
      const reviewed = await api.previewSecretScan(request);
      if (!reviewed.effect_free || reviewed.preview_writes.length > 0 || reviewed.preview_external_effects.length > 0) {
        throw new Error(t("secrets.scan.previewNotEffectFree"));
      }
      if (!reviewed.ready || reviewed.blockers.length > 0) {
        throw new Error(reviewed.blockers.join(" ") || t("secrets.scan.previewBlocked"));
      }
      setPlan(reviewed);
      setIdempotencyKey(newScanIdempotencyKey());
      setStep(1);
    } catch (failure) {
      setPlan(null);
      setIdempotencyKey(null);
      setError(apiProblemMessage(failure, t("secrets.scan.previewFailed")));
    } finally {
      setPreviewBusy(false);
    }
  }

  async function executeReviewed() {
    if (!plan || !idempotencyKey) {
      setError(t("secrets.scan.reviewRequired"));
      return;
    }
    setRunBusy(true);
    setError(null);
    try {
      const scan = await api.scanSecrets(
        {
          path: plan.target_path,
          mode: plan.mode,
          ...(plan.custom_rules_path ? { custom_rules_path: plan.custom_rules_path } : {}),
          preview_fingerprint: plan.request_fingerprint,
        },
        idempotencyKey,
      );
      setResult(scan);
      setRetryable(false);
      setStep(2);
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 409) {
        setPlan(null);
        setIdempotencyKey(null);
        setRetryable(false);
        setStep(0);
        setError(t("secrets.scan.reviewStale"));
      } else {
        setRetryable(!(failure instanceof ApiError) || failure.status >= 500);
        setError(apiProblemMessage(failure, t("secrets.scan.runFailed")));
      }
    } finally {
      setRunBusy(false);
    }
  }

  function startAnother() {
    reset(scanDefaults);
    setPlan(null);
    setResult(null);
    setIdempotencyKey(null);
    setError(null);
    setRetryable(false);
    setStep(0);
  }

  async function submitThirdPartySecretScan(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setThirdPartyError(null);
    setThirdPartyBusy(true);
    try {
      const source = thirdPartySource.trim();
      const artifactPath = thirdPartyArtifactPath.trim();
      if (!source) throw new Error("Source is required");
      if (!artifactPath) throw new Error("Artifact path is required");
      const receipt = await api.ingestThirdPartySecretScan(thirdPartyProvider, {
        source,
        artifact_path: artifactPath,
        ...(thirdPartyEvent.trim() ? { event: thirdPartyEvent.trim() } : {}),
      });
      setThirdPartyReceipt(receipt);
    } catch (failure) {
      setThirdPartyError(apiProblemMessage(failure, t("secrets.thirdPartyScan.errorTitle")));
    } finally {
      setThirdPartyBusy(false);
    }
  }

  return (
    <section aria-labelledby="secret-scanning-heading" className="grid min-w-0 gap-5 border-y border-border py-5">
      <div>
        <h2 id="secret-scanning-heading" className="text-title font-semibold">
          {translateNow("source.code.and.ci.secret.scanning.bridge.27c18d763b")}
        </h2>
        <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{t("secrets.scan.description")}</p>
        {/* F39: previewSecretScan -> scanSecrets -> discovery run/findings -> same-key recovery. */}
      </div>

      <StepShell
        currentIndex={step}
        progressLabel={t("secrets.scan.progress")}
        steps={[
          { id: "configure", label: t("secrets.scan.stepConfigure"), description: t("secrets.scan.stepConfigureHelp") },
          { id: "review", label: t("secrets.scan.stepReview"), description: t("secrets.scan.stepReviewHelp") },
          { id: "prove", label: t("secrets.scan.stepProve"), description: t("secrets.scan.stepProveHelp") },
        ]}
        onPrevious={
          step === 1 && !runBusy
            ? () => {
                setPlan(null);
                setIdempotencyKey(null);
                setError(null);
                setRetryable(false);
                setStep(0);
              }
            : undefined
        }
      >
        {step === 0 ? (
          <form
            aria-label={translateNow("source.run.secret.scan.89f2ed7a1b")}
            onSubmit={(event) => void handleSubmit(review)(event)}
            className="grid gap-4 md:grid-cols-2"
          >
            <Field
              controlId="secret-scan-path"
              label={translateNow("source.path.62fa5a5b0d")}
              required
              error={errors.path?.message}
              description={t("secrets.scan.pathHelp")}
              className="md:col-span-2"
            >
              {(control) => (
                <Input {...control} {...register("path")} placeholder={translateNow("source.github.com.example.payments.8d7be8211f")} autoComplete="off" />
              )}
            </Field>
            <Field label={t("secrets.scan.mode")} required error={errors.mode?.message} description={t("secrets.scan.modeHelp")}>
              {(control) => (
                <Select {...control} {...register("mode")}>
                  <option value="workspace">{t("secrets.scan.modeWorkspace")}</option>
                  <option value="git_history">{t("secrets.scan.modeGitHistory")}</option>
                </Select>
              )}
            </Field>
            <Field label={t("secrets.scan.customRules")} error={errors.customRulesPath?.message} description={t("secrets.scan.customRulesHelp")}>
              {(control) => <Input {...control} {...register("customRulesPath")} placeholder={t("secrets.scan.customRulesPlaceholder")} autoComplete="off" />}
            </Field>
            <div className="md:col-span-2 flex justify-end">
              <Button type="submit" disabled={previewBusy || loadingBlocked}>
                {previewBusy ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <Eye className="h-4 w-4" aria-hidden="true" />}
                {t("secrets.scan.review")}
              </Button>
            </div>
          </form>
        ) : null}

        {step === 1 && plan ? (
          <div className="grid gap-4" aria-label={t("secrets.scan.reviewedPlanLabel")}>
            <div>
              <h3 className="font-semibold">{t("secrets.scan.reviewedPlan")}</h3>
              <p className="mt-1 text-sm text-muted-foreground">{t("secrets.scan.nothingHappened")}</p>
            </div>
            <dl className="grid gap-3 text-sm sm:grid-cols-2 lg:grid-cols-4">
              <div className="min-w-0">
                <dt className="text-muted-foreground">{translateNow("source.path.62fa5a5b0d")}</dt>
                <dd className="break-all font-mono text-xs">{plan.target_path}</dd>
              </div>
              <div>
                <dt className="text-muted-foreground">{t("secrets.scan.mode")}</dt>
                <dd>{plan.mode}</dd>
              </div>
              <div>
                <dt className="text-muted-foreground">{translateNow("source.rules.4228aeb07c")}</dt>
                <dd>{plan.rules_active}</dd>
              </div>
              <div>
                <dt className="text-muted-foreground">{t("secrets.scan.permission")}</dt>
                <dd className="font-mono text-xs">{plan.required_permission}</dd>
              </div>
            </dl>
            <p className="text-sm">{plan.secret_data_handling}</p>
            <div className="grid gap-4 md:grid-cols-2">
              <div>
                <h4 className="font-medium">{t("secrets.scan.executionEffects")}</h4>
                <ul className="mt-1 list-disc space-y-1 pl-5 text-sm text-muted-foreground">
                  {[...plan.execute_external_effects, ...plan.execute_writes].map((item) => (
                    <li key={item}>{item}</li>
                  ))}
                </ul>
              </div>
              <div>
                <h4 className="font-medium">{t("secrets.scan.recovery")}</h4>
                <ul className="mt-1 list-disc space-y-1 pl-5 text-sm text-muted-foreground">
                  {plan.recovery_steps.map((item) => (
                    <li key={item}>{item}</li>
                  ))}
                </ul>
              </div>
            </div>
            <details>
              <summary className="cursor-pointer text-sm font-medium">{t("secrets.scan.exactEvidence")}</summary>
              <p className="mt-2 break-all font-mono text-xs text-muted-foreground">{plan.request_fingerprint}</p>
            </details>
            {error ? (
              <ErrorState title={t("secrets.scan.failedTitle")}>
                <p>{error}</p>
                {retryable ? <p className="mt-2">{t("secrets.scan.retryHelp")}</p> : null}
              </ErrorState>
            ) : null}
            <div className="flex flex-wrap justify-end gap-2">
              <Button type="button" onClick={() => void executeReviewed()} disabled={runBusy}>
                {runBusy ? (
                  <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
                ) : retryable ? (
                  <RotateCcw className="h-4 w-4" aria-hidden="true" />
                ) : (
                  <ScanSearch className="h-4 w-4" aria-hidden="true" />
                )}
                {retryable ? t("secrets.scan.retryReviewed") : t("secrets.scan.runReviewed")}
              </Button>
            </div>
          </div>
        ) : null}

        {step === 2 && result ? (
          <div className="grid gap-4">
            <div>
              <h3 className="font-semibold">{t("secrets.scan.completed")}</h3>
              <p className="mt-1 text-sm text-muted-foreground">{t("secrets.scan.completedHelp")}</p>
            </div>
            <dl className="grid gap-3 text-sm sm:grid-cols-2 lg:grid-cols-5">
              <div className="min-w-0">
                <dt className="text-muted-foreground">{translateNow("source.run.id.26d3e7aaac")}</dt>
                <dd className="break-all font-mono text-xs">{result.run_id}</dd>
              </div>
              <div>
                <dt className="text-muted-foreground">{translateNow("source.scanner.71d4cf953e")}</dt>
                <dd>{result.scanner}</dd>
              </div>
              <div>
                <dt className="text-muted-foreground">{t("secrets.scan.mode")}</dt>
                <dd>{result.mode}</dd>
              </div>
              <div>
                <dt className="text-muted-foreground">{translateNow("source.rules.4228aeb07c")}</dt>
                <dd>{result.rules_active}</dd>
              </div>
              <div>
                <dt className="text-muted-foreground">{translateNow("source.findings.e171c2ff25")}</dt>
                <dd>{result.findings_count}</dd>
              </div>
            </dl>
            <div className="flex flex-wrap gap-2">
              {result.capabilities.map((capability) => (
                <span key={capability} className="rounded-control border border-border px-2 py-1 text-xs text-muted-foreground">
                  {capability}
                </span>
              ))}
            </div>
            <div className="overflow-x-auto">
              <table className="ui-table min-w-[48rem]">
                <caption className="sr-only">{translateNow("source.secret.scan.findings.3462f78805")}</caption>
                <thead>
                  <tr>
                    <th scope="col">{translateNow("source.rule.62845f31a2")}</th>
                    <th scope="col">{translateNow("source.file.50009ce1da")}</th>
                    <th scope="col">{translateNow("source.line.d7852cd0d2")}</th>
                    <th scope="col">{translateNow("source.redacted.reference.f904f7809b")}</th>
                  </tr>
                </thead>
                <tbody>
                  {result.findings.map((finding) => (
                    <tr key={`${finding.rule_id}-${finding.file}-${finding.line}`}>
                      <td>{finding.rule_id}</td>
                      <td>{finding.file}</td>
                      <td className="font-mono text-xs">{finding.line}</td>
                      <td className="font-mono text-xs">{finding.credential_ref}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="flex flex-wrap gap-2">
              <Link className="text-link text-sm font-medium" to={`/discovery?run_id=${encodeURIComponent(result.run_id)}`}>
                {t("secrets.scan.openDiscovery")}
              </Link>
              <Button type="button" variant="outline" onClick={startAnother}>
                {t("secrets.scan.startAnother")}
              </Button>
            </div>
          </div>
        ) : null}
        {step === 0 && error ? <ErrorState title={t("secrets.scan.failedTitle")}>{error}</ErrorState> : null}
      </StepShell>

      <Card>
        {/* TRACE-005 source anchor: secret-scanning triage is library-only; scan automation and redacted discovery handoff are served. */}
        <CardHeader>
          <CardTitle>{t("secrets.scan.automationHeading")}</CardTitle>
          <p className="text-sm text-muted-foreground">{t("secrets.scan.automationHelp")}</p>
        </CardHeader>
        <CardContent>
          <details className="group">
            <summary className="cursor-pointer font-medium text-foreground">
              {t("secrets.scan.advancedSummary")}
              <span className="ms-2 text-sm font-normal text-muted-foreground">{t("secrets.scan.advancedSummaryHelp")}</span>
            </summary>
            <div className="mt-4 grid gap-4">
              {repoPosture && <RepositoryScanPosture posture={repoPosture} />}
              {thirdPartyPosture && <ThirdPartyScanPosture posture={thirdPartyPosture} />}
              <form
                aria-label={t("secrets.thirdPartyScan.form")}
                onSubmit={(event) => void submitThirdPartySecretScan(event)}
                className="grid gap-3 md:grid-cols-[12rem_minmax(0,1fr)_minmax(0,1fr)_minmax(0,1fr)_auto]"
              >
                <label className="grid gap-1 text-sm">
                  <span className="font-medium">{t("secrets.thirdPartyScan.provider")}</span>
                  <select
                    className="rounded-md border border-border bg-background px-3 py-2"
                    value={thirdPartyProvider}
                    onChange={(event) => setThirdPartyProvider(event.target.value)}
                  >
                    {(thirdPartyPosture?.providers ?? defaultThirdPartyProviders()).map((provider) => (
                      <option key={provider.id} value={provider.id}>
                        {provider.name}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="grid gap-1 text-sm">
                  <span className="font-medium">{t("secrets.thirdPartyScan.source")}</span>
                  <input
                    className="rounded-md border border-border bg-background px-3 py-2"
                    value={thirdPartySource}
                    onChange={(event) => setThirdPartySource(event.target.value)}
                    placeholder={t("secrets.thirdPartyScan.sourcePlaceholder")}
                    required
                  />
                </label>
                <label className="grid gap-1 text-sm">
                  <span className="font-medium">{t("secrets.thirdPartyScan.artifactPath")}</span>
                  <input
                    className="rounded-md border border-border bg-background px-3 py-2"
                    value={thirdPartyArtifactPath}
                    onChange={(event) => setThirdPartyArtifactPath(event.target.value)}
                    placeholder={t("secrets.thirdPartyScan.artifactPlaceholder")}
                    required
                  />
                </label>
                <label className="grid gap-1 text-sm">
                  <span className="font-medium">{t("secrets.thirdPartyScan.event")}</span>
                  <input
                    className="rounded-md border border-border bg-background px-3 py-2"
                    value={thirdPartyEvent}
                    onChange={(event) => setThirdPartyEvent(event.target.value)}
                    placeholder={t("secrets.thirdPartyScan.eventPlaceholder")}
                  />
                </label>
                <Button type="submit" className="self-end" disabled={thirdPartyBusy || loadingBlocked}>
                  {thirdPartyBusy ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <Eye className="h-4 w-4" aria-hidden="true" />}
                  {thirdPartyBusy ? t("secrets.thirdPartyScan.queueing") : t("secrets.thirdPartyScan.queue")}
                </Button>
              </form>
              {thirdPartyError && <ErrorState title={t("secrets.thirdPartyScan.errorTitle")}>{thirdPartyError}</ErrorState>}
              {thirdPartyReceipt && (
                <p role="status" className="rounded-control border border-status-success/30 bg-status-success/10 px-3 py-2 text-sm text-status-success">
                  {t("secrets.thirdPartyScan.accepted", { provider: thirdPartyReceipt.provider, run: thirdPartyReceipt.run_id })}
                </p>
              )}
              <UnavailableState title={t("secrets.scan.triageLibraryOnlyTitle")}>{t("secrets.scan.triageLibraryOnlyBody")}</UnavailableState>
            </div>
          </details>
        </CardContent>
      </Card>
    </section>
  );
}
