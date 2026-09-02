import { useEffect, useMemo, useState, type FormEvent } from "react";
import { Loader2, LogIn } from "lucide-react";
import { ErrorState } from "@/components/StatePrimitives";
import { StatusBadge } from "@/components/StatusBadge";
import { Button } from "@/components/ui/button";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { StepShell } from "@/components/wizard/StepShell";
import { useTranslation, translateNow } from "@/i18n/I18nProvider";
import { api, ApiError, type MachineAuthMethod, type MachineLoginPreview, type MachineLoginResponse } from "@/lib/api";
import { apiProblemMessage } from "@/lib/apiProblem";
import { MachineSession, RevealPanel, formatCommandArgv } from "./SecretsPageParts";

function methodKey(method: MachineAuthMethod | undefined): string {
  return method ? JSON.stringify(method) : "";
}

function PlanList({ title, items }: { title: string; items: string[] }) {
  if (items.length === 0) return null;
  return (
    <div>
      <h4 className="font-medium">{title}</h4>
      <ul className="mt-1 list-disc space-y-1 pl-5 text-sm text-muted-foreground">
        {items.map((item) => (
          <li key={item}>{item}</li>
        ))}
      </ul>
    </div>
  );
}

export function MachineAuthWorkflow({
  methods,
  loadBlocked,
  onSessionIssued,
}: {
  methods: MachineAuthMethod[] | null;
  loadBlocked: boolean;
  onSessionIssued: () => Promise<void>;
}) {
  const { t } = useTranslation();
  const [step, setStep] = useState(0);
  const [methodName, setMethodName] = useState("token");
  const [credential, setCredential] = useState("");
  const [review, setReview] = useState<{ requestKey: string; plan: MachineLoginPreview } | null>(null);
  const [reviewBusy, setReviewBusy] = useState(false);
  const [reviewError, setReviewError] = useState<string | null>(null);
  const [reviewStale, setReviewStale] = useState(false);
  const [loginBusy, setLoginBusy] = useState(false);
  const [loginError, setLoginError] = useState<string | null>(null);
  const [session, setSession] = useState<MachineLoginResponse | null>(null);
  const [sessionToken, setSessionToken] = useState("");

  const selectedMethod = useMemo(() => methods?.find((method) => method.name === methodName), [methodName, methods]);
  const currentRequestKey = methodKey(selectedMethod);
  const reviewedPlan = review?.requestKey === currentRequestKey ? review.plan : null;
  const configureReady = Boolean(selectedMethod) && !loadBlocked;

  useEffect(() => {
    if (!methods?.length || methods.some((method) => method.name === methodName)) return;
    setMethodName(methods.find((method) => !method.disabled)?.name ?? methods[0].name);
  }, [methodName, methods]);

  function invalidateReview(nextMethod: string) {
    if (review) setReviewStale(true);
    setMethodName(nextMethod);
    setReview(null);
    setCredential("");
    setSession(null);
    setSessionToken("");
    setLoginError(null);
    setReviewError(null);
    setStep(0);
  }

  async function preview() {
    if (!selectedMethod) return;
    setReviewBusy(true);
    setReviewError(null);
    setLoginError(null);
    setSession(null);
    setSessionToken("");
    try {
      const plan = await api.previewMachineLogin({ method: selectedMethod.name });
      setReview({ requestKey: methodKey(selectedMethod), plan });
      setReviewStale(false);
      setStep(1);
    } catch (error) {
      setReviewError(apiProblemMessage(error, t("secrets.login.reviewFailed")));
    } finally {
      setReviewBusy(false);
    }
  }

  async function login(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!reviewedPlan?.ready || !credential) {
      setLoginError(t("secrets.login.reviewRequired"));
      return;
    }
    setLoginBusy(true);
    setLoginError(null);
    setSession(null);
    try {
      const result = await api.machineLogin({
        method: reviewedPlan.method.name,
        credential,
        preview_fingerprint: reviewedPlan.request_fingerprint,
      });
      setSession(result);
      setSessionToken(result.token);
      setStep(2);
      await onSessionIssued();
    } catch (error) {
      setLoginError(apiProblemMessage(error, t("secrets.login.executionFailed")));
      if (error instanceof ApiError && error.status === 409) {
        setReview(null);
        setReviewStale(true);
        setStep(0);
      }
    } finally {
      setCredential("");
      setLoginBusy(false);
    }
  }

  function startAgain() {
    setReview(null);
    setCredential("");
    setSession(null);
    setSessionToken("");
    setLoginError(null);
    setReviewError(null);
    setReviewStale(false);
    setStep(0);
  }

  const steps = [
    {
      id: "configure",
      label: t("secrets.login.configureStep"),
      description: t("secrets.login.configureStepHelp"),
      progressState: configureReady ? ("done" as const) : ("pending" as const),
    },
    {
      id: "review",
      label: t("secrets.login.reviewStep"),
      description: t("secrets.login.reviewStepHelp"),
      progressState: reviewedPlan?.ready ? ("done" as const) : reviewedPlan ? ("blocked" as const) : ("pending" as const),
    },
    {
      id: "verify",
      label: t("secrets.login.verifyStep"),
      description: t("secrets.login.verifyStepHelp"),
      progressState: session ? ("done" as const) : ("pending" as const),
    },
  ];

  return (
    <form aria-label={translateNow("source.machine.login.test.7f62ed2b92")} onSubmit={(event) => void login(event)} className="grid gap-4">
      <StepShell
        steps={steps}
        currentIndex={step}
        nextDisabled={!configureReady || reviewBusy}
        nextLabel={reviewBusy ? t("secrets.login.reviewing") : t("secrets.login.reviewAction")}
        onNext={step === 0 ? () => void preview() : undefined}
        onPrevious={step > 0 ? () => setStep(step - 1) : undefined}
        progressLabel={t("secrets.login.progress")}
      >
        {step === 0 && (
          <div className="grid gap-4">
            <Field label={translateNow("source.method.52a0f9b65b")} description={t("secrets.login.methodHelp")} required>
              {(control) => (
                <Select {...control} value={methodName} onChange={(event) => invalidateReview(event.target.value)} disabled={!methods?.length} required>
                  {methods?.map((method) => (
                    <option key={method.name} value={method.name}>
                      {t(method.disabled ? "secrets.login.methodOptionDisabled" : "secrets.login.methodOption", {
                        name: method.name,
                        type: method.type,
                        source: method.source,
                      })}
                    </option>
                  ))}
                </Select>
              )}
            </Field>
            {!methods?.length && <p className="text-sm text-status-warning">{t("secrets.login.noMethods")}</p>}
            {reviewStale && <p className="text-sm text-status-warning">{t("secrets.login.reviewStale")}</p>}
            {reviewError && <ErrorState title={t("secrets.login.reviewFailed")}>{reviewError}</ErrorState>}
          </div>
        )}

        {step === 1 && reviewedPlan && (
          <section aria-label={t("secrets.login.reviewLabel")} className="grid gap-5">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div>
                <h3 className="font-semibold">{reviewedPlan.ready ? t("secrets.login.reviewReady") : t("secrets.login.reviewBlocked")}</h3>
                <p className="mt-1 text-sm text-muted-foreground">{t("secrets.login.noPreviewEffects")}</p>
              </div>
              <StatusBadge
                value={reviewedPlan.ready ? "ready" : "blocked"}
                label={reviewedPlan.ready ? t("secrets.pki.ready") : t("secrets.pki.blocked")}
                tone={reviewedPlan.ready ? "success" : "warning"}
              />
            </div>
            <dl className="grid gap-3 text-sm sm:grid-cols-2 lg:grid-cols-4">
              <div>
                <dt className="text-muted-foreground">{translateNow("source.method.52a0f9b65b")}</dt>
                <dd className="font-medium">{reviewedPlan.method.name}</dd>
              </div>
              <div>
                <dt className="text-muted-foreground">{t("secrets.methods.type")}</dt>
                <dd className="font-mono text-xs">{reviewedPlan.method.type}</dd>
              </div>
              <div>
                <dt className="text-muted-foreground">{t("secrets.methods.source")}</dt>
                <dd>{reviewedPlan.method.source}</dd>
              </div>
              <div>
                <dt className="text-muted-foreground">{t("secrets.login.sessionTTL")}</dt>
                <dd className="font-medium">{reviewedPlan.session_ttl_seconds}s</dd>
              </div>
              <div>
                <dt className="text-muted-foreground">{t("secrets.pki.permission")}</dt>
                <dd className="font-mono text-xs">{reviewedPlan.required_permission}</dd>
              </div>
              <div className="sm:col-span-2">
                <dt className="text-muted-foreground">{t("secrets.login.tenantBinding")}</dt>
                <dd>{reviewedPlan.tenant_binding}</dd>
              </div>
              <div className="sm:col-span-2">
                <dt className="text-muted-foreground">{t("secrets.login.credentialFormat")}</dt>
                <dd>{reviewedPlan.credential_format}</dd>
              </div>
            </dl>
            <div>
              <h4 className="font-medium">{t("secrets.pki.prerequisites")}</h4>
              <ul className="mt-2 grid gap-2 text-sm sm:grid-cols-2">
                {reviewedPlan.prerequisites.map((item) => (
                  <li key={item.id} className="rounded-control border border-border p-3">
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-mono text-xs">{item.id}</span>
                      <StatusBadge
                        value={item.ready ? "ready" : "blocked"}
                        label={item.ready ? t("secrets.pki.ready") : t("secrets.pki.blocked")}
                        tone={item.ready ? "success" : "warning"}
                      />
                    </div>
                    <p className="mt-2 text-muted-foreground">{item.detail}</p>
                    {!item.ready && item.remediation && <p className="mt-1 text-status-warning">{item.remediation}</p>}
                  </li>
                ))}
              </ul>
            </div>
            {reviewedPlan.blockers.length > 0 && (
              <div>
                <h4 className="font-medium">{t("secrets.pki.blockers")}</h4>
                <ul className="mt-1 list-disc space-y-1 pl-5 text-sm text-destructive">
                  {reviewedPlan.blockers.map((blocker) => (
                    <li key={blocker}>{blocker}</li>
                  ))}
                </ul>
              </div>
            )}
            <div className="grid gap-4 md:grid-cols-3">
              <PlanList title={t("secrets.pki.executionEffects")} items={[...reviewedPlan.execute_writes, ...reviewedPlan.execute_external_effects]} />
              <PlanList title={t("secrets.pki.recovery")} items={reviewedPlan.recovery_steps} />
              <PlanList title={t("secrets.pki.verification")} items={reviewedPlan.verification_steps} />
            </div>
            <div className="rounded-control border border-border bg-muted/40 p-3 text-sm">
              <p className="text-muted-foreground">{t("secrets.login.automation")}</p>
              <code className="mt-1 block break-all font-mono text-xs">{formatCommandArgv(reviewedPlan.cli_argv)}</code>
            </div>
            <p className="text-sm text-muted-foreground">{reviewedPlan.secret_data_handling}</p>
            <p className="break-all font-mono text-xs text-muted-foreground">
              {t("secrets.pki.fingerprint")}: <span>{reviewedPlan.request_fingerprint}</span>
            </p>
            {reviewedPlan.ready && (
              <Field label={translateNow("source.credential.b1c42b3ce1")} description={t("secrets.login.credentialHelp")} required>
                {(control) => (
                  <Input {...control} type="password" autoComplete="off" value={credential} onChange={(event) => setCredential(event.target.value)} required />
                )}
              </Field>
            )}
          </section>
        )}

        {step === 2 && session && (
          <section aria-label={t("secrets.login.verifyLabel")} className="grid gap-4">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <h3 className="font-semibold">{t("secrets.login.verified")}</h3>
                <p className="mt-1 text-sm text-muted-foreground">{t("secrets.login.verifiedHelp")}</p>
              </div>
              <StatusBadge value="active" label={t("secrets.methods.enabled")} tone="success" />
            </div>
            <MachineSession session={session} />
            {sessionToken && (
              <RevealPanel title={t("secrets.login.tokenTitle")} value={sessionToken} onDismiss={() => setSessionToken("")}>
                {t("secrets.login.tokenHelp")}
              </RevealPanel>
            )}
            <PlanList title={t("secrets.pki.verification")} items={reviewedPlan?.verification_steps ?? []} />
          </section>
        )}
      </StepShell>

      {loginError && <ErrorState title={t("secrets.login.executionFailed")}>{loginError}</ErrorState>}
      <div className="flex flex-wrap justify-end gap-2">
        <Button type="button" variant="ghost" onClick={startAgain} disabled={reviewBusy || loginBusy}>
          {step === 2 ? t("secrets.login.startAgain") : translateNow("source.cancel.19766ed6cc")}
        </Button>
        {step === 1 && reviewedPlan?.ready && (
          <Button type="submit" disabled={loginBusy || !credential || loadBlocked} loading={loginBusy}>
            {loginBusy ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <LogIn className="h-4 w-4" aria-hidden="true" />}
            {t("secrets.login.executeReviewed")}
          </Button>
        )}
      </div>
    </form>
  );
}
