import { useMemo, useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { KeyRound, Loader2 } from "lucide-react";
import { ErrorState } from "@/components/StatePrimitives";
import { StatusBadge } from "@/components/StatusBadge";
import { Button } from "@/components/ui/button";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { StepShell } from "@/components/wizard/StepShell";
import { useTranslation, translateNow } from "@/i18n/I18nProvider";
import { api, type PKISecret, type PKISecretPreview, type PKISecretRequest } from "@/lib/api";
import { apiProblemMessage } from "@/lib/apiProblem";
import { RevealPanel, formatCommandArgv } from "./SecretsPageParts";

type CustodyMode = "csr" | "legacy";

function requestFor(mode: CustodyMode, commonName: string, csr: string, ttl: string): PKISecretRequest | null {
  const ttlSeconds = Number(ttl);
  if (!Number.isSafeInteger(ttlSeconds) || ttlSeconds < 0) return null;
  if (mode === "csr") {
    if (!csr.trim()) return null;
    return { csr_pem: csr.trim(), ttl_seconds: ttlSeconds };
  }
  if (!commonName.trim()) return null;
  return { common_name: commonName.trim(), ttl_seconds: ttlSeconds };
}

function requestKey(request: PKISecretRequest | null): string {
  return request ? JSON.stringify(request) : "";
}

export function PKISecretWorkflow({ loadBlocked }: { loadBlocked: boolean }) {
  const { t } = useTranslation();
  const [step, setStep] = useState(0);
  const [mode, setMode] = useState<CustodyMode>("csr");
  const [commonName, setCommonName] = useState("");
  const [csr, setCSR] = useState("");
  const [ttl, setTTL] = useState("900");
  const [review, setReview] = useState<{ requestKey: string; plan: PKISecretPreview } | null>(null);
  const [reviewBusy, setReviewBusy] = useState(false);
  const [reviewError, setReviewError] = useState<string | null>(null);
  const [reviewStale, setReviewStale] = useState(false);
  const [issueBusy, setIssueBusy] = useState(false);
  const [issueError, setIssueError] = useState<string | null>(null);
  const [bundle, setBundle] = useState<PKISecret | null>(null);

  const request = useMemo(() => requestFor(mode, commonName, csr, ttl), [mode, commonName, csr, ttl]);
  const currentRequestKey = requestKey(request);
  const reviewedPlan = review?.requestKey === currentRequestKey ? review.plan : null;

  function invalidateReview(change: () => void) {
    if (review) setReviewStale(true);
    setReview(null);
    setBundle(null);
    setIssueError(null);
    setReviewError(null);
    setStep(0);
    change();
  }

  async function preview() {
    if (!request) return;
    setReviewBusy(true);
    setReviewError(null);
    setIssueError(null);
    setBundle(null);
    try {
      const plan = await api.previewPKISecret(request);
      setReview({ requestKey: requestKey(request), plan });
      setReviewStale(false);
      setStep(1);
    } catch (error) {
      setReviewError(apiProblemMessage(error, t("secrets.pki.reviewFailed")));
    } finally {
      setReviewBusy(false);
    }
  }

  async function issue(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!request || !reviewedPlan?.ready) {
      setIssueError(t("secrets.pki.reviewRequired"));
      return;
    }
    setIssueBusy(true);
    setIssueError(null);
    setBundle(null);
    try {
      const issued = await api.issuePKISecret({ ...request, preview_fingerprint: reviewedPlan.request_fingerprint });
      setBundle(issued);
      setStep(2);
    } catch (error) {
      setIssueError(apiProblemMessage(error, t("secrets.pki.issueFailed")));
    } finally {
      setIssueBusy(false);
    }
  }

  function startAgain() {
    setReview(null);
    setBundle(null);
    setIssueError(null);
    setReviewError(null);
    setReviewStale(false);
    setCSR("");
    setCommonName("");
    setStep(0);
  }

  const configureReady = Boolean(request) && !loadBlocked;
  const steps = [
    {
      id: "configure",
      label: t("secrets.pki.configureStep"),
      description: t("secrets.pki.configureStepHelp"),
      progressState: configureReady ? ("done" as const) : ("pending" as const),
    },
    {
      id: "review",
      label: t("secrets.pki.reviewStep"),
      description: t("secrets.pki.reviewStepHelp"),
      progressState: reviewedPlan?.ready ? ("done" as const) : reviewedPlan ? ("blocked" as const) : ("pending" as const),
    },
    {
      id: "verify",
      label: t("secrets.pki.verifyStep"),
      description: t("secrets.pki.verifyStepHelp"),
      progressState: bundle ? ("done" as const) : ("pending" as const),
    },
  ];

  return (
    <form aria-label={translateNow("source.issue.pki.secret.692ee4b6e2")} onSubmit={(event) => void issue(event)} className="grid gap-4">
      <StepShell
        steps={steps}
        currentIndex={step}
        nextDisabled={!configureReady || reviewBusy}
        nextLabel={reviewBusy ? t("secrets.pki.reviewing") : t("secrets.pki.reviewAction")}
        onNext={step === 0 ? () => void preview() : undefined}
        onPrevious={step > 0 ? () => setStep(step - 1) : undefined}
        progressLabel={t("secrets.pki.progress")}
      >
        {step === 0 && (
          <div className="grid gap-4 md:grid-cols-2">
            <Field label={t("secrets.pki.custodyLabel")} description={t("secrets.pki.custodyHelp")} required>
              {(control) => (
                <Select {...control} value={mode} onChange={(event) => invalidateReview(() => setMode(event.target.value as CustodyMode))}>
                  <option value="csr">{t("secrets.pki.csrMode")}</option>
                  <option value="legacy">{t("secrets.pki.legacyMode")}</option>
                </Select>
              )}
            </Field>
            <Field label={translateNow("source.ttl.seconds.862d08de5a")} description={t("secrets.pki.ttlHelp")} required>
              {(control) => (
                <Input
                  {...control}
                  type="number"
                  min="0"
                  step="1"
                  value={ttl}
                  onChange={(event) => invalidateReview(() => setTTL(event.target.value))}
                  required
                />
              )}
            </Field>
            {mode === "csr" ? (
              <Field className="md:col-span-2" label={t("request.csr.label")} description={t("secrets.pki.csrHelp")} required>
                {(control) => (
                  <Textarea
                    {...control}
                    className="min-h-36 font-mono text-xs"
                    value={csr}
                    onChange={(event) => invalidateReview(() => setCSR(event.target.value))}
                    placeholder={t("secrets.pki.csrPlaceholder")}
                    required
                  />
                )}
              </Field>
            ) : (
              <Field label={translateNow("source.common.name.2d129020eb")} description={t("secrets.pki.commonNameHelp")} required>
                {(control) => (
                  <Input
                    {...control}
                    value={commonName}
                    onChange={(event) => invalidateReview(() => setCommonName(event.target.value))}
                    placeholder={translateNow("source.svc.internal.e50a91019d")}
                    required
                  />
                )}
              </Field>
            )}
            {mode === "legacy" && (
              <p className="text-sm text-status-warning md:col-span-2">
                {t("secrets.pki.legacyWarning")}{" "}
                <Link className="underline" to="/audit?type=issuance.server_side_keygen">
                  {t("secrets.pki.auditLink")}
                </Link>
              </p>
            )}
            {reviewStale && <p className="text-sm text-status-warning md:col-span-2">{t("secrets.pki.reviewStale")}</p>}
            {reviewError && (
              <div className="md:col-span-2">
                <ErrorState title={t("secrets.pki.reviewFailed")}>{reviewError}</ErrorState>
              </div>
            )}
          </div>
        )}

        {step === 1 && reviewedPlan && (
          <section aria-label={t("secrets.pki.reviewLabel")} className="grid gap-5">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div>
                <h3 className="font-semibold">{reviewedPlan.ready ? t("secrets.pki.reviewReady") : t("secrets.pki.reviewBlocked")}</h3>
                <p className="mt-1 text-sm text-muted-foreground">{t("secrets.pki.noPreviewEffects")}</p>
              </div>
              <StatusBadge
                value={reviewedPlan.ready ? "ready" : "blocked"}
                label={reviewedPlan.ready ? t("secrets.pki.ready") : t("secrets.pki.blocked")}
                tone={reviewedPlan.ready ? "success" : "warning"}
              />
            </div>
            <dl className="grid gap-3 text-sm sm:grid-cols-2 lg:grid-cols-4">
              <div>
                <dt className="text-muted-foreground">{t("secrets.pki.subject")}</dt>
                <dd className="break-all font-medium">{reviewedPlan.common_name}</dd>
              </div>
              <div>
                <dt className="text-muted-foreground">{t("secrets.pki.dnsNames")}</dt>
                <dd className="break-all font-medium">{reviewedPlan.dns_names.length > 0 ? reviewedPlan.dns_names.join(", ") : t("secrets.pki.none")}</dd>
              </div>
              <div>
                <dt className="text-muted-foreground">{t("secrets.pki.lifetime")}</dt>
                <dd className="font-medium">{reviewedPlan.effective_ttl_seconds}s</dd>
              </div>
              <div>
                <dt className="text-muted-foreground">{t("secrets.pki.key")}</dt>
                <dd className="font-medium">
                  {reviewedPlan.subject_key_algorithm} {reviewedPlan.subject_key_bits}
                </dd>
              </div>
              <div>
                <dt className="text-muted-foreground">{t("secrets.pki.profile")}</dt>
                <dd className="font-mono text-xs">{reviewedPlan.profile}</dd>
              </div>
              <div>
                <dt className="text-muted-foreground">{t("secrets.pki.custodyLabel")}</dt>
                <dd className="font-medium">{reviewedPlan.custody_mode === "requester_csr" ? t("secrets.pki.csrMode") : t("secrets.pki.legacyMode")}</dd>
              </div>
              <div>
                <dt className="text-muted-foreground">{t("secrets.pki.permission")}</dt>
                <dd className="font-mono text-xs">{reviewedPlan.required_permission}</dd>
              </div>
              <div>
                <dt className="text-muted-foreground">{t("secrets.pki.vaultPath")}</dt>
                <dd className="font-mono text-xs">{reviewedPlan.vault_path}</dd>
              </div>
              <div>
                <dt className="text-muted-foreground">{t("secrets.pki.signer")}</dt>
                <dd className="break-all font-mono text-xs">{reviewedPlan.ca_certificate_sha256 ?? t("secrets.pki.notConnected")}</dd>
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
              <p className="text-muted-foreground">{t("secrets.pki.cliParity")}</p>
              <code className="mt-1 block break-all font-mono text-xs">{formatCommandArgv(reviewedPlan.cli_argv)}</code>
            </div>
            <p className="text-sm text-muted-foreground">{reviewedPlan.secret_data_handling}</p>
            <p className="break-all font-mono text-xs text-muted-foreground">
              {t("secrets.pki.fingerprint")}: {reviewedPlan.request_fingerprint}
            </p>
          </section>
        )}

        {step === 2 && bundle && (
          <section aria-label={t("secrets.pki.verifyLabel")} className="grid gap-4">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <h3 className="font-semibold">{t("secrets.pki.issued")}</h3>
                <p className="mt-1 text-sm text-muted-foreground">{t("secrets.pki.verifyResult", { serial: bundle.serial })}</p>
              </div>
              <StatusBadge value="issued" label={t("secrets.pki.issuedBadge")} tone="success" />
            </div>
            <RevealPanel
              title={translateNow("source.pki.bundle.value1.18184942ea", { value1: bundle.serial })}
              onDismiss={() => setBundle(null)}
              value={bundle.private_key ? `${bundle.certificate}\n${bundle.private_key}` : bundle.certificate}
            >
              {bundle.private_key ? t("secrets.pki.legacyResult") : t("secrets.pki.csrResult")}
            </RevealPanel>
            <PlanList title={t("secrets.pki.verification")} items={reviewedPlan?.verification_steps ?? []} />
          </section>
        )}
      </StepShell>

      {issueError && <ErrorState title={t("secrets.pki.issueFailed")}>{issueError}</ErrorState>}
      <div className="flex flex-wrap justify-end gap-2">
        <Button type="button" variant="ghost" onClick={startAgain} disabled={reviewBusy || issueBusy}>
          {step === 2 ? t("secrets.pki.startAgain") : translateNow("source.cancel.19766ed6cc")}
        </Button>
        {step === 1 && (
          <Button type="submit" disabled={issueBusy || reviewBusy || !reviewedPlan?.ready || loadBlocked} loading={issueBusy}>
            {issueBusy ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <KeyRound className="h-4 w-4" aria-hidden="true" />}
            {t("secrets.pki.issueReviewed")}
          </Button>
        )}
      </div>
    </form>
  );
}

function PlanList({ title, items }: { title: string; items: string[] }) {
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
