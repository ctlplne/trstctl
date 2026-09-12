import { useCallback, useEffect, useId, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { useForm, useWatch } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { useAuth } from "@/auth/AuthProvider";
import { useTranslation } from "@/i18n/I18nProvider";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Button } from "@/components/ui/button";
import { CredentialChip } from "@/components/CredentialChip";
import { FirstIssuanceRetryForm } from "./FirstIssuanceRetryForm";
import { useApiQuery, useQueryClient } from "@/lib/query";
import { retainedFirstCertificateAttempt, retainFirstCertificateAttempt, firstCertificatePrincipalMatches } from "@/lib/firstCertificateMemory";
import {
  wizardCertificateForm,
  newWizardCertificateAttempt,
  submitWizardCertificateAttempt,
  correctWizardCertificateCSR,
  readWizardCertificateResult,
  retryWizardFirstIssuance,
  downloadWizardPublicCertificate,
  wizardFailureKind,
  WizardIssuanceStopped,
  WIZARD_POLL_MS,
  PUBLIC_CSR_LIMIT,
  type WizardCertificateAttempt,
  type WizardCertificateForm,
  type WizardFailureKind,
  type WizardRecordedCertificate,
} from "@/lib/wizardFirstCertificate";

export function FirstCertificateStep({ onRecorded }: { onRecorded: (record: WizardRecordedCertificate | null) => void }) {
  const { user, preview } = useAuth();
  const { t } = useTranslation();
  const principal = useMemo(
    () => (user && !preview && user.subject && user.tenant_id ? { tenantId: user.tenant_id, subject: user.subject } : null),
    [user, preview],
  );
  const readerID = useId();
  const [attempt, setAttempt] = useState<WizardCertificateAttempt | null>(() => (principal ? retainedFirstCertificateAttempt(principal) : null));
  const [busy, setBusy] = useState(false);
  const [correcting, setCorrecting] = useState(false);
  const active = useRef<AbortController | null>(null);
  const [failure, setFailure] = useState<WizardFailureKind | null>(null);
  const [retryFailure, setRetryFailure] = useState(false);
  const [readUntil, setReadUntil] = useState(() => (attempt?.transitionDispatched ? performance.now() + WIZARD_POLL_MS : 0));
  const [paused, setPaused] = useState(false);
  const queryClient = useQueryClient();
  const {
    register,
    handleSubmit,
    control,
    setValue,
    formState: { errors },
  } = useForm<WizardCertificateForm>({
    resolver: zodResolver(wizardCertificateForm),
    defaultValues: attempt?.input ?? {
      name: "",
      applicationID: "",
      environment: "",
      alertContact: "",
      ownershipConfirmed: false,
      wildcardAck: false,
      subjectCSRPEM: "",
    },
  });
  const wildcard = (useWatch({ control, name: "name" }) ?? "").trim().startsWith("*.");
  const retain = useCallback((next: WizardCertificateAttempt) => {
    retainFirstCertificateAttempt(next);
    setAttempt(next);
  }, []);
  const resultKey = [
    "wizard-issuance-result",
    principal?.tenantId,
    principal?.subject,
    attempt?.issuance?.identityId,
    attempt?.issuance?.issueKey,
    readerID,
  ] as const;
  const shouldRead = Boolean(principal && attempt?.transitionDispatched && !attempt.csrRejection && !busy && readUntil && !paused);
  const result = useApiQuery(
    resultKey,
    async ({ signal }) => {
      if (!attempt || !shouldRead || performance.now() >= readUntil) {
        setPaused(true);
        throw new Error("poll_paused");
      }
      const observed = await readWizardCertificateResult(attempt, signal, readUntil);
      if (performance.now() >= readUntil) {
        setPaused(true);
        throw new Error("poll_paused");
      }
      return observed;
    },
    { retry: false, enabled: shouldRead, live: shouldRead ? { intervalMs: 4000 } : undefined },
  );
  const stoppedError = result.errorValue instanceof WizardIssuanceStopped ? result.errorValue : null;
  const stopped = stoppedError?.state ?? null;

  useEffect(() => {
    if (stopped && !result.fetching) setPaused(true);
  }, [stopped, result.fetching]);

  useEffect(() => {
    if (!readUntil || paused) return;
    const left = readUntil - performance.now();
    if (left <= 0) {
      setPaused(true);
      return;
    }
    const timer = window.setTimeout(() => setPaused(true), left);
    return () => window.clearTimeout(timer);
  }, [readUntil, paused]);
  useEffect(() => {
    onRecorded(null);
    return () => active.current?.abort();
  }, [onRecorded]);
  useEffect(() => {
    if (!principal || !firstCertificatePrincipalMatches(principal)) return;
    if (result.data) {
      if (!["pending", "processing"].includes(result.data.result.delivery?.status ?? "")) setPaused(true);
      onRecorded(result.data);
    }
  }, [result.data, principal, onRecorded]);

  async function submit(input?: WizardCertificateForm) {
    if (!principal || active.current || !firstCertificatePrincipalMatches(principal)) return;
    const controller = new AbortController();
    active.current = controller;
    setBusy(true);
    setFailure(null);
    onRecorded(null);
    let next = attempt;
    try {
      if (!next) {
        if (!input) throw new Error("attempt_missing");
        next = newWizardCertificateAttempt(input, principal);
        retain(next);
      }
      if (correcting) {
        if (!input) throw new Error("attempt_missing");
        next = correctWizardCertificateCSR(next, input.subjectCSRPEM);
        retain(next);
        setCorrecting(false);
      }
      await submitWizardCertificateAttempt(next, controller.signal, retain, (kind, value) => {
        queryClient.setQueryData(["wizard-write", principal.tenantId, principal.subject, kind, value.id], value);
        void queryClient.invalidateQueries({ queryKey: [kind] });
      });
    } catch (error) {
      if (!controller.signal.aborted && firstCertificatePrincipalMatches(principal)) setFailure(wizardFailureKind(error));
    } finally {
      if (active.current === controller) active.current = null;
      if (!controller.signal.aborted && firstCertificatePrincipalMatches(principal)) {
        setBusy(false);
        setPaused(false);
        setReadUntil(performance.now() + WIZARD_POLL_MS);
        // A lost transition response can still have a recorded result. Reading
        // its retained key never performs another mutation.
        void queryClient.invalidateQueries({ queryKey: resultKey });
      }
    }
  }
  function readAgain() {
    setPaused(false);
    setReadUntil(performance.now() + WIZARD_POLL_MS);
    if (!paused) result.refetch();
  }
  const record = principal && firstCertificatePrincipalMatches(principal) ? result.data : null;
  const recoveryResult = stoppedError?.result ?? record?.result;
  async function requestRecovery(reason: string) {
    if (!principal || !attempt || !recoveryResult || active.current || !firstCertificatePrincipalMatches(principal)) return;
    const controller = new AbortController();
    active.current = controller;
    setBusy(true);
    setRetryFailure(false);
    try {
      await queryClient.cancelQueries({ queryKey: resultKey });
      const receipt = await retryWizardFirstIssuance(attempt, recoveryResult, reason, controller.signal, retain);
      const next = record
        ? { ...record, result: { ...record.result, retry: undefined, delivery: { status: "pending" as const, attempts: receipt.attempts } } }
        : null;
      queryClient.setQueryData(resultKey, next);
      setPaused(false);
      setReadUntil(performance.now() + WIZARD_POLL_MS);
      void queryClient.invalidateQueries({ queryKey: resultKey });
    } catch {
      if (!controller.signal.aborted && firstCertificatePrincipalMatches(principal)) setRetryFailure(true);
    } finally {
      if (active.current === controller) active.current = null;
      if (!controller.signal.aborted && firstCertificatePrincipalMatches(principal)) setBusy(false);
    }
  }
  const errorText = t("wizard.firstLeaf.fieldError");
  if (!principal) return <p role="alert">{t("wizard.firstLeaf.authRequired")}</p>;

  return (
    <section aria-labelledby="step-cert-heading" className="grid gap-4">
      <h3 id="step-cert-heading" className="text-title font-semibold">
        {t("wizard.firstLeaf.heading")}
      </h3>
      <p className="text-sm text-muted-foreground">{t("wizard.firstLeaf.custody")}</p>
      <p className="text-caption text-muted-foreground">{t("wizard.firstLeaf.reload")}</p>
      <form onSubmit={(event) => void handleSubmit((input) => void submit(input))(event)} className="grid gap-3">
        <Field label={t("wizard.firstLeaf.service")} required error={errors.name ? errorText : undefined}>
          {(control) => <Input {...control} {...register("name")} readOnly={Boolean(attempt)} />}
        </Field>
        <fieldset className="grid gap-3 rounded-control border border-border p-3">
          <legend>{t("wizard.certificate.ownerHeading")}</legend>
          <Field label={t("owners.readiness.applicationID")} required error={errors.applicationID ? errorText : undefined}>
            {(control) => <Input {...control} {...register("applicationID")} readOnly={Boolean(attempt)} />}
          </Field>
          <Field label={t("owners.readiness.environment")} required error={errors.environment ? errorText : undefined}>
            {(control) => <Input {...control} {...register("environment")} readOnly={Boolean(attempt)} />}
          </Field>
          <Field label={t("wizard.certificate.ownerAlertContact")} required error={errors.alertContact ? errorText : undefined}>
            {(control) => <Input {...control} type="email" {...register("alertContact")} readOnly={Boolean(attempt)} />}
          </Field>
          <Field label={t("wizard.certificate.ownerConfirm")} required error={errors.ownershipConfirmed ? errorText : undefined}>
            {(control) => <Input {...control} type="checkbox" {...register("ownershipConfirmed")} disabled={Boolean(attempt)} />}
          </Field>
        </fieldset>
        <Field
          label={t("wizard.firstLeaf.csr")}
          description={t("wizard.firstLeaf.csrHelp")}
          required
          error={errors.subjectCSRPEM ? t("wizard.firstLeaf.csrError") : undefined}
        >
          {(control) => (
            <Textarea
              {...control}
              {...register("subjectCSRPEM")}
              maxLength={PUBLIC_CSR_LIMIT}
              readOnly={Boolean(attempt) && !correcting}
              spellCheck={false}
              autoComplete="off"
              rows={6}
            />
          )}
        </Field>
        {wildcard && (
          <Field label={t("wizard.firstLeaf.wildcard")} required error={errors.wildcardAck ? errorText : undefined}>
            {(control) => <Input {...control} type="checkbox" {...register("wildcardAck")} disabled={Boolean(attempt)} />}
          </Field>
        )}
        {(!attempt || correcting) && (
          <Button type="submit" className="justify-self-start" disabled={busy}>
            {t(correcting ? "wizard.firstLeaf.submitCorrection" : "wizard.firstLeaf.submit")}
          </Button>
        )}
      </form>
      {attempt && !record && (
        <div className="grid justify-items-start gap-2">
          <p className="text-sm">{t("wizard.firstLeaf.retained")}</p>
          {attempt.issuance && <CredentialChip value={attempt.issuance.issueKey} label={t("wizard.firstLeaf.requestKey")} />}
          {attempt.issuance?.phase !== "accepted" && !correcting && !stopped && (
            <Button type="button" onClick={() => void submit()} disabled={busy}>
              {t("wizard.firstLeaf.retry")}
            </Button>
          )}
        </div>
      )}
      {attempt?.csrRejection && !record && (
        <div className="grid justify-items-start gap-2">
          <p role="status">{t("wizard.firstLeaf.correctionDisposition")}</p>
          <Button
            type="button"
            variant="outline"
            disabled={busy}
            onClick={() => {
              setValue("subjectCSRPEM", attempt.input.subjectCSRPEM);
              setCorrecting(!correcting);
            }}
          >
            {t(correcting ? "wizard.firstLeaf.cancelCorrection" : "wizard.firstLeaf.editCSR")}
          </Button>
        </div>
      )}
      {busy && <p role="status">{t("wizard.firstLeaf.submitting")}</p>}
      {failure && !record && !stopped && (
        <p role="alert">
          {t(failure === "approval" ? "wizard.firstLeaf.approval" : failure === "refused" ? "wizard.firstLeaf.refused" : "wizard.firstLeaf.uncertain")}
        </p>
      )}
      {failure === "approval" && !record && <Link to="/approvals">{t("wizard.firstLeaf.approvals")}</Link>}
      {attempt?.transitionDispatched && !attempt.csrRejection && !busy && !record && (
        <div className="grid justify-items-start gap-2">
          <p role={stopped ? "alert" : "status"}>
            {t(
              stopped === "failed"
                ? "wizard.firstLeaf.deliveryFailed"
                : stopped === "unavailable"
                  ? "wizard.firstLeaf.unavailable"
                  : result.error
                    ? "wizard.firstLeaf.readFailed"
                    : paused
                      ? "wizard.firstLeaf.paused"
                      : "wizard.firstLeaf.pending",
            )}
          </p>
          <Button type="button" variant="outline" onClick={readAgain} disabled={result.fetching}>
            {t("wizard.firstLeaf.refresh")}
          </Button>
        </div>
      )}
      {record && (
        <div className="grid justify-items-start gap-3">
          <p role="status">{t("wizard.firstLeaf.recorded")}</p>
          <p>{t("wizard.firstLeaf.authority", { issuer: record.result.certificate.issuer || t("wizard.firstLeaf.unknownAuthority") })}</p>
          <CredentialChip value={record.result.certificate.fingerprint} label={t("wizard.firstLeaf.fingerprint")} />
          <p>{t("wizard.firstLeaf.status", { status: record.result.certificate.status })}</p>
          <p className="text-caption text-muted-foreground">{t("wizard.firstLeaf.trust")}</p>
          <div className="flex flex-wrap gap-2">
            <Button type="button" onClick={() => downloadWizardPublicCertificate(record, "leaf", principal)}>
              {t("wizard.firstLeaf.downloadLeaf")}
            </Button>
            <Button type="button" variant="outline" onClick={() => downloadWizardPublicCertificate(record, "chain", principal)}>
              {t("wizard.firstLeaf.downloadChain")}
            </Button>
          </div>
          <Link to="/certificates">{t("wizard.certificate.openInventory")}</Link>
        </div>
      )}
      {attempt && recoveryResult?.delivery?.status === "failed" && (
        <FirstIssuanceRetryForm
          key={recoveryResult.delivery.attempts}
          result={recoveryResult}
          savedReason={attempt.retryRequest?.attempts === recoveryResult.delivery.attempts ? attempt.retryRequest.reason : undefined}
          busy={busy}
          onRetry={requestRecovery}
        />
      )}
      {retryFailure && <p role="alert">{t("wizard.firstLeaf.recoveryUncertain")}</p>}
      <Link to="/identities">{t("wizard.firstLeaf.inventory")}</Link>
    </section>
  );
}
