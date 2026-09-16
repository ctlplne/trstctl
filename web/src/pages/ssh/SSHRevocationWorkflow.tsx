import { useRef, useState } from "react";
import { Link } from "react-router-dom";
import { useForm, useWatch } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { CapabilityActionNotice } from "@/components/CapabilityTruth";
import { CredentialChip } from "@/components/CredentialChip";
import { ErrorState } from "@/components/StatePrimitives";
import { Num } from "@/components/typography";
import { StepShell } from "@/components/wizard/StepShell";
import { Button, buttonVariants } from "@/components/ui/button";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { useTranslation, translateNow } from "@/i18n/I18nProvider";
import { api, type SSHRevokeCertificateRequest, type SSHStatus } from "@/lib/api";
import { apiProblemMessage } from "@/lib/apiProblem";
import { useCapabilityExecution } from "@/lib/capabilities";

const revocationSchema = z
  .object({
    scope: z.enum(["serial", "key_id", "both"]),
    serial: z.string().trim(),
    keyID: z.string().trim(),
    reason: z.string().trim(),
  })
  .superRefine((values, context) => {
    if (values.scope !== "key_id" && (!/^[0-9]+$/.test(values.serial) || !Number.isSafeInteger(Number(values.serial)) || Number(values.serial) <= 0)) {
      context.addIssue({ code: "custom", path: ["serial"], message: translateNow("sshTrust.revoke.invalidSerial") });
    }
    if (values.scope !== "serial" && !values.keyID) {
      context.addIssue({ code: "custom", path: ["keyID"], message: translateNow("sshTrust.revoke.requiredKeyID") });
    }
  });

type RevocationForm = z.infer<typeof revocationSchema>;
export type SSHRevocationSeed = { serial: number; key_id: string };

export function SSHRevocationWorkflow({
  initialCertificate,
  onPublished,
}: {
  initialCertificate?: SSHRevocationSeed;
  onPublished: (status: SSHStatus) => void;
}) {
  const { t } = useTranslation();
  const action = useCapabilityExecution("F43", "revokeSSHCertificate");
  const [step, setStep] = useState(0);
  const [reviewed, setReviewed] = useState<{ request: SSHRevokeCertificateRequest; key: string } | null>(null);
  const [published, setPublished] = useState<SSHStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [publishing, setPublishing] = useState(false);
  const submitting = useRef(false);
  const {
    register,
    control,
    handleSubmit,
    formState: { errors },
  } = useForm<RevocationForm>({
    resolver: zodResolver(revocationSchema),
    defaultValues: {
      scope: "serial",
      serial: initialCertificate ? String(initialCertificate.serial) : "",
      keyID: initialCertificate?.key_id ?? "",
      reason: "operator requested revocation",
    },
  });
  const scope = useWatch({ control, name: "scope" });
  const review = handleSubmit((values) => {
    const request: SSHRevokeCertificateRequest = {
      ...(values.scope !== "key_id" ? { serial: Number(values.serial) } : {}),
      ...(values.scope !== "serial" ? { key_id: values.keyID } : {}),
      ...(values.reason ? { reason: values.reason } : {}),
    };
    // A repeated review of the same request keeps its identity, including after
    // a lost response. A deliberate scope/target change starts a new operation.
    setReviewed((previous) =>
      previous && JSON.stringify(previous.request) === JSON.stringify(request) ? previous : { request, key: globalThis.crypto.randomUUID() },
    );
    setError(null);
    setStep(1);
  });

  async function publish() {
    if (!reviewed || submitting.current || !action.runnable) return;
    submitting.current = true;
    setPublishing(true);
    setError(null);
    try {
      const result = await api.revokeSSHCertificate(reviewed.request, reviewed.key);
      setPublished(result);
      onPublished(result);
      setStep(2);
    } catch (cause) {
      setError(apiProblemMessage(cause, t("sshTrust.revoke.failed")));
    } finally {
      submitting.current = false;
      setPublishing(false);
    }
  }

  return (
    <section aria-labelledby="krl-heading" className="grid gap-3 border-y border-border py-4">
      <h2 id="krl-heading" className="text-title font-semibold">
        {t("source.krl.revocation.7e579fb6c5")}
      </h2>
      <CapabilityActionNotice action={action} />
      <StepShell
        steps={[
          { id: "scope", label: t("sshTrust.revoke.choose"), description: t("sshTrust.revoke.chooseBody"), progressState: reviewed ? "done" : "pending" },
          {
            id: "review",
            label: t("sshTrust.revoke.reviewHeading"),
            description: t("sshTrust.revoke.reviewBody"),
            progressState: published ? "done" : "pending",
          },
          { id: "published", label: t("sshTrust.revoke.publishedStep"), description: t("sshTrust.revoke.publishedBody"), progressState: "pending" },
        ]}
        currentIndex={step}
        progressLabel={t("sshTrust.revoke.progress")}
        onPrevious={step === 1 && !publishing ? () => setStep(0) : undefined}
      >
        {step === 0 ? (
          <form aria-label={t("source.revoke.ssh.certificate.63b6e335c3")} className="grid gap-4" onSubmit={review} noValidate>
            <Field label={t("sshTrust.revoke.scope")} required>
              {(props) => (
                <Select {...props} {...register("scope")}>
                  <option value="serial">{t("sshTrust.revoke.scopeSerial")}</option>
                  <option value="key_id">{t("sshTrust.revoke.scopeKeyID")}</option>
                  <option value="both">{t("sshTrust.revoke.scopeBoth")}</option>
                </Select>
              )}
            </Field>
            {scope !== "key_id" ? (
              <Field label={t("sshTrust.revoke.serial")} error={errors.serial?.message} required>
                {(props) => <Input {...props} {...register("serial")} inputMode="numeric" autoComplete="off" />}
              </Field>
            ) : null}
            {scope !== "serial" ? (
              <Field label={t("source.key.id.d54d56ee0a")} description={t("sshTrust.revoke.keyIDHelp")} error={errors.keyID?.message} required>
                {(props) => <Input {...props} {...register("keyID")} autoComplete="off" />}
              </Field>
            ) : null}
            <Field label={t("source.reason.f81ab834de")} description={t("sshTrust.revoke.reasonHelp")}>
              {(props) => <Input {...props} {...register("reason")} />}
            </Field>
            <div className="flex justify-end">
              <Button type="submit" variant="destructive-outline" disabled={!action.runnable}>
                {t("sshTrust.revoke.reviewAction")}
              </Button>
            </div>
          </form>
        ) : null}
        {step === 1 && reviewed ? (
          <section className="grid gap-4" aria-label={t("sshTrust.revoke.reviewHeading")}>
            {reviewed.request.serial ? (
              <p>{t(reviewed.request.key_id ? "sshTrust.revoke.serialBothEffect" : "sshTrust.revoke.serialEffect", { serial: reviewed.request.serial })}</p>
            ) : null}
            {reviewed.request.key_id ? (
              <p className="border-s-2 border-status-warning ps-3">{t("sshTrust.revoke.keyIDEffect", { keyID: reviewed.request.key_id })}</p>
            ) : null}
            <p className="border-s-2 border-status-warning ps-3 text-sm">{t("sshTrust.revoke.anyCA")}</p>
            <dl className="grid gap-3 sm:grid-cols-2">
              {reviewed.request.serial ? (
                <div>
                  <dt className="text-caption text-muted-foreground">{t("sshTrust.revoke.serial")}</dt>
                  <dd>
                    <CredentialChip value={String(reviewed.request.serial)} label={t("sshTrust.revoke.serial")} />
                  </dd>
                </div>
              ) : null}
              {reviewed.request.key_id ? (
                <div>
                  <dt className="text-caption text-muted-foreground">{t("source.key.id.d54d56ee0a")}</dt>
                  <dd>
                    <CredentialChip value={reviewed.request.key_id} label={t("source.key.id.d54d56ee0a")} />
                  </dd>
                </div>
              ) : null}
              <div>
                <dt className="text-caption text-muted-foreground">{t("source.reason.f81ab834de")}</dt>
                <dd className="break-words text-sm">{reviewed.request.reason || t("sshTrust.revoke.noReason")}</dd>
              </div>
            </dl>
            <p className="text-sm text-muted-foreground">{t("sshTrust.revoke.distributionBoundary")}</p>
            {error ? (
              <ErrorState title={t("sshTrust.revoke.failed")}>
                <p>{error}</p>
                <p className="mt-2">{t("sshTrust.revoke.retryHelp")}</p>
              </ErrorState>
            ) : null}
            <div className="flex justify-end">
              <Button type="button" variant="destructive" loading={publishing} disabled={publishing || !action.runnable} onClick={() => void publish()}>
                {t(error ? "sshTrust.revoke.retryAction" : "source.revoke.and.publish.krl.d5e98fd13c")}
              </Button>
            </div>
          </section>
        ) : null}
        {step === 2 && published ? (
          <section className="grid gap-4" aria-labelledby="ssh-krl-published">
            <h3 id="ssh-krl-published" className="text-title font-semibold">
              {t("sshTrust.revoke.published")}
            </h3>
            <p>{t("sshTrust.revoke.nextSteps")}</p>
            <dl className="grid gap-3 sm:grid-cols-2">
              <div>
                <dt className="text-caption text-muted-foreground">{t("source.krl.version.2381c27676")}</dt>
                <dd>
                  <Num>{published.krl_version}</Num>
                </dd>
              </div>
              <div>
                <dt className="text-caption text-muted-foreground">{t("sshTrust.revoke.entries")}</dt>
                <dd>
                  <Num>{published.revoked_count}</Num>
                </dd>
              </div>
            </dl>
            <p className="text-sm text-muted-foreground">{t("sshTrust.revoke.countHelp")}</p>
            <div className="flex flex-wrap gap-3">
              <a href="/ssh/krl" download="trstctl.krl" className={buttonVariants({ variant: "outline" })}>
                {t("sshTrust.revoke.download")}
              </a>
              <Link to="/audit" className={buttonVariants({ variant: "outline" })}>
                {t("sshTrust.revoke.audit")}
              </Link>
              <Button
                type="button"
                variant="outline"
                onClick={() => {
                  setReviewed(null);
                  setPublished(null);
                  setStep(0);
                }}
              >
                {t("sshTrust.revoke.another")}
              </Button>
            </div>
          </section>
        ) : null}
      </StepShell>
    </section>
  );
}
