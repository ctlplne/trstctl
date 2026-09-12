import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { useTranslation } from "@/i18n/I18nProvider";
import { Field } from "@/components/ui/field";
import { Textarea } from "@/components/ui/textarea";
import { Button } from "@/components/ui/button";
import { CapabilityActionNotice } from "@/components/CapabilityTruth";
import { useCapabilityExecution } from "@/lib/capabilities";
import { wizardIssuanceRetryForm, type WizardIssuanceRetryForm, type WizardPublicResult } from "@/lib/wizardFirstCertificate";

export function FirstIssuanceRetryForm({
  result,
  savedReason,
  busy,
  onRetry,
}: {
  result: WizardPublicResult;
  savedReason?: string;
  busy: boolean;
  onRetry: (reason: string) => Promise<void>;
}) {
  const { t } = useTranslation();
  const action = useCapabilityExecution("F4", "retryFirstIssuance");
  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm<WizardIssuanceRetryForm>({
    resolver: zodResolver(wizardIssuanceRetryForm),
    defaultValues: { reason: savedReason ?? "" },
  });
  if (result.delivery?.status !== "failed" || !result.retry) return null;
  return (
    <div className="grid gap-3">
      {result.state === "issued" && <p role="alert">{t("wizard.firstLeaf.deliveryFailed")}</p>}
      <p role="status">{result.retry.reason}</p>
      {result.retry.allowed && (
        <>
          <p className="text-caption text-muted-foreground">{t("wizard.firstLeaf.recoveryHelp")}</p>
          <CapabilityActionNotice action={action} />
          <form
            className="grid gap-3"
            onSubmit={(event) =>
              void handleSubmit(async ({ reason }) => {
                if (action.runnable && !busy) await onRetry(reason);
              })(event)
            }
          >
            <Field label={t("wizard.firstLeaf.recoveryReason")} required error={errors.reason ? t("wizard.firstLeaf.recoveryReasonError") : undefined}>
              {(control) => (
                <Textarea
                  {...control}
                  {...register("reason")}
                  readOnly={savedReason !== undefined}
                  disabled={busy || !action.runnable}
                  maxLength={1024}
                  rows={2}
                />
              )}
            </Field>
            <Button type="submit" className="justify-self-start" disabled={busy || !action.runnable}>
              {t(savedReason !== undefined ? "wizard.firstLeaf.recoveryRepeat" : "wizard.firstLeaf.recoverySubmit")}
            </Button>
          </form>
        </>
      )}
    </div>
  );
}
