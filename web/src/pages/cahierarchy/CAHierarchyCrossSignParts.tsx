import { useState } from "react";
import { useForm, useWatch } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { useQueryClient } from "@tanstack/react-query";
import { z } from "zod";
import { FileKey2, RefreshCw } from "lucide-react";
import { CredentialChip } from "@/components/CredentialChip";
import { ErrorState } from "@/components/StatePrimitives";
import { Num } from "@/components/typography";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { StepShell } from "@/components/wizard/StepShell";
import { useTranslation } from "@/i18n/I18nProvider";
import { useApiQuery } from "@/lib/query";
import { api, type CAAuthority, type CACeremonyPlanPreview } from "@/lib/api";

const schema = z
  .object({
    issuerID: z.string().uuid(),
    targetID: z.string().trim(),
    targetPEM: z.string().trim(),
    reason: z.string().trim().min(1),
  })
  .refine((v) => Boolean(v.targetID || v.targetPEM), { path: ["targetID"] })
  .refine((v) => !(v.targetID && v.targetPEM), { path: ["targetPEM"] });
type Values = z.infer<typeof schema>;
type Review = { key: string; issuerID: string; targetPEM: string; targetSHA: string; reason: string; preview: CACeremonyPlanPreview };

async function certificateSHA(pem: string, invalid: string): Promise<string> {
  const blocks = [...pem.matchAll(/-----BEGIN CERTIFICATE-----\s*([A-Za-z0-9+/=\s]+)-----END CERTIFICATE-----/g)];
  if (blocks.length !== 1) throw new Error(invalid);
  const bytes = Uint8Array.from(atob(blocks[0][1].replace(/\s/g, "")), (c) => c.charCodeAt(0));
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((n) => n.toString(16).padStart(2, "0")).join("");
}

function formKey(values: Values): string {
  return JSON.stringify([values.issuerID.trim(), values.targetID.trim(), values.targetPEM.trim(), values.reason.trim()]);
}

/** Event-sourced public CA cross-signing, with target review and indexed receipt. */
export function CACrossSignPanel({ authorities }: { authorities: CAAuthority[] }) {
  const { t } = useTranslation();
  const cache = useQueryClient();
  const [step, setStep] = useState(0);
  const [reviewed, setReviewed] = useState<Review | null>(null);
  const [ceremonyID, setCeremonyID] = useState("");
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const {
    register,
    handleSubmit,
    setValue,
    control,
    formState: { errors },
  } = useForm<Values>({
    resolver: zodResolver(schema),
    mode: "onTouched",
    defaultValues: { issuerID: "", targetID: "", targetPEM: "", reason: "" },
  });
  const issuerID = useWatch({ control, name: "issuerID" }) ?? "";
  const targetID = useWatch({ control, name: "targetID" }) ?? "";
  const targetPEM = useWatch({ control, name: "targetPEM" }) ?? "";
  const reason = useWatch({ control, name: "reason" }) ?? "";
  const current = reviewed?.key === formKey({ issuerID, targetID, targetPEM, reason });
  const validCeremonyID = z.string().uuid().safeParse(ceremonyID).success;
  const ceremony = useApiQuery(["ca-cross-sign-ceremony", ceremonyID], () => api.caCeremony(ceremonyID), { enabled: validCeremonyID, retry: false });
  const receipt = useApiQuery(["ca-cross-sign-receipt", ceremonyID], () => api.getCACrossSignReceipt(ceremonyID), {
    enabled: validCeremonyID && ceremony.data?.status === "completed",
    retry: false,
  });
  const matching = reviewed && ceremony.data?.purpose === `cross-sign:${reviewed.issuerID}:${reviewed.targetSHA}`;
  const targetField = register("targetID");
  const pemField = register("targetPEM");
  const steps = [
    { id: "target", label: t("caHierarchy.crossSign.stepSelect"), description: t("caHierarchy.crossSign.stepSelectDetail") },
    { id: "review", label: t("caHierarchy.crossSign.stepReview"), description: t("caHierarchy.crossSign.stepReviewDetail") },
    { id: "prove", label: t("caHierarchy.crossSign.stepProve"), description: t("caHierarchy.crossSign.stepProveDetail") },
  ];
  function fail(error: unknown) {
    setActionError(error instanceof Error ? error.message : t("caHierarchy.crossSign.unknownError"));
  }

  const review = handleSubmit(async (values) => {
    setBusy(true);
    setActionError(null);
    try {
      const publicTarget = values.targetPEM || authorities.find((ca) => ca.id === values.targetID)?.certificate_pem || "";
      const digest = await certificateSHA(publicTarget, t("caHierarchy.crossSign.invalidPEM"));
      const preview = await api.previewCACeremony({
        operation: "cross_sign_ca",
        authority_id: values.issuerID,
        target_certificate_pem: publicTarget,
        threshold: 2,
        reason: values.reason,
      });
      if (!preview.ready) throw new Error(t("caHierarchy.crossSign.notReady"));
      setReviewed({ key: formKey(values), issuerID: values.issuerID, targetPEM: publicTarget, targetSHA: digest, reason: values.reason, preview });
      setStep(1);
    } catch (error) {
      fail(error);
    } finally {
      setBusy(false);
    }
  });

  async function enterCeremony() {
    if (!reviewed || !current) return;
    if (ceremonyID) {
      if (!matching) {
        setActionError(t("caHierarchy.crossSign.purposeMismatch"));
        return;
      }
      setStep(2);
      return;
    }
    setBusy(true);
    setActionError(null);
    try {
      const next = await api.createCACeremony({
        operation: "cross_sign_ca",
        authority_id: reviewed.issuerID,
        target_certificate_pem: reviewed.targetPEM,
        threshold: 2,
        reason: reviewed.reason,
      });
      cache.setQueryData(["ca-cross-sign-ceremony", next.id], next);
      setCeremonyID(next.id);
      setStep(2);
      await cache.invalidateQueries({ queryKey: ["ca-cross-sign-ceremony", next.id] });
    } catch (error) {
      fail(error);
    } finally {
      setBusy(false);
    }
  }

  async function activate() {
    if (!reviewed || !current || !matching || ceremony.data?.status !== "pending" || ceremony.data.approvals < ceremony.data.threshold) return;
    setBusy(true);
    setActionError(null);
    try {
      const next = await api.crossSignCAAuthority(reviewed.issuerID, {
        ceremony_id: ceremony.data.id,
        certificate_pem: reviewed.targetPEM,
      });
      cache.setQueryData(["ca-cross-sign-receipt", ceremony.data.id], next);
      await cache.invalidateQueries({ queryKey: ["ca-cross-sign-ceremony", ceremony.data.id] });
      await cache.invalidateQueries({ queryKey: ["ca-cross-sign-receipt", ceremony.data.id] });
    } catch (error) {
      fail(error);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section aria-labelledby="ca-cross-sign-heading" className="grid gap-4 border-b border-border py-5">
      <div className="flex items-start gap-3">
        <FileKey2 className="mt-1 h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
        <div>
          <h2 id="ca-cross-sign-heading" className="text-title font-semibold">
            {t("caHierarchy.crossSign.title")}
          </h2>
          <p className="text-sm text-muted-foreground">{t("caHierarchy.crossSign.description")}</p>
        </div>
      </div>
      {actionError && <ErrorState title={t("caHierarchy.crossSign.error")}>{actionError}</ErrorState>}
      <Card>
        <CardHeader>
          <CardTitle>{t("caHierarchy.crossSign.resume")}</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-wrap items-end gap-3">
          <Field label={t("caHierarchy.crossSign.ceremonyID")} controlId="cross-sign-ceremony-id">
            {(field) => <Input {...field} value={ceremonyID} onChange={(event) => setCeremonyID(event.target.value.trim())} />}
          </Field>
          <Button type="button" variant="outline" disabled={!validCeremonyID || ceremony.fetching} onClick={() => ceremony.refetch()}>
            <RefreshCw className="h-4 w-4" aria-hidden="true" /> {t("caHierarchy.crossSign.refresh")}
          </Button>
          {ceremony.error && <ErrorState title={t("caHierarchy.crossSign.lookupError")}>{ceremony.error}</ErrorState>}
          {ceremony.data && (
            <p role="status" className="text-sm">
              {t("caHierarchy.crossSign.status")}: {ceremony.data.status}; {t("caHierarchy.crossSign.approvals")}:{" "}
              <Num>
                {ceremony.data.approvals}/{ceremony.data.threshold}
              </Num>
            </p>
          )}
        </CardContent>
      </Card>
      <StepShell
        currentIndex={step}
        steps={steps}
        progressLabel={t("caHierarchy.crossSign.progress")}
        onPrevious={step > 0 ? () => setStep(step - 1) : undefined}
        onNext={step === 0 ? () => void review() : step === 1 ? () => void enterCeremony() : undefined}
        nextDisabled={busy || (step === 1 && (!current || Boolean(ceremonyID && !matching)))}
        nextLabel={step === 0 ? t("caHierarchy.crossSign.review") : ceremonyID ? t("caHierarchy.crossSign.continue") : t("caHierarchy.crossSign.start")}
      >
        {step === 0 && (
          <div className="grid gap-4">
            <Field
              label={t("caHierarchy.crossSign.issuer")}
              error={errors.issuerID && t("caHierarchy.crossSign.selectIssuer")}
              controlId="cross-sign-issuer"
              required
            >
              {(field) => (
                <Select {...field} {...register("issuerID")}>
                  <option value="">{t("caHierarchy.crossSign.selectIssuer")}</option>
                  {authorities
                    .filter((ca) => ca.status === "active" && ca.signer_handle)
                    .map((ca) => (
                      <option key={ca.id} value={ca.id}>
                        {ca.common_name} ({ca.id})
                      </option>
                    ))}
                </Select>
              )}
            </Field>
            <Field label={t("caHierarchy.crossSign.target")} error={errors.targetID && t("caHierarchy.crossSign.selectTarget")} controlId="cross-sign-target">
              {(field) => (
                <Select
                  {...field}
                  {...targetField}
                  onChange={(event) => {
                    void targetField.onChange(event);
                    setValue("targetPEM", "");
                  }}
                >
                  <option value="">{t("caHierarchy.crossSign.selectTarget")}</option>
                  {authorities
                    .filter((ca) => ca.id !== issuerID)
                    .map((ca) => (
                      <option key={ca.id} value={ca.id}>
                        {ca.common_name} ({ca.id})
                      </option>
                    ))}
                </Select>
              )}
            </Field>
            <Field
              label={t("caHierarchy.crossSign.externalTarget")}
              error={errors.targetPEM && t("caHierarchy.crossSign.invalidPEM")}
              controlId="cross-sign-public-pem"
            >
              {(field) => (
                <Textarea
                  {...field}
                  {...pemField}
                  rows={4}
                  onChange={(event) => {
                    void pemField.onChange(event);
                    setValue("targetID", "");
                  }}
                />
              )}
            </Field>
            <Field
              label={t("caHierarchy.crossSign.reason")}
              error={errors.reason && t("caHierarchy.crossSign.required")}
              controlId="cross-sign-reason"
              required
            >
              {(field) => <Input {...field} {...register("reason")} />}
            </Field>
          </div>
        )}
        {step === 1 && reviewed && (
          <div className="grid gap-3 text-sm">
            <strong>{t("caHierarchy.crossSign.reviewed")}</strong>
            <p>
              {reviewed.preview.authority?.common_name} ({reviewed.issuerID})
            </p>
            <p>
              {t("caHierarchy.crossSign.targetSHA")}: <CredentialChip value={reviewed.targetSHA} label={t("caHierarchy.crossSign.targetSHA")} fullValue />
            </p>
            <p>
              {t("caHierarchy.crossSign.fingerprint")}:{" "}
              <CredentialChip value={reviewed.preview.request_fingerprint} label={t("caHierarchy.crossSign.fingerprint")} fullValue />
            </p>
            <p>
              {t("caHierarchy.crossSign.quorum")}: <Num>{reviewed.preview.approval_threshold}</Num>
            </p>
            <p>{t("caHierarchy.crossSign.reviewEffect")}</p>
            {!current && <ErrorState title={t("caHierarchy.crossSign.staleReview")}>{t("caHierarchy.crossSign.staleReviewDetail")}</ErrorState>}
            {ceremonyID && ceremony.data && !matching && <ErrorState title={t("caHierarchy.crossSign.purposeMismatch")}>{ceremony.data.purpose}</ErrorState>}
          </div>
        )}
        {step === 2 && (
          <div className="grid gap-3 text-sm">
            {reviewed && (
              <p>
                {t("caHierarchy.crossSign.issuer")}: <CredentialChip value={reviewed.issuerID} label={t("caHierarchy.crossSign.issuer")} />;{" "}
                {t("caHierarchy.crossSign.targetSHA")}: <CredentialChip value={reviewed.targetSHA} label={t("caHierarchy.crossSign.targetSHA")} fullValue />
              </p>
            )}
            {reviewed && (
              <p>
                {t("caHierarchy.crossSign.reason")}: {reviewed.reason}
              </p>
            )}
            <p>
              {t("caHierarchy.crossSign.ceremonyID")}: {ceremonyID && <CredentialChip value={ceremonyID} label={t("caHierarchy.crossSign.ceremonyID")} />}
            </p>
            {ceremony.data?.status === "pending" && <p>{t("caHierarchy.crossSign.approvalHelp")}</p>}
            {ceremony.data && (
              <p>
                {t("caHierarchy.crossSign.status")}: {ceremony.data.status}; {t("caHierarchy.crossSign.approvals")}:{" "}
                <Num>
                  {ceremony.data.approvals}/{ceremony.data.threshold}
                </Num>
              </p>
            )}
            <Button
              type="button"
              loading={busy}
              disabled={!current || !matching || ceremony.data?.status !== "pending" || (ceremony.data?.approvals ?? 0) < (ceremony.data?.threshold ?? 1)}
              onClick={() => void activate()}
            >
              {t("caHierarchy.crossSign.activate")}
            </Button>
          </div>
        )}
      </StepShell>
      {receipt.error && ceremony.data?.status === "completed" && <ErrorState title={t("caHierarchy.crossSign.receiptUnavailable")}>{receipt.error}</ErrorState>}
      {receipt.data && (
        <Card>
          <CardHeader>
            <CardTitle>{t("caHierarchy.crossSign.receipt")}</CardTitle>
          </CardHeader>
          <CardContent className="grid gap-3">
            <p>
              {t("caHierarchy.crossSign.issuer")}: <CredentialChip value={receipt.data.issuer_authority_id} label={t("caHierarchy.crossSign.issuer")} />
            </p>
            <p>
              {t("caHierarchy.crossSign.targetSHA")}:{" "}
              <CredentialChip value={receipt.data.target_sha256} label={t("caHierarchy.crossSign.targetSHA")} fullValue />
            </p>
            <Field label={t("caHierarchy.crossSign.publicPEM")} controlId="cross-sign-receipt-pem">
              {(field) => <Textarea {...field} readOnly rows={10} value={receipt.data?.certificate_pem ?? ""} />}
            </Field>
            <p className="text-sm text-muted-foreground">{t("caHierarchy.crossSign.verifyHelp")}</p>
          </CardContent>
        </Card>
      )}
    </section>
  );
}
