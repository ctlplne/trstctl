import { useEffect, useRef, useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { useAuth } from "@/auth/AuthProvider";
import { CredentialChip } from "@/components/CredentialChip";
import { DataGrid } from "@/components/DataGrid";
import { Num } from "@/components/typography";
import { StepShell } from "@/components/wizard/StepShell";
import { Button } from "@/components/ui/button";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { useTranslation } from "@/i18n/I18nProvider";
import { api, type ManagedTenant, type ManagedTenantProvisionRequest } from "@/lib/api";
import { ApiError, UnauthorizedError } from "@/lib/apiTransport";
import {
  completeManagedTenantAttempt,
  listManagedTenantAttempts,
  managedTenantRequestSchema,
  ManagedTenantRecoveryError,
  prepareManagedTenantAttempt,
  type ManagedTenantAttempt,
  type ManagedTenantPrincipal,
} from "@/lib/managedTenantAttempts";

const defaults: ManagedTenantProvisionRequest = {
  tenant_id: "",
  name: "",
  region: "us-east-1",
  data_residency: "US",
  plan: "enterprise",
  support_tier: "24x7",
  slo_tier: "99.95",
};
const stepsFields: Array<Array<keyof ManagedTenantProvisionRequest>> = [
  ["tenant_id", "name"],
  ["region", "data_residency"],
  ["plan", "support_tier", "slo_tier"],
];
const fieldKeys = {
  tenant_id: "source.hosted.id.16f3dc88ea",
  name: "source.hosted.name.af1e0d31be",
  region: "source.region.d3a008ef13",
  data_residency: "source.data.residency.4ab08acdfa",
  plan: "source.plan.fa8ed0bdab",
  support_tier: "source.support.tier.2dfba0f890",
  slo_tier: "source.slo.tier.9d31a12006",
} as const;

export function ManagedTenantProvisioning({ enabled }: { enabled: boolean }) {
  const { user, preview } = useAuth();
  const { t } = useTranslation();
  if (!user || preview) return <p>{t("managedRecovery.signIn")}</p>;
  const principal = { tenantId: user.tenant_id, subject: user.subject };
  return <ProvisioningWorkspace key={JSON.stringify(principal)} principal={principal} enabled={enabled} />;
}

function ProvisioningWorkspace({ principal, enabled }: { principal: ManagedTenantPrincipal; enabled: boolean }) {
  const { t } = useTranslation();
  const [step, setStep] = useState(0);
  const [pending, setPending] = useState<ManagedTenantAttempt[]>([]);
  const [attempt, setAttempt] = useState<ManagedTenantAttempt | null>(null);
  const [review, setReview] = useState<ManagedTenantProvisionRequest | null>(null);
  const [receipt, setReceipt] = useState<ManagedTenant | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(true);
  const alive = useRef(true);
  const inFlight = useRef(false);
  const {
    register,
    handleSubmit,
    trigger,
    reset,
    formState: { errors },
  } = useForm<ManagedTenantProvisionRequest>({
    resolver: zodResolver(managedTenantRequestSchema),
    defaultValues: defaults,
  });

  function failureMessage(failure: unknown): string {
    if (failure instanceof ManagedTenantRecoveryError) {
      switch (failure.code) {
        case "pending_request_changed":
          return t("managedRecovery.changed");
        case "pending_limit":
          return t("managedRecovery.limit");
        case "invalid_record":
          return t("managedRecovery.invalidRecord");
        case "invalid_request":
          return t("managedRecovery.invalidRequest");
        case "unverified_response":
          return t("managedRecovery.unverifiedResponse");
        default:
          return t("managedRecovery.storageUnavailable");
      }
    }
    if (failure instanceof UnauthorizedError) return t("managedRecovery.sessionExpired");
    if (failure instanceof ApiError) return `${failure.message} ${t("managedRecovery.retryNeeded")}`;
    return t("managedRecovery.retryNeeded");
  }

  async function refreshPending() {
    const records = await listManagedTenantAttempts(principal);
    if (alive.current) setPending(records);
  }

  useEffect(() => {
    alive.current = true;
    void listManagedTenantAttempts({ tenantId: principal.tenantId, subject: principal.subject })
      .then((records) => {
        if (alive.current) setPending(records);
      })
      .catch((failure: unknown) => {
        if (alive.current)
          setError(
            failure instanceof ManagedTenantRecoveryError && failure.code === "invalid_record"
              ? t("managedRecovery.invalidRecord")
              : t("managedRecovery.storageUnavailable"),
          );
      })
      .finally(() => {
        if (alive.current) setLoading(false);
      });
    return () => {
      alive.current = false;
    };
  }, [principal.tenantId, principal.subject, t]);

  async function next() {
    if (busy || inFlight.current) return;
    if (step < 2) {
      if (await trigger(stepsFields[step])) setStep(step + 1);
    } else {
      await handleSubmit((values) => {
        setReview(values);
        setStep(3);
      })();
    }
  }

  function resume(saved: ManagedTenantAttempt) {
    if (inFlight.current) return;
    setAttempt(saved);
    setReview(saved.request);
    reset(saved.request);
    setReceipt(null);
    setError(null);
    setStep(3);
  }

  async function provision() {
    if (!review || !enabled || inFlight.current) return;
    inFlight.current = true;
    setBusy(true);
    setError(null);
    try {
      const retained = await prepareManagedTenantAttempt(principal, review);
      if (!alive.current) return;
      setAttempt(retained);
      await refreshPending();
      if (!alive.current) return;
      const created = await api.provisionManagedTenant(retained.request, retained.key, { tenant_id: principal.tenantId, subject: principal.subject });
      if (!alive.current) return;
      if (
        created.tenant_id !== retained.request.tenant_id ||
        created.provider_tenant_id !== principal.tenantId ||
        created.name !== retained.request.name ||
        !created.managed ||
        created.deployment_model !== "managed_provider" ||
        created.provisioned_by !== principal.subject ||
        !Number.isSafeInteger(created.event_sequence) ||
        created.event_sequence <= 0 ||
        !["region", "data_residency", "plan", "support_tier", "slo_tier"].every(
          (field) => (created[field as keyof ManagedTenant] ?? "") === (retained.request[field as keyof ManagedTenantProvisionRequest] ?? ""),
        )
      ) {
        throw new ManagedTenantRecoveryError("unverified_response");
      }
      setReceipt(created);
      try {
        await completeManagedTenantAttempt(principal, retained);
      } catch {
        if (alive.current) setError(t("managedRecovery.cleanupFailed"));
      }
      if (!alive.current) return;
      setAttempt(null);
      setReview(null);
      reset(defaults);
      setStep(0);
      await refreshPending().catch(() => {
        if (alive.current) setError(t("managedRecovery.refreshFailed"));
      });
    } catch (failure) {
      if (alive.current) {
        setError(failureMessage(failure));
        await refreshPending().catch(() => {});
      }
    } finally {
      inFlight.current = false;
      if (alive.current) setBusy(false);
    }
  }

  function newCustomer() {
    setAttempt(null);
    setReview(null);
    setReceipt(null);
    setError(null);
    reset(defaults);
    setStep(0);
  }

  const labels = ["managedRecovery.customer", "managedRecovery.placement", "managedRecovery.service", "managedRecovery.review"] as const;
  const descriptions = ["managedRecovery.customerHelp", "managedRecovery.placementHelp", "managedRecovery.serviceHelp", "managedRecovery.reviewHelp"] as const;
  return (
    <div className="grid gap-4">
      {error && (
        <p role="alert" className="text-sm text-risk-critical">
          {error}
        </p>
      )}
      {receipt && (
        <div role="status" className="grid gap-2">
          <p>{t("managedRecovery.created", { name: receipt.name })}</p>
          <CredentialChip value={receipt.tenant_id} label={t("source.hosted.id.16f3dc88ea")} />
          <p className="text-sm text-muted-foreground">
            {t("managedRecovery.event")} <Num>{receipt.event_sequence}</Num>
          </p>
        </div>
      )}
      {(loading || pending.length > 0) && (
        <section className="grid gap-2" aria-label={t("managedRecovery.pending")}>
          <h3 className="font-semibold">{t("managedRecovery.pending")}</h3>
          <p className="text-sm text-muted-foreground">{t("managedRecovery.pendingHelp")}</p>
          <DataGrid
            className="[&_table]:min-w-0 [&_table]:table-fixed"
            ariaLabel={t("managedRecovery.pending")}
            rows={pending}
            getRowId={(saved) => saved.scope}
            state={loading ? "loading" : "ready"}
            columns={[
              {
                id: "customer",
                header: t("managedRecovery.customer"),
                cell: (saved) => (
                  <div className="grid min-w-0 gap-1">
                    <span className="break-words">{saved.request.name}</span>
                    <CredentialChip value={saved.request.tenant_id} label={t(fieldKeys.tenant_id)} />
                  </div>
                ),
              },
              {
                id: "recovery",
                header: t("managedRecovery.recovery"),
                className: "w-28",
                cell: (saved) => (
                  <Button
                    type="button"
                    variant="outline"
                    disabled={busy}
                    aria-label={t("managedRecovery.resume", { name: saved.request.name })}
                    onClick={() => resume(saved)}
                  >
                    {t("managedRecovery.reviewShort")}
                  </Button>
                ),
              },
            ]}
          />
        </section>
      )}
      <StepShell
        currentIndex={step}
        steps={labels.map((key, index) => ({ id: key, label: t(key), description: t(descriptions[index]) }))}
        progressLabel={t("managedRecovery.progress")}
        onPrevious={step > 0 && !attempt && !busy ? () => setStep(step - 1) : undefined}
        onNext={step < 3 ? () => void next() : undefined}
        nextDisabled={busy || loading || !enabled}
      >
        {step < 3 ? (
          <form
            onSubmit={(event) => {
              event.preventDefault();
              void next();
            }}
            className="grid gap-3"
          >
            {stepsFields[step].map((field) => (
              <Field
                key={field}
                label={t(fieldKeys[field])}
                required={field === "name" || field === "tenant_id"}
                error={
                  errors[field]
                    ? t(
                        field === "tenant_id"
                          ? "managedRecovery.uuidRequired"
                          : field === "name"
                            ? "managedRecovery.nameRequired"
                            : "managedRecovery.metadataLimit",
                      )
                    : undefined
                }
              >
                {(control) => <Input {...control} {...register(field)} disabled={busy || !enabled} />}
              </Field>
            ))}
          </form>
        ) : (
          <div className="grid gap-4">
            <dl className="grid gap-2 text-sm">
              {(Object.keys(fieldKeys) as Array<keyof ManagedTenantProvisionRequest>).map((field) => (
                <div key={field}>
                  <dt className="font-medium">{t(fieldKeys[field])}</dt>
                  <dd className="break-words">{review?.[field] || "—"}</dd>
                </div>
              ))}
            </dl>
            {attempt && <p className="text-sm text-muted-foreground">{t("managedRecovery.savedRequest")}</p>}
            <Button type="button" loading={busy} disabled={busy || loading || !enabled} onClick={() => void provision()}>
              {attempt ? t("managedRecovery.retry") : t("source.provision.tenant.e6e411f04c")}
            </Button>
            {attempt && (
              <details>
                <summary>{t("managedRecovery.requestKey")}</summary>
                <CredentialChip value={attempt.key} label={t("managedRecovery.requestKey")} />
              </details>
            )}
            {attempt && (
              <Button type="button" variant="outline" disabled={busy} onClick={newCustomer}>
                {t("managedRecovery.another")}
              </Button>
            )}
          </div>
        )}
      </StepShell>
    </div>
  );
}
