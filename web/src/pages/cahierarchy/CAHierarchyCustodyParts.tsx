import { useEffect, useMemo, useState } from "react";
import { AlertTriangle, CheckCircle2, KeyRound, ShieldCheck } from "lucide-react";
import { CredentialChip } from "@/components/CredentialChip";
import { EmptyState } from "@/components/EmptyState";
import { ErrorState, LoadingState, UnavailableState } from "@/components/StatePrimitives";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Field } from "@/components/ui/field";
import { Select } from "@/components/ui/select";
import { StepShell, type CarouselStep } from "@/components/wizard/StepShell";
import { translateNow, useTranslation } from "@/i18n/I18nProvider";
import {
  api,
  type ManagedKey,
  type ManagedKeyCustodyPlan,
  type ManagedKeyGenerateRequest,
  type ManagedKeyGenerationPreview,
  type ManagedKeyGenerationPreviewRequest,
} from "@/lib/api";
import { apiProblemMessage } from "@/lib/apiProblem";

const algorithms: ManagedKeyGenerateRequest["algorithm"][] = ["ECDSA-P256", "ECDSA-P384", "ECDSA-P521", "RSA-2048", "RSA-3072", "RSA-4096"];

/** ManagedKeyCustodyWorkspace owns one complete operator journey. The browser
 * only selects a provider and algorithm. Provider credentials and device paths
 * remain startup configuration read by the control plane and isolated signer;
 * this component never accepts, stores, or sends those values. */
export function ManagedKeyCustodyWorkspace() {
  const { t } = useTranslation();
  const [plan, setPlan] = useState<ManagedKeyCustodyPlan | null>(null);
  const [planError, setPlanError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [provider, setProvider] = useState<ManagedKeyGenerationPreviewRequest["provider"] | "">("");
  const [algorithm, setAlgorithm] = useState<ManagedKeyGenerateRequest["algorithm"]>("ECDSA-P256");
  const [preview, setPreview] = useState<ManagedKeyGenerationPreview | null>(null);
  const [previewBusy, setPreviewBusy] = useState(false);
  const [previewError, setPreviewError] = useState<string | null>(null);
  const [currentIndex, setCurrentIndex] = useState(0);
  const [managedKey, setManagedKey] = useState<ManagedKey | null>(null);
  const [keyBusy, setKeyBusy] = useState(false);
  const [keyError, setKeyError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    setLoading(true);
    const custodyRead =
      typeof api.managedKeyCustody === "function" ? api.managedKeyCustody() : Promise.reject(new Error("managed-key custody planning is unavailable"));
    custodyRead
      .then((next) => {
        if (!active) return;
        // Older test fixtures and rolling-upgrade peers may omit newly added
        // collection fields. Normalize them to honest empty lists instead of
        // crashing the entire CA workspace while the server contract converges.
        const normalized = {
          ...next,
          blockers: next.blockers ?? [],
          providers: (next.providers ?? []).map((item) => ({ ...item, requirements: item.requirements ?? [] })),
        };
        setPlan(normalized);
        setPlanError(null);
        const initialProvider = normalized.configured_provider || normalized.providers[0]?.id || "";
        setProvider(initialProvider);
      })
      .catch((error) => {
        if (!active) return;
        setPlan(null);
        setPlanError(apiProblemMessage(error, translateNow("caHierarchy.custody.loadFailed")));
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, []);

  const selectedProvider = useMemo(() => plan?.providers.find((item) => item.id === provider) ?? null, [plan, provider]);
  const previewIsSafe = Boolean(preview?.ready && preview.effect_free && preview.preview_writes.length === 0 && preview.preview_external_effects.length === 0);
  const localizedSteps: CarouselStep[] = [
    { id: "configure", label: t("caHierarchy.custody.steps.configure.label"), description: t("caHierarchy.custody.steps.configure.description") },
    { id: "preview", label: t("caHierarchy.custody.steps.preview.label"), description: t("caHierarchy.custody.steps.preview.description") },
    { id: "generate", label: t("caHierarchy.custody.steps.generate.label"), description: t("caHierarchy.custody.steps.generate.description") },
  ];

  function invalidatePreview() {
    setPreview(null);
    setPreviewError(null);
    if (currentIndex > 0) setCurrentIndex(0);
  }

  async function reviewGeneration() {
    if (!provider) return;
    setPreviewBusy(true);
    setPreviewError(null);
    setPreview(null);
    try {
      const next = await api.previewManagedKeyGeneration({ provider, algorithm });
      setPreview({
        ...next,
        blockers: next.blockers ?? [],
        execution_external_effects: next.execution_external_effects ?? [],
        execution_writes: next.execution_writes ?? [],
        preview_external_effects: next.preview_external_effects ?? [],
        preview_writes: next.preview_writes ?? [],
        proof: next.proof ?? [],
        requirements: next.requirements ?? [],
      });
      setCurrentIndex(1);
    } catch (error) {
      setPreviewError(apiProblemMessage(error, t("caHierarchy.custody.previewFailed")));
    } finally {
      setPreviewBusy(false);
    }
  }

  async function generateManagedKey() {
    if (!previewIsSafe || !preview) return;
    setKeyBusy(true);
    setKeyError(null);
    try {
      setManagedKey(await api.generateManagedKey({ algorithm: preview.algorithm as ManagedKeyGenerateRequest["algorithm"] }));
    } catch (error) {
      setKeyError(apiProblemMessage(error, t("caHierarchy.custody.generateFailed")));
    } finally {
      setKeyBusy(false);
    }
  }

  async function runManagedKeyAction(action: "rotate" | "revoke" | "zeroize", keyId: string) {
    setKeyBusy(true);
    setKeyError(null);
    try {
      const next =
        action === "rotate" ? await api.rotateManagedKey(keyId) : action === "revoke" ? await api.revokeManagedKey(keyId) : await api.zeroizeManagedKey(keyId);
      setManagedKey(next);
    } catch (error) {
      setKeyError(apiProblemMessage(error, t("caHierarchy.custody.actionFailed", { action })));
    } finally {
      setKeyBusy(false);
    }
  }

  return (
    <section aria-labelledby="custody-heading" className="grid gap-4 border-y border-border py-4">
      <div className="flex items-start gap-3">
        <KeyRound className="mt-1 h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
        <div>
          <h2 id="custody-heading" className="text-title font-semibold">
            {t("caHierarchy.custody.title")}
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{t("caHierarchy.custody.description")}</p>
        </div>
      </div>

      {loading ? <LoadingState>{t("caHierarchy.custody.loading")}</LoadingState> : null}
      {planError ? <ErrorState title={t("caHierarchy.custody.unavailable")}>{planError}</ErrorState> : null}
      {!loading && !planError && plan ? (
        <StepShell
          currentIndex={currentIndex}
          steps={localizedSteps}
          progressLabel={t("caHierarchy.custody.progress")}
          onPrevious={currentIndex > 0 ? () => setCurrentIndex((index) => Math.max(0, index - 1)) : undefined}
          onNext={currentIndex === 0 ? () => void reviewGeneration() : currentIndex === 1 ? () => setCurrentIndex(2) : undefined}
          nextDisabled={currentIndex === 0 ? !provider || previewBusy : !previewIsSafe}
          nextLabel={currentIndex === 0 ? t("caHierarchy.custody.review") : t("caHierarchy.custody.continue")}
        >
          {currentIndex === 0 ? (
            <CustodyConfiguration
              algorithm={algorithm}
              plan={plan}
              provider={provider}
              previewBusy={previewBusy}
              selectedProvider={selectedProvider}
              onAlgorithmChange={(next) => {
                setAlgorithm(next);
                invalidatePreview();
              }}
              onProviderChange={(next) => {
                setProvider(next);
                invalidatePreview();
              }}
            />
          ) : null}
          {currentIndex === 1 ? <CustodyPreview preview={preview} error={previewError} /> : null}
          {currentIndex === 2 && preview ? (
            <CustodyGeneration
              busy={keyBusy}
              error={keyError}
              managedKey={managedKey}
              preview={preview}
              onGenerate={() => void generateManagedKey()}
              onAction={(action, keyId) => void runManagedKeyAction(action, keyId)}
            />
          ) : null}
        </StepShell>
      ) : null}
    </section>
  );
}

function CustodyConfiguration({
  algorithm,
  plan,
  previewBusy,
  provider,
  selectedProvider,
  onAlgorithmChange,
  onProviderChange,
}: {
  algorithm: ManagedKeyGenerateRequest["algorithm"];
  plan: ManagedKeyCustodyPlan;
  previewBusy: boolean;
  provider: ManagedKeyGenerationPreviewRequest["provider"] | "";
  selectedProvider: ManagedKeyCustodyPlan["providers"][number] | null;
  onAlgorithmChange: (algorithm: ManagedKeyGenerateRequest["algorithm"]) => void;
  onProviderChange: (provider: ManagedKeyGenerationPreviewRequest["provider"]) => void;
}) {
  const { t } = useTranslation();
  const configured = plan.providers.find((item) => item.id === plan.configured_provider);
  return (
    <div className="grid gap-4">
      <Card>
        <CardHeader>
          <CardTitle>{t("caHierarchy.custody.chooseTitle")}</CardTitle>
          <p className="text-sm text-muted-foreground">{t("caHierarchy.custody.chooseDescription")}</p>
        </CardHeader>
        <CardContent className="grid gap-4 sm:grid-cols-2">
          <Field label={t("caHierarchy.custody.provider")} description={t("caHierarchy.custody.providerHelp")} required>
            {(control) => (
              <Select
                {...control}
                value={provider}
                disabled={previewBusy}
                onChange={(event) => onProviderChange(event.target.value as ManagedKeyGenerationPreviewRequest["provider"])}
                required
              >
                {plan.providers.map((item) => (
                  <option key={item.id} value={item.id}>
                    {item.label}
                  </option>
                ))}
              </Select>
            )}
          </Field>
          <Field label={t("caHierarchy.custody.algorithm")} description={t("caHierarchy.custody.algorithmHelp")} required>
            {(control) => (
              <Select
                {...control}
                value={algorithm}
                disabled={previewBusy}
                onChange={(event) => onAlgorithmChange(event.target.value as ManagedKeyGenerateRequest["algorithm"])}
                required
              >
                {algorithms.map((item) => (
                  <option key={item} value={item}>
                    {item}
                  </option>
                ))}
              </Select>
            )}
          </Field>
        </CardContent>
      </Card>

      <div className="grid gap-3 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>{configured ? t("caHierarchy.custody.configured", { provider: configured.label }) : t("caHierarchy.custody.notConfigured")}</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2 text-sm text-muted-foreground">
            <p>{plan.security_boundary}</p>
            <p>{t("caHierarchy.custody.startupOnly")}</p>
            <p className="font-medium text-foreground">
              {plan.lifecycle_attached ? t("caHierarchy.custody.signerAttached") : t("caHierarchy.custody.signerNotAttached")}
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>{selectedProvider?.label ?? t("caHierarchy.custody.requirements")}</CardTitle>
            {selectedProvider ? <p className="text-sm text-muted-foreground">{selectedProvider.custody}</p> : null}
          </CardHeader>
          <CardContent>
            {selectedProvider?.requirements.length ? (
              <ul className="space-y-3">
                {selectedProvider.requirements.map((requirement) => (
                  <li key={requirement.key} className="border-s-2 border-border ps-3 text-sm">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-medium">{requirement.label}</span>
                      <span className="rounded-control border border-border bg-muted/50 px-1.5 py-0.5 text-caption text-muted-foreground">
                        {requirement.required ? t("caHierarchy.custody.required") : t("caHierarchy.custody.optional")}
                      </span>
                      {requirement.kind === "secret_file" ? (
                        <span className="rounded-control border border-border bg-muted/50 px-1.5 py-0.5 text-caption text-muted-foreground">
                          {t("caHierarchy.custody.fileReference")}
                        </span>
                      ) : null}
                    </div>
                    <p className="mt-1 text-muted-foreground">{requirement.description}</p>
                    <code className="mt-1 block break-all text-caption text-foreground">{requirement.environment_variable}</code>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-sm text-muted-foreground">{t("caHierarchy.custody.noRequirements")}</p>
            )}
          </CardContent>
        </Card>
      </div>
      {plan.blockers.length ? (
        <UnavailableState title={t("caHierarchy.custody.setupNeeded")}>
          <ul className="list-disc space-y-1 ps-5">
            {plan.blockers.map((blocker) => (
              <li key={blocker}>{blocker}</li>
            ))}
          </ul>
        </UnavailableState>
      ) : null}
    </div>
  );
}

function CustodyPreview({ preview, error }: { preview: ManagedKeyGenerationPreview | null; error: string | null }) {
  const { t } = useTranslation();
  if (error) return <ErrorState title={t("caHierarchy.custody.previewFailed")}>{error}</ErrorState>;
  if (!preview) return <LoadingState>{t("caHierarchy.custody.previewLoading")}</LoadingState>;
  return (
    <div className="grid gap-4">
      <Card className={preview.effect_free ? "border-status-success/40" : "border-destructive/40"}>
        <CardHeader>
          <div className="flex items-start gap-2">
            {preview.effect_free ? (
              <CheckCircle2 className="mt-0.5 h-5 w-5 shrink-0 text-status-success" aria-hidden="true" />
            ) : (
              <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-destructive" aria-hidden="true" />
            )}
            <div>
              <CardTitle>{t("caHierarchy.custody.nothingChanged")}</CardTitle>
              <p className="mt-1 text-sm text-muted-foreground">
                {t("caHierarchy.custody.previewCounts", { writes: preview.preview_writes.length, calls: preview.preview_external_effects.length })}
              </p>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <dl className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <Fact label={t("caHierarchy.custody.provider")} value={preview.provider_label} />
            <Fact label={t("caHierarchy.custody.algorithm")} value={preview.algorithm} />
            <Fact label={t("caHierarchy.custody.privateKey")} value={preview.private_key_location} />
            <Fact label={t("caHierarchy.custody.extractable")} value={preview.extractable ? t("platform.idempotency.yes") : t("platform.idempotency.no")} />
            <Fact label={t("caHierarchy.custody.permission")} value={preview.required_permission} />
            <Fact label={t("caHierarchy.custody.approval")} value={preview.approval_required ? t("platform.idempotency.yes") : t("platform.idempotency.no")} />
          </dl>
        </CardContent>
      </Card>

      {preview.blockers.length ? (
        <ErrorState title={t("caHierarchy.custody.blocked")}>
          <ul className="list-disc space-y-1 ps-5">
            {preview.blockers.map((blocker) => (
              <li key={blocker}>{blocker}</li>
            ))}
          </ul>
        </ErrorState>
      ) : null}

      <div className="grid gap-3 lg:grid-cols-3">
        <ReviewList title={t("caHierarchy.custody.executionWrites")} items={preview.execution_writes} />
        <ReviewList title={t("caHierarchy.custody.outsideEffects")} items={preview.execution_external_effects} />
        <ReviewList title={t("caHierarchy.custody.proof")} items={preview.proof} />
      </div>
    </div>
  );
}

function CustodyGeneration({
  busy,
  error,
  managedKey,
  preview,
  onAction,
  onGenerate,
}: {
  busy: boolean;
  error: string | null;
  managedKey: ManagedKey | null;
  preview: ManagedKeyGenerationPreview;
  onAction: (action: "rotate" | "revoke" | "zeroize", keyId: string) => void;
  onGenerate: () => void;
}) {
  const { t } = useTranslation();
  return (
    <div className="grid gap-4">
      <Card>
        <CardHeader>
          <div className="flex items-start gap-2">
            <ShieldCheck className="mt-0.5 h-5 w-5 shrink-0 text-status-success" aria-hidden="true" />
            <div>
              <CardTitle>{t("caHierarchy.custody.reviewedReady")}</CardTitle>
              <p className="mt-1 text-sm text-muted-foreground">
                {t("caHierarchy.custody.reviewedReadyDetail", { provider: preview.provider_label, algorithm: preview.algorithm })}
              </p>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <Button type="button" disabled={busy || Boolean(managedKey)} onClick={onGenerate}>
            {busy ? t("caHierarchy.custody.generating") : t("caHierarchy.custody.generate")}
          </Button>
        </CardContent>
      </Card>
      {error ? <ErrorState title={t("caHierarchy.custody.actionFailedTitle")}>{error}</ErrorState> : null}
      {managedKey ? (
        <ManagedKeyPanel managedKey={managedKey} busy={busy} onAction={onAction} />
      ) : (
        <EmptyState title={t("caHierarchy.custody.noKey")}>{t("caHierarchy.custody.noKeyDetail")}</EmptyState>
      )}
    </div>
  );
}

function ManagedKeyPanel({
  busy,
  managedKey,
  onAction,
}: {
  busy: boolean;
  managedKey: ManagedKey;
  onAction: (action: "rotate" | "revoke" | "zeroize", keyId: string) => void;
}) {
  const { t } = useTranslation();
  return (
    <section aria-labelledby="managed-key-heading" className="ui-panel p-comfortable text-sm">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h3 id="managed-key-heading" className="text-title font-semibold">
            {t("caHierarchy.custody.managedKey")}
          </h3>
          <p className="mt-1">
            <CredentialChip value={managedKey.key_id} label={t("caHierarchy.custody.keyID")} />
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          {(["rotate", "revoke", "zeroize"] as const).map((action) => (
            <Button
              key={action}
              type="button"
              size="sm"
              variant="outline"
              disabled={busy}
              onClick={() => onAction(action, managedKey.key_id)}
              aria-label={t(`caHierarchy.custody.actions.${action}.label`, { keyId: managedKey.key_id })}
            >
              {t(`caHierarchy.custody.actions.${action}.button`)}
            </Button>
          ))}
        </div>
      </div>
      <dl className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
        <Fact label={t("caHierarchy.custody.algorithm")} value={managedKey.algorithm} />
        <Fact label={t("caHierarchy.custody.version")} value={t("caHierarchy.custody.versionValue", { version: managedKey.version })} />
        <Fact label={t("caHierarchy.custody.state")} value={managedKey.state} />
        <Fact
          label={t("caHierarchy.custody.publicDER")}
          value={managedKey.public_der ? t("caHierarchy.custody.bytes", { count: managedKey.public_der.length }) : "-"}
        />
        <Fact label={t("caHierarchy.custody.extractable")} value={managedKey.extractable ? t("platform.idempotency.yes") : t("platform.idempotency.no")} />
      </dl>
    </section>
  );
}

function ReviewList({ title, items }: { title: string; items: string[] }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>{title}</CardTitle>
      </CardHeader>
      <CardContent>
        {items.length ? (
          <ul className="list-disc space-y-2 ps-5 text-sm text-muted-foreground">
            {items.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        ) : (
          <p className="text-sm text-muted-foreground">—</p>
        )}
      </CardContent>
    </Card>
  );
}

function Fact({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt className="text-caption font-medium text-muted-foreground">{label}</dt>
      <dd className="mt-0.5 break-words font-medium">{value}</dd>
    </div>
  );
}
