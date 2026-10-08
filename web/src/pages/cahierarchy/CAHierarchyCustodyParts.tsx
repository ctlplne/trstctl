import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { useAuth } from "@/auth/AuthProvider";
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
  ApiError,
  type ManagedKey,
  type ManagedKeyOperation,
  type ManagedKeyRecord,
  type ManagedKeyCustodyPlan,
  type ManagedKeyGenerateRequest,
  type ManagedKeyGenerationPreview,
  type ManagedKeyGenerationPreviewRequest,
} from "@/lib/api";
import { apiProblemMessage } from "@/lib/apiProblem";
import { clearManagedKeyActionIntent, getOrCreateManagedKeyActionIntent } from "@/lib/managedKeyActionIntent";
import { useApiQuery } from "@/lib/query";

const algorithms: ManagedKeyGenerateRequest["algorithm"][] = ["ECDSA-P256", "ECDSA-P384", "ECDSA-P521", "RSA-2048", "RSA-3072", "RSA-4096"];

type PendingManagedKeyApproval = { requestId: string; intentDigest: string };

function isManagedKeyOperation(value: ManagedKey | ManagedKeyOperation): value is ManagedKeyOperation {
  return "operation_id" in value;
}

function pendingManagedKeyApproval(error: unknown): PendingManagedKeyApproval | null {
  if (!(error instanceof ApiError) || error.status !== 403) return null;
  try {
    const problem = JSON.parse(error.body) as { code?: unknown; approval_request_id?: unknown; intent_digest?: unknown };
    if (
      problem.code !== "managed_key_approval_pending" ||
      typeof problem.approval_request_id !== "string" ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(problem.approval_request_id) ||
      typeof problem.intent_digest !== "string" ||
      !/^sha256:[0-9a-f]{64}$/i.test(problem.intent_digest)
    )
      return null;
    return { requestId: problem.approval_request_id, intentDigest: problem.intent_digest };
  } catch {
    return null;
  }
}

/** ManagedKeyCustodyWorkspace owns one complete operator journey. The browser
 * only selects a provider and algorithm. Provider credentials and device paths
 * remain startup configuration read by the control plane and isolated signer;
 * this component never accepts, stores, or sends those values. */
export function ManagedKeyCustodyWorkspace() {
  const { t } = useTranslation();
  const { user } = useAuth();
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
  const [managedKeyProvider, setManagedKeyProvider] = useState("");
  const [keyBusy, setKeyBusy] = useState(false);
  const [keyError, setKeyError] = useState<string | null>(null);
  const [pendingApproval, setPendingApproval] = useState<PendingManagedKeyApproval | null>(null);
  const [operation, setOperation] = useState<ManagedKeyOperation | null>(null);
  const [operationAction, setOperationAction] = useState<{ action: "rotate" | "revoke" | "zeroize"; keyId: string } | null>(null);
  const [inventory, setInventory] = useState<ManagedKeyRecord[]>([]);
  const [inventoryCursor, setInventoryCursor] = useState("");
  const [inventoryBusy, setInventoryBusy] = useState(false);
  const [inventoryError, setInventoryError] = useState<string | null>(null);
  const operationRead = useApiQuery(["managed-key-operation", operation?.operation_id], () => api.getManagedKeyOperation(operation!.operation_id), {
    enabled: operation?.status === "queued",
    retry: false,
    live: { intervalMs: 2000 },
  });

  const loadInventory = useCallback(async (cursor = "") => {
    setInventoryBusy(true);
    setInventoryError(null);
    try {
      const page = await api.listManagedKeys({ limit: 20, cursor });
      setInventory((current) => (cursor ? [...current, ...page.items] : page.items));
      setInventoryCursor(page.next_cursor);
    } catch (error) {
      setInventoryError(apiProblemMessage(error, translateNow("caHierarchy.custody.inventoryLoadFailed")));
    } finally {
      setInventoryBusy(false);
    }
  }, []);

  useEffect(() => {
    let active = true;
    setLoading(true);
    api
      .managedKeyCustody()
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

  useEffect(() => {
    if (plan?.lifecycle_attached) void loadInventory();
  }, [loadInventory, plan?.lifecycle_attached]);

  useEffect(() => {
    const next = operationRead.data;
    if (!next || !operation || next.operation_id !== operation.operation_id || next.status === "queued" || next.status === operation.status) return;
    if (operationAction && user) {
      clearManagedKeyActionIntent(user, operationAction.action, operationAction.keyId);
      setOperationAction(null);
    }
    setOperation(next);
    void loadInventory();
    if (next.provider && (next.result_key_id || next.key_id)) {
      void api
        .getManagedKey(next.provider, next.result_key_id || next.key_id!)
        .then((key) => {
          setManagedKey(key);
          setManagedKeyProvider(next.provider!);
        })
        .catch((error) => setKeyError(apiProblemMessage(error, translateNow("caHierarchy.custody.inventoryLoadFailed"))));
    }
  }, [operationRead.data, operation, operationAction, user, loadInventory]);

  async function selectManagedKey(key: ManagedKeyRecord) {
    setKeyBusy(true);
    setKeyError(null);
    setPendingApproval(null);
    setOperation(null);
    try {
      const current = await api.getManagedKey(key.provider, key.key_id);
      setManagedKey(current);
      setManagedKeyProvider(key.provider);
      setPreview(null);
      setCurrentIndex(0);
    } catch (error) {
      setManagedKey(null);
      setKeyError(apiProblemMessage(error, t("caHierarchy.custody.inventoryLoadFailed")));
    } finally {
      setKeyBusy(false);
    }
  }

  async function refreshInventory() {
    const selected = managedKey && managedKeyProvider ? { provider: managedKeyProvider, keyId: managedKey.key_id } : null;
    setKeyBusy(true);
    try {
      await loadInventory();
      if (!selected) return;
      const current = await api.getManagedKey(selected.provider, selected.keyId);
      setManagedKey((previous) => (previous?.key_id === selected.keyId ? current : previous));
    } catch (error) {
      setKeyError(apiProblemMessage(error, t("caHierarchy.custody.inventoryLoadFailed")));
    } finally {
      setKeyBusy(false);
    }
  }

  const selectedProvider = plan?.providers.find((item) => item.id === provider) ?? null;
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
    setManagedKey(null);
    setManagedKeyProvider("");
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
    setPendingApproval(null);
    setOperation(null);
    try {
      const generated = await api.generateManagedKey({ provider: preview.provider, algorithm: preview.algorithm as ManagedKeyGenerateRequest["algorithm"] });
      if (isManagedKeyOperation(generated)) {
        setOperation(generated);
        await loadInventory();
        return;
      }
      const generatedProvider = plan?.configured_provider === "aws" ? "aws-kms" : (plan?.configured_provider ?? "");
      setManagedKey(generated);
      setManagedKeyProvider(generatedProvider);
      await loadInventory();
    } catch (error) {
      setKeyError(apiProblemMessage(error, t("caHierarchy.custody.generateFailed")));
    } finally {
      setKeyBusy(false);
    }
  }

  async function runManagedKeyAction(action: "rotate" | "revoke" | "zeroize" | "verify_custody", keyId: string) {
    let accepted = false;
    setKeyBusy(true);
    setKeyError(null);
    setPendingApproval(null);
    setOperation(null);
    setOperationAction(null);
    try {
      const requestKey = action === "verify_custody" ? undefined : user ? getOrCreateManagedKeyActionIntent(user, action, keyId) : null;
      if (requestKey === null) {
        setKeyError(t("caHierarchy.custody.intent.unavailable"));
        return;
      }
      const actionMethods: Record<typeof action, (keyId: string, requestKey?: string) => Promise<ManagedKey | ManagedKeyOperation>> = {
        rotate: api.rotateManagedKey,
        revoke: api.revokeManagedKey,
        zeroize: api.zeroizeManagedKey,
        verify_custody: api.verifyManagedKeyCustody,
      };
      const next = await actionMethods[action](keyId, requestKey);
      const queued = isManagedKeyOperation(next) && next.status === "queued";
      if (action !== "verify_custody") {
        if (queued) setOperationAction({ action, keyId });
        else clearManagedKeyActionIntent(user!, action, keyId);
      }
      if (isManagedKeyOperation(next)) {
        setOperation(next);
        accepted = true;
        return;
      }
      setManagedKey(next);
    } catch (error) {
      const pending = pendingManagedKeyApproval(error);
      if (pending) setPendingApproval(pending);
      else setKeyError(apiProblemMessage(error, t("caHierarchy.custody.actionFailed", { action: action === "verify_custody" ? "verify" : action })));
    } finally {
      if (accepted) await refreshInventory();
      else await loadInventory();
      setKeyBusy(false);
    }
  }

  return (
    <section aria-labelledby="custody-heading" className="grid gap-4 border-y border-border py-4">
      <div>
        <h2 id="custody-heading" className="text-title font-semibold">
          {t("caHierarchy.custody.title")}
        </h2>
        <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{t("caHierarchy.custody.description")}</p>
      </div>

      {loading ? <LoadingState>{t("caHierarchy.custody.loading")}</LoadingState> : null}
      {planError ? <ErrorState title={t("caHierarchy.custody.unavailable")}>{planError}</ErrorState> : null}
      {!loading && !planError && plan ? (
        <>
          {plan.lifecycle_attached ? (
            <Card>
              <CardHeader>
                <CardTitle>{t("caHierarchy.custody.inventoryTitle")}</CardTitle>
              </CardHeader>
              <CardContent className="grid gap-3">
                <p className="text-sm text-muted-foreground">{t("caHierarchy.custody.inventoryDetail")}</p>
                <Button type="button" size="sm" variant="outline" disabled={inventoryBusy} onClick={() => void refreshInventory()}>
                  {t("caHierarchy.workspace.refresh")}
                </Button>
                {inventoryError ? <ErrorState title={t("caHierarchy.custody.inventoryLoadFailed")}>{inventoryError}</ErrorState> : null}
                {inventory.length === 0 && !inventoryBusy && !inventoryError ? <EmptyState title={t("caHierarchy.custody.inventoryEmpty")} /> : null}
                {inventory.length > 0 ? (
                  <ul className="grid gap-2" aria-label={t("caHierarchy.custody.inventoryTitle")}>
                    {inventory.map((key) => (
                      <li
                        key={`${key.provider}:${key.key_id}`}
                        className="flex flex-wrap items-center justify-between gap-2 rounded-md border border-border p-2"
                      >
                        <span className="text-sm">
                          <CredentialChip value={key.key_id} label={t("caHierarchy.custody.keyID")} /> · {key.provider} · {t("caHierarchy.custody.state")}:{" "}
                          {key.state} · {t("caHierarchy.custody.custodyStatus")}: {t(`caHierarchy.custody.status.${key.custody_status ?? "not_checked"}`)}
                        </span>
                        <Button type="button" size="sm" variant="outline" disabled={keyBusy} onClick={() => void selectManagedKey(key)}>
                          {t("caHierarchy.custody.inspectKey")}
                        </Button>
                      </li>
                    ))}
                  </ul>
                ) : null}
                {inventoryCursor ? (
                  <Button type="button" variant="outline" disabled={inventoryBusy} onClick={() => void loadInventory(inventoryCursor)}>
                    {t("caHierarchy.custody.loadMore")}
                  </Button>
                ) : null}
                {inventoryBusy ? <LoadingState>{t("caHierarchy.custody.inventoryLoading")}</LoadingState> : null}
              </CardContent>
            </Card>
          ) : null}
          {keyError && currentIndex !== 2 ? <ErrorState title={t("caHierarchy.custody.actionFailedTitle")}>{keyError}</ErrorState> : null}
          {pendingApproval && currentIndex !== 2 ? <ManagedKeyPendingApproval approval={pendingApproval} /> : null}
          {operation ? <ManagedKeyOperationPanel operation={operation} error={operationRead.error} onRefresh={operationRead.refetch} /> : null}
          {managedKey && currentIndex !== 2 ? (
            <ManagedKeyPanel
              managedKey={managedKey}
              busy={keyBusy || operation?.status === "queued"}
              onAction={(action, keyId) => void runManagedKeyAction(action, keyId)}
              actionsDisabled={!isCurrentManagedKeyProvider(managedKeyProvider, plan.configured_provider)}
            />
          ) : null}
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
                busy={keyBusy || operation?.status === "queued"}
                error={keyError}
                pendingApproval={pendingApproval}
                managedKey={managedKey}
                preview={preview}
                onGenerate={() => void generateManagedKey()}
                onAction={(action, keyId) => void runManagedKeyAction(action, keyId)}
                actionsDisabled={!isCurrentManagedKeyProvider(managedKeyProvider, plan.configured_provider)}
              />
            ) : null}
          </StepShell>
        </>
      ) : null}
    </section>
  );
}

function isCurrentManagedKeyProvider(keyProvider: string, configuredProvider: string) {
  return keyProvider === configuredProvider || (keyProvider === "aws-kms" && configuredProvider === "aws");
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
          <CardTitle>{t(preview.effect_free ? "caHierarchy.custody.nothingChanged" : "caHierarchy.custody.blocked")}</CardTitle>
          <p className="mt-1 text-sm text-muted-foreground">
            {t("caHierarchy.custody.previewCounts", { writes: preview.preview_writes.length, calls: preview.preview_external_effects.length })}
          </p>
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

function ManagedKeyOperationPanel({ operation, error, onRefresh }: { operation: ManagedKeyOperation; error: string | null; onRefresh: () => void }) {
  const { t } = useTranslation();
  return (
    <div role="status" aria-live="polite" className="grid gap-2 rounded-control border border-border p-4 text-sm">
      <p>{t(`caHierarchy.custody.operation.${operation.status}`)}</p>
      <CredentialChip value={operation.operation_id} label={t("apiExplorer.operationId")} />
      {error ? <p>{error}</p> : null}
      {operation.status === "queued" ? (
        <Button type="button" size="sm" variant="outline" onClick={onRefresh}>
          {t("caHierarchy.workspace.refresh")}
        </Button>
      ) : null}
    </div>
  );
}

function CustodyGeneration({
  busy,
  error,
  pendingApproval,
  managedKey,
  preview,
  onAction,
  onGenerate,
  actionsDisabled,
}: {
  busy: boolean;
  error: string | null;
  pendingApproval: PendingManagedKeyApproval | null;
  managedKey: ManagedKey | null;
  preview: ManagedKeyGenerationPreview;
  onAction: (action: "rotate" | "revoke" | "zeroize" | "verify_custody", keyId: string) => void;
  onGenerate: () => void;
  actionsDisabled: boolean;
}) {
  const { t } = useTranslation();
  return (
    <div className="grid gap-4">
      <Card>
        <CardHeader>
          <CardTitle>{t("caHierarchy.custody.reviewedReady")}</CardTitle>
          <p className="mt-1 text-sm text-muted-foreground">
            {t("caHierarchy.custody.reviewedReadyDetail", { provider: preview.provider_label, algorithm: preview.algorithm })}
          </p>
        </CardHeader>
        <CardContent>
          <Button type="button" disabled={busy || Boolean(managedKey)} onClick={onGenerate}>
            {busy ? t("caHierarchy.custody.generating") : t("caHierarchy.custody.generate")}
          </Button>
        </CardContent>
      </Card>
      {error ? <ErrorState title={t("caHierarchy.custody.actionFailedTitle")}>{error}</ErrorState> : null}
      {pendingApproval ? <ManagedKeyPendingApproval approval={pendingApproval} /> : null}
      {managedKey ? (
        <ManagedKeyPanel managedKey={managedKey} busy={busy} onAction={onAction} actionsDisabled={actionsDisabled} />
      ) : (
        <EmptyState title={t("caHierarchy.custody.noKey")}>{t("caHierarchy.custody.noKeyDetail")}</EmptyState>
      )}
    </div>
  );
}

function ManagedKeyPendingApproval({ approval }: { approval: PendingManagedKeyApproval }) {
  const { t } = useTranslation();
  return (
    <UnavailableState title={t("caHierarchy.custody.approvalPendingTitle")}>
      <p>{t("caHierarchy.custody.approvalPendingDetail")}</p>
      <p className="mt-2">
        <CredentialChip value={approval.requestId} label={t("caHierarchy.custody.approvalRequestID")} fullValue />
      </p>
      <p className="mt-2">{t("caHierarchy.custody.approvalPendingNext")}</p>
      <Link className="mt-2 inline-block text-sm font-medium text-primary underline" to="/approvals">
        {t("caHierarchy.custody.openApprovalRequests")}
      </Link>
    </UnavailableState>
  );
}

function ManagedKeyPanel({
  busy,
  managedKey,
  onAction,
  actionsDisabled,
}: {
  busy: boolean;
  managedKey: ManagedKey;
  onAction: (action: "rotate" | "revoke" | "zeroize" | "verify_custody", keyId: string) => void;
  actionsDisabled: boolean;
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
          <Button
            type="button"
            size="sm"
            disabled={busy || actionsDisabled || managedKey.state !== "active"}
            onClick={() => onAction("verify_custody", managedKey.key_id)}
          >
            {t("caHierarchy.custody.verifyButton")}
          </Button>
          {(["rotate", "revoke", "zeroize"] as const).map((action) => (
            <Button
              key={action}
              type="button"
              size="sm"
              variant="outline"
              disabled={busy || actionsDisabled}
              onClick={() => onAction(action, managedKey.key_id)}
              aria-label={t(`caHierarchy.custody.actions.${action}.label`, { keyId: managedKey.key_id })}
            >
              {t(`caHierarchy.custody.actions.${action}.button`)}
            </Button>
          ))}
        </div>
      </div>
      {actionsDisabled ? <p className="mt-3 text-sm text-status-warning">{t("caHierarchy.custody.providerUnavailable")}</p> : null}
      <dl className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
        <Fact label={t("caHierarchy.custody.algorithm")} value={managedKey.algorithm} />
        <Fact label={t("caHierarchy.custody.version")} value={t("caHierarchy.custody.versionValue", { version: managedKey.version })} />
        <Fact label={t("caHierarchy.custody.state")} value={managedKey.state} />
        <Fact
          label={t("caHierarchy.custody.custodyStatus")}
          value={`${t(`caHierarchy.custody.status.${managedKey.custody_status ?? "not_checked"}`)}${managedKey.custody_status !== "pending" && managedKey.custody_checked_at ? ` · ${new Date(managedKey.custody_checked_at).toLocaleString()}` : ""}`}
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
