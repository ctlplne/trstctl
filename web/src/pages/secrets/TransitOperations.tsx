import { useEffect, useMemo, useState, type FormEvent } from "react";
import { zodResolver } from "@hookform/resolvers/zod";
import { Eye, KeyRound, Loader2, RefreshCw, RotateCw } from "lucide-react";
import { useForm } from "react-hook-form";
import { Link } from "react-router-dom";
import { z } from "zod";
import { useCan } from "@/components/rbac";
import { ErrorState, UnavailableState } from "@/components/StatePrimitives";
import { StatusBadge } from "@/components/StatusBadge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { useTranslation, translateNow } from "@/i18n/I18nProvider";
import { api, type TransitCiphertext, type TransitHMAC, type TransitKey, type TransitKeyList, type TransitSignature } from "@/lib/api";
import { apiProblemMessage } from "@/lib/apiProblem";
import { useApiQuery, useQueryClient } from "@/lib/query";
import { RevealPanel, Snippet, decodeTransitBytes, encodeTransitBytes } from "./SecretsPageParts";

const transitKinds = ["aead", "hmac", "sign"] as const;
const transitAuditTypes = [
  "transit.key.created",
  "transit.key.rotated",
  "transit.encrypt",
  "transit.decrypt",
  "transit.rewrap",
  "transit.hmac",
  "transit.sign",
  "transit.verify",
].join(",");
const emptyTransitKeys: TransitKey[] = [];
type TransitKind = (typeof transitKinds)[number];
type CreateKeyValues = { name: string; kind: TransitKind };

function isTransitKind(value: string): value is TransitKind {
  return transitKinds.includes(value as TransitKind);
}

async function loadTransitKeys(): Promise<TransitKeyList> {
  const result = await api.transitKeys();
  for (const key of result.items) {
    if (!isTransitKind(key.kind)) {
      throw new Error(translateNow("secrets.transit.contractMismatch", { kind: JSON.stringify(key.kind), name: key.name }));
    }
  }
  return result;
}

function replaceKey(items: readonly TransitKey[], replacement: TransitKey): TransitKey[] {
  return [...items.filter((key) => key.name !== replacement.name), replacement].sort((left, right) => left.name.localeCompare(right.name));
}

export function TransitOperations({ nativeStoreUnavailable }: { nativeStoreUnavailable: boolean }) {
  const { t } = useTranslation();
  const canRead = useCan("keys:read");
  const canWrite = useCan("keys:write");
  const canReadAudit = useCan("audit:read");
  const queryClient = useQueryClient();
  const keyQuery = useApiQuery(["transit-keys"], loadTransitKeys, { enabled: canRead });
  const postureQuery = useApiQuery(["transit-posture"], () => api.transitPosture(), { enabled: canRead, live: { intervalMs: 15_000 } });
  const auditQuery = useApiQuery(["transit-audit"], () => api.auditEvents({ type: transitAuditTypes, limit: 8 }), {
    enabled: canReadAudit,
    live: { intervalMs: 15_000 },
  });
  const keys = keyQuery.data?.items ?? emptyTransitKeys;
  const aeadKeys = useMemo(() => keys.filter((key) => key.kind === "aead"), [keys]);
  const hmacKeys = useMemo(() => keys.filter((key) => key.kind === "hmac"), [keys]);
  const signingKeys = useMemo(() => keys.filter((key) => key.kind === "sign"), [keys]);
  const [aeadKey, setAEADKey] = useState("");
  const [hmacKey, setHMACKey] = useState("");
  const [signingKey, setSigningKey] = useState("");
  const [historyKey, setHistoryKey] = useState("");
  const [keyBusy, setKeyBusy] = useState<"create" | string | null>(null);
  const [keyError, setKeyError] = useState<string | null>(null);
  const [keyNotice, setKeyNotice] = useState<string | null>(null);
  const createKeySchema = useMemo(
    () =>
      z.object({
        name: z.string().trim().min(1, t("secrets.transit.keyNameRequired")),
        kind: z.enum(transitKinds),
      }),
    [t],
  );
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors: createErrors },
  } = useForm<CreateKeyValues>({
    resolver: zodResolver(createKeySchema),
    mode: "onTouched",
    defaultValues: { name: "", kind: "aead" },
  });

  useEffect(() => {
    if (!aeadKeys.some((key) => key.name === aeadKey)) setAEADKey(aeadKeys[0]?.name ?? "");
    if (!hmacKeys.some((key) => key.name === hmacKey)) setHMACKey(hmacKeys[0]?.name ?? "");
    if (!signingKeys.some((key) => key.name === signingKey)) setSigningKey(signingKeys[0]?.name ?? "");
    if (!keys.some((key) => key.name === historyKey)) setHistoryKey(keys[0]?.name ?? "");
  }, [aeadKey, aeadKeys, historyKey, hmacKey, hmacKeys, keys, signingKey, signingKeys]);

  const versionQuery = useApiQuery(["transit-key-versions", historyKey], () => api.transitKeyVersions(historyKey), { enabled: canRead && Boolean(historyKey) });

  const createKey = handleSubmit(async (values) => {
    setKeyError(null);
    setKeyNotice(null);
    setKeyBusy("create");
    try {
      const created = await api.createTransitKey(values);
      queryClient.setQueryData<TransitKeyList>(["transit-keys"], (current) => ({ items: replaceKey(current?.items ?? [], created) }));
      if (created.kind === "aead") setAEADKey(created.name);
      if (created.kind === "hmac") setHMACKey(created.name);
      if (created.kind === "sign") setSigningKey(created.name);
      setHistoryKey(created.name);
      void queryClient.invalidateQueries({ queryKey: ["transit-audit"] });
      reset({ name: "", kind: values.kind });
      setKeyNotice(t("secrets.transit.createdNotice", { name: created.name, version: created.version }));
    } catch (error) {
      setKeyError(apiProblemMessage(error, t("secrets.transit.createFailed")));
    } finally {
      setKeyBusy(null);
    }
  });

  async function rotateKey(name: string) {
    setKeyError(null);
    setKeyNotice(null);
    setKeyBusy(name);
    try {
      const rotated = await api.rotateTransitKey({ name });
      queryClient.setQueryData<TransitKeyList>(["transit-keys"], (current) => ({ items: replaceKey(current?.items ?? [], rotated) }));
      setHistoryKey(rotated.name);
      void queryClient.invalidateQueries({ queryKey: ["transit-key-versions", rotated.name] });
      void queryClient.invalidateQueries({ queryKey: ["transit-audit"] });
      setKeyNotice(t("secrets.transit.rotatedNotice", { name: rotated.name, version: rotated.version }));
    } catch (error) {
      setKeyError(apiProblemMessage(error, t("secrets.transit.rotateFailed")));
    } finally {
      setKeyBusy(null);
    }
  }

  const [transitPlaintext, setTransitPlaintext] = useState("");
  const [transitAAD, setTransitAAD] = useState("");
  const [transitCiphertextInput, setTransitCiphertextInput] = useState("");
  const [transitMessage, setTransitMessage] = useState("");
  const [transitBusy, setTransitBusy] = useState<"encrypt" | "decrypt" | "hmac" | "rewrap" | "sign" | "verify" | null>(null);
  const [transitError, setTransitError] = useState<string | null>(null);
  const [transitCiphertext, setTransitCiphertext] = useState<TransitCiphertext | null>(null);
  const [transitPlaintextResult, setTransitPlaintextResult] = useState<string | null>(null);
  const [transitHMACResult, setTransitHMACResult] = useState<TransitHMAC | null>(null);
  const [transitSignature, setTransitSignature] = useState<TransitSignature | null>(null);
  const [signatureInput, setSignatureInput] = useState("");
  const [publicDERInput, setPublicDERInput] = useState("");
  const [signatureValid, setSignatureValid] = useState<boolean | null>(null);

  async function encryptTransit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setTransitError(null);
    setTransitPlaintextResult(null);
    setTransitBusy("encrypt");
    try {
      const ciphertext = await api.encryptTransit({
        key: aeadKey,
        plaintext: encodeTransitBytes(transitPlaintext),
        ...(transitAAD.trim() ? { aad: encodeTransitBytes(transitAAD.trim()) } : {}),
      });
      setTransitCiphertext(ciphertext);
      setTransitCiphertextInput(ciphertext.ciphertext);
      setTransitPlaintext("");
    } catch (error) {
      setTransitError(apiProblemMessage(error, t("secrets.transit.encryptFailed")));
    } finally {
      setTransitBusy(null);
    }
  }

  async function decryptTransit() {
    setTransitError(null);
    setTransitPlaintextResult(null);
    setTransitBusy("decrypt");
    try {
      const result = await api.decryptTransit({
        key: aeadKey,
        ciphertext: transitCiphertextInput.trim(),
        ...(transitAAD.trim() ? { aad: encodeTransitBytes(transitAAD.trim()) } : {}),
      });
      setTransitPlaintextResult(decodeTransitBytes(result.plaintext));
    } catch (error) {
      setTransitError(apiProblemMessage(error, t("secrets.transit.decryptFailed")));
    } finally {
      setTransitBusy(null);
    }
  }

  async function rewrapTransit() {
    setTransitError(null);
    setTransitBusy("rewrap");
    try {
      const result = await api.rewrapTransit({
        key: aeadKey,
        ciphertext: transitCiphertextInput.trim(),
        ...(transitAAD.trim() ? { aad: encodeTransitBytes(transitAAD.trim()) } : {}),
      });
      setTransitCiphertext(result);
      setTransitCiphertextInput(result.ciphertext);
    } catch (error) {
      setTransitError(apiProblemMessage(error, t("secrets.transit.rewrapFailed")));
    } finally {
      setTransitBusy(null);
    }
  }

  async function hmacTransit() {
    setTransitError(null);
    setTransitHMACResult(null);
    setTransitBusy("hmac");
    try {
      setTransitHMACResult(await api.hmacTransit({ key: hmacKey, data: encodeTransitBytes(transitMessage) }));
    } catch (error) {
      setTransitError(apiProblemMessage(error, t("secrets.transit.hmacFailed")));
    } finally {
      setTransitBusy(null);
    }
  }

  async function signTransit() {
    setTransitError(null);
    setTransitSignature(null);
    setTransitBusy("sign");
    try {
      setTransitSignature(await api.signTransit({ key: signingKey, message: encodeTransitBytes(transitMessage) }));
    } catch (error) {
      setTransitError(apiProblemMessage(error, t("secrets.transit.signFailed")));
    } finally {
      setTransitBusy(null);
    }
  }

  useEffect(() => {
    if (!transitSignature) return;
    setSignatureInput(transitSignature.signature);
    setPublicDERInput(transitSignature.public_der);
    setSignatureValid(null);
    void queryClient.invalidateQueries({ queryKey: ["transit-audit"] });
  }, [queryClient, transitSignature]);

  async function verifyTransit() {
    setTransitError(null);
    setSignatureValid(null);
    setTransitBusy("verify");
    try {
      const result = await api.verifyTransit({
        message: encodeTransitBytes(transitMessage),
        signature: signatureInput.trim(),
        public_der: publicDERInput.trim(),
      });
      setSignatureValid(result.valid);
      void queryClient.invalidateQueries({ queryKey: ["transit-audit"] });
    } catch (error) {
      setTransitError(apiProblemMessage(error, t("secrets.transit.verifyFailed")));
    } finally {
      setTransitBusy(null);
    }
  }

  const selectedAEAD = aeadKeys.find((key) => key.name === aeadKey) ?? null;
  const selectedHMAC = hmacKeys.find((key) => key.name === hmacKey) ?? null;
  const selectedSigning = signingKeys.find((key) => key.name === signingKey) ?? null;

  return (
    <section id="task-panel-transit" aria-labelledby="transit-heading" className="grid gap-4 border-y border-border py-4">
      <div>
        <h2 id="transit-heading" className="text-title font-semibold">
          {translateNow("source.transit.and.kmip.bbf61786e0")}
        </h2>
        <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{translateNow("source.transit.operations.keep.key.material.serve.be62c8b11a")}</p>
      </div>
      {nativeStoreUnavailable ? (
        <p role="note" className="rounded-control border border-brand-accent/25 bg-brand-accent/5 p-3 text-sm text-muted-foreground">
          {t("secrets.transit.independentFromStore")}
        </p>
      ) : null}

      <div className="grid gap-4 xl:grid-cols-2">
        <Card>
          <CardHeader>
            <div className="flex flex-wrap items-center justify-between gap-2">
              <CardTitle>{t("secrets.transit.recoveryHeading")}</CardTitle>
              <Button
                type="button"
                size="sm"
                variant="ghost"
                onClick={() => {
                  postureQuery.refetch();
                  keyQuery.refetch();
                }}
                disabled={!canRead || postureQuery.fetching}
              >
                <RefreshCw className={`h-4 w-4 ${postureQuery.fetching ? "animate-spin" : ""}`} aria-hidden="true" />
                {t("secrets.transit.refreshProof")}
              </Button>
            </div>
            <p className="text-sm text-muted-foreground">{t("secrets.transit.recoveryDescription")}</p>
          </CardHeader>
          <CardContent className="grid gap-4 text-sm">
            {postureQuery.error ? (
              <ErrorState title={t("secrets.transit.postureUnavailable")}>{postureQuery.error}</ErrorState>
            ) : postureQuery.loading || !postureQuery.data ? (
              <p role="status" className="text-muted-foreground">
                {t("secrets.transit.loadingPosture")}
              </p>
            ) : (
              <>
                <div className="grid gap-1 border-s-2 border-border ps-3">
                  <StatusBadge
                    value={postureQuery.data.transit.restore_state}
                    label={postureQuery.data.transit.recovery_ready ? t("secrets.transit.restoreReady") : t("secrets.transit.restoreBlocked")}
                    tone={postureQuery.data.transit.recovery_ready ? "success" : "warning"}
                  />
                  <p className="text-muted-foreground">{postureQuery.data.transit.detail}</p>
                  {postureQuery.data.transit.recovery ? <p className="text-status-warning">{postureQuery.data.transit.recovery}</p> : null}
                </div>
                <div className="grid gap-1 border-s-2 border-border ps-3">
                  <StatusBadge
                    value={postureQuery.data.kmip.state}
                    label={postureQuery.data.kmip.state === "listening" ? t("secrets.transit.kmipListening") : t("secrets.transit.kmipNotConfigured")}
                    tone={postureQuery.data.kmip.state === "listening" ? "success" : "neutral"}
                  />
                  <p className="font-medium">{postureQuery.data.kmip.profile}</p>
                  <p className="text-muted-foreground">{postureQuery.data.kmip.detail}</p>
                  <p className="flex flex-wrap gap-x-1 text-caption text-muted-foreground">
                    <span>{postureQuery.data.kmip.transport}</span>
                    {postureQuery.data.kmip.operations.map((operation) => (
                      <span key={operation}>
                        <span aria-hidden="true">{String.fromCharCode(183)}</span> {operation}
                      </span>
                    ))}
                    {postureQuery.data.kmip.address ? (
                      <span>
                        <span aria-hidden="true">{String.fromCharCode(183)}</span> {postureQuery.data.kmip.address}
                      </span>
                    ) : null}
                  </p>
                  {postureQuery.data.kmip.recovery ? <p className="text-status-warning">{postureQuery.data.kmip.recovery}</p> : null}
                </div>
                <details className="border-t border-border pt-3">
                  <summary className="cursor-pointer font-medium">{t("secrets.transit.failedRecovery")}</summary>
                  <ol className="mt-2 grid list-decimal gap-2 ps-5 text-muted-foreground">
                    {postureQuery.data.recovery_steps.map((step) => (
                      <li key={step}>{step}</li>
                    ))}
                  </ol>
                </details>
              </>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>{t("secrets.transit.proofHeading")}</CardTitle>
            <p className="text-sm text-muted-foreground">{t("secrets.transit.proofDescription")}</p>
          </CardHeader>
          <CardContent className="grid gap-4 text-sm">
            <div className="grid gap-2">
              <Field label={t("secrets.transit.historyKey")} description={t("secrets.transit.historyDescription")}>
                {(control) => (
                  <Select
                    {...control}
                    value={historyKey}
                    onChange={(event) => setHistoryKey(event.target.value)}
                    disabled={!canRead || keyQuery.loading || Boolean(keyQuery.error)}
                  >
                    <option value="">{t("secrets.transit.selectKey")}</option>
                    {keys.map((key) => (
                      <option key={key.name} value={key.name}>
                        {key.name}
                      </option>
                    ))}
                  </Select>
                )}
              </Field>
              {versionQuery.error ? (
                <p role="alert" className="text-status-warning">
                  {versionQuery.error}
                </p>
              ) : versionQuery.loading && historyKey ? (
                <p role="status" className="text-muted-foreground">
                  {t("secrets.transit.loadingVersions")}
                </p>
              ) : versionQuery.data ? (
                <ul className="flex flex-wrap gap-x-4 gap-y-2" aria-label={t("secrets.transit.versionHistory")}>
                  {versionQuery.data.versions.map((version) => (
                    <li key={version.version}>
                      <StatusBadge
                        value={version.current ? "current" : "retained"}
                        label={
                          version.current
                            ? t("secrets.transit.currentVersion", { version: version.version })
                            : t("secrets.transit.retainedVersion", { version: version.version })
                        }
                        tone={version.current ? "success" : "neutral"}
                      />
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="text-muted-foreground">{t("secrets.transit.noVersionHistory")}</p>
              )}
            </div>
            <div className="grid gap-2 border-t border-border pt-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <h3 className="font-semibold">{t("secrets.transit.auditHeading")}</h3>
                <Link className="text-caption font-medium text-brand-accent hover:underline" to={`/audit?type=${encodeURIComponent(transitAuditTypes)}`}>
                  {t("secrets.transit.openAudit")}
                </Link>
              </div>
              {!canReadAudit ? (
                <p className="text-muted-foreground">{t("secrets.transit.auditPermission")}</p>
              ) : auditQuery.error ? (
                <p role="alert" className="text-status-warning">
                  {auditQuery.error}
                </p>
              ) : auditQuery.loading ? (
                <p role="status" className="text-muted-foreground">
                  {t("secrets.transit.loadingAudit")}
                </p>
              ) : auditQuery.data?.length ? (
                <ul className="grid gap-2">
                  {auditQuery.data.map((event) => (
                    <li key={`${event.sequence}-${event.type}`} className="flex flex-wrap items-baseline justify-between gap-2 border-s-2 border-border ps-3">
                      <span className="font-mono text-xs">{event.type}</span>
                      <span className="text-caption text-muted-foreground">
                        #{event.sequence} · {event.time}
                      </span>
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="text-muted-foreground">{t("secrets.transit.noAudit")}</p>
              )}
            </div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>{t("secrets.transit.keySetupHeading")}</CardTitle>
          <p className="text-sm text-muted-foreground">{t("secrets.transit.keySetupDescription")}</p>
        </CardHeader>
        <CardContent className="grid gap-4">
          {!canRead ? (
            <UnavailableState title={t("secrets.transit.keyReadBlocked")}>{t("secrets.transit.keyReadBlockedDetail")}</UnavailableState>
          ) : keyQuery.error ? (
            <ErrorState title={t("secrets.transit.inventoryUnavailable")}>{keyQuery.error}</ErrorState>
          ) : keyQuery.loading ? (
            <p role="status" className="text-sm text-muted-foreground">
              {t("secrets.transit.loadingKeys")}
            </p>
          ) : (
            <p className="text-sm text-muted-foreground">{t("secrets.transit.inventorySummary", { count: keys.length })}</p>
          )}

          <form
            aria-label={t("secrets.transit.createFormLabel")}
            onSubmit={createKey}
            className="grid gap-3 md:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_auto] md:items-start"
          >
            <Field label={t("secrets.transit.keyName")} description={t("secrets.transit.keyNameDescription")} error={createErrors.name?.message} required>
              {(control) => <Input {...control} {...register("name")} autoComplete="off" placeholder={translateNow("source.payments.pii.643f35ba95")} />}
            </Field>
            <Field label={t("secrets.transit.keyPurpose")} description={t("secrets.transit.keyPurposeDescription")} required>
              {(control) => (
                <Select {...control} {...register("kind")}>
                  <option value="aead">{t("secrets.transit.kindAEAD")}</option>
                  <option value="hmac">{t("secrets.transit.kindHMAC")}</option>
                  <option value="sign">{t("secrets.transit.kindSign")}</option>
                </Select>
              )}
            </Field>
            <Button type="submit" className="md:mt-6" loading={keyBusy === "create"} disabled={!canWrite || keyBusy === "create"}>
              <KeyRound className="h-4 w-4" aria-hidden="true" />
              {t("secrets.transit.createKey")}
            </Button>
          </form>
          {!canWrite ? <p className="text-caption text-muted-foreground">{t("secrets.transit.keyWriteBlocked")}</p> : null}
          {keyNotice ? (
            <p role="status" className="rounded-control border border-status-success/30 bg-status-success/10 p-3 text-sm">
              {keyNotice}
            </p>
          ) : null}
          {keyError ? <ErrorState title={t("secrets.transit.lifecycleFailed")}>{keyError}</ErrorState> : null}
        </CardContent>
      </Card>

      <form
        aria-label={translateNow("source.transit.encrypt.and.decrypt.f3ae0fd83f")}
        onSubmit={(event) => void encryptTransit(event)}
        className="grid gap-3 xl:grid-cols-2"
      >
        <Field
          label={t("secrets.transit.encryptionKey")}
          description={selectedAEAD ? t("secrets.transit.selectedVersion", { version: selectedAEAD.version }) : t("secrets.transit.noEncryptionKey")}
        >
          {(control) => (
            <Select
              {...control}
              value={aeadKey}
              onChange={(event) => setAEADKey(event.target.value)}
              disabled={!canRead || keyQuery.loading || Boolean(keyQuery.error)}
            >
              <option value="">{t("secrets.transit.selectKey")}</option>
              {aeadKeys.map((key) => (
                <option key={key.name} value={key.name}>
                  {key.name}
                </option>
              ))}
            </Select>
          )}
        </Field>
        <div className="flex items-end">
          <Button
            type="button"
            variant="outline"
            onClick={() => selectedAEAD && void rotateKey(selectedAEAD.name)}
            disabled={!canWrite || !selectedAEAD || keyBusy === selectedAEAD?.name}
            aria-label={selectedAEAD ? t("secrets.transit.rotateAria", { name: selectedAEAD.name }) : t("secrets.transit.rotate")}
          >
            {keyBusy === selectedAEAD?.name ? (
              <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
            ) : (
              <RotateCw className="h-4 w-4" aria-hidden="true" />
            )}
            {t("secrets.transit.rotate")}
          </Button>
        </div>
        <Field label={translateNow("source.aad.9adbaf62d8")} description={t("secrets.transit.aadDescription")}>
          {(control) => (
            <Input
              {...control}
              value={transitAAD}
              onChange={(event) => setTransitAAD(event.target.value)}
              placeholder={translateNow("source.optional.associated.data.52eba643ce")}
            />
          )}
        </Field>
        <div aria-hidden="true" />
        <Field label={translateNow("source.plaintext.0707c5d972")} className="xl:col-span-2">
          {(control) => (
            <Textarea
              {...control}
              className="min-h-24"
              value={transitPlaintext}
              onChange={(event) => setTransitPlaintext(event.target.value)}
              placeholder={translateNow("source.local.plaintext.to.encrypt.a67b9e7b54")}
            />
          )}
        </Field>
        <Field label={translateNow("source.ciphertext.47955e6673")} className="xl:col-span-2">
          {(control) => (
            <Textarea
              {...control}
              className="min-h-24 font-mono text-xs"
              value={transitCiphertextInput}
              onChange={(event) => setTransitCiphertextInput(event.target.value)}
              placeholder={translateNow("source.encrypted.result.or.ciphertext.to.decrypt.88441adfe9")}
            />
          )}
        </Field>
        <div className="flex flex-wrap gap-2 xl:col-span-2">
          <Button type="submit" disabled={!canWrite || !selectedAEAD || transitBusy === "encrypt" || !transitPlaintext.trim()}>
            {transitBusy === "encrypt" ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <KeyRound className="h-4 w-4" aria-hidden="true" />}
            {translateNow("source.encrypt.4f03bf1cdf")}
          </Button>
          <Button
            type="button"
            variant="outline"
            onClick={() => void decryptTransit()}
            disabled={!canWrite || !selectedAEAD || transitBusy === "decrypt" || !transitCiphertextInput.trim()}
          >
            {transitBusy === "decrypt" ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <Eye className="h-4 w-4" aria-hidden="true" />}
            {translateNow("source.decrypt.2e4629449b")}
          </Button>
          <Button
            type="button"
            variant="outline"
            onClick={() => void rewrapTransit()}
            disabled={!canWrite || !selectedAEAD || transitBusy === "rewrap" || !transitCiphertextInput.trim()}
          >
            {transitBusy === "rewrap" ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <RotateCw className="h-4 w-4" aria-hidden="true" />}
            {translateNow("source.rewrap.49c8c07065")}
          </Button>
        </div>
      </form>

      <div className="grid gap-4 xl:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>{translateNow("source.transit.result.7a54cd2a67")}</CardTitle>
          </CardHeader>
          <CardContent className="text-sm">
            {transitCiphertext ? (
              <dl className="grid gap-2">
                <div>
                  <dt className="font-medium text-muted-foreground">{translateNow("source.ciphertext.47955e6673")}</dt>
                  <dd className="break-all font-mono text-xs">{transitCiphertext.ciphertext}</dd>
                </div>
                <div>
                  <dt className="font-medium text-muted-foreground">{translateNow("source.key.version.aa5d87c789")}</dt>
                  <dd className="font-mono text-xs">v{transitCiphertext.version}</dd>
                </div>
              </dl>
            ) : (
              <p className="text-muted-foreground">{translateNow("source.no.transit.ciphertext.yet.f9d6c9870b")}</p>
            )}
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>{translateNow("source.hmac.and.signing.a21f893b5b")}</CardTitle>
          </CardHeader>
          <CardContent className="grid gap-3 text-sm">
            <div className="grid gap-4 sm:grid-cols-2">
              <div className="grid gap-2">
                <Field
                  label={t("secrets.transit.hmacKey")}
                  description={selectedHMAC ? t("secrets.transit.selectedVersion", { version: selectedHMAC.version }) : t("secrets.transit.noHMACKey")}
                >
                  {(control) => (
                    <Select
                      {...control}
                      value={hmacKey}
                      onChange={(event) => setHMACKey(event.target.value)}
                      disabled={!canRead || keyQuery.loading || Boolean(keyQuery.error)}
                    >
                      <option value="">{t("secrets.transit.selectKey")}</option>
                      {hmacKeys.map((key) => (
                        <option key={key.name} value={key.name}>
                          {key.name}
                        </option>
                      ))}
                    </Select>
                  )}
                </Field>
                <Button
                  type="button"
                  size="sm"
                  variant="outline"
                  onClick={() => selectedHMAC && void rotateKey(selectedHMAC.name)}
                  disabled={!canWrite || !selectedHMAC || keyBusy === selectedHMAC?.name}
                  aria-label={selectedHMAC ? t("secrets.transit.rotateAria", { name: selectedHMAC.name }) : t("secrets.transit.rotate")}
                >
                  {keyBusy === selectedHMAC?.name ? (
                    <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
                  ) : (
                    <RotateCw className="h-4 w-4" aria-hidden="true" />
                  )}
                  {t("secrets.transit.rotate")}
                </Button>
              </div>
              <div className="grid gap-2">
                <Field
                  label={t("secrets.transit.signingKey")}
                  description={selectedSigning ? t("secrets.transit.selectedVersion", { version: selectedSigning.version }) : t("secrets.transit.noSigningKey")}
                >
                  {(control) => (
                    <Select
                      {...control}
                      value={signingKey}
                      onChange={(event) => setSigningKey(event.target.value)}
                      disabled={!canRead || keyQuery.loading || Boolean(keyQuery.error)}
                    >
                      <option value="">{t("secrets.transit.selectKey")}</option>
                      {signingKeys.map((key) => (
                        <option key={key.name} value={key.name}>
                          {key.name}
                        </option>
                      ))}
                    </Select>
                  )}
                </Field>
                <Button
                  type="button"
                  size="sm"
                  variant="outline"
                  onClick={() => selectedSigning && void rotateKey(selectedSigning.name)}
                  disabled={!canWrite || !selectedSigning || keyBusy === selectedSigning?.name}
                  aria-label={selectedSigning ? t("secrets.transit.rotateAria", { name: selectedSigning.name }) : t("secrets.transit.rotate")}
                >
                  {keyBusy === selectedSigning?.name ? (
                    <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
                  ) : (
                    <RotateCw className="h-4 w-4" aria-hidden="true" />
                  )}
                  {t("secrets.transit.rotate")}
                </Button>
              </div>
            </div>
            <Field label={translateNow("source.message.2f77668a9d")}>
              {(control) => (
                <Textarea
                  {...control}
                  className="min-h-20"
                  value={transitMessage}
                  onChange={(event) => {
                    setTransitMessage(event.target.value);
                    setSignatureValid(null);
                  }}
                  placeholder={translateNow("source.message.bytes.to.mac.or.sign.1400a97072")}
                />
              )}
            </Field>
            <div className="flex flex-wrap gap-2">
              <Button
                type="button"
                variant="outline"
                onClick={() => void hmacTransit()}
                disabled={!canWrite || !selectedHMAC || transitBusy === "hmac" || !transitMessage.trim()}
              >
                {transitBusy === "hmac" ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <KeyRound className="h-4 w-4" aria-hidden="true" />}
                {translateNow("source.compute.hmac.4809a2f350")}
              </Button>
              <Button
                type="button"
                variant="outline"
                onClick={() => void signTransit()}
                disabled={!canWrite || !selectedSigning || transitBusy === "sign" || !transitMessage.trim()}
              >
                {transitBusy === "sign" ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <KeyRound className="h-4 w-4" aria-hidden="true" />}
                {translateNow("source.sign.message.516e35c2fc")}
              </Button>
            </div>
            {transitHMACResult ? <Snippet title={translateNow("source.hmac.32fd6f051c")} text={transitHMACResult.hmac} /> : null}
            <div className="grid gap-3 border-t border-border pt-3">
              <div>
                <h3 className="font-semibold">{t("secrets.transit.verifyHeading")}</h3>
                <p className="mt-1 text-caption text-muted-foreground">{t("secrets.transit.verifyDescription")}</p>
              </div>
              <Field label={t("secrets.transit.signature")}>
                {(control) => (
                  <Textarea
                    {...control}
                    className="min-h-16 font-mono text-xs"
                    value={signatureInput}
                    onChange={(event) => {
                      setSignatureInput(event.target.value);
                      setSignatureValid(null);
                    }}
                    placeholder={t("secrets.transit.signaturePlaceholder")}
                  />
                )}
              </Field>
              <Field label={t("secrets.transit.publicKey")} description={t("secrets.transit.publicKeyDescription")}>
                {(control) => (
                  <Textarea
                    {...control}
                    className="min-h-16 font-mono text-xs"
                    value={publicDERInput}
                    onChange={(event) => {
                      setPublicDERInput(event.target.value);
                      setSignatureValid(null);
                    }}
                    placeholder={t("secrets.transit.publicKeyPlaceholder")}
                  />
                )}
              </Field>
              <div className="flex flex-wrap items-center gap-3">
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => void verifyTransit()}
                  disabled={!canRead || transitBusy === "verify" || !transitMessage.trim() || !signatureInput.trim() || !publicDERInput.trim()}
                >
                  {transitBusy === "verify" ? (
                    <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
                  ) : (
                    <KeyRound className="h-4 w-4" aria-hidden="true" />
                  )}
                  {t("secrets.transit.verifySignature")}
                </Button>
                {signatureValid === true ? <StatusBadge value="valid" label={t("secrets.transit.validSignature")} tone="success" role="status" /> : null}
                {signatureValid === false ? <StatusBadge value="invalid" label={t("secrets.transit.invalidSignature")} tone="warning" role="status" /> : null}
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
      {transitError ? (
        <ErrorState title={translateNow("source.transit.operation.failed.22502fa40b")}>
          <p>{transitError}</p>
          <p className="mt-2">{t("secrets.transit.operationRecovery")}</p>
          <Button
            type="button"
            size="sm"
            variant="outline"
            className="mt-3"
            onClick={() => {
              postureQuery.refetch();
              keyQuery.refetch();
              versionQuery.refetch();
              if (canReadAudit) auditQuery.refetch();
            }}
          >
            <RefreshCw className="h-4 w-4" aria-hidden="true" />
            {t("secrets.transit.refreshRecovery")}
          </Button>
        </ErrorState>
      ) : null}
      {transitPlaintextResult ? (
        <RevealPanel
          title={translateNow("source.decrypted.plaintext.675dd9b983")}
          onDismiss={() => setTransitPlaintextResult(null)}
          value={transitPlaintextResult}
        >
          {translateNow("source.this.plaintext.was.decoded.locally.from.th.fbd3275222")}
        </RevealPanel>
      ) : null}
    </section>
  );
}
