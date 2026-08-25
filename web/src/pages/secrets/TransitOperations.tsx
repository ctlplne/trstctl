import { useEffect, useMemo, useState, type FormEvent } from "react";
import { zodResolver } from "@hookform/resolvers/zod";
import { Eye, KeyRound, Loader2, RotateCw } from "lucide-react";
import { useForm } from "react-hook-form";
import { z } from "zod";
import { useCan } from "@/components/rbac";
import { ErrorState, UnavailableState } from "@/components/StatePrimitives";
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
  const queryClient = useQueryClient();
  const keyQuery = useApiQuery(["transit-keys"], loadTransitKeys, { enabled: canRead });
  const keys = keyQuery.data?.items ?? emptyTransitKeys;
  const aeadKeys = useMemo(() => keys.filter((key) => key.kind === "aead"), [keys]);
  const hmacKeys = useMemo(() => keys.filter((key) => key.kind === "hmac"), [keys]);
  const signingKeys = useMemo(() => keys.filter((key) => key.kind === "sign"), [keys]);
  const [aeadKey, setAEADKey] = useState("");
  const [hmacKey, setHMACKey] = useState("");
  const [signingKey, setSigningKey] = useState("");
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
  }, [aeadKey, aeadKeys, hmacKey, hmacKeys, signingKey, signingKeys]);

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
  const [transitBusy, setTransitBusy] = useState<"encrypt" | "decrypt" | "hmac" | "rewrap" | "sign" | null>(null);
  const [transitError, setTransitError] = useState<string | null>(null);
  const [transitCiphertext, setTransitCiphertext] = useState<TransitCiphertext | null>(null);
  const [transitPlaintextResult, setTransitPlaintextResult] = useState<string | null>(null);
  const [transitHMACResult, setTransitHMACResult] = useState<TransitHMAC | null>(null);
  const [transitSignature, setTransitSignature] = useState<TransitSignature | null>(null);

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
                  onChange={(event) => setTransitMessage(event.target.value)}
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
            {transitSignature ? (
              <Snippet title={translateNow("source.signature.f1a73e2204")} text={`${transitSignature.signature}\npublic_der: ${transitSignature.public_der}`} />
            ) : null}
          </CardContent>
        </Card>
      </div>
      {transitError ? <ErrorState title={translateNow("source.transit.operation.failed.22502fa40b")}>{transitError}</ErrorState> : null}
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
