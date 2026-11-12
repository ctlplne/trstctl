// SPDX-License-Identifier: BUSL-1.1

import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { ErrorState } from "@/components/StatePrimitives";
import { useTranslation } from "@/i18n/I18nProvider";
import { ApiError, api, type CodeSigningKeyCertificate as KeyCertificate } from "@/lib/api";
import { newIdempotencyKey } from "@/lib/apiTransport";

/** CodeSigningKeyCertificate reads the certificate chain stock signing tools
 * get for a managed code-signing key, and attaches or rotates it (P9-L1):
 * the server checks the chain against the key and serves it at once, with no
 * configuration change or restart. */
export function CodeSigningKeyCertificate() {
  const { t } = useTranslation();
  const [keyID, setKeyID] = useState("");
  const [chainPEM, setChainPEM] = useState("");
  const [certificate, setCertificate] = useState<KeyCertificate | null>(null);
  const [missing, setMissing] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  async function load() {
    setBusy(true);
    setError(null);
    setNotice(null);
    setMissing(false);
    try {
      setCertificate(await api.codeSigningKeyCertificate(keyID.trim()));
    } catch (failure) {
      setCertificate(null);
      if (failure instanceof ApiError && failure.status === 404) {
        setMissing(true);
      } else {
        setError(failure instanceof Error ? failure.message : t("codesign.keyCertificate.error"));
      }
    } finally {
      setBusy(false);
    }
  }

  async function attach() {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const attached = await api.attachCodeSigningKeyCertificate(keyID.trim(), chainPEM, newIdempotencyKey());
      setCertificate(attached);
      setMissing(false);
      setChainPEM("");
      setNotice(t("codesign.keyCertificate.attached", { keyId: attached.key_id }));
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : t("codesign.keyCertificate.error"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="grid gap-4">
      <div className="flex flex-wrap items-end gap-3">
        <Field label={t("codesign.keyCertificate.keyId")} description={t("codesign.keyCertificate.keyIdHelp")}>
          {(control) => <Input {...control} value={keyID} onChange={(event) => setKeyID(event.target.value)} />}
        </Field>
        <Button type="button" variant="outline" disabled={busy || keyID.trim() === ""} onClick={() => void load()}>
          {t("codesign.keyCertificate.load")}
        </Button>
      </div>
      {error ? <ErrorState title={t("codesign.keyCertificate.error")}>{error}</ErrorState> : null}
      {notice ? (
        <p role="status" className="text-sm text-muted-foreground">
          {notice}
        </p>
      ) : null}
      {missing ? <p className="text-sm text-muted-foreground">{t("codesign.keyCertificate.none")}</p> : null}
      {certificate ? (
        <dl className="grid gap-2 rounded-panel border border-border p-3 text-sm md:grid-cols-2">
          <div>
            <dt className="text-muted-foreground">{t("codesign.keyCertificate.source")}</dt>
            <dd>{certificate.source === "attached" ? t("codesign.keyCertificate.sourceAttached") : t("codesign.keyCertificate.sourceConfigured")}</dd>
          </div>
          <div>
            <dt className="text-muted-foreground">{t("codesign.keyCertificate.expires")}</dt>
            <dd>{new Date(certificate.not_after).toISOString().slice(0, 10)}</dd>
          </div>
          <div className="md:col-span-2">
            <dt className="text-muted-foreground">{t("codesign.keyCertificate.fingerprint")}</dt>
            <dd className="break-all font-mono text-xs">{certificate.leaf_fingerprint}</dd>
          </div>
          {certificate.attached_by ? (
            <div className="md:col-span-2">
              <dt className="text-muted-foreground">{t("codesign.keyCertificate.attachedBy")}</dt>
              <dd>{certificate.attached_by}</dd>
            </div>
          ) : null}
        </dl>
      ) : null}
      <Field label={t("codesign.keyCertificate.chain")} description={t("codesign.keyCertificate.chainHelp")}>
        {(control) => <Textarea {...control} value={chainPEM} onChange={(event) => setChainPEM(event.target.value)} className="min-h-32 font-mono text-xs" />}
      </Field>
      <div>
        <Button type="button" disabled={busy || keyID.trim() === "" || chainPEM.trim() === ""} onClick={() => void attach()}>
          {t("codesign.keyCertificate.attach")}
        </Button>
      </div>
    </div>
  );
}
