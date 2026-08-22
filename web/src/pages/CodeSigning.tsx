import { FormEvent, useState } from "react";
import { api, type CodeSigningSignature } from "@/lib/api";
import { PageHeader } from "@/components/PageHeader";
import { SectionCard } from "@/components/dashboard";
import { Button } from "@/components/ui/button";
import { ErrorState } from "@/components/StatePrimitives";
import { useTranslation, translateNow } from "@/i18n/I18nProvider";

type Mode = "key" | "keyless";

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function encodeSHA256Digest(input: string): string {
  const trimmed = input.trim();
  const hex = trimmed.toLowerCase().startsWith("sha256:") ? trimmed.slice(7) : trimmed;
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
    throw new Error("Artifact digest must be exactly 64 hexadecimal SHA-256 characters, with an optional sha256: prefix.");
  }
  const bytes = new Uint8Array(32);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }
  return bytesToBase64(bytes);
}

function encodeIdentityPayload(input: string): string {
  const value = input.trim();
  if (!value) throw new Error("Identity payload is required for keyless signing.");
  return bytesToBase64(new TextEncoder().encode(value));
}

const auditReceipts = [
  "the artifact digest is the signed subject; artifact bytes never enter the browser",
  "approval, policy decision, signer identity, and timestamp become audit evidence",
  "signing key material stays inside the dedicated signer or the keyless provider",
];

/** CodeSigning submits a real signing request to the served code-signing
 * endpoints — key-backed (POST /code-signing/sign) or keyless/Fulcio
 * (POST /code-signing/keyless) — and renders the returned signature receipt.
 * Only the digest is sent; artifact bytes and private keys never touch the SPA. */
export function CodeSigning() {
  const { t } = useTranslation();
  const [mode, setMode] = useState<Mode>("key");
  const [artifactType, setArtifactType] = useState("container");
  const [digest, setDigest] = useState("");
  const [keyId, setKeyId] = useState("");
  const [identityMethod, setIdentityMethod] = useState("github_oidc");
  const [identityPayload, setIdentityPayload] = useState("");
  const [signature, setSignature] = useState<CodeSigningSignature | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!digest.trim()) return;
    setBusy(true);
    setError(null);
    setSignature(null);
    try {
      const encodedDigest = encodeSHA256Digest(digest);
      const result =
        mode === "key"
          ? await api.signCode({ artifact_type: artifactType, digest: encodedDigest, key_id: keyId.trim() })
          : await api.signCodeKeyless({
              artifact_type: artifactType,
              digest: encodedDigest,
              identity_method: identityMethod,
              identity_payload: encodeIdentityPayload(identityPayload),
            });
      setSignature(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section aria-labelledby="codesign-heading" className="grid gap-6">
      <PageHeader
        titleId="codesign-heading"
        title={t("nav.item.codeSigning")}
        description="See which release digests can be signed, where the keys stay, and how someone verifies each signature. The software and private key never enter this browser."
        technicalDetails="Exact evidence includes the artifact digest, signing mode, managed key or provider identity, policy and approval decision, signature receipt, timestamp or transparency proof, signer identity, and immutable audit event."
      />

      <SectionCard
        title={translateNow("source.sign.an.artifact.fb729a3d5b")}
        description="Submit a digest for key-backed or keyless signing against the served endpoints."
      >
        <form onSubmit={submit} className="grid gap-4">
          <fieldset className="grid gap-2">
            <legend className="text-sm font-medium">{translateNow("source.signing.mode.0ba52a4363")}</legend>
            <div className="flex flex-wrap gap-2">
              <Button type="button" variant={mode === "key" ? "default" : "outline"} aria-pressed={mode === "key"} onClick={() => setMode("key")}>
                {translateNow("source.key.backed.4eae20ec94")}
              </Button>
              <Button type="button" variant={mode === "keyless" ? "default" : "outline"} aria-pressed={mode === "keyless"} onClick={() => setMode("keyless")}>
                {translateNow("source.keyless.fulcio.42a397ffc7")}
              </Button>
            </div>
          </fieldset>

          <div className="grid gap-3 md:grid-cols-2">
            <label className="grid gap-1 text-sm font-medium" htmlFor="codesign-type">
              {translateNow("source.artifact.type.c4984fa09a")}
              <input
                id="codesign-type"
                value={artifactType}
                onChange={(e) => setArtifactType(e.target.value)}
                className="rounded-md border border-border bg-background px-3 py-2 text-sm"
              />
            </label>
            <label className="grid gap-1 text-sm font-medium" htmlFor="codesign-digest">
              {translateNow("source.artifact.digest.f7f37af3fe")}
              <input
                id="codesign-digest"
                value={digest}
                onChange={(e) => setDigest(e.target.value)}
                placeholder={t("codesign.digest.placeholder")}
                className="rounded-md border border-border bg-background px-3 py-2 font-mono text-xs"
              />
            </label>
            {mode === "key" ? (
              <label className="grid gap-1 text-sm font-medium" htmlFor="codesign-keyid">
                {translateNow("source.managed.key.id.8d05580702")}
                <input
                  id="codesign-keyid"
                  value={keyId}
                  onChange={(e) => setKeyId(e.target.value)}
                  className="rounded-md border border-border bg-background px-3 py-2 text-sm"
                />
              </label>
            ) : (
              <>
                <label className="grid gap-1 text-sm font-medium" htmlFor="codesign-id-method">
                  {translateNow("source.identity.method.324ef3acce")}
                  <input
                    id="codesign-id-method"
                    value={identityMethod}
                    onChange={(e) => setIdentityMethod(e.target.value)}
                    className="rounded-md border border-border bg-background px-3 py-2 text-sm"
                  />
                </label>
                <label className="grid gap-1 text-sm font-medium" htmlFor="codesign-id-payload">
                  {translateNow("source.identity.payload.7cafae50c5")}
                  <input
                    id="codesign-id-payload"
                    value={identityPayload}
                    onChange={(e) => setIdentityPayload(e.target.value)}
                    className="rounded-md border border-border bg-background px-3 py-2 text-sm"
                  />
                </label>
              </>
            )}
          </div>

          <div>
            <Button type="submit" disabled={busy || !digest.trim()}>
              {busy ? translateNow("source.signing.bdabe34a39") : translateNow("source.sign.artifact.57261585fa")}
            </Button>
          </div>
        </form>

        {error ? <ErrorState title={translateNow("source.could.not.sign.artifact.67ae96a355")}>{error}</ErrorState> : null}

        {signature ? (
          <section aria-labelledby="signature-heading" className="mt-4 rounded-panel border border-border p-comfortable text-sm">
            <h3 id="signature-heading" className="text-title font-semibold">
              {translateNow("source.signature.receipt.8d8dcf3028")}
            </h3>
            <dl className="mt-3 grid gap-2 sm:grid-cols-2">
              <div>
                <dt className="font-medium text-muted-foreground">{translateNow("source.algorithm.d704d8af25")}</dt>
                <dd>{signature.algorithm}</dd>
              </div>
              <div>
                <dt className="font-medium text-muted-foreground">{translateNow("source.artifact.type.c4984fa09a")}</dt>
                <dd>{signature.artifact_type}</dd>
              </div>
              {signature.key_id ? (
                <div>
                  <dt className="font-medium text-muted-foreground">{translateNow("source.signing.key.49395b9594")}</dt>
                  <dd className="font-mono text-xs">{signature.key_id}</dd>
                </div>
              ) : null}
              {signature.fulcio_issuer ? (
                <div>
                  <dt className="font-medium text-muted-foreground">{translateNow("source.fulcio.issuer.6baae4cd90")}</dt>
                  <dd className="font-mono text-xs">{signature.fulcio_issuer}</dd>
                </div>
              ) : null}
              {signature.fulcio_san ? (
                <div>
                  <dt className="font-medium text-muted-foreground">{t("codesign.receipt.fulcioSAN")}</dt>
                  <dd className="break-all font-mono text-xs">{signature.fulcio_san}</dd>
                </div>
              ) : null}
              {signature.transparency_destination ? (
                <div>
                  <dt className="font-medium text-muted-foreground">{t("codesign.receipt.transparencyDestination")}</dt>
                  <dd className="font-mono text-xs">{signature.transparency_destination}</dd>
                </div>
              ) : null}
              <div className="sm:col-span-2">
                <dt className="font-medium text-muted-foreground">{t("codesign.receipt.signatureBase64")}</dt>
                <dd className="break-all font-mono text-xs">{signature.signature}</dd>
                <a
                  href={`data:application/octet-stream;base64,${signature.signature}`}
                  download="artifact.sig"
                  className="mt-2 inline-flex text-xs font-medium text-primary underline"
                >
                  {t("codesign.receipt.downloadSignature")}
                </a>
              </div>
              <div className="sm:col-span-2">
                <dt className="font-medium text-muted-foreground">{translateNow("source.public.key.der.606443a2d8")}</dt>
                <dd className="break-all font-mono text-xs">{signature.public_key_der}</dd>
              </div>
            </dl>
          </section>
        ) : null}
      </SectionCard>

      <SectionCard title={translateNow("source.audit.and.key.boundary.1ff2138216")} description="What the browser can and cannot see during signing.">
        <ul className="grid gap-2 md:grid-cols-3">
          {auditReceipts.map((receipt) => (
            <li key={receipt} className="rounded-panel border border-border p-3 text-sm text-muted-foreground">
              {receipt}
            </li>
          ))}
        </ul>
      </SectionCard>
    </section>
  );
}
