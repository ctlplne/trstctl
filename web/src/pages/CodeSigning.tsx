import { FormEvent, useState } from "react";
import { api, type CodeSigningSignature } from "@/lib/api";
import { PageHeader } from "@/components/PageHeader";
import { SectionCard } from "@/components/dashboard";
import { Button } from "@/components/ui/button";
import { ErrorState } from "@/components/StatePrimitives";

type Mode = "key" | "keyless";

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
  const [mode, setMode] = useState<Mode>("key");
  const [artifactType, setArtifactType] = useState("container");
  const [digest, setDigest] = useState("");
  const [keyId, setKeyId] = useState("");
  const [identityMethod, setIdentityMethod] = useState("oidc");
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
      const result =
        mode === "key"
          ? await api.signCode({ artifact_type: artifactType, digest: digest.trim(), key_id: keyId.trim() })
          : await api.signCodeKeyless({
              artifact_type: artifactType,
              digest: digest.trim(),
              identity_method: identityMethod,
              identity_payload: identityPayload.trim(),
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
        title="Code signing"
        description="Bind an artifact digest to a signature through the dedicated signer (key-backed) or a keyless provider (Fulcio). Only the digest is submitted — artifact bytes and private keys never enter the browser."
      />

      <SectionCard title="Sign an artifact" description="Submit a digest for key-backed or keyless signing against the served endpoints.">
        <form onSubmit={submit} className="grid gap-4">
          <fieldset className="grid gap-2">
            <legend className="text-sm font-medium">Signing mode</legend>
            <div className="flex flex-wrap gap-2">
              <Button type="button" variant={mode === "key" ? "default" : "outline"} aria-pressed={mode === "key"} onClick={() => setMode("key")}>
                Key-backed
              </Button>
              <Button type="button" variant={mode === "keyless" ? "default" : "outline"} aria-pressed={mode === "keyless"} onClick={() => setMode("keyless")}>
                Keyless (Fulcio)
              </Button>
            </div>
          </fieldset>

          <div className="grid gap-3 md:grid-cols-2">
            <label className="grid gap-1 text-sm font-medium" htmlFor="codesign-type">
              Artifact type
              <input
                id="codesign-type"
                value={artifactType}
                onChange={(e) => setArtifactType(e.target.value)}
                className="rounded-md border border-border bg-background px-3 py-2 text-sm"
              />
            </label>
            <label className="grid gap-1 text-sm font-medium" htmlFor="codesign-digest">
              Artifact digest
              <input
                id="codesign-digest"
                value={digest}
                onChange={(e) => setDigest(e.target.value)}
                placeholder="sha256:…"
                className="rounded-md border border-border bg-background px-3 py-2 font-mono text-xs"
              />
            </label>
            {mode === "key" ? (
              <label className="grid gap-1 text-sm font-medium" htmlFor="codesign-keyid">
                Managed key id
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
                  Identity method
                  <input
                    id="codesign-id-method"
                    value={identityMethod}
                    onChange={(e) => setIdentityMethod(e.target.value)}
                    className="rounded-md border border-border bg-background px-3 py-2 text-sm"
                  />
                </label>
                <label className="grid gap-1 text-sm font-medium" htmlFor="codesign-id-payload">
                  Identity payload
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
              {busy ? "Signing…" : "Sign artifact"}
            </Button>
          </div>
        </form>

        {error ? <ErrorState title="Could not sign artifact">{error}</ErrorState> : null}

        {signature ? (
          <section aria-labelledby="signature-heading" className="mt-4 rounded-panel border border-border p-comfortable text-sm">
            <h3 id="signature-heading" className="text-title font-semibold">
              Signature receipt
            </h3>
            <dl className="mt-3 grid gap-2 sm:grid-cols-2">
              <div>
                <dt className="font-medium text-muted-foreground">Algorithm</dt>
                <dd>{signature.algorithm}</dd>
              </div>
              <div>
                <dt className="font-medium text-muted-foreground">Artifact type</dt>
                <dd>{signature.artifact_type}</dd>
              </div>
              {signature.key_id ? (
                <div>
                  <dt className="font-medium text-muted-foreground">Signing key</dt>
                  <dd className="font-mono text-xs">{signature.key_id}</dd>
                </div>
              ) : null}
              {signature.fulcio_issuer ? (
                <div>
                  <dt className="font-medium text-muted-foreground">Fulcio issuer</dt>
                  <dd className="font-mono text-xs">{signature.fulcio_issuer}</dd>
                </div>
              ) : null}
              <div className="sm:col-span-2">
                <dt className="font-medium text-muted-foreground">Public key (DER)</dt>
                <dd className="break-all font-mono text-xs">{signature.public_key_der}</dd>
              </div>
            </dl>
          </section>
        ) : null}
      </SectionCard>

      <SectionCard title="Audit and key boundary" description="What the browser can and cannot see during signing.">
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
