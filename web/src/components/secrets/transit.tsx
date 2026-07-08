import { useState } from "react";
import { SectionCard } from "@/components/dashboard";
import { api } from "@/lib/api";

function b64encode(value: string): string {
  const bytes = new TextEncoder().encode(value);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function b64decode(value: string): string {
  const binary = atob(value);
  return new TextDecoder().decode(Uint8Array.from(binary, (char) => char.charCodeAt(0)));
}

export function TransitConsole() {
  const [key, setKey] = useState("");
  const [plaintext, setPlaintext] = useState("");
  const [ciphertext, setCiphertext] = useState("");
  const [revealed, setRevealed] = useState<string | null>(null);
  const [hmac, setHmac] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function run<T>(label: string, fn: () => Promise<T>, after: (result: T) => void) {
    setBusy(label);
    setError(null);
    try {
      after(await fn());
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(null);
    }
  }

  const encrypt = () =>
    run(
      "encrypt",
      () => api.encryptTransit({ key: key.trim(), plaintext: b64encode(plaintext) }),
      (result) => {
        setCiphertext(result.ciphertext);
        setRevealed(null);
      },
    );
  const decrypt = () =>
    run(
      "decrypt",
      () => api.decryptTransit({ key: key.trim(), ciphertext: ciphertext.trim() }),
      (result) => setRevealed(b64decode(result.plaintext)),
    );
  const computeHmac = () =>
    run(
      "hmac",
      () => api.hmacTransit({ key: key.trim(), data: b64encode(plaintext) }),
      (result) => setHmac(result.hmac),
    );

  return (
    <SectionCard title="Transit encryption" description="encryption-as-a-service: encrypt, decrypt, HMAC — plaintext stays in your browser">
      <div className="grid gap-3">
        <label className="grid gap-1 text-body">
          <span className="font-medium">Key name</span>
          <input
            value={key}
            onChange={(event) => setKey(event.target.value)}
            className="rounded-control border border-border bg-background px-3 py-2"
            placeholder="transit-key-1"
          />
        </label>
        <label className="grid gap-1 text-body">
          <span className="font-medium">Plaintext</span>
          <textarea
            value={plaintext}
            onChange={(event) => setPlaintext(event.target.value)}
            rows={2}
            className="rounded-control border border-border bg-background px-3 py-2 font-mono text-caption"
          />
        </label>
        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            onClick={() => void encrypt()}
            disabled={busy !== null}
            className="min-h-9 rounded-control border border-border px-3 text-body disabled:opacity-60"
          >
            Encrypt
          </button>
          <button
            type="button"
            onClick={() => void decrypt()}
            disabled={busy !== null || !ciphertext}
            className="min-h-9 rounded-control border border-border px-3 text-body disabled:opacity-60"
          >
            Decrypt
          </button>
          <button
            type="button"
            onClick={() => void computeHmac()}
            disabled={busy !== null}
            className="min-h-9 rounded-control border border-border px-3 text-body disabled:opacity-60"
          >
            HMAC
          </button>
        </div>
        {ciphertext ? <p className="break-all font-mono text-caption text-muted-foreground">ciphertext: {ciphertext}</p> : null}
        {revealed !== null ? <p className="break-all font-mono text-caption">decrypted: {revealed}</p> : null}
        {hmac ? <p className="break-all font-mono text-caption text-muted-foreground">hmac: {hmac}</p> : null}
        {error ? (
          <p role="alert" className="text-caption text-risk-critical">
            {error}
          </p>
        ) : null}
      </div>
    </SectionCard>
  );
}
