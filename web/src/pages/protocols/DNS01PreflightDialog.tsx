import { useRef, useState, type FormEvent } from "react";
import { X } from "lucide-react";
import { Dialog } from "@/components/Dialog";
import { ErrorState } from "@/components/StatePrimitives";
import { Button } from "@/components/ui/button";
import { useTranslation, translateNow } from "@/i18n/I18nProvider";
import { api, ApiError, type ACMEDNS01Preflight, type ACMEDNS01PreflightRequest, type ACMEDNS01ProviderConfig } from "@/lib/api";
import { DNS01PreflightResultPanel } from "@/pages/protocols/DNS01PreflightResultPanel";

const acmeMethodOptions = ["http-01", "dns-01", "tls-alpn-01"] as const;
type ACMEChallengeMethod = (typeof acmeMethodOptions)[number];

function isACMEChallengeMethod(value: string): value is ACMEChallengeMethod {
  return (acmeMethodOptions as readonly string[]).includes(value);
}

function protocolStatusError(err: unknown): string {
  if (err instanceof ApiError) return err.body || err.message;
  if (err instanceof Error) return err.message;
  return "The responder status check failed.";
}

/** The DNS-01 dry-run workflow is split from the protocol overview so the
 * served page stays reviewable while this dialog keeps its own bounded state. */
export function DNS01PreflightDialog({ config, onClose }: { config: ACMEDNS01ProviderConfig; onClose: () => void }) {
  const { t } = useTranslation();
  const [domain, setDomain] = useState("");
  const [expectedTXT, setExpectedTXT] = useState("");
  const [methodOverride, setMethodOverride] = useState<"" | ACMEChallengeMethod>("");
  const [observedTXT, setObservedTXT] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ACMEDNS01Preflight | null>(null);
  const domainRef = useRef<HTMLInputElement>(null);
  const titleId = "dns01-preflight-heading";

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const input: ACMEDNS01PreflightRequest = { config_id: config.id, domain: domain.trim() };
    const expected = expectedTXT.trim();
    if (expected) input.expected_txt = expected;
    if (methodOverride) input.method_override = methodOverride;
    const observed = observedTXT
      .split("\n")
      .map((line) => line.trim())
      .filter(Boolean);
    if (observed.length > 0) input.observed_txt = observed;
    setBusy(true);
    setError(null);
    try {
      setResult(await api.acmeDNS01Preflight(input));
    } catch (err) {
      setResult(null);
      setError(protocolStatusError(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog
      open
      onClose={onClose}
      titleId={titleId}
      initialFocusRef={domainRef}
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      overlayClassName="absolute inset-0 bg-black/55"
      panelClassName="relative max-h-[calc(100vh-2rem)] w-full max-w-2xl overflow-y-auto rounded-panel border border-border bg-card shadow-elevation2"
    >
      <header className="flex items-center justify-between gap-3 border-b border-border px-5 py-4">
        <div className="min-w-0">
          <h2 id={titleId} className="truncate text-title font-semibold">
            {translateNow("source.dns.01.preflight.0cb459fa6f")} {config.name}
          </h2>
          <p className="mt-1 text-sm text-muted-foreground">{t("parity.validatesDelegationTxtPropagationCaaPolicy_1ceb4c")}</p>
        </div>
        <Button type="button" variant="ghost" size="icon" onClick={onClose} aria-label={t("parity.closePreflightDialog_97a0fb")}>
          <X className="h-4 w-4" aria-hidden="true" />
        </Button>
      </header>
      <form className="grid gap-4 p-5" onSubmit={(event) => void submit(event)}>
        {error && <ErrorState title={t("parity.preflightRequestFailed_69f031")}>{error}</ErrorState>}
        <div className="grid gap-4 sm:grid-cols-2">
          <label className="grid gap-1 text-body font-medium">
            {t("parity.domain_9b1091")}
            <input
              ref={domainRef}
              required
              value={domain}
              onChange={(event) => setDomain(event.target.value)}
              placeholder={
                config.zone ? translateNow("source.api.value1.b2b38d558b", { value1: config.zone }) : translateNow("source.api.example.com.d0c43d3885")
              }
              className="min-h-9 rounded-control border border-border bg-background px-3 py-2 text-body"
            />
          </label>
          <label className="grid gap-1 text-body font-medium">
            {t("parity.methodOverrideOptional_154ad0")}
            <select
              value={methodOverride}
              onChange={(event) => setMethodOverride(isACMEChallengeMethod(event.target.value) ? event.target.value : "")}
              className="min-h-9 rounded-control border border-border bg-background px-3 py-2 text-body"
            >
              <option value="">{t("parity.policyDefault_38146c")}</option>
              {acmeMethodOptions.map((method) => (
                <option key={method} value={method}>
                  {method}
                </option>
              ))}
            </select>
          </label>
        </div>
        <label className="grid gap-1 text-body font-medium">
          {t("parity.expectedTxtValueOptional_c4e94f")}
          <input
            value={expectedTXT}
            onChange={(event) => setExpectedTXT(event.target.value)}
            className="min-h-9 rounded-control border border-border bg-background px-3 py-2 text-body"
          />
        </label>
        <label className="grid gap-1 text-body font-medium">
          {t("parity.observedTxtRecordsOptionalOnePer_9b6c49")}
          <textarea
            rows={3}
            value={observedTXT}
            onChange={(event) => setObservedTXT(event.target.value)}
            className="min-h-24 rounded-control border border-border bg-background px-3 py-2 font-mono text-xs"
          />
        </label>
        <div className="flex justify-end gap-2">
          <Button type="button" variant="outline" onClick={onClose}>
            {translateNow("source.close.7d9eb7acb1")}
          </Button>
          <Button type="submit" disabled={busy || domain.trim() === ""}>
            {result ? translateNow("source.re.run.preflight.8d65b96680") : translateNow("source.run.preflight.3cd0b7ebda")}
          </Button>
        </div>
        {result && <DNS01PreflightResultPanel result={result} />}
      </form>
    </Dialog>
  );
}
