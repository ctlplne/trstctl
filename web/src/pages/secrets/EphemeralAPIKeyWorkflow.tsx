import { useEffect, useRef, useState, type FormEvent } from "react";
import { BadgeCheck, Ban, Eye, KeyRound, Loader2, RotateCcw } from "lucide-react";
import { Link } from "react-router-dom";
import { ErrorState } from "@/components/StatePrimitives";
import { Button } from "@/components/ui/button";
import { formatDateTime } from "@/i18n/format";
import { useTranslation } from "@/i18n/I18nProvider";
import { ApiError, api, type EphemeralAPIKey, type EphemeralAPIKeyPreview, type EphemeralAPIKeyRequest } from "@/lib/api";
import { apiProblemMessage } from "@/lib/apiProblem";
import { RevealPanel, parseScopeList } from "./SecretsPageParts";

function newEphemeralIdempotencyKey(): string {
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) return crypto.randomUUID();
  return `ephemeral-api-key-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function requestFromInputs(subjectInput: string, scopesInput: string, ttlInput: string): EphemeralAPIKeyRequest {
  const subject = subjectInput.trim();
  const scopes = parseScopeList(scopesInput);
  const ttl = Number(ttlInput);
  if (!subject) throw new Error("Subject is required.");
  if (scopes.length === 0) throw new Error("At least one scope is required.");
  if (!Number.isInteger(ttl) || ttl < 1 || ttl > 3600) throw new Error("Lifetime must be a whole number from 1 through 3,600 seconds.");
  return { subject, scopes, ttl_seconds: ttl };
}

export default function EphemeralAPIKeyWorkflow({ canGrant, nativeStoreUnavailable }: { canGrant: boolean; nativeStoreUnavailable: boolean }) {
  // TRACE-005 source anchor: ephemeral API-key issuance is served through POST /api/v1/ephemeral/api-keys,
  // trstctl-cli ephemeral api-keys issue, and durable api_token.revoked verification.
  const { t } = useTranslation();
  const subjectRef = useRef<HTMLInputElement>(null);
  const [subject, setSubject] = useState("");
  const [scopes, setScopes] = useState("access:read");
  const [ttl, setTTL] = useState("900");
  const [preview, setPreview] = useState<EphemeralAPIKeyPreview | null>(null);
  const [previewBusy, setPreviewBusy] = useState(false);
  const [previewError, setPreviewError] = useState<string | null>(null);
  const [previewStale, setPreviewStale] = useState(false);
  const [issueBusy, setIssueBusy] = useState(false);
  const [issueError, setIssueError] = useState<string | null>(null);
  const [issueAmbiguous, setIssueAmbiguous] = useState(false);
  const [idempotencyKey, setIdempotencyKey] = useState<string | null>(null);
  const [issued, setIssued] = useState<EphemeralAPIKey | null>(null);
  const [verifyBusy, setVerifyBusy] = useState(false);
  const [verifyError, setVerifyError] = useState<string | null>(null);
  const [verified, setVerified] = useState(false);
  const [revokeBusy, setRevokeBusy] = useState(false);
  const [revokeError, setRevokeError] = useState<string | null>(null);
  const [revoked, setRevoked] = useState(false);

  useEffect(() => subjectRef.current?.focus(), []);

  function invalidatePreview() {
    if (preview) setPreviewStale(true);
    setPreview(null);
    setPreviewError(null);
    setIssueError(null);
    setIssueAmbiguous(false);
    setIdempotencyKey(null);
  }

  async function review(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setPreviewBusy(true);
    setPreviewError(null);
    setIssueError(null);
    setIssued(null);
    setVerified(false);
    setRevoked(false);
    try {
      const plan = await api.previewEphemeralAPIKey(requestFromInputs(subject, scopes, ttl));
      if (!plan.effect_free) throw new Error(t("secrets.ephemeral.previewNotEffectFree"));
      if (!plan.ready || plan.blockers.length > 0) {
        throw new Error(plan.blockers.join(" ") || t("secrets.ephemeral.previewBlocked"));
      }
      setPreview(plan);
      setPreviewStale(false);
      setIdempotencyKey(newEphemeralIdempotencyKey());
      setIssueAmbiguous(false);
    } catch (error) {
      setPreview(null);
      setIdempotencyKey(null);
      setPreviewError(apiProblemMessage(error, t("secrets.ephemeral.previewFallback")));
    } finally {
      setPreviewBusy(false);
    }
  }

  async function executeReviewed() {
    if (!preview || !idempotencyKey) {
      setIssueError(t("secrets.ephemeral.reviewRequired"));
      return;
    }
    setIssueBusy(true);
    setIssueError(null);
    setVerifyError(null);
    setVerified(false);
    setRevoked(false);
    try {
      const result = await api.issueEphemeralAPIKey(
        {
          subject: preview.subject,
          scopes: preview.scopes,
          ttl_seconds: preview.effective_ttl_seconds,
          preview_fingerprint: preview.request_fingerprint,
        },
        idempotencyKey,
      );
      setIssued(result);
      setPreview(null);
      setIdempotencyKey(null);
      setIssueAmbiguous(false);
      setSubject("");
      setScopes("access:read");
      setTTL("900");
    } catch (error) {
      if (error instanceof ApiError && error.status === 409) {
        setPreview(null);
        setIdempotencyKey(null);
        setPreviewStale(true);
        setIssueAmbiguous(false);
        setIssueError(t("secrets.ephemeral.reviewStale"));
      } else {
        setIssueAmbiguous(!(error instanceof ApiError) || error.status >= 500);
        setIssueError(apiProblemMessage(error, t("secrets.ephemeral.issueFallback")));
      }
    } finally {
      setIssueBusy(false);
    }
  }

  async function verifyBearer() {
    if (!issued) return;
    setVerifyBusy(true);
    setVerifyError(null);
    setVerified(false);
    try {
      await api.verifyEphemeralAPIKey(issued.token);
      setVerified(true);
    } catch (error) {
      setVerifyError(apiProblemMessage(error, t("secrets.ephemeral.verifyFallback")));
    } finally {
      setVerifyBusy(false);
    }
  }

  async function revokeBearer() {
    if (!issued) return;
    setRevokeBusy(true);
    setRevokeError(null);
    try {
      await api.revokeAPIToken(issued.id);
      setIssued(null);
      setVerified(false);
      setRevoked(true);
    } catch (error) {
      setRevokeError(apiProblemMessage(error, t("secrets.ephemeral.revokeFallback")));
    } finally {
      setRevokeBusy(false);
    }
  }

  const canVerify = issued?.scopes.includes("access:read") ?? false;

  return (
    <section id="task-panel-machine" aria-labelledby="ephemeral-api-heading" className="grid gap-4 border-y border-border py-4">
      <div>
        <h2 id="ephemeral-api-heading" className="text-title font-semibold">
          {t("secrets.ephemeral.heading")}
        </h2>
        <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{t("secrets.ephemeral.description")}</p>
        {/* F38: previewEphemeralAPIKey -> issueEphemeralAPIKey -> access token ledger/revoke -> bearer verification. */}
      </div>
      {nativeStoreUnavailable ? (
        <p role="note" className="rounded-control border border-brand-accent/25 bg-brand-accent/5 p-3 text-sm text-muted-foreground">
          {t("secrets.ephemeral.independentFromStore")}
        </p>
      ) : null}
      {!canGrant ? <ErrorState title={t("secrets.ephemeral.permissionBlocked")}>{t("secrets.ephemeral.permissionBlockedDetail")}</ErrorState> : null}
      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(20rem,0.8fr)]">
        <form aria-label={t("secrets.ephemeral.formLabel")} onSubmit={(event) => void review(event)} className="grid content-start gap-3">
          <div className="grid gap-1 text-sm">
            <label className="font-medium" htmlFor="ephemeral-api-key-subject">
              {t("secrets.ephemeral.subject")}
            </label>
            <input
              ref={subjectRef}
              id="ephemeral-api-key-subject"
              aria-describedby="ephemeral-api-key-subject-help"
              className="rounded-md border border-border bg-background px-3 py-2"
              value={subject}
              onChange={(event) => {
                setSubject(event.target.value);
                invalidatePreview();
              }}
              placeholder={t("secrets.ephemeral.subjectPlaceholder")}
              autoComplete="off"
              required
            />
            <span id="ephemeral-api-key-subject-help" className="text-xs text-muted-foreground">
              {t("secrets.ephemeral.subjectHelp")}
            </span>
          </div>
          <div className="grid gap-1 text-sm">
            <label className="font-medium" htmlFor="ephemeral-api-key-scopes">
              {t("secrets.ephemeral.scopes")}
            </label>
            <textarea
              id="ephemeral-api-key-scopes"
              aria-describedby="ephemeral-api-key-scopes-help"
              className="min-h-24 rounded-md border border-border bg-background px-3 py-2"
              value={scopes}
              onChange={(event) => {
                setScopes(event.target.value);
                invalidatePreview();
              }}
              placeholder="access:read"
              required
            />
            <span id="ephemeral-api-key-scopes-help" className="text-xs text-muted-foreground">
              {t("secrets.ephemeral.scopesHelp")}
            </span>
          </div>
          <div className="grid gap-1 text-sm">
            <label className="font-medium" htmlFor="ephemeral-api-key-ttl">
              {t("secrets.ephemeral.ttl")}
            </label>
            <input
              id="ephemeral-api-key-ttl"
              aria-describedby="ephemeral-api-key-ttl-help"
              className="rounded-md border border-border bg-background px-3 py-2"
              type="number"
              min="1"
              max="3600"
              step="1"
              value={ttl}
              onChange={(event) => {
                setTTL(event.target.value);
                invalidatePreview();
              }}
              required
            />
            <span id="ephemeral-api-key-ttl-help" className="text-xs text-muted-foreground">
              {t("secrets.ephemeral.ttlHelp")}
            </span>
          </div>
          <Button type="submit" disabled={previewBusy || issueBusy || !canGrant}>
            {previewBusy ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <Eye className="h-4 w-4" aria-hidden="true" />}
            {t("secrets.ephemeral.review")}
          </Button>
          {previewError ? <ErrorState title={t("secrets.ephemeral.previewFailedTitle")}>{previewError}</ErrorState> : null}
          {previewStale && !preview ? <p className="text-sm text-risk-warning">{t("secrets.ephemeral.reviewStale")}</p> : null}
        </form>

        <div className="ui-panel grid content-start gap-3 p-comfortable text-sm">
          <h3 className="text-title font-semibold">{t("secrets.ephemeral.safetyHeading")}</h3>
          <ol className="grid list-decimal gap-2 pl-5 text-muted-foreground">
            <li>{t("secrets.ephemeral.safetyReview")}</li>
            <li>{t("secrets.ephemeral.safetyReveal")}</li>
            <li>{t("secrets.ephemeral.safetyVerify")}</li>
            <li>{t("secrets.ephemeral.safetyRecover")}</li>
          </ol>
          <Link className="text-link text-sm font-medium" to="/secrets/access">
            {t("secrets.ephemeral.openLedger")}
          </Link>
        </div>
      </div>

      {preview ? (
        <div className="ui-panel grid gap-4 p-comfortable" aria-label={t("secrets.ephemeral.reviewedPlanLabel")}>
          <div>
            <p className="font-semibold">{t("secrets.ephemeral.reviewedPlan")}</p>
            <p className="mt-1 text-sm text-muted-foreground">{t("secrets.ephemeral.nothingCreated")}</p>
          </div>
          <dl className="grid gap-3 text-sm sm:grid-cols-2 lg:grid-cols-4">
            <div>
              <dt className="text-muted-foreground">{t("secrets.ephemeral.subject")}</dt>
              <dd className="break-all font-medium">{preview.subject}</dd>
            </div>
            <div>
              <dt className="text-muted-foreground">{t("secrets.ephemeral.scopes")}</dt>
              <dd className="break-all font-mono text-xs">{preview.scopes.join(", ")}</dd>
            </div>
            <div>
              <dt className="text-muted-foreground">{t("secrets.ephemeral.lifetime")}</dt>
              <dd className="font-medium">{t("secrets.ephemeral.lifetimeValue", { seconds: preview.effective_ttl_seconds })}</dd>
            </div>
            <div>
              <dt className="text-muted-foreground">{t("secrets.ephemeral.permission")}</dt>
              <dd className="font-mono text-xs">{preview.required_permission}</dd>
            </div>
          </dl>
          <p className="text-sm">{preview.token_data_handling}</p>
          <div className="grid gap-3 md:grid-cols-2">
            <div>
              <h4 className="font-medium">{t("secrets.ephemeral.recoveryHeading")}</h4>
              <ul className="mt-1 list-disc space-y-1 pl-5 text-sm text-muted-foreground">
                {preview.recovery_steps.map((step) => (
                  <li key={step}>{step}</li>
                ))}
              </ul>
            </div>
            <div>
              <h4 className="font-medium">{t("secrets.ephemeral.verificationHeading")}</h4>
              <ul className="mt-1 list-disc space-y-1 pl-5 text-sm text-muted-foreground">
                {preview.verification_steps.map((step) => (
                  <li key={step}>{step}</li>
                ))}
              </ul>
            </div>
          </div>
          <p className="break-all font-mono text-xs text-muted-foreground">
            {t("secrets.ephemeral.fingerprint")}: {preview.request_fingerprint}
          </p>
          <Button type="button" onClick={() => void executeReviewed()} disabled={issueBusy || !canGrant}>
            {issueBusy ? (
              <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
            ) : issueAmbiguous ? (
              <RotateCcw className="h-4 w-4" aria-hidden="true" />
            ) : (
              <KeyRound className="h-4 w-4" aria-hidden="true" />
            )}
            {issueAmbiguous ? t("secrets.ephemeral.retrySame") : t("secrets.ephemeral.issueReviewed")}
          </Button>
        </div>
      ) : null}
      {issueError ? <ErrorState title={t("secrets.ephemeral.issueFailedTitle")}>{issueError}</ErrorState> : null}

      {issued ? (
        <div className="grid gap-3">
          <RevealPanel title={t("secrets.ephemeral.revealTitle")} onDismiss={() => setIssued(null)} value={issued.token}>
            {t("secrets.ephemeral.revealGuidance", {
              id: issued.id,
              subject: issued.subject,
              expiresAt: formatDateTime(issued.expires_at),
              scopes: issued.scopes.join(", "),
            })}
          </RevealPanel>
          <div className="flex flex-wrap gap-2">
            <Button type="button" variant="outline" onClick={() => void verifyBearer()} disabled={verifyBusy || !canVerify}>
              {verifyBusy ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <BadgeCheck className="h-4 w-4" aria-hidden="true" />}
              {t("secrets.ephemeral.verify")}
            </Button>
            <Button type="button" variant="destructive" onClick={() => void revokeBearer()} disabled={revokeBusy}>
              {revokeBusy ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <Ban className="h-4 w-4" aria-hidden="true" />}
              {t("secrets.ephemeral.revoke")}
            </Button>
          </div>
          {!canVerify ? <p className="text-sm text-muted-foreground">{t("secrets.ephemeral.verifyUnavailable")}</p> : null}
          {verified ? (
            <p role="status" className="text-sm text-risk-healthy">
              {t("secrets.ephemeral.verifyPassed")}
            </p>
          ) : null}
          {verifyError ? <ErrorState title={t("secrets.ephemeral.verifyFailedTitle")}>{verifyError}</ErrorState> : null}
          {revokeError ? <ErrorState title={t("secrets.ephemeral.revokeFailedTitle")}>{revokeError}</ErrorState> : null}
        </div>
      ) : null}
      {revoked ? (
        <p role="status" className="text-sm text-risk-healthy">
          {t("secrets.ephemeral.revoked")}
        </p>
      ) : null}
    </section>
  );
}
