import { useEffect, useRef, useState, type FormEvent } from "react";
import { Eye, Loader2, Share2 } from "lucide-react";
import { ErrorState } from "@/components/StatePrimitives";
import { Button } from "@/components/ui/button";
import { formatDateTime as formatDate } from "@/i18n/format";
import { useTranslation, translateNow } from "@/i18n/I18nProvider";
import { ApiError, api, type SharePreview, type ShareToken, type ShareValue } from "@/lib/api";
import { apiProblemMessage } from "@/lib/apiProblem";
import { RevealPanel, SecretApprovalQueue, type SecretApprovalQueueItem } from "./SecretsPageParts";

function newShareIdempotencyKey(): string {
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) return crypto.randomUUID();
  return `share-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

export default function SecretSharingWorkflow({
  approvalItems,
  approvalBusyKey,
  canRetryApproval,
  onApprove,
  onRetryApproval,
  blocked,
}: {
  approvalItems: SecretApprovalQueueItem[];
  approvalBusyKey: string | null;
  canRetryApproval: (item: SecretApprovalQueueItem) => boolean;
  onApprove: (item: SecretApprovalQueueItem) => void;
  onRetryApproval: (item: SecretApprovalQueueItem) => void;
  blocked: boolean;
}) {
  const { t } = useTranslation();
  const [shareValueInput, setShareValueInput] = useState("");
  const [shareTTL, setShareTTL] = useState("300");
  const [sharePreview, setSharePreview] = useState<SharePreview | null>(null);
  const [sharePreviewBusy, setSharePreviewBusy] = useState(false);
  const [sharePreviewError, setSharePreviewError] = useState<string | null>(null);
  const [sharePreviewStale, setSharePreviewStale] = useState(false);
  const [shareRecoveryKey, setShareRecoveryKey] = useState<string | null>(null);
  const [shareAmbiguous, setShareAmbiguous] = useState(false);
  const [shareBusy, setShareBusy] = useState(false);
  const [shareError, setShareError] = useState<string | null>(null);
  const [shareToken, setShareToken] = useState<ShareToken | null>(null);
  const [redeemToken, setRedeemToken] = useState("");
  const [redeemBusy, setRedeemBusy] = useState(false);
  const [redeemError, setRedeemError] = useState<string | null>(null);
  const [redeemed, setRedeemed] = useState<ShareValue | null>(null);
  const [redeemAmbiguous, setRedeemAmbiguous] = useState(false);
  const redeemRequest = useRef<{ token: string; key: string } | null>(null);
  const shareValueRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    shareValueRef.current?.focus();
  }, []);

  function invalidateSharePreview() {
    setSharePreview((current) => {
      if (current) setSharePreviewStale(true);
      return null;
    });
    setSharePreviewError(null);
    setShareRecoveryKey(null);
    setShareAmbiguous(false);
    setShareError(null);
    setShareToken(null);
  }

  async function submitShare(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSharePreviewError(null);
    setShareError(null);
    setShareToken(null);
    setShareAmbiguous(false);
    setSharePreviewBusy(true);
    try {
      const ttl = Number(shareTTL);
      const plan = await api.previewShare({ ttl_seconds: Number.isFinite(ttl) ? ttl : undefined });
      if (!plan.effect_free) throw new Error(t("secrets.share.previewNotEffectFree"));
      if (!plan.ready) throw new Error(plan.blockers.join(" ") || t("secrets.share.previewBlocked"));
      setSharePreview(plan);
      setSharePreviewStale(false);
      setShareRecoveryKey(newShareIdempotencyKey());
    } catch (err) {
      setSharePreview(null);
      setShareRecoveryKey(null);
      setSharePreviewError(apiProblemMessage(err, t("secrets.share.previewFailed")));
    } finally {
      setSharePreviewBusy(false);
    }
  }

  async function executeReviewedShare() {
    if (!sharePreview || !shareRecoveryKey) {
      setShareError(t("secrets.share.reviewRequired"));
      return;
    }
    setShareError(null);
    setShareToken(null);
    setShareBusy(true);
    try {
      const ttl = Number(shareTTL);
      const created = await api.createShare(
        {
          value: shareValueInput,
          ttl_seconds: Number.isFinite(ttl) ? ttl : undefined,
          preview_fingerprint: sharePreview.request_fingerprint,
        },
        shareRecoveryKey,
      );
      setShareToken(created);
      setShareValueInput("");
      setSharePreview(null);
      setShareRecoveryKey(null);
      setShareAmbiguous(false);
      setSharePreviewStale(false);
    } catch (err) {
      if (err instanceof ApiError) {
        setShareAmbiguous(false);
        setShareError(apiProblemMessage(err, t("secrets.share.createFailed")));
        if (err.status === 409) {
          setSharePreview(null);
          setShareRecoveryKey(null);
          setSharePreviewStale(true);
        }
      } else {
        setShareAmbiguous(true);
        setShareError(t("secrets.share.ambiguousFailure"));
      }
    } finally {
      setShareBusy(false);
    }
  }

  async function submitRedeem(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    // Consumption may have committed before a response was lost. Retain the
    // exact request only in memory so a retry can recover that original result.
    const request = redeemRequest.current ?? { token: redeemToken, key: newShareIdempotencyKey() };
    redeemRequest.current = request;
    setRedeemError(null);
    setRedeemed(null);
    setRedeemBusy(true);
    try {
      setRedeemed(await api.redeemShare({ token: request.token }, request.key));
      redeemRequest.current = null;
      setRedeemAmbiguous(false);
    } catch (err) {
      if (err instanceof ApiError && err.status < 500) {
        redeemRequest.current = null;
        setRedeemAmbiguous(false);
        setRedeemError(apiProblemMessage(err, t("secrets.share.redeemFailed")));
      } else {
        setRedeemAmbiguous(true);
        setRedeemError(t("secrets.share.redeemAmbiguous"));
      }
    } finally {
      setRedeemBusy(false);
    }
  }

  return (
    <section id="task-panel-share" aria-labelledby="share-heading" className="grid gap-4 border-y border-border py-4">
      <div>
        <h2 id="share-heading" className="text-title font-semibold">
          {translateNow("source.one.time.sharing.9db928cd78")}
        </h2>
        <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{t("secrets.share.description")}</p>
      </div>
      <div className="grid gap-4 xl:grid-cols-2">
        <form
          aria-label={translateNow("source.create.one.time.share.fd95a197d6")}
          onSubmit={(event) => void submitShare(event)}
          className="grid content-start gap-3"
        >
          <label className="grid gap-1 text-sm">
            <span className="font-medium">{translateNow("source.value.to.share.fa56b0a913")}</span>
            <input
              id="share-value"
              ref={shareValueRef}
              className="rounded-md border border-border bg-background px-3 py-2"
              type="password"
              value={shareValueInput}
              onChange={(event) => {
                setShareValueInput(event.target.value);
                invalidateSharePreview();
              }}
              autoComplete="off"
              required
            />
          </label>
          <label className="grid gap-1 text-sm">
            <span className="font-medium">{translateNow("source.ttl.seconds.862d08de5a")}</span>
            <input
              className="rounded-md border border-border bg-background px-3 py-2"
              type="number"
              min="60"
              max="604800"
              value={shareTTL}
              onChange={(event) => {
                setShareTTL(event.target.value);
                invalidateSharePreview();
              }}
            />
          </label>
          <Button type="submit" disabled={sharePreviewBusy || shareBusy || blocked}>
            {sharePreviewBusy ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <Eye className="h-4 w-4" aria-hidden="true" />}
            {t("secrets.share.review")}
          </Button>
          {sharePreviewError && <ErrorState title={t("secrets.share.previewFailedTitle")}>{sharePreviewError}</ErrorState>}
          {sharePreviewStale && !sharePreview && <p className="text-sm text-risk-warning">{t("secrets.share.reviewStale")}</p>}
          {sharePreview && (
            <div className="ui-panel grid gap-3 p-4" aria-label={t("secrets.share.reviewedPlanLabel")}>
              <div>
                <p className="font-semibold">{t("secrets.share.reviewedPlan")}</p>
                <p className="mt-1 text-sm text-muted-foreground">{t("secrets.share.nothingStored")}</p>
              </div>
              <dl className="grid gap-2 text-sm sm:grid-cols-2">
                <div>
                  <dt className="text-muted-foreground">{t("secrets.share.lifetime")}</dt>
                  <dd className="font-medium">{t("secrets.share.lifetimeValue", { seconds: sharePreview.effective_ttl_seconds })}</dd>
                </div>
                <div>
                  <dt className="text-muted-foreground">{t("secrets.share.permission")}</dt>
                  <dd className="font-mono text-xs">{sharePreview.required_permission}</dd>
                </div>
              </dl>
              <p className="text-sm">{sharePreview.secret_data_handling}</p>
              <p className="text-sm text-muted-foreground">
                {sharePreview.sensitive_change_approval_configured ? t("secrets.share.approvalConfigured") : t("secrets.share.approvalUnavailable")}
              </p>
              <Button type="button" onClick={() => void executeReviewedShare()} disabled={shareBusy || blocked}>
                {shareBusy ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <Share2 className="h-4 w-4" aria-hidden="true" />}
                {shareAmbiguous ? t("secrets.share.retrySame") : t("secrets.share.createReviewed")}
              </Button>
            </div>
          )}
          {shareError && <ErrorState title={translateNow("source.share.create.failed.9078694d49")}>{shareError}</ErrorState>}
        </form>
        <form
          aria-label={translateNow("source.redeem.one.time.share.2294329e1f")}
          onSubmit={(event) => void submitRedeem(event)}
          className="grid content-start gap-3"
        >
          <label className="grid gap-1 text-sm">
            <span className="font-medium">{translateNow("source.share.token.f3310a3b89")}</span>
            <input
              className="rounded-md border border-border bg-background px-3 py-2"
              value={redeemToken}
              onChange={(event) => {
                setRedeemToken(event.target.value);
                redeemRequest.current = null;
                setRedeemAmbiguous(false);
                setRedeemError(null);
                setRedeemed(null);
              }}
              autoComplete="off"
              disabled={redeemBusy}
              required
            />
          </label>
          <Button type="submit" variant="outline" disabled={redeemBusy || blocked}>
            {redeemBusy ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <Eye className="h-4 w-4" aria-hidden="true" />}
            {redeemAmbiguous ? t("secrets.share.retryRedeem") : translateNow("source.redeem.share.1b54732322")}
          </Button>
          {redeemError && <ErrorState title={translateNow("source.share.redeem.failed.674fa95c57")}>{redeemError}</ErrorState>}
        </form>
      </div>
      {shareToken && (
        <RevealPanel title={translateNow("source.one.time.share.token.20234cd9a0")} onDismiss={() => setShareToken(null)} value={shareToken.token}>
          {t("secrets.share.tokenGuidance", { expiresAt: formatDate(shareToken.expires_at) })}
        </RevealPanel>
      )}
      {redeemed && (
        <RevealPanel title={translateNow("source.redeemed.share.value.1455d94a16")} onDismiss={() => setRedeemed(null)} value={redeemed.value}>
          {translateNow("source.this.value.is.the.exact.once.redeem.result.ed19b63953")}
        </RevealPanel>
      )}
      <SecretApprovalQueue items={approvalItems} busyKey={approvalBusyKey} canRetry={canRetryApproval} onApprove={onApprove} onRetry={onRetryApproval} />
    </section>
  );
}
