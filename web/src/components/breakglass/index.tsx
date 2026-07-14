import { FormEvent, useState } from "react";
import { api, type BreakglassIssueRequest, type BreakglassIssueResponse, type BreakglassReconcileResponse } from "@/lib/api";
import { SectionCard } from "@/components/dashboard";
import { Button } from "@/components/ui/button";
import { ErrorState } from "@/components/StatePrimitives";
import { useTranslation, translateNow } from "@/i18n/I18nProvider";

/** BreakGlassReconcile takes the bundles a quorum issued OFFLINE during an outage
 * (when the control plane could not be reached) and reconciles them back into the
 * event log through the served POST /breakglass/reconcile endpoint, so the
 * emergency certificates become first-class, audited records after the fact. */
export function BreakGlassReconcile() {
  const { t } = useTranslation();
  const [issueBody, setIssueBody] = useState("");
  const [issueResult, setIssueResult] = useState<BreakglassIssueResponse | null>(null);
  const [issueBusy, setIssueBusy] = useState(false);
  const [issueError, setIssueError] = useState<string | null>(null);
  const [bundles, setBundles] = useState("");
  const [result, setResult] = useState<BreakglassReconcileResponse | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function issue(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setIssueBusy(true);
    setIssueError(null);
    setIssueResult(null);
    let parsed: BreakglassIssueRequest;
    try {
      const value = JSON.parse(issueBody) as unknown;
      if (!value || Array.isArray(value) || typeof value !== "object") {
        throw new Error("request must be object");
      }
      parsed = value as BreakglassIssueRequest;
    } catch {
      setIssueError(t("breakglass.issue.invalidJson"));
      setIssueBusy(false);
      return;
    }
    try {
      setIssueResult(await api.breakglassIssue(parsed));
    } catch (err) {
      setIssueError(err instanceof Error ? err.message : String(err));
    } finally {
      setIssueBusy(false);
    }
  }

  async function reconcile(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    setResult(null);
    let parsed: unknown;
    try {
      parsed = JSON.parse(bundles);
    } catch {
      setError("Bundles must be a JSON array of offline-issued break-glass bundles.");
      setBusy(false);
      return;
    }
    const list = Array.isArray(parsed) ? parsed : [parsed];
    try {
      setResult(await api.breakglassReconcile({ bundles: list as never }));
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <SectionCard
      title={translateNow("source.break.glass.reconciliation.7351236672")}
      description="Reconcile offline-issued, quorum-approved break-glass certificate bundles back into the control plane once connectivity returns."
    >
      <form onSubmit={issue} className="mb-5 grid gap-3 border-b border-border pb-5">
        <div>
          <h3 className="text-sm font-semibold">{t("breakglass.issue.heading")}</h3>
          <p className="mt-1 text-sm text-muted-foreground">{t("breakglass.issue.description")}</p>
        </div>
        <label className="grid gap-1 text-sm font-medium" htmlFor="breakglass-issue">
          {t("breakglass.issue.label")}
          <textarea
            id="breakglass-issue"
            value={issueBody}
            onChange={(event) => setIssueBody(event.target.value)}
            rows={5}
            placeholder='{"request_id":"bg-001","subject":"recovery.svc.example.test","csr_der":"...base64-csr...","reason":"regional outage","approvals":["op1","op2"],"ttl_seconds":900}'
            className="rounded-md border border-border bg-background px-3 py-2 font-mono text-xs"
          />
        </label>
        <div>
          <Button type="submit" disabled={issueBusy || !issueBody.trim()}>
            {issueBusy ? t("breakglass.issue.busy") : t("breakglass.issue.submit")}
          </Button>
        </div>
      </form>
      {issueError ? <ErrorState title={t("breakglass.issue.errorTitle")}>{issueError}</ErrorState> : null}
      {issueResult ? (
        <p role="status" className="mb-3 rounded-panel border border-border p-comfortable text-sm">
          {t("breakglass.issue.status", { count: issueResult.reconciled })}
        </p>
      ) : null}
      <form onSubmit={reconcile} className="grid gap-3">
        <label className="grid gap-1 text-sm font-medium" htmlFor="breakglass-bundles">
          {translateNow("source.offline.issued.bundles.json.58401e65e9")}<textarea
            id="breakglass-bundles"
            value={bundles}
            onChange={(event) => setBundles(event.target.value)}
            rows={6}
            placeholder='[{"request_id":"…","subject":"…","approvals":["…"],"cert_der":"…","signature":"…","issued_at":"…","reason":"…"}]'
            className="rounded-md border border-border bg-background px-3 py-2 font-mono text-xs"
          />
        </label>
        <div>
          <Button type="submit" disabled={busy || !bundles.trim()}>
            {busy ? "Reconciling…" : "Reconcile break-glass bundles"}
          </Button>
        </div>
      </form>
      {error ? <ErrorState title={translateNow("source.reconcile.failed.45e781836d")}>{error}</ErrorState> : null}
      {result ? (
        <p role="status" className="mt-3 rounded-panel border border-border p-comfortable text-sm">
          {translateNow("source.reconciled.2d5676cba2")}{" "}{result.reconciled} {" "}{translateNow("source.break.glass.bundle.37f85fd7cf")}{result.reconciled === 1 ? "" : "s"} {" "}{translateNow("source.into.the.event.log.5f4b11117b")}</p>
      ) : null}
    </SectionCard>
  );
}
