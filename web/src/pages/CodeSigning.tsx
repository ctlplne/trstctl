import { type ReactNode } from "react";
import { Link } from "react-router-dom";
import { AlertTriangle, CheckCircle2, Clock3, FileSignature, KeyRound, Stamp } from "lucide-react";
import { api, type CodeSigningIdentity } from "@/lib/api";
import { PageHeader } from "@/components/PageHeader";
import { SectionCard } from "@/components/dashboard";
import { LoadingState } from "@/components/StatePrimitives";
import { useTranslation, translateNow } from "@/i18n/I18nProvider";
import { useApiQuery } from "@/lib/query";
import { useCapabilityExecution } from "@/lib/capabilities";
import { CodeSigningWorkflow } from "@/pages/codesigning/CodeSigningWorkflow";

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
  const operationList = useCapabilityExecution("F50", "listCodeSigningIdentities");
  const approvalList = useCapabilityExecution("F33", "listApprovalRequests");
  const operations = useApiQuery(["code-signing", "identities"], api.codeSigningIdentities, {
    enabled: !operationList.checking && operationList.runnable,
    live: { intervalMs: 30_000 },
  });
  const approvals = useApiQuery(["approval-requests"], api.approvalRequests, {
    enabled: !approvalList.checking && approvalList.runnable,
    live: { intervalMs: 30_000 },
  });
  const protocols = useApiQuery(["protocol-statuses"], api.protocolStatuses, { live: { intervalMs: 60_000 } });
  const loading =
    operationList.checking ||
    approvalList.checking ||
    (operationList.runnable && operations.loading) ||
    (approvalList.runnable && approvals.loading) ||
    protocols.loading;
  const operationsUnavailable = !operationList.runnable || operations.error !== null;
  const approvalsUnavailable = !approvalList.runnable || approvals.error !== null;
  const sourceUnavailable = operationsUnavailable || approvalsUnavailable || protocols.error !== null;
  const signingApprovals = (approvals.data ?? []).filter((row) => row.status === "pending" && row.resource_kind === "code_signing");
  const failedOperations = (operations.data?.items ?? []).filter((row) => row.status === "failed" || row.transparency === "failed");
  const tsa = protocols.data?.items.find((row) => row.protocol.toLowerCase() === "tsa");
  const tsaNeedsAction = protocols.data !== null && (!tsa || !tsa.enabled || !tsa.served);
  const attentionCount = failedOperations.length + signingApprovals.length + (tsaNeedsAction ? 1 : 0);

  return (
    <section aria-labelledby="codesign-heading" className="grid gap-6">
      <PageHeader titleId="codesign-heading" title={t("nav.item.codeSigning")} description={t("codesign.answer")} technicalDetails={t("codesign.technical")} />

      {loading ? (
        <LoadingState>{t("codesign.overview.loading")}</LoadingState>
      ) : (
        <>
          <section aria-labelledby="codesign-attention-heading" className="ui-panel space-y-3 p-comfortable">
            <div className="flex items-start gap-3">
              {sourceUnavailable || attentionCount > 0 ? (
                <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-status-warning" aria-hidden="true" />
              ) : (
                <CheckCircle2 className="mt-0.5 h-5 w-5 shrink-0 text-status-success" aria-hidden="true" />
              )}
              <div>
                <h2 id="codesign-attention-heading" className="text-title font-semibold">
                  {sourceUnavailable
                    ? t("codesign.attention.unknown")
                    : attentionCount > 0
                      ? t("codesign.attention.count", { count: String(attentionCount) })
                      : t("codesign.attention.clear")}
                </h2>
                <p className="mt-1 text-sm text-muted-foreground">{sourceUnavailable ? t("codesign.attention.unknownHelp") : t("codesign.attention.help")}</p>
              </div>
            </div>
            {sourceUnavailable ? (
              <ul className="grid gap-1 text-sm text-muted-foreground">
                {operationsUnavailable ? <li>{t("codesign.source.operationsUnavailable")}</li> : null}
                {approvalsUnavailable ? <li>{t("codesign.source.approvalsUnavailable")}</li> : null}
                {protocols.error ? <li>{t("codesign.source.tsaUnavailable")}</li> : null}
              </ul>
            ) : null}
          </section>

          <section aria-labelledby="codesign-health-heading" className="space-y-3">
            <div>
              <h2 id="codesign-health-heading" className="text-title font-semibold">
                {t("codesign.health.title")}
              </h2>
              <p className="mt-1 text-sm text-muted-foreground">{t("codesign.health.help")}</p>
            </div>
            <ul aria-label={t("codesign.health.label")} className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
              <SoftwareHealth
                icon={<FileSignature className="h-4 w-4" aria-hidden="true" />}
                urgent={operationsUnavailable || failedOperations.length > 0}
                label={
                  operationsUnavailable
                    ? t("codesign.health.operationsUnavailable")
                    : failedOperations.length === 1
                      ? t("codesign.health.failures.one")
                      : t("codesign.health.failures.many", { count: String(failedOperations.length) })
                }
              />
              <SoftwareHealth
                icon={<Clock3 className="h-4 w-4" aria-hidden="true" />}
                urgent={approvalsUnavailable || signingApprovals.length > 0}
                label={
                  approvalsUnavailable
                    ? t("codesign.health.approvalsUnavailable")
                    : signingApprovals.length === 1
                      ? t("codesign.health.approvals.one")
                      : t("codesign.health.approvals.many", { count: String(signingApprovals.length) })
                }
                to="/operations?type=approval"
              />
              <SoftwareHealth
                icon={<Stamp className="h-4 w-4" aria-hidden="true" />}
                urgent={protocols.error !== null || tsaNeedsAction}
                label={
                  protocols.error
                    ? t("codesign.health.tsaUnavailable")
                    : tsa?.enabled && tsa.served
                      ? t("codesign.health.tsaServing")
                      : t("codesign.health.tsaReview")
                }
                to="/tsa"
              />
              <SoftwareHealth icon={<KeyRound className="h-4 w-4" aria-hidden="true" />} urgent label={t("codesign.health.keysUnavailable")} to="/ca" />
              <SoftwareHealth
                icon={<CheckCircle2 className="h-4 w-4" aria-hidden="true" />}
                urgent={operationsUnavailable}
                label={
                  operationsUnavailable
                    ? t("codesign.health.operationsUnavailable")
                    : operations.data?.total === 1
                      ? t("codesign.health.operations.one")
                      : t("codesign.health.operations.many", { count: String(operations.data?.total ?? 0) })
                }
              />
            </ul>
          </section>

          {(operations.data?.items ?? []).length > 0 ? <SigningOutcomes items={operations.data?.items ?? []} /> : null}
        </>
      )}

      <SectionCard title={t("codesign.workflow.title")} description={t("codesign.workflow.description")}>
        <CodeSigningWorkflow />
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

function SoftwareHealth({ icon, label, urgent, to }: { icon: ReactNode; label: string; urgent: boolean; to?: string }) {
  const content = (
    <>
      <span className={urgent ? "text-status-warning" : "text-status-success"}>{icon}</span>
      <span className="text-sm font-semibold">{label}</span>
    </>
  );
  return (
    <li>
      {to ? (
        <Link to={to} className="ui-panel flex min-h-20 items-center gap-3 p-4 hover:border-brand-accent/50">
          {content}
        </Link>
      ) : (
        <div className="ui-panel flex min-h-20 items-center gap-3 p-4">{content}</div>
      )}
    </li>
  );
}

function SigningOutcomes({ items }: { items: CodeSigningIdentity[] }) {
  const { t } = useTranslation();
  return (
    <section aria-labelledby="codesign-outcomes-heading" className="min-w-0 space-y-3">
      <div>
        <h2 id="codesign-outcomes-heading" className="text-title font-semibold">
          {t("codesign.outcomes.title")}
        </h2>
        <p className="mt-1 text-sm text-muted-foreground">{t("codesign.outcomes.help")}</p>
      </div>
      <div className="min-w-0 overflow-x-auto rounded-panel border border-border">
        <table aria-label={t("codesign.outcomes.label")} className="ui-table min-w-full">
          <thead>
            <tr>
              <th scope="col">{t("codesign.outcomes.operation")}</th>
              <th scope="col">{t("codesign.outcomes.mode")}</th>
              <th scope="col">{t("codesign.outcomes.result")}</th>
              <th scope="col">{t("codesign.outcomes.transparency")}</th>
              <th scope="col">{t("codesign.outcomes.evidence")}</th>
            </tr>
          </thead>
          <tbody>
            {items.slice(0, 10).map((item) => (
              <tr key={item.operation_id}>
                <td className="font-mono text-xs">{item.operation_id}</td>
                <td>{t(item.mode === "managed" ? "codesign.mode.managed" : item.mode === "keyless" ? "codesign.mode.keyless" : "codesign.mode.unknown")}</td>
                <td>{item.status}</td>
                <td>
                  {t(
                    item.transparency === "verified"
                      ? "codesign.transparency.verified"
                      : item.transparency === "pending"
                        ? "codesign.transparency.pending"
                        : item.transparency === "failed"
                          ? "codesign.transparency.failed"
                          : "codesign.transparency.notPublished",
                  )}
                </td>
                <td className="max-w-sm text-sm text-muted-foreground">{item.last_error || item.transparency_error || t("codesign.outcomes.noError")}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
