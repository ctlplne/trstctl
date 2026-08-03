import { useCallback, useEffect, useState } from "react";
import { EmptyState } from "@/components/EmptyState";
import { ErrorState, LoadingState } from "@/components/StatePrimitives";
import { api, type ADCSPosture } from "@/lib/api";
import { formatDateTime } from "@/i18n/format";
import { translateNow } from "@/i18n/I18nProvider";

/**
 * AD CS certificate template posture (epic F1).
 *
 * A Windows PKI's real attack surface is its template list. What an operator
 * needs from this panel is not an inventory — it is the answer to "which of my
 * templates can be used to become someone else, and does a CA actually offer
 * them". So the verdict leads and the directory attributes follow.
 *
 * It fetches on mount rather than through useApiQuery so a consumer test does
 * not need a QueryClientProvider — the same shape CTMonitoringPanel uses, and
 * the reason two protocol acceptance tests are currently broken elsewhere.
 */
export function ADCSTemplatePanel() {
  const [posture, setPosture] = useState<ADCSPosture | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setError(null);
    setLoading(true);
    try {
      setPosture(await api.adcsPosture());
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const templates = posture?.templates ?? [];

  return (
    <section aria-labelledby="adcs-heading" className="grid gap-3 border-y border-border py-4">
      <div>
        <h2 id="adcs-heading" className="text-title font-semibold">
          {translateNow("source.adcs.heading.f1adcs0001")}
        </h2>
        <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{translateNow("source.adcs.description.f1adcs0002")}</p>
      </div>

      {loading && <LoadingState>{translateNow("source.adcs.loading.f1adcs0003")}</LoadingState>}
      {error && <ErrorState title={translateNow("source.adcs.error.f1adcs0004")}>{error}</ErrorState>}

      {!loading && !error && !posture?.observed && (
        // "No AD CS estate" and "nobody has looked" are opposite facts, and an
        // empty table cannot tell them apart. The panel says which one this is.
        <EmptyState title={translateNow("source.adcs.unobserved.title.f1adcs0005")}>{translateNow("source.adcs.unobserved.body.f1adcs0006")}</EmptyState>
      )}

      {!loading && !error && posture?.observed && (
        <>
          <dl className="grid gap-2 rounded-md border border-border p-3 text-sm sm:grid-cols-3">
            <div>
              <dt className="text-caption text-muted-foreground">{translateNow("source.adcs.critical.f1adcs0007")}</dt>
              <dd className={posture.critical > 0 ? "font-medium text-status-critical" : "font-medium"}>{posture.critical}</dd>
            </div>
            <div>
              <dt className="text-caption text-muted-foreground">{translateNow("source.adcs.high.f1adcs0008")}</dt>
              <dd className={posture.high > 0 ? "font-medium text-status-warning" : "font-medium"}>{posture.high}</dd>
            </div>
            <div>
              <dt className="text-caption text-muted-foreground">{translateNow("source.adcs.templates.f1adcs0009")}</dt>
              <dd className="font-medium">{templates.length}</dd>
            </div>
          </dl>

          <div className="overflow-x-auto">
            <table className="ui-table min-w-[52rem]">
              <caption className="sr-only">{translateNow("source.adcs.heading.f1adcs0001")}</caption>
              <thead>
                <tr>
                  <th scope="col">{translateNow("source.adcs.col.template.f1adcs0010")}</th>
                  <th scope="col">{translateNow("source.adcs.col.risk.f1adcs0011")}</th>
                  <th scope="col">{translateNow("source.adcs.col.published.f1adcs0012")}</th>
                  <th scope="col">{translateNow("source.adcs.col.findings.f1adcs0013")}</th>
                </tr>
              </thead>
              <tbody>
                {templates.map((template) => (
                  <tr key={`${template.domain}/${template.template}`} className="align-top">
                    <td>
                      <span className="font-mono text-xs font-semibold">{template.template}</span>
                      {template.display_name ? <span className="block text-xs text-muted-foreground">{template.display_name}</span> : null}
                    </td>
                    <td>
                      <SeverityBadge severity={template.worst_severity} />
                    </td>
                    <td className="text-xs">
                      {(template.published_by ?? []).length === 0 ? (
                        // A dangerous template nobody publishes is a latent risk
                        // an operator can fix calmly; a published one is not.
                        <span className="text-muted-foreground">{translateNow("source.adcs.unpublished.f1adcs0014")}</span>
                      ) : (
                        (template.published_by ?? []).join(", ")
                      )}
                    </td>
                    <td>
                      {(template.findings ?? []).length === 0 ? (
                        <span className="text-xs text-muted-foreground">{translateNow("source.adcs.clean.f1adcs0015")}</span>
                      ) : (
                        <ul className="grid gap-2">
                          {(template.findings ?? []).map((finding) => (
                            <li key={finding.id}>
                              <span className="font-mono text-xs">{finding.id}</span>
                              <span className="block text-xs">{finding.summary}</span>
                              <span className="block text-xs text-muted-foreground">
                                {translateNow("source.adcs.remediation.f1adcs0016")} {finding.remediation}
                              </span>
                            </li>
                          ))}
                        </ul>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {templates[0]?.observed_at ? (
            // A dangerous template an operator is reading might have been
            // observed last week by a relay that has since stopped running.
            <p className="text-xs text-muted-foreground">
              {translateNow("source.adcs.observed.f1adcs0017")} {formatDateTime(templates[0].observed_at)}
              {templates[0].observed_by ? (
                <>
                  {" · "}
                  {translateNow("source.adcs.observedby.f1adcs0022")} <span className="font-mono">{templates[0].observed_by}</span>
                </>
              ) : null}
            </p>
          ) : null}
        </>
      )}

      {posture?.guidance ? <p className="text-xs text-status-warning">{posture.guidance}</p> : null}
    </section>
  );
}

/** SeverityBadge renders the worst finding on a template. An empty severity is
 * a real state — no findings — and reads as clean rather than unknown. */
function SeverityBadge({ severity }: { severity: string }) {
  if (severity === "critical") {
    return (
      <span className="rounded-full border border-status-critical px-2 py-0.5 text-xs text-status-critical">
        {translateNow("source.adcs.sev.critical.f1adcs0018")}
      </span>
    );
  }
  if (severity === "high") {
    return (
      <span className="rounded-full border border-status-warning px-2 py-0.5 text-xs text-status-warning">
        {translateNow("source.adcs.sev.high.f1adcs0019")}
      </span>
    );
  }
  if (severity === "medium") {
    return (
      <span className="rounded-full border border-border px-2 py-0.5 text-xs text-muted-foreground">{translateNow("source.adcs.sev.medium.f1adcs0020")}</span>
    );
  }
  return <span className="rounded-full border border-border px-2 py-0.5 text-xs text-muted-foreground">{translateNow("source.adcs.sev.none.f1adcs0021")}</span>;
}
