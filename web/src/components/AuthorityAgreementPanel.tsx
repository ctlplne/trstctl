// SPDX-License-Identifier: MPL-2.0

import { useEffect, useState } from "react";
import { translateNow } from "@/i18n/I18nProvider";
import { api, type AuthorityAgreementReport } from "@/lib/api";
import { useRuntimeOperationExecution } from "@/lib/capabilities";

// C4: do the configured authorities agree, and where do they not?
//
// XREC compares what each authority believes it issued against what the others
// and this control plane believe, and raises a witness naming exactly the
// differing subset. Until this panel it had nowhere to say so — the drift
// projection accumulated every witness and no surface read it.
//
// The whole design problem here is that SILENCE RENDERS AS AGREEMENT. "0 open
// witnesses" looks identical whether reconciliation found nothing, is not
// licensed, is not configured, or has consumed no events yet. So the panel
// refuses to show a reassuring zero it cannot stand behind: an unlicensed or
// unconfigured deployment gets the reason instead of the number, and a
// configured one carries its replay watermark next to the count.
export function AuthorityAgreementPanel() {
  const [report, setReport] = useState<AuthorityAgreementReport | null>(null);
  const [unavailable, setUnavailable] = useState<string | null>(null);
  const agreementRead = useRuntimeOperationExecution("getAuthorityAgreement");

  useEffect(() => {
    let active = true;
    if (agreementRead.checking) {
      return () => {
        active = false;
      };
    }
    if (!agreementRead.runnable) {
      setReport(null);
      setUnavailable(
        agreementRead.unavailable?.detail ??
          (agreementRead.state === "denied" ? translateNow("capabilities.reason.permissionBlocked") : translateNow("capabilities.reason.notAttached")),
      );
      return () => {
        active = false;
      };
    }
    api
      .authorityAgreement()
      .then((r) => {
        if (active) {
          setReport(r);
          setUnavailable(null);
        }
      })
      .catch((err) => {
        // A licensed route answers 402/403 without the entitlement. That is not
        // an error to red-flag — it is a feature this deployment does not have,
        // and rendering it as a failure would train operators to ignore the
        // panel that also reports real divergence.
        if (active) setUnavailable(err instanceof Error ? err.message : String(err));
      });
    return () => {
      active = false;
    };
  }, [agreementRead.checking, agreementRead.runnable, agreementRead.state, agreementRead.unavailable?.detail]);

  if (unavailable) {
    return (
      <section className="ui-panel p-comfortable" aria-labelledby="authority-agreement-heading">
        <h2 id="authority-agreement-heading" className="text-title font-semibold">
          {translateNow("source.authority.agreement.c4xr000001")}
        </h2>
        <p className="mt-2 max-w-3xl text-caption text-muted-foreground">{translateNow("source.agreement.unavailable.c4xr000002")}</p>
      </section>
    );
  }

  return (
    <section className="ui-panel p-comfortable" aria-labelledby="authority-agreement-heading">
      <h2 id="authority-agreement-heading" className="text-title font-semibold">
        {translateNow("source.authority.agreement.c4xr000001")}
      </h2>
      {!report ? (
        <p className="mt-2 text-caption text-muted-foreground">{translateNow("source.loading.4f9d1e0e3a")}</p>
      ) : (
        <>
          <p className="mt-1 max-w-3xl text-caption text-muted-foreground">{report.detail}</p>
          {report.configured && !report.collecting ? (
            /* Attached and looking at nothing. Shown as a warning rather than a
               clean result, because every ingredient of "we checked and your
               authorities agree" is present except anything doing the checking. */
            <p className="mt-2 text-caption text-status-warning">{translateNow("source.not.collecting.c4xr000010")}</p>
          ) : null}
          {report.configured && report.collecting ? (
            <>
              <dl className="mt-4 grid gap-4 sm:grid-cols-3">
                <div>
                  <dt className="text-caption font-medium text-muted-foreground">{translateNow("source.open.witnesses.c4xr000003")}</dt>
                  <dd
                    className={report.open_witnesses > 0 ? "text-title font-semibold tabular-nums text-status-danger" : "text-title font-semibold tabular-nums"}
                  >
                    {report.open_witnesses}
                  </dd>
                </div>
                <div>
                  <dt className="text-caption font-medium text-muted-foreground">{translateNow("source.replay.watermark.c4xr000004")}</dt>
                  {/* Next to the count on purpose. A projection lagging the
                      event log reports an old world confidently, and an
                      operator reading zero deserves to know whether that is
                      news or silence. */}
                  <dd className="text-title font-semibold tabular-nums">{report.replay_watermark}</dd>
                </div>
                <div>
                  <dt className="text-caption font-medium text-muted-foreground">{translateNow("source.median.resolution.c4xr000005")}</dt>
                  <dd className="text-title font-semibold tabular-nums">{report.median_resolution_seconds}s</dd>
                  {/* Sample size, so a median over one witness cannot pass for
                      a trend. */}
                  <span className="mt-1 block text-xs text-muted-foreground">
                    {translateNow("source.over.n.resolved.c4xr000006")} {report.resolved_in_window}
                  </span>
                </div>
              </dl>
              {(report.authorities ?? []).length > 0 ? (
                <div className="mt-4 overflow-x-auto">
                  <table className="w-full text-caption">
                    <thead>
                      <tr>
                        <th scope="col">{translateNow("source.authority.c4xr000007")}</th>
                        <th scope="col">{translateNow("source.divergences.c4xr000008")}</th>
                        <th scope="col">{translateNow("source.by.class.c4xr000009")}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(report.authorities ?? []).map((authority) => (
                        <tr key={authority.authority_id}>
                          <td className="font-medium">{authority.authority_id}</td>
                          <td className="tabular-nums">{authority.total}</td>
                          <td>{(authority.witnesses ?? []).map((w) => `${w.class} (${w.count})`).join(", ")}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : null}
            </>
          ) : null}
          <p className="mt-4 max-w-3xl text-xs text-muted-foreground">{report.guidance}</p>
        </>
      )}
    </section>
  );
}
