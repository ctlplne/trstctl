// SPDX-License-Identifier: BUSL-1.1

import { useInfiniteQuery } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { UnavailableState } from "@/components/StatePrimitives";
import { useTranslation } from "@/i18n/I18nProvider";
import { ApiError, api, type MisuseFinding } from "@/lib/api";

// M2-L1: the misuse findings of this tenant's API tokens, newest first.
// Detection alerts within an hourly budget; this lists every finding, so one
// whose alert was capped is still seen. The route is Enterprise governance: a
// server without it answers 404, a lapsed license 402.
export function MisuseFindingsPanel() {
  const { t, formatDateTime } = useTranslation();
  const findings = useInfiniteQuery({
    queryKey: ["misuse-findings"],
    queryFn: ({ pageParam }) => api.misuseFindings({ cursor: pageParam || undefined }),
    initialPageParam: "",
    getNextPageParam: (page, _pages, _lastPageParam, pageParams) => (page.next_cursor && !pageParams.includes(page.next_cursor) ? page.next_cursor : undefined),
    retry: false,
  });
  const status = findings.error instanceof ApiError ? findings.error.status : 0;
  const items = findings.data?.pages.flatMap((page) => page.items) ?? [];

  const what = (finding: MisuseFinding) =>
    finding.rule === "new_source_lease"
      ? t("risk.misuse.newSourceLease", { source: finding.source })
      : t("risk.misuse.secretReadBurst", { count: finding.observed_count, source: finding.source, baseline: finding.baseline });

  return (
    <section aria-labelledby="misuse-findings-heading" className="grid min-w-0 gap-2">
      <h3 id="misuse-findings-heading" className="text-sm font-semibold">
        {t("risk.misuse.title")}
      </h3>
      <p className="text-sm text-muted-foreground">{t("risk.misuse.description")}</p>
      {findings.isPending ? <p className="text-sm text-muted-foreground">{t("risk.misuse.loading")}</p> : null}
      {status === 404 || status === 402 ? (
        <p className="text-sm text-muted-foreground">{t("risk.misuse.notInEdition")}</p>
      ) : findings.error ? (
        <UnavailableState title={t("risk.misuse.unavailable")}>{findings.error.message}</UnavailableState>
      ) : null}
      {findings.data && items.length === 0 ? <p className="text-sm text-muted-foreground">{t("risk.misuse.empty")}</p> : null}
      {items.length > 0 ? (
        <div className="min-w-0 overflow-x-auto">
          <table className="w-full text-sm">
            <caption className="sr-only">{t("risk.misuse.caption")}</caption>
            <thead>
              <tr className="text-left">
                <th scope="col">{t("risk.misuse.col.token")}</th>
                <th scope="col">{t("risk.misuse.col.what")}</th>
                <th scope="col">{t("risk.misuse.col.hour")}</th>
                <th scope="col">{t("risk.misuse.col.alert")}</th>
              </tr>
            </thead>
            <tbody>
              {items.map((finding) => (
                <tr key={finding.id} className="align-top">
                  <td>
                    <span className="block font-mono text-xs">{finding.credential_id}</span>
                    {finding.principal ? <span className="block text-xs text-muted-foreground">{finding.principal}</span> : null}
                  </td>
                  <td>{what(finding)}</td>
                  <td>{formatDateTime(finding.window_start)}</td>
                  <td>{finding.alerted ? t("risk.misuse.alerted") : t("risk.misuse.notAlerted")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
      {findings.hasNextPage ? (
        <div>
          <Button type="button" variant="outline" disabled={findings.isFetchingNextPage} onClick={() => void findings.fetchNextPage()}>
            {t("risk.misuse.older")}
          </Button>
        </div>
      ) : null}
    </section>
  );
}
