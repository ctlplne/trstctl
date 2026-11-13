// SPDX-License-Identifier: BUSL-1.1

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { UnavailableState } from "@/components/StatePrimitives";
import { useTranslation } from "@/i18n/I18nProvider";
import { ApiError, api, type MisuseIncidentResolution } from "@/lib/api";

const resolutions = [
  { value: "token_revoked", messageKey: "risk.misuseIncidents.resolution.tokenRevoked" },
  { value: "expected_use", messageKey: "risk.misuseIncidents.resolution.expectedUse" },
  { value: "other", messageKey: "risk.misuseIncidents.resolution.other" },
] as const;

// M2-L3: the open misuse incidents, one per API token a finding flagged, each
// closed with a resolution. The route is Enterprise governance: a server
// without it answers 404, a lapsed license 402, and the section stays out of
// the way.
export function MisuseIncidentsPanel() {
  const { t, formatDateTime } = useTranslation();
  const queryClient = useQueryClient();
  const incidents = useQuery({ queryKey: ["misuse-incidents", "open"], queryFn: () => api.misuseIncidents("open"), retry: false });
  const [chosen, setChosen] = useState<Record<string, MisuseIncidentResolution>>({});
  const close = useMutation({
    mutationFn: ({ id, resolution }: { id: string; resolution: MisuseIncidentResolution }) => api.closeMisuseIncident(id, { resolution }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["misuse-incidents"] }),
  });
  const status = incidents.error instanceof ApiError ? incidents.error.status : 0;
  if (status === 404 || status === 402) {
    return null;
  }
  const items = incidents.data?.items ?? [];

  return (
    <section aria-labelledby="misuse-incidents-heading" className="grid min-w-0 gap-2">
      <h3 id="misuse-incidents-heading" className="text-sm font-semibold">
        {t("risk.misuseIncidents.title")}
      </h3>
      <p className="text-sm text-muted-foreground">{t("risk.misuseIncidents.description")}</p>
      {incidents.error ? <UnavailableState title={t("risk.misuseIncidents.unavailable")}>{incidents.error.message}</UnavailableState> : null}
      {incidents.data && items.length === 0 ? <p className="text-sm text-muted-foreground">{t("risk.misuseIncidents.empty")}</p> : null}
      {items.length > 0 ? (
        <div className="min-w-0 overflow-x-auto">
          <table className="w-full text-sm">
            <caption className="sr-only">{t("risk.misuseIncidents.caption")}</caption>
            <thead>
              <tr className="text-left">
                <th scope="col">{t("risk.misuseIncidents.col.token")}</th>
                <th scope="col">{t("risk.misuseIncidents.col.opened")}</th>
                <th scope="col">{t("risk.misuseIncidents.col.findings")}</th>
                <th scope="col">{t("risk.misuseIncidents.col.close")}</th>
              </tr>
            </thead>
            <tbody>
              {items.map((incident) => {
                const resolution = chosen[incident.id] ?? "token_revoked";
                return (
                  <tr key={incident.id} className="align-top">
                    <td>
                      <span className="block font-mono text-xs">{incident.credential_id}</span>
                      {incident.principal ? <span className="block text-xs text-muted-foreground">{incident.principal}</span> : null}
                    </td>
                    <td>{formatDateTime(incident.opened_at)}</td>
                    <td>{incident.findings}</td>
                    <td className="flex flex-wrap gap-2">
                      <select
                        aria-label={t("risk.misuseIncidents.resolutionLabel", { token: incident.credential_id })}
                        className="rounded border px-1 text-sm"
                        value={resolution}
                        onChange={(event) => setChosen({ ...chosen, [incident.id]: event.target.value as MisuseIncidentResolution })}
                      >
                        {resolutions.map((r) => (
                          <option key={r.value} value={r.value}>
                            {t(r.messageKey)}
                          </option>
                        ))}
                      </select>
                      <Button type="button" variant="outline" disabled={close.isPending} onClick={() => close.mutate({ id: incident.id, resolution })}>
                        {t("risk.misuseIncidents.close")}
                      </Button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      ) : null}
      {close.error ? <p className="text-sm text-destructive">{t("risk.misuseIncidents.closeFailed", { reason: close.error.message })}</p> : null}
    </section>
  );
}
