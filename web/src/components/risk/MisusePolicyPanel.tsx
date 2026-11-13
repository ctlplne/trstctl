// SPDX-License-Identifier: BUSL-1.1

import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { UnavailableState } from "@/components/StatePrimitives";
import { useTranslation } from "@/i18n/I18nProvider";
import { ApiError, api, type MisusePolicyThresholds } from "@/lib/api";

const fields = [
  { key: "normal_days", messageKey: "risk.misusePolicy.normalDays", min: 1, max: 30 },
  { key: "burst_floor", messageKey: "risk.misusePolicy.burstFloor", min: 1, max: 100000 },
  { key: "burst_factor", messageKey: "risk.misusePolicy.burstFactor", min: 2, max: 100 },
  { key: "burst_lookback_days", messageKey: "risk.misusePolicy.lookbackDays", min: 1, max: 90 },
  { key: "hourly_alert_cap", messageKey: "risk.misusePolicy.alertCap", min: 1, max: 1000 },
] as const;

// M2-L2: the thresholds misuse detection uses for this tenant, the defaults
// until the tenant sets its own. A caller who may write policy changes them;
// they apply from the next detection pass. The route is Enterprise
// governance: a server without it answers 404, a lapsed license 402, and the
// section stays out of the way.
export function MisusePolicyPanel() {
  const { t, formatDateTime } = useTranslation();
  const queryClient = useQueryClient();
  const policy = useQuery({ queryKey: ["misuse-policy"], queryFn: () => api.misusePolicy(), retry: false });
  const [draft, setDraft] = useState<MisusePolicyThresholds | null>(null);
  useEffect(() => {
    if (policy.data) {
      const { normal_days, burst_floor, burst_factor, burst_lookback_days, hourly_alert_cap } = policy.data;
      setDraft({ normal_days, burst_floor, burst_factor, burst_lookback_days, hourly_alert_cap });
    }
  }, [policy.data]);
  const save = useMutation({
    mutationFn: (input: MisusePolicyThresholds) => api.setMisusePolicy(input),
    onSuccess: (view) => queryClient.setQueryData(["misuse-policy"], view),
  });
  const status = policy.error instanceof ApiError ? policy.error.status : 0;
  if (status === 404 || status === 402) {
    return null;
  }
  const saveStatus = save.error instanceof ApiError ? save.error.status : 0;

  return (
    <section aria-labelledby="misuse-policy-heading" className="grid min-w-0 gap-2">
      <h3 id="misuse-policy-heading" className="text-sm font-semibold">
        {t("risk.misusePolicy.title")}
      </h3>
      <p className="text-sm text-muted-foreground">{t("risk.misusePolicy.description")}</p>
      {policy.error ? <UnavailableState title={t("risk.misusePolicy.unavailable")}>{policy.error.message}</UnavailableState> : null}
      {policy.data ? (
        <p className="text-sm text-muted-foreground">
          {policy.data.custom && policy.data.updated_at
            ? t("risk.misusePolicy.custom", { who: policy.data.set_by || "-", when: formatDateTime(policy.data.updated_at) })
            : t("risk.misusePolicy.defaults")}
        </p>
      ) : null}
      {draft ? (
        <form
          className="grid gap-2 sm:grid-cols-2"
          onSubmit={(event) => {
            event.preventDefault();
            save.mutate(draft);
          }}
        >
          {fields.map((field) => (
            <label key={field.key} className="grid gap-1 text-sm">
              <span>{t(field.messageKey)}</span>
              <Input
                type="number"
                min={field.min}
                max={field.max}
                required
                value={draft[field.key]}
                onChange={(event) => setDraft({ ...draft, [field.key]: Number(event.target.value) })}
              />
            </label>
          ))}
          <div className="sm:col-span-2">
            <Button type="submit" disabled={save.isPending}>
              {t("risk.misusePolicy.save")}
            </Button>
          </div>
        </form>
      ) : null}
      {save.isSuccess ? <p className="text-sm">{t("risk.misusePolicy.saved")}</p> : null}
      {saveStatus === 403 ? <p className="text-sm text-muted-foreground">{t("risk.misusePolicy.readOnly")}</p> : null}
      {save.error && saveStatus !== 403 ? (
        <p className="text-sm text-destructive">{t("risk.misusePolicy.saveFailed", { reason: save.error.message })}</p>
      ) : null}
    </section>
  );
}
