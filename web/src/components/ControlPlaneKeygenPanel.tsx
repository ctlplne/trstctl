// SPDX-License-Identifier: BUSL-1.1

import { useState } from "react";
import { api, type ControlPlaneKeygen } from "@/lib/api";
import { newIdempotencyKey } from "@/lib/apiTransport";
import { useApiQuery, useQueryClient } from "@/lib/query";
import { translateNow } from "@/i18n/I18nProvider";
import { formatDateTime } from "@/i18n/format";
import { useCan } from "@/components/rbac";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

// Owner decision 2026-10-24: the tenant's switch over control-plane key
// generation. New tenants start with it off; a change names its reason, and
// the panel shows who decided and how many identities' renewals depend on it.
export function ControlPlaneKeygenPanel() {
  const canWrite = useCan("access:write");
  const queryClient = useQueryClient();
  const policy = useApiQuery(["tenant", "key-generation"], () => api.controlPlaneKeygen());
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  if (typeof api.controlPlaneKeygen !== "function") return null;
  const p: ControlPlaneKeygen | undefined = policy.data ?? undefined;

  const change = async (enabled: boolean) => {
    setBusy(true);
    setError("");
    setMessage("");
    try {
      await api.putControlPlaneKeygen({ enabled, reason: reason.trim() }, newIdempotencyKey());
      setMessage(translateNow(enabled ? "keygen.changed.on" : "keygen.changed.off"));
      setReason("");
      void queryClient.invalidateQueries({ queryKey: ["tenant", "key-generation"] });
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  const state = !p ? "" : !p.decided ? "keygen.state.undecided" : p.enabled ? "keygen.state.on" : "keygen.state.off";
  return (
    <section aria-labelledby="keygen-heading" className="ui-panel space-y-2 p-comfortable">
      <h2 id="keygen-heading" className="text-title font-semibold">
        {translateNow("keygen.heading")}
      </h2>
      <p className="text-caption text-muted-foreground">{translateNow("keygen.intro")}</p>
      {policy.error ? (
        <p role="alert" className="text-sm text-risk-critical">
          {String(policy.error)}
        </p>
      ) : null}
      {state ? <p className="text-sm font-medium">{translateNow(state)}</p> : null}
      {p?.decided && p.set_at ? (
        <p className="text-caption text-muted-foreground">
          {translateNow("keygen.decidedBy", { who: p.set_by || "?", at: formatDateTime(p.set_at), reason: p.reason || "" })}
        </p>
      ) : null}
      {p && p.control_plane_identities > 0 ? <p className="text-caption">{translateNow("keygen.renewals", { count: p.control_plane_identities })}</p> : null}
      {p ? <p className="text-caption text-muted-foreground">{p.guidance}</p> : null}
      {canWrite && p ? (
        <div className="flex flex-wrap items-center gap-2">
          <Input
            aria-label={translateNow("keygen.reason")}
            placeholder={translateNow("keygen.reason")}
            value={reason}
            onChange={(event) => setReason(event.target.value)}
          />
          <Button type="button" variant="outline" disabled={busy || !reason.trim()} onClick={() => void change(!p.enabled)}>
            {translateNow(p.enabled ? "keygen.turnOff" : "keygen.turnOn")}
          </Button>
        </div>
      ) : null}
      {message ? (
        <p role="status" className="text-caption text-success">
          {message}
        </p>
      ) : null}
      {error ? (
        <p role="alert" className="text-caption text-risk-critical">
          {error}
        </p>
      ) : null}
    </section>
  );
}
