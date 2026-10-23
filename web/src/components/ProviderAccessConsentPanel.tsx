// SPDX-License-Identifier: BUSL-1.1

import { useState } from "react";
import { api, type ProviderAccessPolicy, type ProviderAccessRequest } from "@/lib/api";
import { newIdempotencyKey } from "@/lib/apiTransport";
import { useApiQuery, useQueryClient } from "@/lib/query";
import { translateNow } from "@/i18n/I18nProvider";
import { formatDateTime } from "@/i18n/format";
import { useCan } from "@/components/rbac";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

// A95: the customer's side of Provider emergency access. The policy says
// whether this tenant's own consent is required before a Provider may use an
// emergency grant; the requests the Provider recorded under this tenant are
// listed here with this tenant's decisions, and each person decides once.
export function ProviderAccessConsentPanel() {
  const canWrite = useCan("access:write");
  const queryClient = useQueryClient();
  const policy = useApiQuery(["provider-access", "policy"], () => api.providerAccessPolicy());
  const requests = useApiQuery(["provider-access", "requests"], () => api.providerAccessRequests(), { live: { intervalMs: 30_000 } });
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [reasons, setReasons] = useState<Record<string, string>>({});
  if (typeof api.providerAccessPolicy !== "function") return null;
  const p: ProviderAccessPolicy | undefined = policy.data ?? undefined;

  const refresh = () => {
    void queryClient.invalidateQueries({ queryKey: ["provider-access", "policy"] });
    void queryClient.invalidateQueries({ queryKey: ["provider-access", "requests"] });
  };
  const setPolicy = async (require: boolean) => {
    setBusy(true);
    setError("");
    setMessage("");
    try {
      await api.putProviderAccessPolicy({ require_tenant_consent: require, approvals: p?.approvals || 2 }, newIdempotencyKey());
      setMessage(translateNow(require ? "providerAccess.policy.enabled" : "providerAccess.policy.disabled"));
      refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };
  const decide = async (request: ProviderAccessRequest, approve: boolean) => {
    setBusy(true);
    setError("");
    setMessage("");
    try {
      await api.consentProviderAccess(request.grant_id, { approve, reason: reasons[request.grant_id] ?? "" }, newIdempotencyKey());
      setMessage(translateNow(approve ? "providerAccess.decision.approved" : "providerAccess.decision.denied", { grant: request.grant_id }));
      refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <section aria-labelledby="provider-access-heading" className="ui-panel space-y-2 p-comfortable">
      <h2 id="provider-access-heading" className="text-title font-semibold">
        {translateNow("providerAccess.heading")}
      </h2>
      <p className="text-caption text-muted-foreground">{translateNow("providerAccess.intro")}</p>
      {policy.error ? (
        <p role="alert" className="text-sm text-risk-critical">
          {String(policy.error)}
        </p>
      ) : null}
      <p className="text-sm">
        {p?.require_tenant_consent
          ? translateNow("providerAccess.policy.required", { approvals: p.approvals })
          : translateNow("providerAccess.policy.notRequired")}
      </p>
      {canWrite ? (
        <Button type="button" variant="outline" disabled={busy} onClick={() => void setPolicy(!p?.require_tenant_consent)}>
          {translateNow(p?.require_tenant_consent ? "providerAccess.policy.turnOff" : "providerAccess.policy.turnOn")}
        </Button>
      ) : null}
      <h3 className="text-sm font-semibold">{translateNow("providerAccess.requests.heading")}</h3>
      {(requests.data ?? []).length === 0 ? (
        <p className="text-caption text-muted-foreground">{translateNow("providerAccess.requests.none")}</p>
      ) : (
        <ul className="grid gap-2">
          {(requests.data ?? []).map((request) => (
            <li key={request.grant_id} className="rounded-control border border-border p-2 text-sm">
              <p>
                <span className="font-mono">{request.grant_id}</span> · {request.operator_email || "?"}
              </p>
              <p className="text-caption text-muted-foreground">
                {request.reason} · {translateNow("providerAccess.requests.expires", { at: formatDateTime(request.expires_at) })}
              </p>
              <p className="text-caption">
                {request.denied
                  ? translateNow("providerAccess.requests.denied")
                  : translateNow("providerAccess.requests.approvals", { count: request.approvals })}
              </p>
              {canWrite && !request.denied ? (
                <div className="mt-2 flex flex-wrap items-center gap-2">
                  <Input
                    aria-label={translateNow("providerAccess.decision.reason")}
                    placeholder={translateNow("providerAccess.decision.reason")}
                    value={reasons[request.grant_id] ?? ""}
                    onChange={(event) => setReasons((current) => ({ ...current, [request.grant_id]: event.target.value }))}
                  />
                  <Button type="button" size="sm" disabled={busy} onClick={() => void decide(request, true)}>
                    {translateNow("providerAccess.decision.approve")}
                  </Button>
                  <Button
                    type="button"
                    size="sm"
                    variant="destructive-outline"
                    disabled={busy || !(reasons[request.grant_id] ?? "").trim()}
                    onClick={() => void decide(request, false)}
                  >
                    {translateNow("providerAccess.decision.deny")}
                  </Button>
                </div>
              ) : null}
            </li>
          ))}
        </ul>
      )}
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
