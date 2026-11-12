// SPDX-License-Identifier: BUSL-1.1

import { useState } from "react";
import { useAuth } from "@/auth/AuthProvider";
import { Button } from "@/components/ui/button";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { useTranslation } from "@/i18n/I18nProvider";
import type { MessageKey } from "@/i18n/messages";
import { api } from "@/lib/api";
import { hasPermission } from "@/lib/access";
import { newIdempotencyKey } from "@/lib/apiTransport";
import { useApiQuery, useQueryClient } from "@/lib/query";

const keyStateLabel: Record<string, MessageKey> = {
  active: "workloads.jwtKeys.state.active",
  next: "workloads.jwtKeys.state.next",
  retiring: "workloads.jwtKeys.state.retiring",
  retired: "workloads.jwtKeys.state.retired",
};

const hour = 3600;

// N5 / N5-L3: the tenant's published OpenID issuer that clouds register, and
// the JWT signing keys behind it. A rotation publishes the next key ahead of
// signing with it and keeps the replaced key published for a retain window,
// so a cloud's cached key set keeps verifying every token.
export function OIDCIssuerPanel() {
  const { t, formatDateTime } = useTranslation();
  const { user } = useAuth();
  const canRotate = hasPermission(user, "issuers:write");
  const queryClient = useQueryClient();
  // An issuer that is not published answers 404 at once; asking again changes nothing.
  const issuer = useApiQuery(["oidc-issuer"], api.oidcIssuer, { retry: false });
  const keys = useApiQuery(["workload-jwt-keys"], api.workloadJWTKeys);
  const [draft, setDraft] = useState({ aheadHours: "24", retainHours: "24" });
  // A retried rotation keeps its key, so a lost response never rotates twice.
  const [key, setKey] = useState(() => newIdempotencyKey());
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [rotated, setRotated] = useState(false);
  const pending = (keys.data?.keys ?? []).find((k) => k.state === "next");

  const edit = (next: Partial<typeof draft>) => {
    setDraft({ ...draft, ...next });
    setKey(newIdempotencyKey());
    setRotated(false);
  };

  const rotate = async () => {
    setBusy(true);
    setError(null);
    try {
      await api.rotateWorkloadJWTKey(
        {
          publish_ahead_seconds: Math.round(Number(draft.aheadHours) * hour),
          retain_seconds: Math.round(Number(draft.retainHours) * hour),
        },
        key,
      );
      setKey(newIdempotencyKey());
      setRotated(true);
      void queryClient.invalidateQueries({ queryKey: ["workload-jwt-keys"] });
      void queryClient.invalidateQueries({ queryKey: ["oidc-issuer"] });
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  const ahead = Number(draft.aheadHours);
  const retain = Number(draft.retainHours);
  const valid = draft.aheadHours !== "" && draft.retainHours !== "" && ahead >= 0 && ahead <= 720 && retain >= 1 && retain <= 720;

  return (
    <section aria-labelledby="oidc-issuer-heading" className="grid gap-3 border-y border-border py-4">
      <div>
        <h2 id="oidc-issuer-heading" className="text-title font-semibold">
          {t("workloads.oidcIssuer.heading")}
        </h2>
        <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{t("workloads.oidcIssuer.description")}</p>
      </div>
      {issuer.error ? <p className="text-sm text-muted-foreground">{issuer.error}</p> : null}
      {issuer.data ? (
        <dl className="grid gap-1 text-sm md:grid-cols-[max-content_1fr] md:gap-x-4">
          <dt className="font-medium">{t("workloads.oidcIssuer.issuer")}</dt>
          <dd className="break-all font-mono text-xs">{issuer.data.issuer}</dd>
          <dt className="font-medium">{t("workloads.oidcIssuer.discovery")}</dt>
          <dd className="break-all font-mono text-xs">{issuer.data.discovery_url}</dd>
          <dt className="font-medium">{t("workloads.oidcIssuer.jwks")}</dt>
          <dd className="break-all font-mono text-xs">{issuer.data.jwks_uri}</dd>
          <dt className="font-medium">{t("workloads.oidcIssuer.algorithms")}</dt>
          <dd>{issuer.data.algorithms.join(", ")}</dd>
          <dt className="font-medium">{t("workloads.oidcIssuer.tokenEndpoint")}</dt>
          <dd className="break-all font-mono text-xs">{issuer.data.token_endpoint}</dd>
        </dl>
      ) : null}
      {issuer.data && !issuer.data.algorithms.includes("RS256") ? (
        <p className="max-w-3xl text-sm text-muted-foreground">{t("workloads.oidcIssuer.rs256Hint")}</p>
      ) : null}

      <h3 className="font-medium">{t("workloads.jwtKeys.heading")}</h3>
      {keys.error ? <p className="text-sm text-muted-foreground">{keys.error}</p> : null}
      {keys.data ? (
        <div className="min-w-0 overflow-x-auto">
          <table className="w-full text-sm">
            <caption className="sr-only">{t("workloads.jwtKeys.caption")}</caption>
            <thead>
              <tr className="text-left">
                <th scope="col">{t("workloads.jwtKeys.col.key")}</th>
                <th scope="col">{t("workloads.jwtKeys.col.state")}</th>
                <th scope="col">{t("workloads.jwtKeys.col.signs")}</th>
                <th scope="col">{t("workloads.jwtKeys.col.retires")}</th>
              </tr>
            </thead>
            <tbody>
              {keys.data.keys.map((k) => (
                <tr key={k.key_id} className="align-top">
                  <td className="font-mono text-xs">{k.key_id}</td>
                  <td>{t(keyStateLabel[k.state] ?? "workloads.jwtKeys.state.active")}</td>
                  <td>{k.activates_at ? formatDateTime(k.activates_at) : t("workloads.jwtKeys.firstKey")}</td>
                  <td>{k.retires_at ? formatDateTime(k.retires_at) : "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}

      {canRotate && keys.data ? (
        <section className="grid gap-3 md:grid-cols-3" aria-labelledby="jwt-key-rotate-heading">
          <h4 id="jwt-key-rotate-heading" className="font-medium md:col-span-3">
            {t("workloads.jwtKeys.rotate.heading")}
          </h4>
          <p className="text-sm text-muted-foreground md:col-span-3">{t("workloads.jwtKeys.rotate.help")}</p>
          {pending?.activates_at ? (
            <p className="text-sm md:col-span-3">
              {t("workloads.jwtKeys.rotate.pending", { key: pending.key_id, date: formatDateTime(pending.activates_at) })}
            </p>
          ) : (
            <>
              <Field label={t("workloads.jwtKeys.rotate.ahead")} controlId="jwt-key-ahead">
                {(control) => (
                  <Input {...control} type="number" min={0} max={720} value={draft.aheadHours} onChange={(event) => edit({ aheadHours: event.target.value })} />
                )}
              </Field>
              <Field label={t("workloads.jwtKeys.rotate.retain")} controlId="jwt-key-retain">
                {(control) => (
                  <Input
                    {...control}
                    type="number"
                    min={1}
                    max={720}
                    value={draft.retainHours}
                    onChange={(event) => edit({ retainHours: event.target.value })}
                  />
                )}
              </Field>
              <div className="self-end">
                <Button type="button" loading={busy} disabled={busy || !valid} onClick={() => void rotate()}>
                  {t("workloads.jwtKeys.rotate.submit")}
                </Button>
              </div>
            </>
          )}
          {error ? (
            <p role="alert" className="text-sm text-status-danger md:col-span-3">
              {error}
            </p>
          ) : null}
          {rotated ? (
            <p role="status" className="text-sm md:col-span-3">
              {t("workloads.jwtKeys.rotate.done")}
            </p>
          ) : null}
        </section>
      ) : null}
    </section>
  );
}
