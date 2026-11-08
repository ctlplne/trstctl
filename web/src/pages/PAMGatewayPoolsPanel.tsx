/* eslint-disable jsx-a11y/no-noninteractive-tabindex -- The named table overflow region needs keyboard focus for horizontal scrolling. */
import { useId, useMemo, useState } from "react";
import { api, type PAMGatewayMember, type PAMGatewayPool } from "@/lib/api";
import { useApiQuery, useQueryClient } from "@/lib/query";
import { useTranslation } from "@/i18n/I18nProvider";
import { formatDateTime, type FormatPolicy } from "@/i18n/format";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { StatusBadge } from "@/components/StatusBadge";
import { ErrorState, LoadingState, UnavailableState } from "@/components/StatePrimitives";

// A278: gateways in a pool share sessions. A session starts on the healthy,
// undrained member with the fewest live sessions and is owned by it; a
// member that stops reporting is lost, its sessions end, and new ones go to
// the others. Draining a member stops new sessions on it.

type Draft = { name: string; members: string; revision: number };

const HEALTH_TONE = { healthy: "success", draining: "warning", lost: "critical", offboarded: "neutral" } as const;
const HEALTH_LABEL = {
  healthy: "admin.access.gatewayPools.healthHealthy",
  draining: "admin.access.gatewayPools.healthDraining",
  lost: "admin.access.gatewayPools.healthLost",
  offboarded: "admin.access.gatewayPools.healthOffboarded",
} as const;

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/** parseMembers reads one gateway per line: its agent ID and address. */
export function parseMembers(text: string, previous: PAMGatewayMember[] = []): { agent_id: string; address: string; draining?: boolean }[] | null {
  const out: { agent_id: string; address: string; draining?: boolean }[] = [];
  for (const line of text.split("\n")) {
    const fields = line.trim().split(/\s+/).filter(Boolean);
    if (fields.length === 0) continue;
    if (fields.length !== 2) return null;
    const [agent_id, address] = fields;
    const draining = previous.find((m) => m.agent_id === agent_id)?.draining;
    out.push({ agent_id, address, ...(draining ? { draining } : {}) });
  }
  return out.length > 0 ? out : null;
}

export function PAMGatewayPoolsPanel({ canManage }: { canManage: boolean }) {
  const { locale, timeZone, t } = useTranslation();
  const policy = useMemo<FormatPolicy>(() => ({ locale, timeZone }), [locale, timeZone]);
  const queryClient = useQueryClient();
  const ids = { name: useId(), members: useId() };
  const pools = useApiQuery(["pam-gateway-pools"], () => api.pamGatewayPools(), { retry: false, live: { intervalMs: 15_000 } });
  const [draft, setDraft] = useState<Draft | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  async function act(work: () => Promise<string>) {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      setNotice(await work());
      await queryClient.invalidateQueries({ queryKey: ["pam-gateway-pools"] });
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  const save = (pool: PAMGatewayPool, members: { agent_id: string; address: string; draining?: boolean }[], message: string) =>
    act(async () => {
      await api.savePAMGatewayPool(pool.name, { members, revision: pool.revision }, crypto.randomUUID());
      return message;
    });
  const toggleDrain = (pool: PAMGatewayPool, member: PAMGatewayMember) =>
    save(
      pool,
      pool.members.map((m) => ({
        agent_id: m.agent_id,
        address: m.address,
        ...((m.agent_id === member.agent_id ? !member.draining : m.draining) ? { draining: true } : {}),
      })),
      t(member.draining ? "admin.access.gatewayPools.resumed" : "admin.access.gatewayPools.drained", { gateway: member.agent_id }),
    );

  function submit() {
    if (!draft) return;
    const current = pools.data?.items.find((p) => p.name === draft.name);
    const members = parseMembers(draft.members, current?.members);
    if (!members) {
      setError(t("admin.access.gatewayPools.membersInvalid"));
      return;
    }
    void act(async () => {
      await api.savePAMGatewayPool(draft.name.trim(), { members, ...(draft.revision ? { revision: draft.revision } : {}) }, crypto.randomUUID());
      setDraft(null);
      return t("admin.access.gatewayPools.saved", { pool: draft.name.trim() });
    });
  }

  const items = pools.data?.items ?? [];
  return (
    <section aria-labelledby="pam-gateway-pools-heading" className="grid gap-3">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h3 id="pam-gateway-pools-heading" className="text-body font-semibold">
            {t("admin.access.gatewayPools.heading")}
          </h3>
          <p className="text-sm text-muted-foreground">{t("admin.access.gatewayPools.description")}</p>
        </div>
        {canManage && !draft ? (
          <Button type="button" size="sm" variant="outline" onClick={() => setDraft({ name: "", members: "", revision: 0 })}>
            {t("admin.access.gatewayPools.create")}
          </Button>
        ) : null}
      </div>
      {notice ? (
        <p role="status" className="text-sm">
          {notice}
        </p>
      ) : null}
      {error ? <ErrorState title={t("admin.access.gatewayPools.failed")}>{error}</ErrorState> : null}
      {pools.loading ? <LoadingState>{t("admin.access.gatewayPools.loading")}</LoadingState> : null}
      {pools.data && items.length === 0 ? <UnavailableState title={t("admin.access.gatewayPools.none")} /> : null}
      {items.map((pool) => (
        <div key={pool.name} className="grid gap-2 rounded-panel border border-border p-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <h4 className="text-sm font-semibold">{pool.name}</h4>
            {canManage ? (
              <div className="flex gap-2">
                <Button
                  type="button"
                  size="sm"
                  variant="outline"
                  disabled={busy}
                  aria-label={t("admin.access.gatewayPools.editFor", { pool: pool.name })}
                  onClick={() =>
                    setDraft({ name: pool.name, members: pool.members.map((m) => `${m.agent_id} ${m.address}`).join("\n"), revision: pool.revision })
                  }
                >
                  {t("admin.access.gatewayPools.edit")}
                </Button>
                <Button
                  type="button"
                  size="sm"
                  variant="ghost"
                  disabled={busy}
                  aria-label={t("admin.access.gatewayPools.deleteFor", { pool: pool.name })}
                  onClick={() =>
                    void act(async () => {
                      await api.deletePAMGatewayPool(pool.name, pool.revision, crypto.randomUUID());
                      return t("admin.access.gatewayPools.deleted", { pool: pool.name });
                    })
                  }
                >
                  {t("admin.access.gatewayPools.delete")}
                </Button>
              </div>
            ) : null}
          </div>
          <div className="overflow-auto" tabIndex={0} role="region" aria-label={t("admin.access.gatewayPools.membersFor", { pool: pool.name })}>
            <table className="ui-table">
              <caption className="sr-only">{t("admin.access.gatewayPools.membersFor", { pool: pool.name })}</caption>
              <thead>
                <tr>
                  <th scope="col">{t("admin.access.gatewayPools.gateway")}</th>
                  <th scope="col">{t("admin.access.gatewayPools.address")}</th>
                  <th scope="col">{t("admin.access.gatewayPools.health")}</th>
                  <th scope="col">{t("admin.access.gatewayPools.lastSeen")}</th>
                  <th scope="col">{t("admin.access.gatewayPools.live")}</th>
                  {canManage ? <th scope="col">{t("admin.access.gatewayPools.next")}</th> : null}
                </tr>
              </thead>
              <tbody>
                {pool.members.map((m) => (
                  <tr key={m.agent_id}>
                    <td className="font-mono text-xs">{m.agent_id}</td>
                    <td className="font-mono text-xs">{m.address}</td>
                    <td>
                      <StatusBadge value={m.health ?? "healthy"} label={t(HEALTH_LABEL[m.health ?? "healthy"])} tone={HEALTH_TONE[m.health ?? "healthy"]} />
                    </td>
                    <td>{m.last_seen_at ? formatDateTime(m.last_seen_at, policy) : "—"}</td>
                    <td>{m.live_sessions}</td>
                    {canManage ? (
                      <td>
                        <Button
                          type="button"
                          size="sm"
                          variant="outline"
                          disabled={busy}
                          aria-label={t(m.draining ? "admin.access.gatewayPools.resumeFor" : "admin.access.gatewayPools.drainFor", { gateway: m.agent_id })}
                          onClick={() => void toggleDrain(pool, m)}
                        >
                          {t(m.draining ? "admin.access.gatewayPools.resume" : "admin.access.gatewayPools.drain")}
                        </Button>
                      </td>
                    ) : null}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ))}
      {draft ? (
        <form
          className="grid gap-2 rounded-panel border border-border p-3 text-sm"
          aria-label={t("admin.access.gatewayPools.form")}
          onSubmit={(event) => {
            event.preventDefault();
            submit();
          }}
        >
          <label htmlFor={ids.name}>{t("admin.access.gatewayPools.name")}</label>
          <Input
            id={ids.name}
            required
            pattern="[a-z0-9][a-z0-9_\-]{0,63}"
            readOnly={draft.revision > 0}
            value={draft.name}
            onChange={(event) => setDraft({ ...draft, name: event.target.value })}
          />
          <label htmlFor={ids.members}>{t("admin.access.gatewayPools.membersLabel")}</label>
          <Textarea id={ids.members} required rows={4} value={draft.members} onChange={(event) => setDraft({ ...draft, members: event.target.value })} />
          <p className="text-caption text-muted-foreground">{t("admin.access.gatewayPools.membersHelp")}</p>
          <div className="flex gap-2">
            <Button type="submit" size="sm" disabled={busy || !draft.name.trim() || !draft.members.trim()}>
              {t("admin.access.gatewayPools.save")}
            </Button>
            <Button type="button" size="sm" variant="ghost" onClick={() => setDraft(null)}>
              {t("admin.access.gatewayPools.cancel")}
            </Button>
          </div>
        </form>
      ) : null}
    </section>
  );
}
