import { useEffect, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { api, type PAMWindowsLocalAccountScan } from "@/lib/api";
import { useApiQuery, useQueryClient, type ApiQueryResult } from "@/lib/query";
import { isAccessDenied } from "@/lib/apiTransport";
import { useTranslation } from "@/i18n/I18nProvider";
import { DataGrid, type DataGridState } from "@/components/DataGrid";
import { Button } from "@/components/ui/button";
import { ErrorState, UnavailableState } from "@/components/StatePrimitives";
import { Eyebrow, Num } from "@/components/typography";

function state<T>(query: ApiQueryResult<T>, rows: unknown[]): DataGridState {
  if (query.errorValue && isAccessDenied(query.errorValue)) return "permission-denied";
  if (query.error) return "error";
  if (query.loading) return "loading";
  return rows.length ? "ready" : "empty";
}
function validID(value: string) {
  return z.string().uuid().safeParse(value).success;
}
function currentScan(value: PAMWindowsLocalAccountScan, host: string, id: string) {
  return (
    !!value?.intent &&
    value.id === id &&
    value.intent.agent_id === host &&
    value.intent.run_id === id &&
    (!value.report || (value.report.run_id === id && value.report.binding_digest === value.intent.binding_digest))
  );
}
type InventoryReader = Pick<typeof api, "pamWindowsLocalAccountHosts" | "pamWindowsLocalAccountScans" | "pamWindowsLocalAccountScan">;
export function PAMWindowsLocalAccounts({ canManage, reader = api }: { canManage: boolean; reader?: InventoryReader }) {
  const { t, formatDateTime } = useTranslation();
  const [search, setSearch] = useSearchParams();
  const [after, setAfter] = useState("");
  const [history, setHistory] = useState<string[]>([]);
  const hosts = useApiQuery(["pam-windows-local-hosts", after], () => reader.pamWindowsLocalAccountHosts(after), {
    retry: false,
    gcTime: 0,
    live: { intervalMs: 10000 },
  });
  const rows = hosts.data?.items ?? [];
  const host = search.get("windows_host") ?? "";
  const run = search.get("windows_run") ?? "";
  function select(id: string) {
    setSearch((current) => {
      const next = new URLSearchParams(current);
      next.set("windows_host", id);
      next.delete("windows_run");
      return next;
    });
  }
  return (
    <section className="grid gap-3 border-t border-border pt-4" aria-labelledby="windows-local-heading">
      <h4 id="windows-local-heading" className="text-body font-semibold">
        {t("admin.access.windowsLocal.heading")}
      </h4>
      <p className="text-sm text-muted-foreground">{t("admin.access.windowsLocal.description")}</p>
      <DataGrid
        ariaLabel={t("admin.access.windowsLocal.hosts")}
        emptyStateHeadingAs="h5"
        rows={rows}
        getRowId={(row) => row.id}
        state={state(hosts, rows)}
        stateTitle={
          hosts.errorValue && isAccessDenied(hosts.errorValue)
            ? t("admin.access.windowsLocal.hostDenied")
            : hosts.error
              ? t("admin.access.windowsLocal.hostError")
              : t("admin.access.windowsLocal.noHosts")
        }
        stateMessage={hosts.errorValue && isAccessDenied(hosts.errorValue) ? t("admin.access.windowsLocal.hostDenied") : (hosts.error ?? undefined)}
        onRowOpen={(row) => select(row.id)}
        rowActionLabel={(row) => t("admin.access.windowsLocal.inspect", { name: row.name })}
        columns={[
          { id: "name", header: t("admin.access.windowsLocal.name"), cell: (row) => row.name },
          { id: "id", header: t("admin.access.windowsLocal.id"), cell: (row) => <Num>{row.id}</Num> },
          { id: "status", header: t("admin.access.windowsLocal.status"), cell: (row) => row.status },
          {
            id: "seen",
            header: t("admin.access.windowsLocal.lastSeen"),
            cell: (row) => (row.last_seen_at ? formatDateTime(row.last_seen_at) : t("admin.access.windowsLocal.unknown")),
          },
        ]}
        pagination={
          <div className="flex gap-2">
            <Button
              type="button"
              variant="outline"
              disabled={!history.length || hosts.fetching}
              onClick={() => {
                setAfter(history[history.length - 1]);
                setHistory((current) => current.slice(0, -1));
              }}
            >
              {t("admin.access.windowsLocal.previousHosts")}
            </Button>
            <Button
              type="button"
              variant="outline"
              disabled={!hosts.data?.next_cursor || hosts.fetching}
              onClick={() => {
                setHistory((current) => [...current, after]);
                setAfter(hosts.data!.next_cursor!);
              }}
            >
              {t("admin.access.windowsLocal.nextHosts")}
            </Button>
          </div>
        }
      />
      {hosts.error ? (
        <Button type="button" variant="outline" onClick={hosts.refetch}>
          {t("admin.access.windowsLocal.retry")}
        </Button>
      ) : null}
      {host && !validID(host) ? <ErrorState title={t("admin.access.windowsLocal.invalidHost")} /> : null}
      {host && validID(host) ? <HostInventory key={host} host={host} run={run} canManage={canManage} reader={reader} /> : null}
    </section>
  );
}
function HostInventory({ host, run, canManage, reader }: { host: string; run: string; canManage: boolean; reader: InventoryReader }) {
  const { t, formatDateTime } = useTranslation();
  const [, setSearch] = useSearchParams();
  const client = useQueryClient();
  const [after, setAfter] = useState("");
  const [history, setHistory] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [finished, setFinished] = useState("");
  const requestKey = useRef<string | null>(null);
  const active = useRef(true);
  useEffect(() => {
    active.current = true;
    return () => {
      active.current = false;
    };
  }, []);
  const form = useForm<{ agentID: string }>({
    defaultValues: { agentID: host },
    resolver: zodResolver(z.object({ agentID: z.string().uuid(t("admin.access.windowsLocal.invalidHost")) })),
  });
  const scans = useApiQuery(["pam-windows-local-runs", host, after], () => reader.pamWindowsLocalAccountScans(host, after), {
    retry: false,
    gcTime: 0,
    live: { intervalMs: 5000 },
  });
  const detail = useApiQuery(["pam-windows-local-run", host, run], () => reader.pamWindowsLocalAccountScan(host, run), {
    enabled: validID(run),
    retry: false,
    gcTime: 0,
    live: run && finished !== run ? { intervalMs: 3000 } : undefined,
  });
  const value = detail.data;
  const bound = !!value && currentScan(value, host, run);
  const complete = bound && value.status === "complete" && value.report?.status === "complete" && !!value.report.inventory;
  useEffect(() => {
    if (bound && (value.status === "complete" || value.status === "failed")) setFinished(run);
  }, [bound, value?.status, run]);
  const inventory = complete ? value!.report!.inventory : undefined;
  const accounts = inventory?.accounts ?? [];
  const rows = scans.data?.items ?? [];
  const pending =
    bound && (value.status === "queued" || value.status === "retrying") && (value.delivery_status === "pending" || value.delivery_status === "claimed");
  function open(id: string) {
    setSearch((current) => {
      const next = new URLSearchParams(current);
      next.set("windows_host", host);
      next.set("windows_run", id);
      return next;
    });
  }
  async function scan(agentID: string) {
    if (!canManage || busy) return;
    setBusy(true);
    setError(null);
    requestKey.current ??= crypto.randomUUID();
    try {
      const saved = await api.runPAMWindowsLocalAccountInventory(agentID, requestKey.current);
      if (!active.current) return;
      if (!currentScan(saved, agentID, saved.id) || !validID(saved.id)) throw new Error(t("admin.access.windowsLocal.bindingError"));
      requestKey.current = null;
      client.setQueryData(["pam-windows-local-run", host, saved.id], saved);
      open(saved.id);
      await Promise.all(
        [["pam-windows-local-runs", host], ["pam-windows-local-run", host, saved.id], ["pam-discovery-sources"], ["pam-discovered-accounts", "staged"]].map(
          (queryKey) => client.invalidateQueries({ queryKey }),
        ),
      );
    } catch (err) {
      if (active.current) setError(err instanceof Error ? err.message : String(err));
    } finally {
      if (active.current) setBusy(false);
    }
  }
  const accountState: DataGridState =
    detail.errorValue && isAccessDenied(detail.errorValue)
      ? "permission-denied"
      : detail.error || (value && !bound)
        ? "error"
        : detail.loading && validID(run)
          ? "loading"
          : !complete
            ? "unavailable"
            : accounts.length
              ? "ready"
              : "empty";
  return (
    <div className="grid gap-3">
      <p className="text-sm">
        <Eyebrow>{t("admin.access.windowsLocal.selectedHost")}</Eyebrow> <Num>{host}</Num>
      </p>
      {canManage ? (
        <>
          <p className="text-sm text-muted-foreground">{t("admin.access.windowsLocal.grant")}</p>
          <pre className="overflow-auto rounded-control border border-border p-3 text-sm">
            <code>{t("admin.access.windowsLocal.profile")}</code>
          </pre>
          <form
            onSubmit={(event) => {
              void form.handleSubmit((v) => scan(v.agentID))(event);
            }}
          >
            <Button type="submit" disabled={busy || pending || !!scans.error || scans.loading}>
              {t("admin.access.windowsLocal.scan")}
            </Button>
            {form.formState.errors.agentID?.message ? <ErrorState title={form.formState.errors.agentID.message} /> : null}
          </form>
        </>
      ) : null}
      {error ? <ErrorState title={t("admin.access.windowsLocal.mutationError")}>{error}</ErrorState> : null}
      <DataGrid
        ariaLabel={t("admin.access.windowsLocal.runs")}
        emptyStateHeadingAs="h5"
        rows={rows}
        getRowId={(row) => row.id}
        state={state(scans, rows)}
        stateTitle={scans.error ? t("admin.access.windowsLocal.runsError") : t("admin.access.windowsLocal.noRuns")}
        stateMessage={scans.error ?? undefined}
        onRowOpen={(row) => open(row.id)}
        rowActionLabel={(row) => t("admin.access.windowsLocal.viewRun", { id: row.id })}
        columns={[
          { id: "id", header: t("admin.access.windowsLocal.run"), cell: (row) => <Num>{row.id}</Num> },
          { id: "status", header: t("admin.access.windowsLocal.status"), cell: (row) => row.status },
          { id: "delivery", header: t("admin.access.windowsLocal.delivery"), cell: (row) => row.delivery_status },
          { id: "at", header: t("admin.access.windowsLocal.queuedAt"), cell: (row) => formatDateTime(row.queued_at) },
        ]}
        pagination={
          <div className="flex gap-2">
            <Button
              type="button"
              variant="outline"
              disabled={!history.length || scans.fetching}
              onClick={() => {
                setAfter(history[history.length - 1]);
                setHistory((current) => current.slice(0, -1));
              }}
            >
              {t("admin.access.windowsLocal.previousRuns")}
            </Button>
            <Button
              type="button"
              variant="outline"
              disabled={!scans.data?.next_cursor || scans.fetching}
              onClick={() => {
                setHistory((current) => [...current, after]);
                setAfter(scans.data!.next_cursor!);
              }}
            >
              {t("admin.access.windowsLocal.nextRuns")}
            </Button>
          </div>
        }
      />
      {run ? (
        <>
          {bound ? (
            <dl className="grid gap-2 text-sm md:grid-cols-2">
              <div>
                <Eyebrow as="dt">{t("admin.access.windowsLocal.status")}</Eyebrow>
                <dd>{value.status}</dd>
              </div>
              <div>
                <Eyebrow as="dt">{t("admin.access.windowsLocal.delivery")}</Eyebrow>
                <dd>{value.delivery_status}</dd>
              </div>
              {value.report_digest ? (
                <div>
                  <Eyebrow as="dt">{t("admin.access.windowsLocal.reportDigest")}</Eyebrow>
                  <dd className="break-all">
                    <Num>{value.report_digest}</Num>
                  </dd>
                </div>
              ) : null}
              {value.signer_fingerprint ? (
                <div>
                  <Eyebrow as="dt">{t("admin.access.windowsLocal.signer")}</Eyebrow>
                  <dd className="break-all">
                    <Num>{value.signer_fingerprint}</Num>
                  </dd>
                </div>
              ) : null}
            </dl>
          ) : null}
          {inventory ? (
            <>
              <dl className="grid gap-2 text-sm md:grid-cols-2">
                <div>
                  <Eyebrow as="dt">{t("admin.access.windowsLocal.machine")}</Eyebrow>
                  <dd>{inventory.machine.name}</dd>
                </div>
                <div>
                  <Eyebrow as="dt">{t("admin.access.windowsLocal.machineSID")}</Eyebrow>
                  <dd>
                    <Num>{inventory.machine.sid}</Num>
                  </dd>
                </div>
                <div>
                  <Eyebrow as="dt">{t("admin.access.windowsLocal.observedAt")}</Eyebrow>
                  <dd>{formatDateTime(value!.report!.observed_at)}</dd>
                </div>
              </dl>
              <p className="text-sm">
                {t("admin.access.windowsLocal.coverage", {
                  external: inventory.external_members,
                  groups: inventory.group_members,
                  deleted: inventory.deleted_members,
                })}
              </p>
            </>
          ) : null}
          <DataGrid
            ariaLabel={t("admin.access.windowsLocal.result")}
            emptyStateHeadingAs="h5"
            rows={accounts}
            getRowId={(row) => row.sid}
            state={accountState}
            stateTitle={
              value && !bound
                ? t("admin.access.windowsLocal.bindingError")
                : detail.errorValue && isAccessDenied(detail.errorValue)
                  ? t("admin.access.windowsLocal.readDenied")
                  : detail.error
                    ? t("admin.access.windowsLocal.readError")
                    : complete
                      ? t("admin.access.windowsLocal.noAccounts")
                      : t("admin.access.windowsLocal.unavailable")
            }
            stateMessage={
              detail.errorValue && isAccessDenied(detail.errorValue)
                ? t("admin.access.windowsLocal.readDenied")
                : (detail.error ??
                  (value && !bound
                    ? undefined
                    : bound && value.failure
                      ? value.failure
                      : bound && value.delivery_status === "failed"
                        ? t("admin.access.windowsLocal.stopped")
                        : t("admin.access.windowsLocal.pending")))
            }
            columns={[
              { id: "name", header: t("admin.access.windowsLocal.account"), cell: (row) => row.name },
              { id: "sid", header: t("admin.access.windowsLocal.sid"), cell: (row) => <Num>{row.sid}</Num> },
              {
                id: "state",
                header: t("admin.access.windowsLocal.accountState"),
                cell: (row) => (
                  <>
                    {row.enabled ? t("admin.access.windowsLocal.enabled") : t("admin.access.windowsLocal.disabled")}
                    {" · "}
                    {row.locked ? t("admin.access.windowsLocal.locked") : t("admin.access.windowsLocal.unlocked")}
                  </>
                ),
              },
              {
                id: "password",
                header: t("admin.access.windowsLocal.passwordPolicy"),
                cell: (row) => (row.password_required ? t("admin.access.windowsLocal.passwordRequired") : t("admin.access.windowsLocal.passwordNotRequired")),
              },
            ]}
          />
          {detail.error ? (
            <Button type="button" variant="outline" onClick={detail.refetch}>
              {t("admin.access.windowsLocal.retry")}
            </Button>
          ) : null}
        </>
      ) : (
        <UnavailableState title={t("admin.access.windowsLocal.chooseRun")} />
      )}
      <p className="text-sm text-muted-foreground">{t("admin.access.windowsLocal.noRotation")}</p>
    </div>
  );
}
