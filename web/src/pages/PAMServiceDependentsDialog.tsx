import { useId, useRef, useState, type RefObject } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { api, type PAMDiscoveredAccount, type PAMServiceDependentHost, type PAMServiceDependentScan } from "@/lib/api";
import { useApiQuery, useQueryClient } from "@/lib/query";
import { useTranslation } from "@/i18n/I18nProvider";
import { Dialog } from "@/components/Dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Field } from "@/components/ui/field";
import { ErrorState, LoadingState } from "@/components/StatePrimitives";

export function PAMServiceDependentsDialog({
  account,
  canManage,
  onClose,
  returnFocusRef,
}: {
  account: PAMDiscoveredAccount;
  canManage: boolean;
  onClose: () => void;
  returnFocusRef?: RefObject<HTMLElement | null>;
}) {
  const { t } = useTranslation();
  const title = useId(),
    description = useId();
  const client = useQueryClient();
  const [after, setAfter] = useState("");
  const [history, setHistory] = useState<string[]>([]);
  const [runID, setRunID] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const keys = useRef(new Map<string, string>());
  const key = ["pam-dependent-hosts", account.id, after];
  const hosts = useApiQuery(key, () => api.pamServiceDependentHosts(account.id, after), { retry: false, live: { intervalMs: 5000 } });
  const scan = useApiQuery(["pam-dependent-scan", runID], () => api.pamServiceDependentScan(runID!), {
    enabled: !!runID,
    retry: false,
    live: { intervalMs: 3000 },
  });
  const form = useForm<{ agentID: string }>({
    resolver: zodResolver(z.object({ agentID: z.string().trim().uuid(t("admin.access.dependents.invalidHost")) })),
    defaultValues: { agentID: "" },
  });
  function requestKey(action: string) {
    let value = keys.current.get(action);
    if (!value) {
      value = crypto.randomUUID();
      keys.current.set(action, value);
    }
    return value;
  }
  async function act(action: string, work: (key: string) => Promise<void>) {
    setBusy(true);
    setError(null);
    try {
      await work(requestKey(action));
      keys.current.delete(action);
      await client.invalidateQueries({ queryKey: ["pam-dependent-hosts", account.id] });
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }
  function cacheHost(host: PAMServiceDependentHost) {
    client.setQueryData(key, (current: { items: PAMServiceDependentHost[]; next_cursor?: string } | undefined) => ({
      ...current,
      items: [...(current?.items ?? []).filter((h) => h.binding.agent_id !== host.binding.agent_id), host].sort((a, b) =>
        a.binding.agent_id.localeCompare(b.binding.agent_id),
      ),
    }));
  }
  function save(agentID: string, enabled: boolean) {
    return act("save:" + agentID + ":" + enabled, async (key) => {
      cacheHost(await api.savePAMServiceDependentHost(account.id, agentID, enabled, key));
      form.reset();
    });
  }
  function run(agentID: string) {
    return act("run:" + agentID, async (key) => {
      const value = await api.runPAMServiceDependentInventory(account.id, agentID, key);
      client.setQueryData(["pam-dependent-scan", value.id], value);
      await client.invalidateQueries({ queryKey: ["pam-dependent-scan", value.id] });
      setRunID(value.id);
    });
  }
  const result = scan.data;
  const coverageIncomplete = result?.report?.coverage.some((c) => c.status !== "complete");
  return (
    <Dialog
      open
      onClose={onClose}
      titleId={title}
      descriptionId={description}
      returnFocusRef={returnFocusRef}
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      overlayClassName="absolute inset-0 bg-black/55"
      panelClassName="relative max-h-[90vh] w-full max-w-3xl overflow-auto rounded-panel border border-border bg-card p-5 shadow-elevation2"
    >
      <h2 id={title} className="text-title font-semibold">
        {t("admin.access.dependents.title", { name: account.name })}
      </h2>
      <p id={description} className="mt-2 text-sm text-muted-foreground">
        {t("admin.access.dependents.description")}
      </p>
      <p className="mt-2 break-all text-sm">
        <code>{String(account.details?.native_sid ?? "")}</code>
      </p>
      {canManage ? (
        <form
          className="mt-4 flex items-end gap-2"
          onSubmit={(event) => {
            void form.handleSubmit((v) => save(v.agentID, true))(event);
          }}
        >
          <Field
            label={t("admin.access.dependents.hostID")}
            description={t("admin.access.dependents.hostHelp")}
            error={form.formState.errors.agentID?.message}
            required
          >
            {(control) => <Input {...control} {...form.register("agentID")} autoComplete="off" />}
          </Field>
          <Button type="submit" disabled={busy}>
            {t("admin.access.dependents.addHost")}
          </Button>
        </form>
      ) : null}
      {error ? <ErrorState title={error} /> : null}
      {hosts.loading ? <LoadingState>{t("admin.access.dependents.loading")}</LoadingState> : null}
      {hosts.error ? (
        <ErrorState title={hosts.error}>
          <Button type="button" variant="outline" onClick={hosts.refetch}>
            {t("admin.access.dependents.retry")}
          </Button>
        </ErrorState>
      ) : null}
      <ul className="mt-4 grid gap-3">
        {(hosts.data?.items ?? []).map((host) => (
          <li key={host.binding.agent_id} className="rounded-panel border border-border p-3">
            <p className="break-all font-mono text-xs">{host.binding.agent_id}</p>
            <p className="text-sm">{host.binding.enabled ? t("admin.access.dependents.enabled") : t("admin.access.dependents.disabled")}</p>
            {host.latest_scan ? (
              <div className="mt-1 text-sm">
                <p>
                  {t("admin.access.dependents.latest", {
                    status: host.latest_scan.status,
                    services: host.latest_scan.service_count,
                    tasks: host.latest_scan.task_count,
                    pools: host.latest_scan.pool_count,
                  })}
                </p>
                {!host.latest_scan.current ? <p role="status">{t("admin.access.dependents.stale")}</p> : null}
                {host.latest_scan.failure ? <p>{host.latest_scan.failure}</p> : null}
                {host.latest_scan.delivery_status ? <p>{t("admin.access.dependents.delivery", { status: host.latest_scan.delivery_status })}</p> : null}
                <Button type="button" variant="outline" size="sm" onClick={() => setRunID(host.latest_scan!.id)}>
                  {t("admin.access.dependents.view")}
                </Button>
              </div>
            ) : (
              <p className="text-sm">{t("admin.access.dependents.noScan")}</p>
            )}
            {canManage ? (
              <div className="mt-2 flex gap-2">
                <Button type="button" size="sm" disabled={busy || !host.binding.enabled} onClick={() => void run(host.binding.agent_id)}>
                  {t("admin.access.dependents.scan")}
                </Button>
                <Button type="button" variant="outline" size="sm" disabled={busy} onClick={() => void save(host.binding.agent_id, !host.binding.enabled)}>
                  {host.binding.enabled ? t("admin.access.dependents.disable") : t("admin.access.dependents.enable")}
                </Button>
              </div>
            ) : null}
          </li>
        ))}
      </ul>
      {hosts.data?.items.length === 0 ? <p className="mt-3 text-sm">{t("admin.access.dependents.noHosts")}</p> : null}
      <div className="mt-3 flex gap-2">
        {history.length > 0 ? (
          <Button
            type="button"
            variant="outline"
            onClick={() => {
              setAfter(history[history.length - 1]);
              setHistory((h) => h.slice(0, -1));
            }}
          >
            {t("admin.access.dependents.previous")}
          </Button>
        ) : null}
        {hosts.data?.next_cursor ? (
          <Button
            type="button"
            variant="outline"
            onClick={() => {
              setHistory((h) => [...h, after]);
              setAfter(hosts.data!.next_cursor!);
            }}
          >
            {t("admin.access.dependents.next")}
          </Button>
        ) : null}
      </div>
      {runID ? (
        <section className="mt-4 border-t border-border pt-3" aria-label={t("admin.access.dependents.result")}>
          {scan.loading ? <LoadingState>{t("admin.access.dependents.loading")}</LoadingState> : null}
          {scan.error ? (
            <ErrorState title={scan.error}>
              <Button type="button" variant="outline" onClick={scan.refetch}>
                {t("admin.access.dependents.retry")}
              </Button>
            </ErrorState>
          ) : null}
          {result ? (
            <>
              <p className="break-all text-sm">{t("admin.access.dependents.runStatus", { id: result.id, status: result.status })}</p>
              {result.failure ? <p role="status">{result.failure}</p> : null}
              {result.delivery_status ? <p>{t("admin.access.dependents.delivery", { status: result.delivery_status })}</p> : null}
              {result.delivery_status === "failed" ? <p role="status">{t("admin.access.dependents.deliveryFailed")}</p> : null}
              {!result.report ? (
                <p>{t("admin.access.dependents.pending")}</p>
              ) : (
                <>
                  <p className="text-xs">{result.report.observed_at}</p>
                  {coverageIncomplete ? <p role="status">{t("admin.access.dependents.incomplete")}</p> : <p>{t("admin.access.dependents.complete")}</p>}
                  <ul>
                    {result.report.coverage.map((c) => (
                      <li key={c.family}>
                        {c.family}: {c.status}
                        {c.failure ? " — " + c.failure : ""}
                      </li>
                    ))}
                  </ul>
                  <NativeItems report={result.report} />
                  <p className="mt-2 text-xs text-muted-foreground">{t("admin.access.dependents.hashHelp")}</p>
                </>
              )}
            </>
          ) : null}
        </section>
      ) : null}
      <div className="mt-4 flex justify-end">
        <Button type="button" variant="outline" onClick={onClose}>
          {t("admin.access.dependents.close")}
        </Button>
      </div>
    </Dialog>
  );
}
function NativeItems({ report }: { report: NonNullable<PAMServiceDependentScan["report"]> }) {
  return (
    <ul className="mt-2 grid gap-2 text-sm">
      {(report.services ?? []).map((s) => (
        <li key={"service:" + s.name}>
          <strong>{s.name}</strong>
          <div className="break-all font-mono text-xs">
            {s.account_sid} · {s.config_sha256}
          </div>
          {s.dependencies?.length ? <p>{s.dependencies.join(", ")}</p> : null}
        </li>
      ))}
      {(report.tasks ?? []).map((s) => (
        <li key={"task:" + s.path}>
          <strong>{s.path}</strong>
          <div className="break-all font-mono text-xs">
            {s.account_sid} · {s.config_sha256}
          </div>
        </li>
      ))}
      {(report.pools ?? []).map((s) => (
        <li key={"pool:" + s.name}>
          <strong>{s.name}</strong>
          <div className="break-all font-mono text-xs">
            {s.account_sid} · {s.config_sha256} · {s.encryption_provider}
          </div>
        </li>
      ))}
    </ul>
  );
}
