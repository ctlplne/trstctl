/* eslint-disable jsx-a11y/no-noninteractive-tabindex -- The named table overflow regions need keyboard focus for horizontal scrolling. */
import { useEffect, useId, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { PAMDependentRotation } from "./PAMDependentRotation";
import { api, type PAMDiscoveredAccount, type PAMDiscoveryImportRequest, type PAMDiscoveryImportReview } from "@/lib/api";
import { useApiQuery, useQueryClient } from "@/lib/query";
import { useTranslation } from "@/i18n/I18nProvider";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { PAMServiceDependentsDialog } from "./PAMServiceDependentsDialog";
import { Dialog } from "@/components/Dialog";
import { ErrorState, LoadingState, UnavailableState } from "@/components/StatePrimitives";

// A260: privileged account discovery. A source is one of the tenant's
// dynamic-secret providers; a scan reads its target read-only and stages the
// privileged accounts it finds. Selected accounts are imported into a folder
// after independent review, or one is dismissed with a reason. Importing
// grants nothing.

const DISCOVERABLE = new Set(["postgresql", "mysql", "mssql", "unix", "ldap"]);
const INTERVALS = [0, 86400, 604800];

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

export function PAMDiscoveryPanel({ canManage }: { canManage: boolean }) {
  const { t } = useTranslation();
  const [search, setSearch] = useSearchParams();
  const queryClient = useQueryClient();
  const ids = { provider: useId(), interval: useId(), folder: useId(), template: useId(), reason: useId(), dismiss: useId() };
  const sources = useApiQuery(["pam-discovery-sources"], api.pamDiscoverySources, { retry: false, live: { intervalMs: 5000 } });
  const staged = useApiQuery(["pam-discovered-accounts", "staged"], () => api.pamDiscoveredAccounts({ status: "staged" }), { retry: false });
  const imported = useApiQuery(["pam-imported-accounts"], () => api.pamImportedAccounts(), { retry: false });
  const importedNative = useApiQuery(["pam-discovered-accounts", "imported"], () => api.pamDiscoveredAccounts({ status: "imported" }), {
    enabled: !!imported.data?.items.some((a) => a.kind === "directory_service_account" || a.kind === "directory_user"),
    retry: false,
  });
  const providers = useApiQuery(["dynamic-secret-providers"], api.dynamicSecretProviders, { enabled: canManage, retry: false });
  const completedScans = (sources.data?.items ?? [])
    .filter((s) => s.last_run?.status === "completed")
    .map((s) => s.last_run!.id)
    .sort()
    .join(",");
  useEffect(() => {
    void queryClient.invalidateQueries({ queryKey: ["pam-discovered-accounts", "staged"] });
  }, [completedScans, queryClient]);
  const [sourceForm, setSourceForm] = useState({ provider: "", interval: 0 });
  const [selected, setSelected] = useState<string[]>([]);
  const [dependentAccount, setDependentAccount] = useState<PAMDiscoveredAccount | null>(null);
  const [importOpen, setImportOpen] = useState(false);
  const [importForm, setImportForm] = useState({ folder: "", template: "", reason: "" });
  const [pending, setPending] = useState<{ request: PAMDiscoveryImportRequest; review: PAMDiscoveryImportReview } | null>(null);
  const [dismissing, setDismissing] = useState<PAMDiscoveredAccount | null>(null);
  const [dismissReason, setDismissReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const keys = useRef({ request: crypto.randomUUID(), apply: crypto.randomUUID(), dismiss: crypto.randomUUID() });
  const returnFocus = useRef<HTMLButtonElement | null>(null);

  async function refresh() {
    await Promise.all(
      [["pam-discovery-sources"], ["pam-discovered-accounts", "staged"], ["pam-imported-accounts"]].map((queryKey) =>
        queryClient.invalidateQueries({ queryKey }),
      ),
    );
  }
  async function act(work: () => Promise<string>) {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      setNotice(await work());
      await refresh();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }
  const saveSource = () =>
    act(async () => {
      const saved = await api.savePAMDiscoverySource(sourceForm.provider, sourceForm.interval);
      return t("admin.access.discovery.sourceSaved", { provider: saved.provider_id });
    });
  const scan = (providerID: string) =>
    act(async () => {
      const run = await api.runPAMDiscovery(providerID);
      return run.status === "queued"
        ? t("admin.access.discovery.scanQueued", { provider: providerID, id: run.id })
        : run.status === "completed"
          ? t("admin.access.discovery.scanned", {
              provider: providerID,
              accounts: run.accounts,
              added: run.added,
              removed: run.removed,
              changed: run.changed,
            })
          : t("admin.access.discovery.scanFailed", { provider: providerID, failure: run.failure ?? "error" });
    });
  const requestImport = () =>
    act(async () => {
      const request: PAMDiscoveryImportRequest = {
        request_id: crypto.randomUUID(),
        account_ids: selected,
        folder: importForm.folder.trim(),
        reason: importForm.reason.trim(),
        ...(importForm.template.trim() ? { template_id: importForm.template.trim() } : {}),
      };
      const review = await api.requestPAMDiscoveryImport(request, keys.current.request);
      keys.current.request = crypto.randomUUID();
      setPending({ request, review });
      return t("admin.access.discovery.importRequested", { count: review.required_approvals });
    });
  const applyImport = () =>
    act(async () => {
      if (!pending) return "";
      const result = await api.applyPAMDiscoveryImport(
        { ...pending.request, approval_request_id: pending.review.approval_request_id, intent_digest: pending.review.intent_digest },
        keys.current.apply,
      );
      keys.current.apply = crypto.randomUUID();
      setPending(null);
      setImportOpen(false);
      setSelected([]);
      setImportForm({ folder: "", template: "", reason: "" });
      return t("admin.access.discovery.imported", { count: result.items.length, folder: pending.request.folder });
    });
  const dismiss = () =>
    act(async () => {
      if (!dismissing) return "";
      const updated = await api.dismissPAMDiscoveredAccount(dismissing.id, dismissReason.trim(), keys.current.dismiss);
      keys.current.dismiss = crypto.randomUUID();
      setDismissing(null);
      setDismissReason("");
      return t("admin.access.discovery.dismissed", { name: updated.name });
    });

  const discoverable = (providers.data?.configured_providers ?? []).filter((p) => DISCOVERABLE.has(p.type));
  const stagedItems = staged.data?.items ?? [];
  const importedNativeByID = new Map((importedNative.data?.items ?? []).map((a) => [a.id, a]));
  return (
    <section aria-labelledby="pam-discovery-heading" className="grid gap-3">
      <div>
        <h3 id="pam-discovery-heading" className="text-body font-semibold">
          {t("admin.access.discovery.heading")}
        </h3>
        <p className="text-sm text-muted-foreground">{t("admin.access.discovery.description")}</p>
      </div>
      {notice ? (
        <p role="status" className="text-sm text-status-success">
          {notice}
        </p>
      ) : null}
      {error ? <ErrorState title={t("admin.access.discovery.failed")}>{error}</ErrorState> : null}

      {sources.loading ? <LoadingState>{t("admin.access.discovery.loading")}</LoadingState> : null}
      {sources.data && sources.data.items.length === 0 ? <UnavailableState title={t("admin.access.discovery.noSources")} /> : null}
      {sources.data && sources.data.items.length > 0 ? (
        <div className="overflow-auto" tabIndex={0} role="region" aria-label={t("admin.access.discovery.sources")}>
          <table className="ui-table">
            <caption className="sr-only">{t("admin.access.discovery.sources")}</caption>
            <thead>
              <tr>
                <th scope="col">{t("admin.access.discovery.provider")}</th>
                <th scope="col">{t("admin.access.discovery.schedule")}</th>
                <th scope="col">{t("admin.access.discovery.lastRun")}</th>
                <th scope="col">{t("admin.access.discovery.actions")}</th>
              </tr>
            </thead>
            <tbody>
              {sources.data.items.map((source) => (
                <tr key={source.provider_id}>
                  <td>
                    {source.provider_id} <span className="text-muted-foreground">({source.provider_type})</span>
                  </td>
                  <td>
                    {source.interval_seconds === 0
                      ? t("admin.access.discovery.onDemand")
                      : t("admin.access.discovery.everyHours", { hours: source.interval_seconds / 3600 })}
                  </td>
                  <td>
                    {source.last_run
                      ? source.last_run.status === "queued"
                        ? source.last_run.delivery_status === "failed"
                          ? t("admin.access.discovery.deliveryStopped")
                          : t("admin.access.discovery.scanWaiting", { id: source.last_run.id })
                        : source.last_run.status === "completed"
                          ? t("admin.access.discovery.lastRunCompleted", {
                              accounts: source.last_run.accounts,
                              added: source.last_run.added,
                              removed: source.last_run.removed,
                            })
                          : t("admin.access.discovery.lastRunFailed", { failure: source.last_run.failure ?? "error" })
                      : t("admin.access.discovery.neverRun")}
                  </td>
                  <td>
                    {canManage ? (
                      <Button
                        type="button"
                        size="sm"
                        variant="outline"
                        disabled={busy || source.last_run?.status === "queued"}
                        onClick={() => void scan(source.provider_id)}
                      >
                        {t("admin.access.discovery.scanNow", { provider: source.provider_id })}
                      </Button>
                    ) : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
      {canManage ? (
        <form
          className="flex flex-wrap items-end gap-2"
          onSubmit={(event) => {
            event.preventDefault();
            if (sourceForm.provider) void saveSource();
          }}
        >
          <label htmlFor={ids.provider} className="grid gap-1 text-sm">
            {t("admin.access.discovery.provider")}
            <Select id={ids.provider} value={sourceForm.provider} onChange={(event) => setSourceForm({ ...sourceForm, provider: event.target.value })}>
              <option value="">{t("admin.access.discovery.chooseProvider")}</option>
              {discoverable.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.id} ({p.type})
                </option>
              ))}
            </Select>
          </label>
          <label htmlFor={ids.interval} className="grid gap-1 text-sm">
            {t("admin.access.discovery.schedule")}
            <Select
              id={ids.interval}
              value={String(sourceForm.interval)}
              onChange={(event) => setSourceForm({ ...sourceForm, interval: Number(event.target.value) })}
            >
              {INTERVALS.map((seconds) => (
                <option key={seconds} value={seconds}>
                  {seconds === 0 ? t("admin.access.discovery.onDemand") : t("admin.access.discovery.everyHours", { hours: seconds / 3600 })}
                </option>
              ))}
            </Select>
          </label>
          <Button type="submit" size="sm" disabled={busy || !sourceForm.provider}>
            {t("admin.access.discovery.saveSource")}
          </Button>
        </form>
      ) : null}

      <h4 className="text-sm font-semibold">{t("admin.access.discovery.staged")}</h4>
      {staged.data && stagedItems.length === 0 ? <UnavailableState title={t("admin.access.discovery.noStaged")} /> : null}
      {stagedItems.length > 0 ? (
        <div className="overflow-auto" tabIndex={0} role="region" aria-label={t("admin.access.discovery.staged")}>
          <table className="ui-table">
            <caption className="sr-only">{t("admin.access.discovery.staged")}</caption>
            <thead>
              <tr>
                {canManage ? <th scope="col">{t("admin.access.discovery.select")}</th> : null}
                <th scope="col">{t("admin.access.discovery.account")}</th>
                <th scope="col">{t("admin.access.discovery.privileges")}</th>
                <th scope="col">{t("admin.access.discovery.provider")}</th>
                <th scope="col">{t("admin.access.discovery.actions")}</th>
              </tr>
            </thead>
            <tbody>
              {stagedItems.map((account) => (
                <tr key={account.id}>
                  {canManage ? (
                    <td>
                      <input
                        type="checkbox"
                        aria-label={t("admin.access.discovery.selectAccount", { name: account.name })}
                        checked={selected.includes(account.id)}
                        onChange={(event) =>
                          setSelected((current) => (event.target.checked ? [...current, account.id] : current.filter((id) => id !== account.id)))
                        }
                      />
                    </td>
                  ) : null}
                  <td>
                    {account.name}{" "}
                    <span className="text-muted-foreground">
                      {account.kind === "directory_service_account"
                        ? account.disabled
                          ? t("admin.access.discovery.kindDisabled", { kind: t("admin.access.discovery.serviceKind") })
                          : t("admin.access.discovery.serviceKind")
                        : account.disabled
                          ? t("admin.access.discovery.kindDisabled", { kind: account.kind })
                          : t("admin.access.discovery.kind", { kind: account.kind })}
                    </span>
                    {account.kind === "directory_service_account" ? (
                      <div className="text-xs text-muted-foreground">
                        {typeof account.details?.native_sid === "string" ? (
                          <div>
                            {t("admin.access.discovery.serviceSID")} <code>{account.details.native_sid}</code>
                          </div>
                        ) : null}
                        {typeof account.details?.native_guid === "string" ? (
                          <div>
                            {t("admin.access.discovery.serviceGUID")} <code>{account.details.native_guid}</code>
                          </div>
                        ) : null}
                      </div>
                    ) : null}
                  </td>
                  <td className="font-mono text-xs">
                    {account.privileges.length === 0 && account.kind === "directory_service_account"
                      ? t("admin.access.discovery.noInferredPrivileges")
                      : account.privileges.join(" ")}
                  </td>
                  <td>{account.provider_id}</td>
                  <td>
                    {typeof account.details?.native_sid === "string" ? (
                      <Button
                        type="button"
                        size="sm"
                        variant="outline"
                        onClick={(event) => {
                          returnFocus.current = event.currentTarget;
                          setDependentAccount(account);
                        }}
                      >
                        {t("admin.access.dependents.open")}
                      </Button>
                    ) : null}
                    {canManage ? (
                      <Button
                        type="button"
                        size="sm"
                        variant="outline"
                        onClick={(event) => {
                          returnFocus.current = event.currentTarget;
                          setDismissing(account);
                        }}
                      >
                        {t("admin.access.discovery.dismiss", { name: account.name })}
                      </Button>
                    ) : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
      {canManage && stagedItems.length > 0 ? (
        <div>
          <Button
            type="button"
            size="sm"
            disabled={selected.length === 0}
            onClick={(event) => {
              returnFocus.current = event.currentTarget;
              setImportOpen(true);
            }}
          >
            {t("admin.access.discovery.importSelected", { count: selected.length })}
          </Button>
        </div>
      ) : null}

      <h4 className="text-sm font-semibold">{t("admin.access.discovery.importedHeading")}</h4>
      {importedNative.error ? <ErrorState title={importedNative.error} /> : null}
      {imported.data && imported.data.items.length === 0 ? <UnavailableState title={t("admin.access.discovery.noImported")} /> : null}
      {imported.data && imported.data.items.length > 0 ? (
        <div className="overflow-auto" tabIndex={0} role="region" aria-label={t("admin.access.discovery.importedHeading")}>
          <table className="ui-table">
            <caption className="sr-only">{t("admin.access.discovery.importedHeading")}</caption>
            <thead>
              <tr>
                <th scope="col">{t("admin.access.discovery.folder")}</th>
                <th scope="col">{t("admin.access.discovery.account")}</th>
                <th scope="col">{t("admin.access.discovery.privileges")}</th>
                <th scope="col">{t("admin.access.discovery.importedBy")}</th>
                <th scope="col">{t("admin.access.discovery.actions")}</th>
              </tr>
            </thead>
            <tbody>
              {imported.data.items.map((account) => (
                <tr key={`${account.provider_id}/${account.key}`}>
                  <td>{account.folder}</td>
                  <td>
                    {account.name} <span className="text-muted-foreground">({account.provider_id})</span>
                  </td>
                  <td className="font-mono text-xs">{account.privileges.join(" ")}</td>
                  <td>{account.imported_by}</td>
                  <td>
                    {typeof importedNativeByID.get(account.id)?.details?.native_sid === "string" ? (
                      <Button
                        type="button"
                        size="sm"
                        variant="outline"
                        onClick={(event) => {
                          returnFocus.current = event.currentTarget;
                          setDependentAccount(importedNativeByID.get(account.id)!);
                        }}
                      >
                        {t("admin.access.dependents.open")}
                      </Button>
                    ) : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}

      {search.get("dependent_account") && (search.get("dependent_rotation") || (search.get("dependent_review") && search.get("dependent_approval"))) ? (
        <PAMDependentRotation
          key={[search.get("dependent_account"), search.get("dependent_rotation"), search.get("dependent_review"), search.get("dependent_approval")].join(":")}
          accountID={search.get("dependent_account")!}
          canManage={canManage}
          rotationID={search.get("dependent_rotation") ?? undefined}
          reviewID={search.get("dependent_review") ?? undefined}
          approvalID={search.get("dependent_approval") ?? undefined}
          onRotationID={(id) => {
            const next = new URLSearchParams(search);
            next.set("dependent_rotation", id);
            next.delete("dependent_review");
            next.delete("dependent_approval");
            setSearch(next);
          }}
        />
      ) : null}
      {dependentAccount ? (
        <PAMServiceDependentsDialog
          account={dependentAccount}
          canManage={canManage}
          onReviewID={(review, approval) => {
            const next = new URLSearchParams(search);
            next.set("dependent_account", dependentAccount.id);
            next.set("dependent_review", review);
            next.set("dependent_approval", approval);
            next.delete("dependent_rotation");
            setSearch(next);
            setDependentAccount(null);
          }}
          onRotationID={(id) => {
            const next = new URLSearchParams(search);
            next.set("dependent_rotation", id);
            next.delete("dependent_review");
            next.delete("dependent_approval");
            next.set("dependent_account", dependentAccount.id);
            setSearch(next);
            setDependentAccount(null);
          }}
          onClose={() => setDependentAccount(null)}
          returnFocusRef={returnFocus}
        />
      ) : null}
      {importOpen ? (
        <Dialog
          open
          onClose={() => setImportOpen(false)}
          titleId="pam-import-heading"
          descriptionId="pam-import-description"
          returnFocusRef={returnFocus}
          className="fixed inset-0 z-50 flex items-center justify-center p-4"
          overlayClassName="absolute inset-0 bg-black/55"
          panelClassName="relative w-full max-w-lg rounded-panel border border-border bg-card p-5 shadow-elevation2"
        >
          <h2 id="pam-import-heading" className="text-title font-semibold">
            {t("admin.access.discovery.importTitle", { count: selected.length })}
          </h2>
          <p id="pam-import-description" className="mt-1 text-sm text-muted-foreground">
            {t("admin.access.discovery.importDescription")}
          </p>
          {pending ? (
            <div className="mt-3 grid gap-2 text-sm">
              <p role="status">{t("admin.access.discovery.awaitingReview", { count: pending.review.required_approvals })}</p>
              <p className="break-all font-mono text-xs">{pending.review.approval_request_id}</p>
              <div className="flex justify-end gap-2">
                <Button type="button" variant="ghost" onClick={() => setImportOpen(false)}>
                  {t("admin.access.discovery.close")}
                </Button>
                <Button type="button" disabled={busy} onClick={() => void applyImport()}>
                  {t("admin.access.discovery.applyImport")}
                </Button>
              </div>
            </div>
          ) : (
            <form
              className="mt-3 grid gap-2"
              onSubmit={(event) => {
                event.preventDefault();
                void requestImport();
              }}
            >
              <label htmlFor={ids.folder} className="grid gap-1 text-sm">
                {t("admin.access.discovery.folder")}
                <Input
                  id={ids.folder}
                  value={importForm.folder}
                  onChange={(event) => setImportForm({ ...importForm, folder: event.target.value })}
                  pattern="[a-z0-9][a-z0-9_-]{0,63}"
                  required
                />
              </label>
              <label htmlFor={ids.template} className="grid gap-1 text-sm">
                {t("admin.access.discovery.templateID")}
                <Input id={ids.template} value={importForm.template} onChange={(event) => setImportForm({ ...importForm, template: event.target.value })} />
              </label>
              <label htmlFor={ids.reason} className="grid gap-1 text-sm">
                {t("admin.access.discovery.reason")}
                <Input id={ids.reason} value={importForm.reason} onChange={(event) => setImportForm({ ...importForm, reason: event.target.value })} required />
              </label>
              <div className="flex justify-end gap-2">
                <Button type="button" variant="ghost" onClick={() => setImportOpen(false)}>
                  {t("admin.access.discovery.close")}
                </Button>
                <Button type="submit" disabled={busy || !importForm.folder.trim() || !importForm.reason.trim()}>
                  {t("admin.access.discovery.requestReview")}
                </Button>
              </div>
            </form>
          )}
        </Dialog>
      ) : null}

      {dismissing ? (
        <Dialog
          open
          onClose={() => setDismissing(null)}
          titleId="pam-dismiss-heading"
          descriptionId="pam-dismiss-description"
          returnFocusRef={returnFocus}
          className="fixed inset-0 z-50 flex items-center justify-center p-4"
          overlayClassName="absolute inset-0 bg-black/55"
          panelClassName="relative w-full max-w-lg rounded-panel border border-border bg-card p-5 shadow-elevation2"
        >
          <h2 id="pam-dismiss-heading" className="text-title font-semibold">
            {t("admin.access.discovery.dismissTitle", { name: dismissing.name })}
          </h2>
          <p id="pam-dismiss-description" className="mt-1 text-sm text-muted-foreground">
            {t("admin.access.discovery.dismissDescription")}
          </p>
          <form
            className="mt-3 grid gap-2"
            onSubmit={(event) => {
              event.preventDefault();
              void dismiss();
            }}
          >
            <label htmlFor={ids.dismiss} className="grid gap-1 text-sm">
              {t("admin.access.discovery.reason")}
              <Input id={ids.dismiss} value={dismissReason} onChange={(event) => setDismissReason(event.target.value)} required />
            </label>
            <div className="flex justify-end gap-2">
              <Button type="button" variant="ghost" onClick={() => setDismissing(null)}>
                {t("admin.access.discovery.close")}
              </Button>
              <Button type="submit" disabled={busy || !dismissReason.trim()}>
                {t("admin.access.discovery.confirmDismiss")}
              </Button>
            </div>
          </form>
        </Dialog>
      ) : null}
    </section>
  );
}
