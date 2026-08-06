import { useEffect, useState, type FormEvent } from "react";
import { KeyRound, Loader2, RefreshCw } from "lucide-react";
import { Dialog } from "@/components/Dialog";
import { StatusBadge } from "@/components/StatusBadge";
import { Button } from "@/components/ui/button";
import { useTranslation } from "@/i18n/I18nProvider";
import { api, type SystemReadout, type TenantKeyDomainStatus, type UsageEvidence } from "@/lib/api";
import type { StatusTone } from "@/lib/statusVocab";

// The default window is the previous whole calendar month: the only period a
// provider can bill without waiting, because it is the only one that is closed.
const previousMonthEnd = new Date(Date.UTC(new Date().getUTCFullYear(), new Date().getUTCMonth(), 1));
const previousMonthStart = new Date(Date.UTC(previousMonthEnd.getUTCFullYear(), previousMonthEnd.getUTCMonth() - 1, 1));
const defaultPeriodStart = previousMonthStart.toISOString().slice(0, 10);
const defaultPeriodEnd = previousMonthEnd.toISOString().slice(0, 10);

export function IdempotencyResultProtectionPanel({
  readout,
  loading,
  requestError,
}: {
  readout: SystemReadout | null;
  loading: boolean;
  requestError: string | null;
}) {
  const { t } = useTranslation();
  const protection = readout?.idempotency_results;
  const stateLabels: Record<NonNullable<typeof protection>["state"], string> = {
    unavailable: t("platform.idempotency.stateUnavailable"),
    empty: t("platform.idempotency.stateEmpty"),
    ready_for_ratchet: t("platform.idempotency.stateReady"),
    partial: t("platform.idempotency.statePartial"),
    failed: t("platform.idempotency.stateFailed"),
    recovery_required: t("platform.idempotency.stateRecovery"),
    complete: t("platform.idempotency.stateComplete"),
  };
  const recoveryCopy: Record<NonNullable<typeof protection>["state"], string> = {
    unavailable: t("platform.idempotency.recoveryUnavailable"),
    empty: t("platform.idempotency.recoveryRatchet"),
    ready_for_ratchet: t("platform.idempotency.recoveryRatchet"),
    partial: t("platform.idempotency.recoveryPartial"),
    failed: t("platform.idempotency.recoveryFailed"),
    recovery_required: t("platform.idempotency.recoveryIndeterminate"),
    complete: t("platform.idempotency.recoveryComplete"),
  };
  const tone: StatusTone =
    protection?.state === "complete"
      ? "success"
      : protection?.state === "failed" || protection?.state === "recovery_required"
        ? "critical"
        : protection?.state === "partial"
          ? "warning"
          : protection?.state === "ready_for_ratchet"
            ? "observe"
            : "neutral";

  return (
    <section className="ui-panel p-comfortable" aria-labelledby="idempotency-result-protection-heading">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 id="idempotency-result-protection-heading" className="text-title font-semibold">
            {t("platform.idempotency.heading")}
          </h2>
          <p className="mt-1 text-sm text-muted-foreground">{t("platform.idempotency.description")}</p>
        </div>
        {protection ? <StatusBadge value={protection.state} label={stateLabels[protection.state]} tone={tone} /> : null}
      </div>

      {loading ? (
        <p className="mt-4 text-sm text-muted-foreground" role="status">
          {t("platform.idempotency.loading")}
        </p>
      ) : null}
      {requestError ? (
        <div className="mt-4 rounded-control border border-destructive/30 bg-destructive/10 p-3 text-sm" role="alert">
          <p className="font-semibold text-destructive">{t("platform.idempotency.requestFailed")}</p>
          <p className="mt-1 text-muted-foreground">{t("platform.idempotency.requestRecovery")}</p>
        </div>
      ) : null}
      {protection ? (
        <div className="mt-4 grid gap-4">
          {protection.failure ? (
            <div className="rounded-control border border-status-warning/30 bg-status-warning/10 p-3 text-sm" role="alert">
              <p className="font-semibold text-status-warning">{stateLabels[protection.state]}</p>
              <p className="mt-1 text-muted-foreground">{recoveryCopy[protection.state]}</p>
            </div>
          ) : null}
          {protection.state === "empty" ? <p className="text-sm text-muted-foreground">{t("platform.idempotency.empty")}</p> : null}
          <dl className="grid gap-3 text-sm sm:grid-cols-2 xl:grid-cols-4">
            <div>
              <dt className="font-medium text-muted-foreground">{t("platform.idempotency.rawRemaining")}</dt>
              <dd className="font-mono">{protection.raw_v0_remaining}</dd>
            </div>
            <div>
              <dt className="font-medium text-muted-foreground">{t("platform.idempotency.dynamicRemaining")}</dt>
              <dd className="font-mono">{protection.legacy_dynamic_remaining}</dd>
            </div>
            <div>
              <dt className="font-medium text-muted-foreground">{t("platform.idempotency.sealed")}</dt>
              <dd className="font-mono">{protection.sealed_results}</dd>
            </div>
            <div>
              <dt className="font-medium text-muted-foreground">{t("platform.idempotency.indeterminate")}</dt>
              <dd className="font-mono">{protection.indeterminate_results}</dd>
            </div>
            <div>
              <dt className="font-medium text-muted-foreground">{t("platform.idempotency.pending")}</dt>
              <dd className="font-mono">{protection.pending_results}</dd>
            </div>
            <div>
              <dt className="font-medium text-muted-foreground">{t("platform.idempotency.fleetReady")}</dt>
              <dd>{protection.fleet_ready ? t("platform.idempotency.yes") : t("platform.idempotency.no")}</dd>
            </div>
            <div>
              <dt className="font-medium text-muted-foreground">{t("platform.idempotency.floor")}</dt>
              <dd>{protection.sealed_only_floor ? t("platform.idempotency.installed") : t("platform.idempotency.notInstalled")}</dd>
            </div>
          </dl>
          {!protection.failure ? (
            <p className="rounded-control border border-border bg-muted/40 p-3 text-sm text-muted-foreground">
              <span className="font-semibold text-foreground">{t("platform.idempotency.recoveryHeading")}: </span>
              {recoveryCopy[protection.state]}
            </p>
          ) : null}
        </div>
      ) : null}
    </section>
  );
}

export function TenantKeyDomainPanel({ canWrite }: { canWrite: boolean }) {
  const { t } = useTranslation();
  const [status, setStatus] = useState<TenantKeyDomainStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [requestError, setRequestError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [wrapperID, setWrapperID] = useState("");
  const [sealConfirmOpen, setSealConfirmOpen] = useState(false);

  async function refreshStatus() {
    setLoading(true);
    setRequestError(null);
    try {
      const next = await api.tenantKeyDomain();
      setStatus(next);
      if (!wrapperID && next.wrapper_id) setWrapperID(next.wrapper_id);
    } catch (err) {
      setRequestError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    let active = true;
    api
      .tenantKeyDomain()
      .then((next) => {
        if (!active) return;
        setStatus(next);
        setWrapperID((current) => current || next.wrapper_id || "");
        setRequestError(null);
      })
      .catch((err) => {
        if (active) setRequestError(err instanceof Error ? err.message : String(err));
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, []);

  async function migrate(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const exactWrapperID = wrapperID.trim();
    if (!exactWrapperID) return;
    setBusy(true);
    setRequestError(null);
    setNotice(null);
    try {
      const next = await api.migrateTenantKeyDomain({ wrapper_kind: "local_file", wrapper_id: exactWrapperID });
      setStatus(next);
      setNotice(t("platform.tenantSeal.noticeMigrated"));
    } catch (err) {
      setRequestError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  async function seal() {
    setSealConfirmOpen(false);
    setBusy(true);
    setRequestError(null);
    setNotice(null);
    try {
      await api.sealTenantKeyDomain();
      setNotice(t("platform.tenantSeal.noticeQueued"));
      const next = await api.tenantKeyDomain();
      setStatus(next);
    } catch (err) {
      setRequestError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  async function unseal() {
    setBusy(true);
    setRequestError(null);
    setNotice(null);
    try {
      const next = await api.unsealTenantKeyDomain();
      setStatus(next);
      setNotice(t("platform.tenantSeal.noticeUnsealed"));
    } catch (err) {
      setRequestError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  const labels: Record<string, string> = {
    legacy: t("platform.tenantSeal.stateLegacy"),
    migrating: t("platform.tenantSeal.stateMigrating"),
    partial: t("platform.tenantSeal.statePartial"),
    unsealed: t("platform.tenantSeal.stateUnsealed"),
    seal_queued: t("platform.tenantSeal.stateSealQueued"),
    sealing: t("platform.tenantSeal.stateSealing"),
    sealed: t("platform.tenantSeal.stateSealed"),
    unsealing: t("platform.tenantSeal.stateUnsealing"),
    wrapper_unavailable: t("platform.tenantSeal.stateWrapperUnavailable"),
    wrong_wrapper: t("platform.tenantSeal.stateWrongWrapper"),
    corrupt: t("platform.tenantSeal.stateCorrupt"),
    unavailable: t("platform.tenantSeal.stateUnavailable"),
  };
  const label = status ? (labels[status.state] ?? status.state) : "";
  const failed = status?.operation_status === "failed" || Boolean(status?.failure);
  const tone: StatusTone =
    failed || status?.state === "corrupt" || status?.state === "wrong_wrapper" || status?.state === "wrapper_unavailable"
      ? "critical"
      : status?.state === "unsealed"
        ? "success"
        : status?.state === "partial" || status?.state === "seal_queued" || status?.state === "migrating"
          ? "warning"
          : status?.state === "sealed"
            ? "observe"
            : "neutral";
  const canMigrate = status?.state === "legacy" || (status?.operation_kind === "migrate" && status.operation_status !== "completed");
  const canSeal =
    status?.state === "unsealed" ||
    (status?.state === "partial" && (status.operation_status === "completed" || (status.operation_kind === "seal" && status.operation_status === "failed")));
  const canUnseal = status?.state === "sealed";

  return (
    <section className="ui-panel p-comfortable" aria-labelledby="tenant-key-domain-heading">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 id="tenant-key-domain-heading" className="text-title font-semibold">
            {t("platform.tenantSeal.heading")}
          </h2>
          <p className="mt-1 text-sm text-muted-foreground">{t("platform.tenantSeal.description")}</p>
        </div>
        {status ? <StatusBadge value={status.state} label={label} tone={tone} /> : null}
      </div>

      {loading ? (
        <p className="mt-4 flex items-center gap-2 text-sm text-muted-foreground" role="status">
          <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
          {t("platform.tenantSeal.loading")}
        </p>
      ) : null}
      {requestError ? (
        <div className="mt-4 rounded-control border border-destructive/30 bg-destructive/10 p-3 text-sm" role="alert">
          <p className="font-semibold text-destructive">{t("platform.tenantSeal.requestFailed")}</p>
          <p className="mt-1 break-words text-muted-foreground">{requestError}</p>
          <Button type="button" variant="outline" className="mt-3" onClick={() => void refreshStatus()} disabled={loading || busy}>
            <RefreshCw className="h-4 w-4" aria-hidden="true" />
            {t("platform.tenantSeal.refresh")}
          </Button>
        </div>
      ) : null}
      {notice ? (
        <p className="mt-4 rounded-control border border-status-success/30 bg-status-success/10 p-3 text-sm text-status-success" role="status">
          {notice}
        </p>
      ) : null}

      {status ? (
        <div className="mt-4 grid gap-4">
          {status.failure ? (
            <div className="rounded-control border border-destructive/30 bg-destructive/10 p-3 text-sm" role="alert">
              <p className="font-semibold text-destructive">{status.failure}</p>
              <p className="mt-1 text-muted-foreground">{status.recovery}</p>
            </div>
          ) : null}
          <dl className="grid gap-3 text-sm sm:grid-cols-2 xl:grid-cols-4">
            <div>
              <dt className="font-medium text-muted-foreground">{t("platform.tenantSeal.protectionMode")}</dt>
              <dd className="font-mono text-xs">{status.protection_mode}</dd>
            </div>
            <div>
              <dt className="font-medium text-muted-foreground">{t("platform.tenantSeal.wrapper")}</dt>
              <dd className="font-mono text-xs">{status.wrapper_id || t("platform.tenantSeal.notConfigured")}</dd>
            </div>
            <div>
              <dt className="font-medium text-muted-foreground">{t("platform.tenantSeal.progress")}</dt>
              <dd>
                {status.progress_total > 0
                  ? t("platform.tenantSeal.progressValue", {
                      completed: status.progress_completed,
                      total: status.progress_total,
                    })
                  : t("platform.tenantSeal.notStarted")}
              </dd>
            </div>
            <div>
              <dt className="font-medium text-muted-foreground">{t("platform.tenantSeal.legacyExposure")}</dt>
              <dd className="font-mono text-xs">{status.legacy_history_exposure}</dd>
            </div>
            <div>
              <dt className="font-medium text-muted-foreground">{t("platform.tenantSeal.zeroEgress")}</dt>
              <dd>{status.local_wrapper_zero_egress ? t("platform.tenantSeal.yes") : t("platform.tenantSeal.no")}</dd>
            </div>
            <div className="sm:col-span-2 xl:col-span-3">
              <dt className="font-medium text-muted-foreground">{t("platform.tenantSeal.lastTransition")}</dt>
              <dd className="break-all font-mono text-xs">{status.last_transition_type || t("platform.tenantSeal.none")}</dd>
            </div>
          </dl>
          <div className="rounded-control border border-border bg-muted/40 p-3 text-sm text-muted-foreground">
            <span className="font-semibold text-foreground">{t("platform.tenantSeal.recovery")}: </span>
            {status.recovery}
          </div>
          {status.last_transition_evidence_refs.length > 0 ? (
            <div>
              <h3 className="text-sm font-semibold">{t("platform.tenantSeal.evidence")}</h3>
              <ul className="mt-2 grid gap-1 text-xs text-muted-foreground">
                {status.last_transition_evidence_refs.map((ref) => (
                  <li key={ref} className="break-all font-mono">
                    {ref}
                  </li>
                ))}
              </ul>
            </div>
          ) : null}

          {canWrite && canMigrate ? (
            <form className="grid gap-3 rounded-control border border-border p-3 sm:grid-cols-[minmax(0,1fr)_auto] sm:items-end" onSubmit={migrate}>
              <label className="grid gap-1 text-sm" htmlFor="tenant-key-domain-wrapper-id">
                <span className="font-medium">{t("platform.tenantSeal.wrapperID")}</span>
                <input
                  id="tenant-key-domain-wrapper-id"
                  className="min-h-10 rounded-control border border-border bg-background px-3 py-2"
                  value={wrapperID}
                  onChange={(event) => setWrapperID(event.target.value)}
                  required
                  autoComplete="off"
                  aria-describedby="tenant-key-domain-wrapper-help"
                />
                <span id="tenant-key-domain-wrapper-help" className="text-xs text-muted-foreground">
                  {t("platform.tenantSeal.wrapperHelp")}
                </span>
              </label>
              <Button type="submit" disabled={busy || !wrapperID.trim()}>
                {busy ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <KeyRound className="h-4 w-4" aria-hidden="true" />}
                {t("platform.tenantSeal.migrate")}
              </Button>
            </form>
          ) : null}

          <div className="flex flex-wrap gap-2">
            {canWrite && canSeal ? (
              <Button type="button" variant="destructive" onClick={() => setSealConfirmOpen(true)} disabled={busy}>
                <KeyRound className="h-4 w-4" aria-hidden="true" />
                {status.operation_kind === "seal" && status.operation_status === "failed" ? t("platform.tenantSeal.retrySeal") : t("platform.tenantSeal.seal")}
              </Button>
            ) : null}
            {canWrite && canUnseal ? (
              <Button type="button" onClick={() => void unseal()} disabled={busy}>
                {busy ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <KeyRound className="h-4 w-4" aria-hidden="true" />}
                {t("platform.tenantSeal.unseal")}
              </Button>
            ) : null}
            <Button type="button" variant="outline" onClick={() => void refreshStatus()} disabled={loading || busy}>
              <RefreshCw className="h-4 w-4" aria-hidden="true" />
              {t("platform.tenantSeal.refresh")}
            </Button>
          </div>
          {!canWrite ? <p className="text-sm text-muted-foreground">{t("platform.tenantSeal.readOnly")}</p> : null}
        </div>
      ) : null}

      <Dialog
        open={sealConfirmOpen}
        onClose={() => setSealConfirmOpen(false)}
        titleId="tenant-key-domain-seal-confirm-title"
        descriptionId="tenant-key-domain-seal-confirm-description"
        role="alertdialog"
        panelClassName="fixed left-1/2 top-1/2 w-[min(32rem,calc(100%-2rem))] -translate-x-1/2 -translate-y-1/2 rounded-panel border border-border bg-background p-5 shadow-2xl"
      >
        <h2 id="tenant-key-domain-seal-confirm-title" className="text-title font-semibold">
          {t("platform.tenantSeal.confirmHeading")}
        </h2>
        <p id="tenant-key-domain-seal-confirm-description" className="mt-2 text-sm text-muted-foreground">
          {t("platform.tenantSeal.confirmDescription")}
        </p>
        <div className="mt-5 flex justify-end gap-2">
          <Button type="button" variant="outline" onClick={() => setSealConfirmOpen(false)}>
            {t("platform.tenantSeal.cancel")}
          </Button>
          <Button type="button" variant="destructive" onClick={() => void seal()}>
            {t("platform.tenantSeal.confirm")}
          </Button>
        </div>
      </Dialog>
    </section>
  );
}

// L2: usage as invoice evidence.
//
// The panel leads with WHETHER THE PERIOD MAY BE BILLED, not with the totals.
// A number a finance team reads as an invoice, drawn from metering that could
// not cover the period, is worse than no panel at all: it turns a gap somebody
// might have questioned into a figure they will act on. So `signable` and its
// reason render above the table, and the table is visibly a partial view when
// the answer is no.
export function UsageEvidencePanel() {
  const { t } = useTranslation();
  const [doc, setDoc] = useState<UsageEvidence | null>(null);
  const [loading, setLoading] = useState(false);
  const [requestError, setRequestError] = useState<string | null>(null);
  const [periodStart, setPeriodStart] = useState(defaultPeriodStart);
  const [periodEnd, setPeriodEnd] = useState(defaultPeriodEnd);

  async function pull(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setLoading(true);
    setRequestError(null);
    try {
      setDoc(await api.usageEvidence(`${periodStart}T00:00:00Z`, `${periodEnd}T00:00:00Z`));
    } catch (err) {
      setDoc(null);
      setRequestError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }

  return (
    <section className="ui-panel p-comfortable" aria-labelledby="usage-evidence-heading">
      <h2 id="usage-evidence-heading" className="text-title font-semibold">
        {t("platform.usageEvidence.heading")}
      </h2>
      <p className="mt-1 max-w-3xl text-caption text-muted-foreground">{t("platform.usageEvidence.description")}</p>

      <form className="mt-4 flex flex-wrap items-end gap-3" onSubmit={pull}>
        <label className="flex flex-col gap-1 text-caption">
          {t("platform.usageEvidence.periodStart")}
          <input
            type="date"
            value={periodStart}
            onChange={(e) => setPeriodStart(e.target.value)}
            className="rounded-control border border-border bg-background px-2 py-1"
          />
        </label>
        <label className="flex flex-col gap-1 text-caption">
          {t("platform.usageEvidence.periodEnd")}
          <input
            type="date"
            value={periodEnd}
            onChange={(e) => setPeriodEnd(e.target.value)}
            className="rounded-control border border-border bg-background px-2 py-1"
          />
        </label>
        <Button type="submit" disabled={loading}>
          {loading ? <Loader2 className="size-4 animate-spin" aria-hidden /> : null}
          {t("platform.usageEvidence.pull")}
        </Button>
      </form>

      {loading && <p className="mt-3 text-caption text-muted-foreground">{t("platform.usageEvidence.loading")}</p>}
      {requestError && (
        <p role="alert" className="mt-3 rounded-control border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm text-destructive">
          {requestError}
        </p>
      )}

      {doc && (
        <div className="mt-4 grid gap-3">
          {/* The verdict comes first and carries its reason. Rendering the
              totals above this would let a reader stop before reaching it. */}
          <div className="flex flex-wrap items-center gap-2">
            <StatusBadge
              value={doc.signable ? "billable" : "not-billable"}
              label={doc.signable ? t("platform.usageEvidence.billable") : t("platform.usageEvidence.notBillable")}
              tone={(doc.signable ? "success" : "warning") as StatusTone}
            />
            <span className="text-caption text-muted-foreground">{doc.reason}</span>
          </div>
          {doc.observed_from && doc.observed_to && (
            <p className="text-caption text-muted-foreground">
              {t("platform.usageEvidence.coverage")}: {doc.observed_from} → {doc.observed_to}
            </p>
          )}
          {doc.lines && doc.lines.length > 0 ? (
            <table className="w-full text-caption">
              <thead>
                <tr className="text-left text-muted-foreground">
                  <th className="py-1">{t("platform.usageEvidence.meter")}</th>
                  <th className="py-1">{t("platform.usageEvidence.kind")}</th>
                  <th className="py-1 text-right">{t("platform.usageEvidence.value")}</th>
                </tr>
              </thead>
              <tbody>
                {doc.lines.map((line) => (
                  <tr key={`${line.meter}:${line.kind}`} className="border-t border-border">
                    <td className="py-1">{line.meter}</td>
                    <td className="py-1">{line.kind}</td>
                    <td className="py-1 text-right tabular-nums">{line.value}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <p className="text-caption text-muted-foreground">{t("platform.usageEvidence.noLines")}</p>
          )}
          <p className="text-caption text-muted-foreground">
            {t("platform.usageEvidence.digest")}: <code className="font-mono">{doc.digest}</code>
          </p>
        </div>
      )}
    </section>
  );
}
