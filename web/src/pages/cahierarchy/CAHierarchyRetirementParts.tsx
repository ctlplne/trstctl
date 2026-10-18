import { useEffect, useState } from "react";
import { zodResolver } from "@hookform/resolvers/zod";
import { useForm } from "react-hook-form";
import { z } from "zod";
import { Button } from "@/components/ui/button";
import { translateNow } from "@/i18n/I18nProvider";
import { api, ApiError, type CAAuthority, type RetirementChecklist } from "@/lib/api";

const retrySchema = z.object({
  reason: z.string().trim().min(8, translateNow("source.retirement.retry.reason.required.h4ret00020")).max(1024),
  confirmed: z.boolean().refine(Boolean, translateNow("source.retirement.retry.confirm.required.h4ret00021")),
});
type RetryFields = z.infer<typeof retrySchema>;

function RetryDeliveryForm({ checklist, onRecovered }: { checklist: RetirementChecklist; onRecovered: () => Promise<unknown> }) {
  const [submitError, setSubmitError] = useState<string | null>(null);
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors, isSubmitting },
  } = useForm<RetryFields>({
    resolver: zodResolver(retrySchema),
    defaultValues: { reason: "", confirmed: false },
  });
  const attempts = checklist.delivery_attempts ?? 0;
  const commandID = checklist.command_event_id ?? "";

  async function submit(values: RetryFields) {
    setSubmitError(null);
    try {
      await api.retryCAKeyRetirement(checklist.key_id, {
        command_event_id: commandID,
        expected_attempts: attempts,
        reason: values.reason,
        confirm_irreversible: true,
      });
      reset();
      await onRecovered();
    } catch (err) {
      setSubmitError(errorText(err, translateNow("source.retirement.retry.failed.h4ret00022")));
    }
  }

  return (
    <form className="grid gap-3 rounded-md border border-destructive/40 p-3" onSubmit={handleSubmit(submit)}>
      <h4 className="text-sm font-semibold">{translateNow("source.retirement.retry.heading.h4ret00017")}</h4>
      <p className="text-sm">{translateNow("source.retirement.retry.explanation.h4ret00018")}</p>
      <label className="grid gap-1 text-sm" htmlFor={`retirement-retry-reason-${checklist.key_id}`}>
        {translateNow("source.retirement.retry.reason.h4ret00019")}
        <textarea className="ui-input" id={`retirement-retry-reason-${checklist.key_id}`} maxLength={1024} {...register("reason")} />
      </label>
      {errors.reason && (
        <span className="text-sm text-destructive" role="alert">
          {errors.reason.message}
        </span>
      )}
      <label className="flex items-start gap-2 text-sm">
        <input type="checkbox" {...register("confirmed")} />
        <span>{translateNow("source.retirement.retry.confirm.h4ret00023")}</span>
      </label>
      {errors.confirmed && (
        <span className="text-sm text-destructive" role="alert">
          {errors.confirmed.message}
        </span>
      )}
      <Button type="submit" variant="destructive" disabled={isSubmitting || !commandID || attempts < 1}>
        {translateNow("source.retirement.retry.action.h4ret00024")}
      </Button>
      {submitError && (
        <p className="text-sm text-destructive" role="alert">
          {submitError}
        </p>
      )}
    </form>
  );
}

// RetirementChecklistPanel explains why a CA key cannot be destroyed yet (H4).
//
// It explains the gate; it is not the gate. The refusal is enforced in the
// isolated signer, and the served guidance says so — an operator who believes
// this panel is the control will route around it, have the key destroyed by
// hand, and the evidence chain the whole feature exists to produce never gets
// written.
//
// An unlicensed deployment returns 501 rather than an empty list, so a failure
// to load renders NOTHING rather than a reassuring zero: "no outstanding
// dependents" is permission to destroy, and it must never appear because a
// request failed.
function RetirementChecklistPanel({ keyId }: { keyId: string }) {
  const [checklist, setChecklist] = useState<RetirementChecklist | null>(null);
  const [loadError, setLoadError] = useState(false);
  const [requestError, setRequestError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [finalEpoch, setFinalEpoch] = useState("1");
  const [confirmed, setConfirmed] = useState(false);

  async function refresh() {
    try {
      const next = await api.caRetirementChecklist(keyId);
      setChecklist(next);
      setLoadError(false);
      return next;
    } catch {
      setChecklist(null);
      setLoadError(true);
      return null;
    }
  }

  useEffect(() => {
    let active = true;
    setChecklist(null);
    setLoadError(false);
    if (!keyId || typeof api.caRetirementChecklist !== "function") return;
    api
      .caRetirementChecklist(keyId)
      .then((res) => {
        if (active) {
          setChecklist(res);
          setLoadError(false);
        }
      })
      .catch(() => {
        if (active) {
          setChecklist(null);
          setLoadError(true);
        }
      });
    return () => {
      active = false;
    };
  }, [keyId]);

  async function requestRetirement() {
    const epoch = Number(finalEpoch);
    if (!confirmed || !Number.isSafeInteger(epoch) || epoch <= 0) return;
    setBusy(true);
    setRequestError(null);
    try {
      await api.retireCAKey(keyId, { final_epoch: epoch, confirm_irreversible: true });
      await refresh();
      setConfirmed(false);
    } catch (err) {
      setRequestError(errorText(err, translateNow("source.retirement.request.failed.h4ret00015")));
    } finally {
      setBusy(false);
    }
  }

  if (loadError) {
    return (
      <section aria-labelledby="retirement-heading" className="ui-panel space-y-3 p-comfortable">
        <h3 id="retirement-heading" className="text-title font-semibold">
          {translateNow("source.retirement.checklist.h4ret00001")}
        </h3>
        <p className="text-sm text-destructive" role="alert">
          {translateNow("source.retirement.unavailable.h4ret00014")}
        </p>
        <Button type="button" variant="outline" onClick={() => void refresh()}>
          {translateNow("source.retirement.refresh.h4ret00007")}
        </Button>
      </section>
    );
  }
  if (!checklist) return null;
  const epoch = Number(finalEpoch);
  const destroyed = checklist.retirement_status === "destroyed";
  const recordHref = checklist.destruction_record ? `data:application/json;charset=utf-8,${encodeURIComponent(checklist.destruction_record)}` : "";
  return (
    <section aria-labelledby="retirement-heading" className="ui-panel space-y-3 p-comfortable">
      <h3 id="retirement-heading" className="text-title font-semibold">
        {translateNow("source.retirement.checklist.h4ret00001")}
      </h3>
      <p className="text-sm">
        {checklist.blocked
          ? translateNow("source.retirement.blocked.h4ret00002", { value1: String(checklist.outstanding?.length ?? 0) })
          : translateNow("source.retirement.clear.h4ret00003")}
      </p>
      {(checklist.outstanding?.length ?? 0) > 0 && (
        <ul className="space-y-1 text-sm">
          {(checklist.outstanding ?? []).map((dep) => (
            <li key={`${dep.kind}:${dep.ref}`} className="flex justify-between gap-3">
              <span className="font-mono text-xs">{dep.ref}</span>
              <span className="text-muted-foreground">{dep.kind}</span>
            </li>
          ))}
        </ul>
      )}
      <dl className="grid gap-1 text-sm sm:grid-cols-2">
        <dt className="text-muted-foreground">{translateNow("source.retirement.status.h4ret00004")}</dt>
        <dd className="font-mono">{checklist.retirement_status || translateNow("source.retirement.not.requested.h4ret00005")}</dd>
        {checklist.command_event_id && (
          <>
            <dt className="text-muted-foreground">{translateNow("source.retirement.command.h4ret00025")}</dt>
            <dd className="break-all font-mono text-xs">{checklist.command_event_id}</dd>
          </>
        )}
        {checklist.delivery_status && (
          <>
            <dt className="text-muted-foreground">{translateNow("source.retirement.delivery.h4ret00026")}</dt>
            <dd className="font-mono">
              {checklist.delivery_status} ({checklist.delivery_attempts ?? 0})
            </dd>
          </>
        )}
      </dl>
      {checklist.retirement_status === "pending" && checklist.delivery_status === "failed" && <RetryDeliveryForm checklist={checklist} onRecovered={refresh} />}
      {checklist.refusal_record && (
        <details className="text-sm">
          <summary>{translateNow("source.retirement.signed.refusal.h4ret00013")}</summary>
          <pre className="mt-2 max-h-48 overflow-auto whitespace-pre-wrap break-all text-xs">{checklist.refusal_record}</pre>
        </details>
      )}
      {checklist.destruction_record && (
        <div className="space-y-2">
          <a className="text-sm font-medium text-brand-accent underline" download={`trstctl-ca-key-${keyId}-destruction-record.json`} href={recordHref}>
            {translateNow("source.retirement.download.record.h4ret00012")}
          </a>
          <details className="text-sm">
            <summary>{translateNow("source.retirement.record.preview.h4ret00016")}</summary>
            <pre className="mt-2 max-h-48 overflow-auto whitespace-pre-wrap break-all text-xs">{checklist.destruction_record}</pre>
          </details>
        </div>
      )}
      {!destroyed && checklist.retirement_status !== "pending" && (
        <div className="grid gap-3 rounded-md border border-destructive/40 p-3">
          <label className="grid gap-1 text-sm" htmlFor={`retirement-final-epoch-${keyId}`}>
            {translateNow("source.retirement.final.epoch.h4ret00006")}
            <input
              className="ui-input"
              id={`retirement-final-epoch-${keyId}`}
              min={1}
              onChange={(event) => setFinalEpoch(event.target.value)}
              type="number"
              value={finalEpoch}
            />
          </label>
          <label className="flex items-start gap-2 text-sm">
            <input checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} type="checkbox" />
            <span>{translateNow("source.retirement.confirm.h4ret00008")}</span>
          </label>
          <div className="flex flex-wrap gap-2">
            <Button
              type="button"
              variant="destructive"
              disabled={busy || !confirmed || !Number.isSafeInteger(epoch) || epoch <= 0}
              onClick={() => void requestRetirement()}
            >
              {translateNow("source.retirement.irreversible.action.h4ret00009")}
            </Button>
            <Button type="button" variant="outline" disabled={busy} onClick={() => void refresh()}>
              {translateNow("source.retirement.refresh.h4ret00007")}
            </Button>
          </div>
          {requestError && (
            <p className="text-sm text-destructive" role="alert">
              {requestError}
            </p>
          )}
        </div>
      )}
      <p className="text-caption text-muted-foreground">{checklist.guidance}</p>
    </section>
  );
}

export function RetirementWorkspace({ candidates }: { candidates: CAAuthority[] }) {
  const [keyId, setKeyId] = useState(candidates[0]?.id ?? "");

  useEffect(() => {
    if (!candidates.some((candidate) => candidate.id === keyId)) {
      setKeyId(candidates[0]?.id ?? "");
    }
  }, [candidates, keyId]);

  if (candidates.length === 0 || !keyId) return null;
  return (
    <div className="space-y-3">
      <label className="grid gap-1 text-sm" htmlFor="retirement-key-selector">
        {translateNow("source.retirement.checklist.h4ret00001")}
        <select className="ui-input" id="retirement-key-selector" onChange={(event) => setKeyId(event.target.value)} value={keyId}>
          {candidates.map((candidate) => (
            <option key={candidate.id} value={candidate.id}>
              {candidate.common_name} ({candidate.status})
            </option>
          ))}
        </select>
      </label>
      <RetirementChecklistPanel key={keyId} keyId={keyId} />
    </div>
  );
}

function errorText(err: unknown, fallback: string): string {
  if (err instanceof ApiError) {
    try {
      const problem = JSON.parse(err.body) as { detail?: string; title?: string };
      return problem.detail || problem.title || fallback;
    } catch {
      return err.body || fallback;
    }
  }
  return err instanceof Error ? err.message : fallback;
}
