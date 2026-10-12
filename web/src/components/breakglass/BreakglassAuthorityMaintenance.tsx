import { useEffect, useState } from "react";
import { zodResolver } from "@hookform/resolvers/zod";
import { useForm, useWatch } from "react-hook-form";
import { z } from "zod";

import { CapabilityActionNotice } from "@/components/CapabilityTruth";
import { DataGrid, type DataGridColumn } from "@/components/DataGrid";
import { ErrorState } from "@/components/StatePrimitives";
import { Button } from "@/components/ui/button";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { useTranslation } from "@/i18n/I18nProvider";
import { api, type BreakglassAuthorityReceipt, type BreakglassAuthorityReceiptList, type BreakglassCeremony } from "@/lib/api";
import { apiProblemMessage } from "@/lib/apiProblem";
import { useCapabilityExecution } from "@/lib/capabilities";
import { invalidateAppQueryKeys, useApiQuery } from "@/lib/query";

type AuthorityKind = "rotation" | "cross_sign";
type AuthorityFields = { reason: string; ttl_seconds: number; certificate_pem: string };
type AuthorityRequest = { kind: "rotation"; reason: string; ttl_seconds: number } | { kind: "cross_sign"; certificate_pem: string };

function requestFromFields(kind: AuthorityKind, values: AuthorityFields): AuthorityRequest {
  if (kind === "rotation") return { kind, reason: values.reason.trim(), ttl_seconds: values.ttl_seconds };
  return { kind, certificate_pem: values.certificate_pem.trim() };
}

/** The ceremony binds the exact public request; changing a field invalidates local execution. */
function AuthorityProcedure({ kind, onCompleted }: { kind: AuthorityKind; onCompleted: (id: string) => void }) {
  const { t } = useTranslation();
  const openAction = useCapabilityExecution("F34", kind === "rotation" ? "startBreakglassRotationCeremony" : "startBreakglassCrossSignCeremony");
  const executeAction = useCapabilityExecution("F34", kind === "rotation" ? "rotateBreakglass" : "crossSignBreakglass");
  const [request, setRequest] = useState<AuthorityRequest | null>(null);
  const [ceremony, setCeremony] = useState<BreakglassCeremony | null>(null);
  const [resumeID, setResumeID] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);
  const authoritySchema = z
    .object({
      reason: z.string(),
      ttl_seconds: z.number(),
      certificate_pem: z.string(),
    })
    .superRefine((values, ctx) => {
      if (kind === "rotation") {
        if (!values.reason.trim()) ctx.addIssue({ code: "custom", path: ["reason"], message: t("breakglass.authority.reasonRequired") });
        if (!Number.isInteger(values.ttl_seconds) || values.ttl_seconds < 1 || values.ttl_seconds > 86400) {
          ctx.addIssue({ code: "custom", path: ["ttl_seconds"], message: t("breakglass.authority.ttlInvalid") });
        }
      } else if (!/^-----BEGIN CERTIFICATE-----[\s\S]+-----END CERTIFICATE-----$/.test(values.certificate_pem.trim())) {
        ctx.addIssue({ code: "custom", path: ["certificate_pem"], message: t("breakglass.authority.certificateInvalid") });
      }
    });
  const {
    register,
    control,
    getValues,
    trigger,
    formState: { errors },
  } = useForm<AuthorityFields>({ resolver: zodResolver(authoritySchema), defaultValues: { reason: "", ttl_seconds: 3600, certificate_pem: "" } });
  const watched = useWatch({ control });
  const currentRequest = requestFromFields(kind, {
    reason: watched.reason ?? "",
    ttl_seconds: watched.ttl_seconds ?? 0,
    certificate_pem: watched.certificate_pem ?? "",
  });
  const unchanged = request !== null && JSON.stringify(request) === JSON.stringify(currentRequest);
  const approved = Boolean(
    ceremony &&
    !["cancelled", "expired", "completed", "consumed"].includes(ceremony.status) &&
    (ceremony.status === "approved" || ceremony.approvals >= ceremony.threshold),
  );

  async function openCeremony() {
    if (!(await trigger()) || !openAction.runnable) return;
    const next = requestFromFields(kind, getValues());
    setBusy(true);
    setError(null);
    setDone(false);
    try {
      const started =
        next.kind === "rotation"
          ? await api.startBreakglassRotationCeremony({ reason: next.reason, ttl_seconds: next.ttl_seconds })
          : await api.startBreakglassCrossSignCeremony({ certificate_pem: next.certificate_pem });
      setRequest(next);
      setCeremony(started);
    } catch (caught) {
      setError(apiProblemMessage(caught, t("breakglass.authority.openFailed")));
    } finally {
      setBusy(false);
    }
  }

  async function refreshCeremony() {
    if (!ceremony) return;
    setBusy(true);
    setError(null);
    try {
      setCeremony(await api.caCeremony(ceremony.id));
    } catch (caught) {
      setError(apiProblemMessage(caught, t("breakglass.ceremony.refreshFailed")));
    } finally {
      setBusy(false);
    }
  }

  async function resumeCeremony() {
    if (!(await trigger()) || !/^[0-9a-fA-F-]{36}$/.test(resumeID.trim())) {
      setError(t("breakglass.authority.resumeInvalid"));
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const loaded = await api.caCeremony(resumeID.trim());
      setRequest(requestFromFields(kind, getValues()));
      setCeremony(loaded);
      setDone(false);
    } catch (caught) {
      setError(apiProblemMessage(caught, t("breakglass.authority.resumeFailed")));
    } finally {
      setBusy(false);
    }
  }

  async function execute() {
    if (!ceremony || !request || !unchanged || !approved || !executeAction.runnable) return;
    setBusy(true);
    setError(null);
    try {
      if (request.kind === "rotation") {
        await api.rotateBreakglass({ ceremony_id: ceremony.id, reason: request.reason, ttl_seconds: request.ttl_seconds });
      } else {
        await api.crossSignBreakglass({ ceremony_id: ceremony.id, certificate_pem: request.certificate_pem });
      }
      invalidateAppQueryKeys([["breakglass-authority-receipts"]]);
      onCompleted(ceremony.id);
      setDone(true);
    } catch (caught) {
      setError(apiProblemMessage(caught, t("breakglass.authority.executeFailed")));
    } finally {
      setBusy(false);
    }
  }

  return (
    <details className="rounded-panel border border-border bg-card">
      <summary className="cursor-pointer px-4 py-3 font-medium">
        {t(kind === "rotation" ? "breakglass.authority.rotateTitle" : "breakglass.authority.crossTitle")}
      </summary>
      <div className="grid gap-4 border-t border-border p-4">
        <p className="text-sm text-muted-foreground">{t(kind === "rotation" ? "breakglass.authority.rotateHelp" : "breakglass.authority.crossHelp")}</p>
        <CapabilityActionNotice action={openAction} />
        <CapabilityActionNotice action={executeAction} />
        {kind === "rotation" ? (
          <div className="grid gap-3 md:grid-cols-2">
            <Field label={t("breakglass.authority.rotationReason")} error={errors.reason?.message} required>
              {(field) => <Input {...field} {...register("reason")} />}
            </Field>
            <Field label={t("breakglass.authority.rotationTTL")} error={errors.ttl_seconds?.message} required>
              {(field) => <Input {...field} type="number" min="1" max="86400" {...register("ttl_seconds", { valueAsNumber: true })} />}
            </Field>
          </div>
        ) : (
          <Field label={t("breakglass.authority.targetCertificate")} error={errors.certificate_pem?.message} required>
            {(field) => <Textarea {...field} className="min-h-36 font-mono text-xs" {...register("certificate_pem")} />}
          </Field>
        )}
        <div>
          <Button type="button" disabled={busy || !openAction.runnable} onClick={() => void openCeremony()}>
            {t(kind === "rotation" ? "breakglass.authority.openRotation" : "breakglass.authority.openCross")}
          </Button>
        </div>
        <div className="grid gap-2 border-t border-border pt-3">
          <p className="text-sm text-muted-foreground">{t("breakglass.authority.resumeHelp")}</p>
          <Field label={t("breakglass.authority.resumeID")}>
            {(field) => <Input {...field} value={resumeID} onChange={(event) => setResumeID(event.target.value)} />}
          </Field>
          <div>
            <Button type="button" variant="outline" disabled={busy || !resumeID.trim()} onClick={() => void resumeCeremony()}>
              {t("breakglass.authority.resume")}
            </Button>
          </div>
        </div>
        {ceremony ? (
          <div className="grid gap-3 rounded-control border border-border p-3 text-sm">
            <p className="font-medium">{t("breakglass.ceremony.progress", { approvals: ceremony.approvals, threshold: ceremony.threshold })}</p>
            <p className="break-all font-mono text-xs">{t("breakglass.history.ceremony", { id: ceremony.id })}</p>
            <p className="break-all font-mono text-xs">{t("breakglass.authority.purpose", { purpose: ceremony.purpose })}</p>
            <p className="text-muted-foreground">{t("breakglass.ceremony.help")}</p>
            {!unchanged ? <ErrorState title={t("breakglass.authority.changed")}>{t("breakglass.authority.changedHelp")}</ErrorState> : null}
            <div className="flex flex-wrap gap-2">
              <Button type="button" variant="outline" disabled={busy} onClick={() => void refreshCeremony()}>
                {t("breakglass.ceremony.refresh")}
              </Button>
              <Button type="button" disabled={busy || done || !unchanged || !approved || !executeAction.runnable} onClick={() => void execute()}>
                {t(kind === "rotation" ? "breakglass.authority.executeRotation" : "breakglass.authority.executeCross")}
              </Button>
            </div>
          </div>
        ) : null}
        {done ? <p role="status">{t("breakglass.authority.recorded")}</p> : null}
        {error ? <ErrorState title={t("breakglass.authority.failed")}>{error}</ErrorState> : null}
      </div>
    </details>
  );
}

function downloadPublicResult(receipt: BreakglassAuthorityReceipt) {
  const result = receipt.rotation ?? receipt.cross_sign;
  if (!result) return;
  const url = URL.createObjectURL(new Blob([JSON.stringify(result, null, 2)], { type: "application/json" }));
  const link = document.createElement("a");
  link.href = url;
  link.download = `breakglass-authority-${receipt.ceremony_id}.json`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 0);
}

function AuthorityHistory({ latestCeremonyID }: { latestCeremonyID: string | null }) {
  const { t, formatDateTime } = useTranslation();
  const [cursor, setCursor] = useState("");
  const [previous, setPrevious] = useState<string[]>([]);
  const [selected, setSelected] = useState("");
  const page = useApiQuery<BreakglassAuthorityReceiptList>(["breakglass-authority-receipts", cursor], () =>
    api.breakglassAuthorityReceipts({ limit: 20, cursor }),
  );
  const detail = useApiQuery<BreakglassAuthorityReceipt>(["breakglass-authority-receipt", selected], () => api.getBreakglassAuthorityReceipt(selected), {
    enabled: selected !== "",
  });

  useEffect(() => {
    if (!latestCeremonyID) return;
    setCursor("");
    setPrevious([]);
    setSelected(latestCeremonyID);
  }, [latestCeremonyID]);

  const columns: Array<DataGridColumn<BreakglassAuthorityReceipt>> = [
    {
      id: "kind",
      header: t("breakglass.authority.kind"),
      cell: (row) => t(row.kind === "rotation" ? "breakglass.authority.rotateTitle" : "breakglass.authority.crossTitle"),
    },
    { id: "subject", header: t("breakglass.authority.subject"), cell: (row) => <span className="break-all font-mono text-xs">{row.subject}</span> },
    { id: "completed", header: t("breakglass.authority.completed"), cell: (row) => formatDateTime(row.completed_at) },
  ];

  return (
    <details open className="rounded-panel border border-border bg-card">
      <summary className="cursor-pointer px-4 py-3 font-medium">{t("breakglass.authority.history")}</summary>
      <div className="grid gap-3 border-t border-border p-4">
        <p className="text-sm text-muted-foreground">{t("breakglass.authority.historyHelp")}</p>
        <DataGrid
          ariaLabel={t("breakglass.authority.history")}
          rows={page.data?.items ?? []}
          columns={columns}
          getRowId={(row) => row.ceremony_id}
          state={page.error ? "error" : page.loading ? "loading" : page.data?.items.length ? "ready" : "empty"}
          stateMessage={page.error ?? t("breakglass.authority.empty")}
          onRowOpen={(row) => setSelected(row.ceremony_id)}
          rowActionLabel={() => t("breakglass.authority.openReceipt")}
          pagination={
            <div className="flex flex-wrap gap-2">
              {previous.length ? (
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => {
                    setCursor(previous[previous.length - 1] ?? "");
                    setPrevious(previous.slice(0, -1));
                  }}
                >
                  {t("breakglass.history.previous")}
                </Button>
              ) : null}
              {page.data?.next_cursor ? (
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => {
                    setPrevious([...previous, cursor]);
                    setCursor(page.data!.next_cursor);
                  }}
                >
                  {t("breakglass.history.more")}
                </Button>
              ) : null}
              <Button type="button" variant="outline" onClick={page.refetch}>
                {t("breakglass.history.refresh")}
              </Button>
            </div>
          }
        />
        {detail.error ? <ErrorState title={t("breakglass.authority.readFailed")}>{detail.error}</ErrorState> : null}
        {detail.data ? (
          <div className="grid gap-2 rounded-control border border-border p-3 text-sm">
            <p className="font-medium">{t(detail.data.kind === "rotation" ? "breakglass.authority.rotateTitle" : "breakglass.authority.crossTitle")}</p>
            <p className="break-all font-mono text-xs">{t("breakglass.history.ceremony", { id: detail.data.ceremony_id })}</p>
            <p>{t("breakglass.history.sequence", { sequence: detail.data.event_sequence })}</p>
            <p>{t("breakglass.authority.digest", { digest: detail.data.request_digest })}</p>
            {detail.data.rotation || detail.data.cross_sign ? (
              <Button type="button" onClick={() => downloadPublicResult(detail.data!)}>
                {t("breakglass.authority.download")}
              </Button>
            ) : null}
          </div>
        ) : null}
      </div>
    </details>
  );
}

export function BreakglassAuthorityMaintenance() {
  const { t } = useTranslation();
  const [latestCeremonyID, setLatestCeremonyID] = useState<string | null>(null);
  return (
    <section aria-label={t("breakglass.authority.title")} className="grid gap-3">
      <div>
        <h2 className="text-title font-semibold">{t("breakglass.authority.title")}</h2>
        <p className="text-sm text-muted-foreground">{t("breakglass.authority.help")}</p>
      </div>
      <AuthorityProcedure kind="rotation" onCompleted={setLatestCeremonyID} />
      <AuthorityProcedure kind="cross_sign" onCompleted={setLatestCeremonyID} />
      <AuthorityHistory latestCeremonyID={latestCeremonyID} />
    </section>
  );
}
