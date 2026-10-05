// SPDX-License-Identifier: BUSL-1.1

import { useEffect, useState } from "react";
import { zodResolver } from "@hookform/resolvers/zod";
import { useForm } from "react-hook-form";
import { z } from "zod";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { translateNow } from "@/i18n/I18nProvider";
import type { MessageKey } from "@/i18n/messages";
import { formatDateTime } from "@/i18n/format";
import { ProviderAuthError, providerApi, type ProviderBreakGlassGrantView, type ProviderBreakGlassState, type ProviderTenantSnapshot } from "@/lib/providerApi";
import { useApiQuery, useQueryClient } from "@/lib/query";

const requestSchema = z.object({
  reason: z.string().trim().min(10, translateNow("provider.emergency.reasonRequired")).max(1000),
  ttl: z.enum(["15m", "30m", "1h", "2h"]),
});

type RequestValues = z.infer<typeof requestSchema>;

const stateKeys: Record<ProviderBreakGlassState, MessageKey> = {
  pending: "provider.emergency.state.pending",
  awaiting_co_consent: "provider.emergency.state.awaiting",
  active: "provider.emergency.state.active",
  denied: "provider.emergency.state.denied",
  withdrawn: "provider.emergency.state.withdrawn",
  revoked: "provider.emergency.state.revoked",
  expired: "provider.emergency.state.expired",
};

export function ProviderBreakGlassPanel({
  customerId,
  customerName,
  operatorId,
  canWrite,
  onAuthError,
  onClose,
}: {
  customerId: string;
  customerName: string;
  operatorId: string;
  canWrite: boolean;
  onAuthError: () => void;
  onClose: () => void;
}) {
  const client = useQueryClient();
  const [cursors, setCursors] = useState([""]);
  const cursor = cursors[cursors.length - 1];
  const queryKey = ["provider", "breakglass", operatorId, customerId, cursor];
  const queue = useApiQuery(queryKey, () => providerApi.listBreakGlass(customerId, cursor), {
    retry: false,
    live: { intervalMs: 15_000 },
  });
  useEffect(() => {
    if (queue.errorValue instanceof ProviderAuthError) onAuthError();
  }, [queue.errorValue, onAuthError]);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [problem, setProblem] = useState<string | null>(null);
  const [snapshot, setSnapshot] = useState<{ grantId: string; data: ProviderTenantSnapshot } | null>(null);
  const form = useForm<RequestValues>({ resolver: zodResolver(requestSchema), defaultValues: { reason: "", ttl: "15m" } });

  const refresh = async () => {
    setCursors([""]);
    await client.invalidateQueries({ queryKey: ["provider", "breakglass", operatorId, customerId] });
    await client.invalidateQueries({ queryKey: ["provider", "activity"] });
  };
  const run = async (id: string, mutation: () => Promise<unknown>) => {
    setBusyId(id);
    setProblem(null);
    setSnapshot(null);
    try {
      await mutation();
      await refresh();
    } catch (error) {
      if (error instanceof ProviderAuthError) {
        onAuthError();
      } else {
        setProblem(error instanceof Error ? error.message : String(error));
        await client.invalidateQueries({ queryKey: ["provider", "breakglass", operatorId, customerId] });
      }
    } finally {
      setBusyId(null);
    }
  };
  const submit = form.handleSubmit(async (values) => {
    await run("request", async () => {
      const grant = await providerApi.requestBreakGlass({ tenant_id: customerId, reason: values.reason, ttl: values.ttl });
      if (grant.tenant_id !== customerId) throw new Error(translateNow("provider.emergency.mismatchedCustomer"));
      form.reset();
    });
  });
  const decision = (grant: ProviderBreakGlassGrantView, approve: boolean) => run(grant.id, () => providerApi.consentBreakGlass(grant.id, customerId, approve));
  const read = (grant: ProviderBreakGlassGrantView) =>
    run(grant.id, async () => {
      const data = await providerApi.breakGlassResults(grant.id, customerId);
      setSnapshot({ grantId: grant.id, data });
    });

  return (
    <section className="mt-4 rounded-md border border-border p-4" aria-label={translateNow("provider.emergency.title")}>
      <div className="flex items-start justify-between gap-3">
        <div>
          <h3 className="text-title font-semibold">
            {translateNow("provider.emergency.title")}: {customerName}
          </h3>
          <p className="mt-1 text-caption text-muted-foreground">{translateNow("provider.emergency.help")}</p>
        </div>
        <Button type="button" variant="outline" onClick={onClose}>
          {translateNow("provider.emergency.close")}
        </Button>
      </div>

      {canWrite ? (
        <form className="mt-4 flex flex-wrap items-end gap-2" onSubmit={(event) => void submit(event)}>
          <label className="grid min-w-64 flex-1 gap-1">
            <span className="text-caption font-medium">{translateNow("provider.emergency.reason")}</span>
            <Input aria-label={translateNow("provider.emergency.reason")} {...form.register("reason")} />
          </label>
          <label className="grid gap-1">
            <span className="text-caption font-medium">{translateNow("provider.emergency.duration")}</span>
            <Select aria-label={translateNow("provider.emergency.duration")} {...form.register("ttl")}>
              <option value="15m">15 {translateNow("provider.emergency.minutes")}</option>
              <option value="30m">30 {translateNow("provider.emergency.minutes")}</option>
              <option value="1h">1 {translateNow("provider.emergency.hour")}</option>
              <option value="2h">2 {translateNow("provider.emergency.hours")}</option>
            </Select>
          </label>
          <Button type="submit" disabled={busyId !== null || form.formState.isSubmitting}>
            {translateNow("provider.emergency.request")}
          </Button>
        </form>
      ) : null}
      {form.formState.errors.reason?.message ? (
        <p role="alert" className="mt-1 text-caption text-status-danger">
          {form.formState.errors.reason.message}
        </p>
      ) : null}
      {problem ? (
        <p role="alert" className="mt-2 text-caption text-status-danger">
          {problem}
        </p>
      ) : null}

      <div className="mt-5 flex items-center justify-between gap-3">
        <h4 className="font-medium">{translateNow("provider.emergency.queue")}</h4>
        <Button type="button" variant="outline" onClick={() => void queue.refetch()}>
          {translateNow("provider.emergency.refresh")}
        </Button>
      </div>
      {queue.error ? (
        <p role="alert" className="mt-2 text-caption text-status-danger">
          {queue.error}
        </p>
      ) : null}
      {queue.loading ? (
        <p role="status" className="mt-2 text-caption">
          {translateNow("capabilities.loading")}
        </p>
      ) : null}
      {!queue.loading && !queue.error && queue.data?.items.length === 0 ? (
        <p className="mt-2 text-caption text-muted-foreground">{translateNow("provider.emergency.empty")}</p>
      ) : null}
      <div className="mt-2 grid gap-3">
        {(queue.data?.items ?? []).map((grant) => {
          const pending = grant.state === "pending" || grant.state === "awaiting_co_consent";
          const requester = grant.operator_id === operatorId;
          const canApprove = canWrite && pending && !requester && grant.consented_by !== operatorId;
          const approvals = Number(!!grant.consented_by) + Number(!!grant.second_consented_by);
          return (
            <article key={grant.id} className="rounded-md border border-border p-3" aria-label={grant.id}>
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div>
                  <p className="font-medium">{grant.reason}</p>
                  <p className="text-caption text-muted-foreground">
                    {translateNow("provider.emergency.requestedBy", { operator: grant.operator_email || grant.operator_id })}
                  </p>
                  <p className="text-caption text-muted-foreground">{translateNow("provider.emergency.expires", { at: formatDateTime(grant.expires_at) })}</p>
                  <p className="text-caption text-muted-foreground">{translateNow("provider.emergency.grantId", { id: grant.id })}</p>
                </div>
                <div className="text-caption">
                  <p>{translateNow(stateKeys[grant.state])}</p>
                  <p>{translateNow("provider.emergency.approvals", { count: approvals })}</p>
                </div>
              </div>
              <div className="mt-2 flex flex-wrap gap-2">
                {canApprove ? (
                  <Button type="button" disabled={busyId !== null} onClick={() => void decision(grant, true)}>
                    {translateNow("provider.emergency.approve")}
                  </Button>
                ) : null}
                {canWrite && pending && !requester ? (
                  <Button type="button" variant="outline" disabled={busyId !== null} onClick={() => void decision(grant, false)}>
                    {translateNow("provider.emergency.deny")}
                  </Button>
                ) : null}
                {canWrite && pending && requester ? (
                  <Button type="button" variant="outline" disabled={busyId !== null} onClick={() => void decision(grant, false)}>
                    {translateNow("provider.emergency.withdraw")}
                  </Button>
                ) : null}
                {canWrite && grant.state === "active" && requester ? (
                  <Button type="button" disabled={busyId !== null} onClick={() => void read(grant)}>
                    {translateNow("provider.emergency.viewResult")}
                  </Button>
                ) : null}
              </div>
            </article>
          );
        })}
      </div>
      <div className="mt-3 flex gap-2">
        {cursors.length > 1 ? (
          <Button type="button" variant="outline" onClick={() => setCursors((current) => current.slice(0, -1))}>
            {translateNow("provider.emergency.newer")}
          </Button>
        ) : null}
        {queue.data?.next_cursor ? (
          <Button type="button" variant="outline" onClick={() => setCursors((current) => [...current, queue.data!.next_cursor!])}>
            {translateNow("provider.emergency.older")}
          </Button>
        ) : null}
      </div>
      {snapshot ? (
        <div className="mt-4 rounded-md border border-border p-3" role="status">
          <h4 className="font-medium">{translateNow("provider.emergency.result")}</h4>
          <p className="text-caption">{translateNow("provider.emergency.grantId", { id: snapshot.grantId })}</p>
          <p className="text-caption">{translateNow("provider.emergency.health", { health: snapshot.data.health })}</p>
          <p className="text-caption">{translateNow("provider.emergency.certificates", { count: snapshot.data.active_certificates })}</p>
          <p className="text-caption">
            {translateNow("provider.emergency.workspace", {
              status: translateNow(
                snapshot.data.workspace_initialized === undefined
                  ? "provider.setup.unknown"
                  : snapshot.data.workspace_initialized
                    ? "provider.setup.configured"
                    : "provider.setup.required",
              ),
            })}
          </p>
        </div>
      ) : null}
    </section>
  );
}
