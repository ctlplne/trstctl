// SPDX-License-Identifier: BUSL-1.1

import { useState } from "react";
import { useAuth } from "@/auth/AuthProvider";
import { Button } from "@/components/ui/button";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { useTranslation } from "@/i18n/I18nProvider";
import { api } from "@/lib/api";
import type { FactoryReconcileRequest, FactoryReconcileResult } from "@/lib/api-types.gen";
import { hasPermission } from "@/lib/access";
import { newIdempotencyKey } from "@/lib/apiTransport";
import { useApiQuery, useQueryClient } from "@/lib/query";

const certificatePEM = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;

// The station's manifest, saved as a file the operator carries to it.
function saveJSON(name: string, value: unknown) {
  const blob = new Blob([JSON.stringify(value, null, 2) + "\n"], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = name;
  link.click();
  URL.revokeObjectURL(url);
}

// P12-L3: device first-boot batches. A batch is a quota of birth certificates
// that a factory station issues offline under an edge delegation, one per
// device; the station's journal is reconciled here afterwards, and each
// device's enrollment into an operational certificate is followed. Births a
// station made while offline are invisible until its journal is reconciled.
export function FactoryBatchesPanel() {
  const { t, formatDateTime } = useTranslation();
  const { user } = useAuth();
  const canWrite = hasPermission(user, "issuers:write");
  const queryClient = useQueryClient();
  const batches = useApiQuery(["factory-batches"], api.factoryBatches);
  const delegations = useApiQuery(["edge-delegations"], api.edgeDelegations);
  const [selected, setSelected] = useState("");
  const detail = useApiQuery(["factory-batch", selected], () => api.factoryBatch(selected), { enabled: Boolean(selected) });
  const [draft, setDraft] = useState({ delegation: "", label: "", quota: "100", ttlHours: "24", profile: "", roots: "" });
  // A retried request keeps its key, so a lost response never creates a second batch.
  const [createKey, setCreateKey] = useState(() => newIdempotencyKey());
  const [journal, setJournal] = useState({ host: "", pem: "" });
  const [reconcileKey, setReconcileKey] = useState(() => newIdempotencyKey());
  const [result, setResult] = useState<FactoryReconcileResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const active = (delegations.data?.items ?? []).filter((delegation) => delegation.status === "active");
  const delegationID = draft.delegation || active[0]?.id || "";
  const batch = detail.data;

  const act = async (work: () => Promise<void>) => {
    setBusy(true);
    setError(null);
    try {
      await work();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  const rootsPEM = (draft.roots.match(certificatePEM) ?? []).map((pem) => pem.trim());
  const createBatch = () =>
    act(async () => {
      const created = await api.createFactoryBatch(
        {
          delegation_id: delegationID,
          label: draft.label.trim(),
          quota: Number(draft.quota),
          birth_ttl_seconds: Math.round(Number(draft.ttlHours) * 3600),
          ...(draft.profile.trim() ? { operational_profile: draft.profile.trim() } : {}),
          // P12-L1: roots each device attests its own key against at birth.
          ...(rootsPEM.length > 0 ? { device_attestation_roots_pem: rootsPEM } : {}),
        },
        createKey,
      );
      setCreateKey(newIdempotencyKey());
      setDraft({ ...draft, label: "", roots: "" });
      setSelected(created.id);
      void queryClient.invalidateQueries({ queryKey: ["factory-batches"] });
    });

  const downloadManifest = () =>
    act(async () => {
      if (!batch) return;
      saveJSON(`factory-manifest-${batch.label}.json`, await api.factoryBatchManifest(batch.id));
    });

  const reconcile = () =>
    act(async () => {
      if (!batch) return;
      let certificates = (journal.pem.match(certificatePEM) ?? []).map((pem) => pem.trim());
      // P12-L1: the station's journal file carries each device's attestation
      // beside its certificate; pasted as JSON, it is posted as the station wrote it.
      let attestations: FactoryReconcileRequest["attestations"];
      try {
        const parsed = JSON.parse(journal.pem) as Partial<FactoryReconcileRequest>;
        if (Array.isArray(parsed.certificates_pem)) certificates = parsed.certificates_pem.map((pem) => pem.trim());
        attestations = parsed.attestations;
      } catch {
        attestations = undefined;
      }
      if (certificates.length === 0) throw new Error(t("edge.factory.reconcile.empty"));
      setResult(
        await api.reconcileFactoryBatch(
          batch.id,
          { host: journal.host.trim(), batch_id: batch.id, certificates_pem: certificates, ...(attestations?.length ? { attestations } : {}) },
          reconcileKey,
        ),
      );
      setReconcileKey(newIdempotencyKey());
      setJournal({ ...journal, pem: "" });
      void queryClient.invalidateQueries({ queryKey: ["factory-batches"] });
      void queryClient.invalidateQueries({ queryKey: ["factory-batch", batch.id] });
    });

  return (
    <section className="ui-panel p-comfortable" aria-labelledby="factory-batches-heading">
      <h2 id="factory-batches-heading" className="text-title font-semibold">
        {t("edge.factory.title")}
      </h2>
      <p className="mt-1 text-caption text-muted-foreground">{t("edge.factory.description")}</p>
      {error ? (
        <p role="alert" className="mt-2 text-caption text-status-danger">
          {error}
        </p>
      ) : null}
      {batches.error ? <p className="mt-2 text-caption text-status-warning">{batches.error}</p> : null}
      {batches.data && batches.data.items.length === 0 ? <p className="mt-2 text-caption text-muted-foreground">{t("edge.factory.empty")}</p> : null}
      {batches.data && batches.data.items.length > 0 ? (
        <div className="mt-3 min-w-0 overflow-x-auto">
          <table className="w-full text-sm">
            <caption className="sr-only">{t("edge.factory.caption")}</caption>
            <thead>
              <tr className="text-left">
                <th scope="col">{t("edge.factory.col.batch")}</th>
                <th scope="col">{t("edge.factory.col.quota")}</th>
                <th scope="col">{t("edge.factory.col.births")}</th>
                <th scope="col">{t("edge.factory.col.created")}</th>
              </tr>
            </thead>
            <tbody>
              {batches.data.items.map((item) => (
                <tr key={item.id} className="align-top">
                  <td>
                    <Button type="button" variant="ghost" onClick={() => setSelected(item.id)}>
                      {item.label}
                    </Button>
                  </td>
                  <td>{t("edge.factory.quota", { quota: item.quota, hours: Math.round(item.birth_ttl_seconds / 3600) })}</td>
                  <td>
                    {t("edge.factory.births", { recorded: item.recorded, enrolled: item.enrolled, over: item.over_quota })}
                    {item.device_attestation_roots_pem?.length ? (
                      <span className="block text-caption text-muted-foreground">{t("edge.factory.attested", { unattested: item.unattested ?? 0 })}</span>
                    ) : null}
                  </td>
                  <td>{t("edge.factory.created", { by: item.created_by, at: formatDateTime(item.created_at) })}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}

      {canWrite ? (
        <section className="mt-4 grid gap-3 md:grid-cols-2" aria-labelledby="factory-batch-new">
          <h3 id="factory-batch-new" className="font-medium md:col-span-2">
            {t("edge.factory.new")}
          </h3>
          {active.length === 0 ? (
            <p className="text-caption text-muted-foreground md:col-span-2">{t("edge.factory.noDelegation")}</p>
          ) : (
            <>
              <Field label={t("edge.factory.delegation")} controlId="factory-delegation">
                {(control) => (
                  <Select {...control} value={delegationID} onChange={(event) => setDraft({ ...draft, delegation: event.target.value })}>
                    {active.map((delegation) => (
                      <option key={delegation.id} value={delegation.id}>
                        {t("edge.factory.delegationOption", { host: delegation.host, name: delegation.common_name })}
                      </option>
                    ))}
                  </Select>
                )}
              </Field>
              <Field label={t("edge.factory.label")} controlId="factory-label">
                {(control) => <Input {...control} value={draft.label} onChange={(event) => setDraft({ ...draft, label: event.target.value })} />}
              </Field>
              <Field label={t("edge.factory.quotaLabel")} controlId="factory-quota">
                {(control) => (
                  <Input {...control} type="number" min={1} value={draft.quota} onChange={(event) => setDraft({ ...draft, quota: event.target.value })} />
                )}
              </Field>
              <Field label={t("edge.factory.ttlLabel")} controlId="factory-ttl">
                {(control) => (
                  <Input {...control} type="number" min={1} value={draft.ttlHours} onChange={(event) => setDraft({ ...draft, ttlHours: event.target.value })} />
                )}
              </Field>
              <Field label={t("edge.factory.profileLabel")} controlId="factory-profile">
                {(control) => <Input {...control} value={draft.profile} onChange={(event) => setDraft({ ...draft, profile: event.target.value })} />}
              </Field>
              <Field label={t("edge.factory.rootsLabel")} controlId="factory-roots" description={t("edge.factory.rootsHelp")} className="md:col-span-2">
                {(control) => <Textarea {...control} rows={3} value={draft.roots} onChange={(event) => setDraft({ ...draft, roots: event.target.value })} />}
              </Field>
              <div className="self-end">
                <Button type="button" disabled={busy || !delegationID || !draft.label.trim() || Number(draft.quota) < 1} onClick={() => void createBatch()}>
                  {t("edge.factory.create")}
                </Button>
              </div>
            </>
          )}
        </section>
      ) : null}

      {batch ? (
        <section className="mt-4 grid gap-3" aria-labelledby="factory-batch-detail">
          <h3 id="factory-batch-detail" className="font-medium">
            {t("edge.factory.detail", { label: batch.label })}
          </h3>
          <div>
            <Button type="button" variant="outline" disabled={busy} onClick={() => void downloadManifest()}>
              {t("edge.factory.manifest")}
            </Button>
          </div>
          {batch.births.length === 0 ? (
            <p className="text-caption text-muted-foreground">{t("edge.factory.noBirths")}</p>
          ) : (
            <div className="min-w-0 overflow-x-auto">
              <table className="w-full text-sm">
                <caption className="sr-only">{t("edge.factory.birthsCaption", { label: batch.label })}</caption>
                <thead>
                  <tr className="text-left">
                    <th scope="col">{t("edge.factory.col.device")}</th>
                    <th scope="col">{t("edge.factory.col.birth")}</th>
                    <th scope="col">{t("edge.factory.col.enrollment")}</th>
                  </tr>
                </thead>
                <tbody>
                  {batch.births.map((birth) => (
                    <tr key={birth.serial} className="align-top">
                      <td>
                        <span className="block">{birth.device_name}</span>
                        <span className="block font-mono text-xs text-muted-foreground">{birth.serial}</span>
                      </td>
                      <td>
                        {t("edge.factory.birthUntil", { at: formatDateTime(birth.not_after) })}
                        {birth.over_quota ? <span className="block text-status-warning">{t("edge.factory.overQuota")}</span> : null}
                        {birth.attestation === "verified" ? <span className="block">{t("edge.factory.attestation.verified")}</span> : null}
                        {birth.attestation === "missing" || birth.attestation === "refused" ? (
                          <span className="block text-status-warning">{t(`edge.factory.attestation.${birth.attestation}`)}</span>
                        ) : null}
                      </td>
                      <td>
                        {birth.enrolled
                          ? t("edge.factory.enrolled", {
                              at: birth.enrolled_at ? formatDateTime(birth.enrolled_at) : "?",
                              serial: birth.operational_serial ?? "?",
                              renewals: birth.renewals,
                            })
                          : t("edge.factory.notEnrolled")}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {canWrite ? (
            <section className="grid gap-2" aria-labelledby="factory-batch-reconcile">
              <h4 id="factory-batch-reconcile" className="text-sm font-medium">
                {t("edge.factory.reconcile.title")}
              </h4>
              <Field label={t("edge.factory.reconcile.host")} controlId="factory-reconcile-host">
                {(control) => <Input {...control} value={journal.host} onChange={(event) => setJournal({ ...journal, host: event.target.value })} />}
              </Field>
              <Field label={t("edge.factory.reconcile.pem")} controlId="factory-reconcile-pem" description={t("edge.factory.reconcile.help")}>
                {(control) => <Textarea {...control} rows={4} value={journal.pem} onChange={(event) => setJournal({ ...journal, pem: event.target.value })} />}
              </Field>
              <div>
                <Button type="button" disabled={busy || !journal.host.trim() || !journal.pem.trim()} onClick={() => void reconcile()}>
                  {t("edge.factory.reconcile.submit")}
                </Button>
              </div>
              {result ? (
                <p role="status" className="text-caption">
                  {t("edge.factory.reconcile.result", {
                    recorded: result.recorded,
                    over: result.over_quota,
                    already: result.already,
                    rejected: result.rejected,
                  })}
                </p>
              ) : null}
            </section>
          ) : null}
        </section>
      ) : null}
    </section>
  );
}
