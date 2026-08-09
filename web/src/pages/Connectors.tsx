import { type FormEvent, type ReactNode, useEffect, useMemo, useRef, useState } from "react";
import { Dialog } from "@/components/Dialog";
import { PageHeader } from "@/components/PageHeader";
import { EmptyState } from "@/components/EmptyState";
import { ErrorState, LoadingState } from "@/components/StatePrimitives";
import { StatusBadge } from "@/components/StatusBadge";
import { describeStatus } from "@/lib/statusVocab";
import { useToast } from "@/components/ToastProvider";
import { Button } from "@/components/ui/button";
import { formatDateTime, formatDateTime as formatDateTimePolicy } from "@/i18n/format";
import {
  api,
  type ConnectorCatalogItem,
  type ConnectorDelivery,
  type DeploymentTarget,
  type EndpointVerification,
  type EndpointKeyCustodyList,
  type Identity,
  type OutboxCircuit,
} from "@/lib/api";
import { useTranslation, translateNow } from "@/i18n/I18nProvider";

// VantageBadge names where a connector's deploy work executes (epic A3), read
// from the live registry census. The distinction the operator cares about: work
// on a host they can put an agent on, work a network relay fronts for an
// appliance, or work the control plane keeps (cloud stores, and anything not
// yet audited for agent execution).
function VantageBadge({ vantage }: { vantage: string }) {
  if (vantage === "host_agent") {
    return (
      <span className="rounded-full border border-border px-2 py-0.5 text-xs text-muted-foreground">{translateNow("source.vantage.host.a3vant0002")}</span>
    );
  }
  if (vantage === "network_relay") {
    return (
      <span className="rounded-full border border-status-warning px-2 py-0.5 text-xs text-status-warning">
        {translateNow("source.vantage.relay.a3vant0003")}
      </span>
    );
  }
  return (
    <span className="rounded-full border border-border px-2 py-0.5 text-xs text-muted-foreground">
      {translateNow("source.vantage.control.plane.a3vant0004")}
    </span>
  );
}

export function Connectors() {
  const { t } = useTranslation();
  const [catalog, setCatalog] = useState<ConnectorCatalogItem[] | null>(null);
  const [targets, setTargets] = useState<DeploymentTarget[] | null>(null);
  const [identities, setIdentities] = useState<Identity[]>([]);
  const [deliveries, setDeliveries] = useState<ConnectorDelivery[] | null>(null);
  // D2: observed endpoint identity. Loaded separately from the connector data
  // so a deployment without the verification surface still renders everything
  // else — and so an endpoint a relay probed, which has no connector target at
  // all, still appears.
  const [endpointVerifications, setEndpointVerifications] = useState<EndpointVerification[]>([]);
  // B2: where each target's private key is generated. Loaded separately for the
  // same reason as the verification rows above — a deployment without this
  // surface still renders the rest of the page.
  const [keyCustody, setKeyCustody] = useState<EndpointKeyCustodyList | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [actionResult, setActionResult] = useState<string | null>(null);
  const [targetName, setTargetName] = useState("edge/prod/payments");
  const [connectorName, setConnectorName] = useState("nginx");
  const [targetConfig, setTargetConfig] = useState('{"credential_ref":"connector-credential-ref","host":"edge-1.internal"}');
  const [selectedTarget, setSelectedTarget] = useState("");
  const [selectedIdentity, setSelectedIdentity] = useState("");
  const [bindingOwnerID, setBindingOwnerID] = useState("");
  const [bindingIdentityName, setBindingIdentityName] = useState("payments.example.test");
  const [reason, setReason] = useState("operator requested deployment");
  const [circuits, setCircuits] = useState<OutboxCircuit[] | null>(null);
  const [deliveriesCursor, setDeliveriesCursor] = useState<string | undefined>(undefined);
  const [deliveriesLoadingMore, setDeliveriesLoadingMore] = useState(false);
  const [deliveryDetail, setDeliveryDetail] = useState<ConnectorDelivery | null>(null);
  const [editTarget, setEditTarget] = useState<DeploymentTarget | null>(null);
  const [editName, setEditName] = useState("");
  const [editConnector, setEditConnector] = useState("");
  const [editConfig, setEditConfig] = useState("{}");
  const [editError, setEditError] = useState<string | null>(null);
  const [editBusy, setEditBusy] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState<DeploymentTarget | null>(null);
  const [deleteConfirmName, setDeleteConfirmName] = useState("");
  const [deleteError, setDeleteError] = useState<string | null>(null);
  const [deleteBusy, setDeleteBusy] = useState(false);
  const editNameRef = useRef<HTMLInputElement>(null);
  const deleteConfirmRef = useRef<HTMLInputElement>(null);
  const { toast } = useToast();

  const refreshCircuits = () =>
    Promise.resolve()
      .then(() => api.outboxCircuits())
      .then((result) => setCircuits(result.items ?? []))
      .catch(() => undefined);

  const refresh = () => {
    void refreshCircuits();
    return Promise.allSettled([api.connectorCatalog(), api.connectorTargets(), api.identities(), api.connectorDeliveries({ limit: 20 })]).then(
      ([catalogResult, targetResult, identityResult, deliveryResult]) => {
        if (catalogResult.status === "fulfilled") setCatalog(catalogResult.value.items ?? []);
        if (deliveryResult.status === "fulfilled") {
          setDeliveries(deliveryResult.value.items ?? []);
          setDeliveriesCursor(deliveryResult.value.next_cursor);
        }
        if (targetResult.status !== "fulfilled" || identityResult.status !== "fulfilled") {
          setError(null);
          return;
        }
        const loadedTargets = targetResult.value.items ?? [];
        setTargets(loadedTargets);
        setIdentities(identityResult.value ?? []);
        setSelectedTarget((current) => (loadedTargets.some((target) => target.id === current) ? current : loadedTargets[0]?.id || ""));
        setSelectedIdentity((current) => (identityResult.value?.some((identity) => identity.id === current) ? current : identityResult.value?.[0]?.id || ""));
        setError(null);
      },
    );
  };

  useEffect(() => {
    let active = true;
    if (typeof api.endpointKeyCustody !== "function") return;
    api
      .endpointKeyCustody()
      .then((list) => {
        if (active) setKeyCustody(list);
      })
      .catch(() => {
        if (active) setKeyCustody(null);
      });
    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    let active = true;
    if (typeof api.endpointVerifications !== "function") return;
    api
      .endpointVerifications()
      .then((list) => {
        if (active) setEndpointVerifications(list.items ?? []);
      })
      .catch(() => {
        if (active) setEndpointVerifications([]);
      });
    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    let cancelled = false;
    refresh().catch((err) => {
      if (!cancelled) setError(err instanceof Error ? err.message : String(err));
    });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const connectorOptions = useMemo(() => (catalog ?? []).map((item) => item.name), [catalog]);

  const createTarget = async (event: FormEvent) => {
    event.preventDefault();
    try {
      const config = JSON.parse(targetConfig) as Record<string, unknown>;
      const created = await api.createConnectorTarget({ name: targetName.trim(), connector: connectorName.trim(), config });
      setActionResult(`target:${created.id}`);
      setSelectedTarget(created.id);
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  const createEndpointBinding = async (event: FormEvent) => {
    event.preventDefault();
    try {
      const config = JSON.parse(targetConfig) as Record<string, unknown>;
      const binding = await api.createEndpointBinding({
        owner_id: bindingOwnerID.trim(),
        identity_name: bindingIdentityName.trim(),
        reason,
        target: { name: targetName.trim(), connector: connectorName.trim(), config },
      });
      setActionResult(`endpoint-binding:${binding.identity.status}:${binding.renewal_intent}`);
      setSelectedTarget(binding.target.id);
      setSelectedIdentity(binding.identity.id);
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  const runTargetAction = async (action: "bind" | "test" | "deploy" | "rollback") => {
    if (!selectedTarget) return;
    try {
      if (action === "bind") {
        if (!selectedIdentity) return;
        const identity = await api.bindIdentityConnectorTarget(selectedIdentity, { target_id: selectedTarget });
        setActionResult(`bound:${identity.id}`);
      } else if (action === "test") {
        const receipt = await api.testConnectorTarget(selectedTarget);
        setActionResult(`${receipt.destination}:${receipt.status}`);
      } else if (action === "deploy") {
        if (!selectedIdentity) return;
        const identity = await api.deployConnectorTarget(selectedTarget, { identity_id: selectedIdentity, reason });
        setActionResult(`deploy:${identity.status}`);
      } else {
        const receipt = await api.rollbackConnectorTarget(selectedTarget, { identity_id: selectedIdentity, reason });
        setActionResult(`${receipt.destination}:${receipt.status}`);
      }
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  const openEdit = (target: DeploymentTarget) => {
    setEditTarget(target);
    setEditName(target.name);
    setEditConnector(target.connector);
    setEditConfig(JSON.stringify(target.config ?? {}, null, 2));
    setEditError(null);
  };

  const closeEdit = () => {
    setEditTarget(null);
    setEditError(null);
  };

  const submitEdit = async (event: FormEvent) => {
    event.preventDefault();
    if (!editTarget) return;
    let config: Record<string, unknown>;
    try {
      config = JSON.parse(editConfig) as Record<string, unknown>;
    } catch {
      setEditError("Config must be valid JSON.");
      return;
    }
    setEditBusy(true);
    try {
      const updated = await api.updateConnectorTarget(editTarget.id, { name: editName.trim(), connector: editConnector.trim(), config });
      setEditTarget(null);
      setEditError(null);
      toast({ kind: "success", title: `Target ${updated.name} updated` });
      await refresh();
    } catch (err) {
      setEditError(err instanceof Error ? err.message : String(err));
    } finally {
      setEditBusy(false);
    }
  };

  const openDelete = (target: DeploymentTarget) => {
    setDeleteTarget(target);
    setDeleteConfirmName("");
    setDeleteError(null);
  };

  const closeDelete = () => {
    setDeleteTarget(null);
    setDeleteConfirmName("");
    setDeleteError(null);
  };

  const confirmDelete = async () => {
    if (!deleteTarget) return;
    const { id: deletedId, name: deletedName } = deleteTarget;
    setDeleteBusy(true);
    try {
      await api.deleteConnectorTarget(deletedId);
      setTargets((current) => (current ? current.filter((target) => target.id !== deletedId) : current));
      setSelectedTarget((current) => (current === deletedId ? "" : current));
      setDeleteTarget(null);
      setDeleteConfirmName("");
      setDeleteError(null);
      toast({ kind: "success", title: `Target ${deletedName} deleted` });
    } catch (err) {
      setDeleteError(err instanceof Error ? err.message : String(err));
    } finally {
      setDeleteBusy(false);
    }
  };

  const loadMoreDeliveries = async () => {
    if (!deliveriesCursor) return;
    setDeliveriesLoadingMore(true);
    try {
      const page = await api.connectorDeliveries({ limit: 20, cursor: deliveriesCursor });
      setDeliveries((current) => [...(current ?? []), ...(page.items ?? [])]);
      setDeliveriesCursor(page.next_cursor);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setDeliveriesLoadingMore(false);
    }
  };

  return (
    <section aria-labelledby="connectors-heading" className="grid gap-6">
      <PageHeader
        titleId="connectors-heading"
        title={translateNow("source.deployment.connectors.6bdaa16cc0")}
        description="Target setup, identity binding, delivery actions, and receipt evidence from the served connector API."
      />
      <h2 className="text-title font-semibold">{t("connectors.deliveryEvidence")}</h2>

      {error && <ErrorState title={translateNow("source.connector.workflow.failed.9b83125cd7")}>{error}</ErrorState>}
      {!catalog && !error && <LoadingState>{translateNow("source.loading.connector.workflow.f8e0fc1515")}</LoadingState>}

      {catalog && targets && (
        <section aria-labelledby="target-setup-heading" className="grid gap-3 border-y border-border py-4">
          <div>
            <h2 id="target-setup-heading" className="text-title font-semibold">
              {translateNow("source.connector.targets.fb63eee9b5")}
            </h2>
          </div>
          <form
            aria-label={translateNow("source.create.connector.target.bb8ec59505")}
            className="ui-panel grid gap-3 md:grid-cols-[1fr_12rem] md:items-end"
            onSubmit={createTarget}
          >
            <label className="grid gap-1 text-sm">
              {translateNow("source.target.978354db0c")}
              <input className="ui-input" value={targetName} onChange={(event) => setTargetName(event.target.value)} required />
            </label>
            <label className="grid gap-1 text-sm">
              {translateNow("source.connector.8f0d706fff")}
              <select className="ui-input" value={connectorName} onChange={(event) => setConnectorName(event.target.value)}>
                {connectorOptions.map((name) => (
                  <option key={name} value={name}>
                    {name}
                  </option>
                ))}
              </select>
            </label>
            <label className="grid gap-1 text-sm md:col-span-2">
              {translateNow("source.config.json.eaa2c019f1")}
              <textarea className="ui-input min-h-24 font-mono text-xs" value={targetConfig} onChange={(event) => setTargetConfig(event.target.value)} />
            </label>
            <Button className="md:col-span-2" type="submit">
              {translateNow("source.create.target.00cf884cbc")}
            </Button>
          </form>

          <form
            aria-label={translateNow("source.create.endpoint.binding.dd5b21a786")}
            className="ui-panel grid gap-3 md:grid-cols-3 md:items-end"
            onSubmit={createEndpointBinding}
          >
            <label className="grid gap-1 text-sm">
              {translateNow("source.owner.id.1611f5e055")}
              <input className="ui-input font-mono text-xs" value={bindingOwnerID} onChange={(event) => setBindingOwnerID(event.target.value)} required />
            </label>
            <label className="grid gap-1 text-sm">
              {translateNow("source.identity.dns.name.c79a6b3b97")}
              <input className="ui-input" value={bindingIdentityName} onChange={(event) => setBindingIdentityName(event.target.value)} required />
            </label>
            <Button type="submit">{translateNow("source.bind.and.enroll.5cb885780a")}</Button>
          </form>

          {targets && targets.length === 0 ? (
            <EmptyState title={translateNow("source.no.connector.targets.5a8adcf783")}>
              {translateNow("source.no.tenant.connector.targets.were.returned.6c7baa9a8d")}
            </EmptyState>
          ) : (
            targets && (
              <div className="ui-panel overflow-x-auto">
                <table className="ui-table min-w-[60rem]">
                  <caption className="sr-only">{translateNow("source.connector.targets.fb63eee9b5")}</caption>
                  <thead>
                    <tr>
                      <th scope="col">{translateNow("source.target.978354db0c")}</th>
                      <th scope="col">{translateNow("source.connector.8f0d706fff")}</th>
                      <th scope="col">{translateNow("source.id.3843971dcf")}</th>
                      <th scope="col">{translateNow("source.created.d70b9e24bc")}</th>
                      <th scope="col">{translateNow("source.actions.ff8059dc67")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {targets.map((target) => (
                      <tr key={target.id} className="align-top">
                        <td>{target.name}</td>
                        <td className="font-mono text-xs">{target.connector}</td>
                        <td className="break-all font-mono text-xs">{target.id}</td>
                        <td>{formatDateTime(target.created_at)}</td>
                        <td>
                          <div className="flex flex-wrap gap-2">
                            <Button type="button" size="sm" variant="outline" onClick={() => openEdit(target)}>
                              {translateNow("source.edit.value1.b3cfc66057", { value1: target.name })}
                            </Button>
                            <Button type="button" size="sm" variant="destructive-outline" onClick={() => openDelete(target)}>
                              {translateNow("source.delete.value1.ff5250d441", { value1: target.name })}
                            </Button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )
          )}
        </section>
      )}

      {targets && (
        <section aria-labelledby="target-actions-heading" className="grid gap-3 border-y border-border py-4">
          <div>
            <h2 id="target-actions-heading" className="text-title font-semibold">
              {translateNow("source.target.actions.4d6d059ed8")}
            </h2>
          </div>
          <div className="ui-panel grid gap-3 md:grid-cols-3">
            <label className="grid gap-1 text-sm">
              {translateNow("source.target.978354db0c")}
              <select className="ui-input" value={selectedTarget} onChange={(event) => setSelectedTarget(event.target.value)}>
                <option value="">{translateNow("source.select.target.adfbe7a33d")}</option>
                {targets.map((target) => (
                  <option key={target.id} value={target.id}>
                    {target.name}
                  </option>
                ))}
              </select>
            </label>
            <label className="grid gap-1 text-sm">
              {translateNow("source.identity.999f23fcd7")}
              <select className="ui-input" value={selectedIdentity} onChange={(event) => setSelectedIdentity(event.target.value)}>
                <option value="">{translateNow("source.select.identity.1b8c8195aa")}</option>
                {identities.map((identity) => (
                  <option key={identity.id} value={identity.id}>
                    {identity.name}
                  </option>
                ))}
              </select>
            </label>
            <label className="grid gap-1 text-sm">
              {translateNow("source.reason.f81ab834de")}
              <input className="ui-input" value={reason} onChange={(event) => setReason(event.target.value)} />
            </label>
            <div className="flex flex-wrap gap-2 md:col-span-3">
              <Button type="button" onClick={() => runTargetAction("bind")} disabled={!selectedTarget || !selectedIdentity}>
                {translateNow("source.bind.56b9b63d28")}
              </Button>
              <Button type="button" onClick={() => runTargetAction("test")} disabled={!selectedTarget}>
                {translateNow("source.test.532eaabd95")}
              </Button>
              <Button type="button" onClick={() => runTargetAction("deploy")} disabled={!selectedTarget || !selectedIdentity}>
                {translateNow("source.deploy.4c236daafb")}
              </Button>
              <Button type="button" onClick={() => runTargetAction("rollback")} disabled={!selectedTarget}>
                {translateNow("source.rollback.c591f55749")}
              </Button>
            </div>
            {actionResult && <output className="font-mono text-xs text-muted-foreground md:col-span-3">{actionResult}</output>}
          </div>
        </section>
      )}

      {catalog && (
        <section aria-labelledby="connectors-registry-heading" className="grid gap-3 border-y border-border py-4">
          <div>
            <h2 id="connectors-registry-heading" className="text-title font-semibold">
              {translateNow("source.connector.registry.714802c316")}
            </h2>
          </div>
          {catalog.length === 0 ? (
            <EmptyState title={translateNow("source.no.connectors.registered.3752f19e55")}>
              {translateNow("source.no.connector.catalog.rows.were.returned.3a8d5bf05f")}
            </EmptyState>
          ) : (
            <div className="ui-panel overflow-x-auto">
              <table className="ui-table min-w-[54rem]">
                <caption className="sr-only">{translateNow("source.connector.registry.714802c316")}</caption>
                <thead>
                  <tr>
                    <th scope="col">{translateNow("source.connector.8f0d706fff")}</th>
                    <th scope="col">{translateNow("source.kind.f5387f9bb6")}</th>
                    <th scope="col">{translateNow("source.delivery.mode.c9585346ea")}</th>
                    <th scope="col">{translateNow("source.executes.on.a3vant0001")}</th>
                    <th scope="col">{translateNow("source.rollback.evidence.bf960c995c")}</th>
                    <th scope="col">{translateNow("source.device.proof.e1dev00001")}</th>
                    <th scope="col">{translateNow("source.relay.migration.e1par00001")}</th>
                  </tr>
                </thead>
                <tbody>
                  {catalog.map((connector) => (
                    <tr key={connector.name} className="align-top">
                      <td className="font-mono text-xs font-semibold">{connector.name}</td>
                      <td>{connector.kind}</td>
                      <td>{connector.delivery_mode}</td>
                      <td>
                        <VantageBadge vantage={connector.target_vantage} />
                      </td>
                      <td>
                        {/* D4: whether trstctl PERFORMS the rollback beside it
                            or only describes it. An operator reaching for this
                            during an incident needs the difference before they
                            reach, not after. */}
                        <span className={connector.executes_rollback ? "font-medium text-status-success" : "text-muted-foreground"}>
                          {connector.executes_rollback ? translateNow("source.executes.rebind.d4rb000003") : translateNow("source.manual.procedure.d4rb000004")}
                        </span>
                        <span className="mt-1 block text-xs text-muted-foreground">{connector.rollback}</span>
                      </td>
                      {/* E1: whether this family's deploy is exercised against a
                          faithful double of its device API, not only the
                          in-memory conformance suite every connector passes.
                          For an appliance the whole implementation IS an API
                          conversation, so conformance alone says nothing about
                          whether the device would have accepted the call. */}
                      <td className="max-w-[30rem]">
                        {connector.device_proven ? (
                          <span className="font-medium text-status-success">{translateNow("source.device.proven.e1dev00002")}</span>
                        ) : connector.target_vantage === "network_relay" ? (
                          <span className="text-status-warning">{translateNow("source.device.unproven.e1dev00003")}</span>
                        ) : (
                          /* Not a gap on a host connector: it writes files and
                             reloads a service, so there is no device API to
                             emulate and this is simply not the proof that
                             covers it. */
                          <span className="text-muted-foreground">{translateNow("source.device.not.applicable.e1dev00004")}</span>
                        )}
                        {/* E3: what that proof actually covers. The API contract
                            and the limits, never a firmware range — nothing here
                            runs against a device, and a version number would be
                            the one line on this page an operator plans a
                            migration around. */}
                        {connector.support ? (
                          <>
                            <span className="mt-1 block text-xs text-muted-foreground">{connector.support.api_contract}</span>
                            {connector.support.known_limits.length > 0 ? (
                              <ul className="mt-1 list-disc pl-4 text-xs text-muted-foreground">
                                {connector.support.known_limits.map((limit) => (
                                  <li key={limit}>{limit}</li>
                                ))}
                              </ul>
                            ) : null}
                            {!connector.support.hardware_tested ? (
                              <span className="mt-1 block text-xs text-status-warning">{translateNow("source.no.hardware.tested.e3sup00001")}</span>
                            ) : null}
                          </>
                        ) : null}
                      </td>
                      {/* E1: the relay migration, per family.
                          The honest headline is that none of the seven is
                          migrated, and the reason is named rather than
                          summarised: cisco is held back by having no rollback
                          and no readback, f5 by HA-peer sync, and all of them by
                          the control plane still executing their deploys. A
                          percentage would let a reader assume the remainder is
                          small and alike. */}
                      <td className="max-w-[26rem]">
                        {!connector.relay_parity ? (
                          /* Not an appliance. There is no relay migration for a
                             connector that writes files on a host, so silence
                             here is accurate rather than a gap. */
                          <span className="text-muted-foreground">
                            {translateNow("source.parity.not.applicable.e1par00002")}
                          </span>
                        ) : connector.relay_parity.relay_migrated ? (
                          <span className="font-medium text-status-success">
                            {translateNow("source.relay.migrated.e1par00003")}
                          </span>
                        ) : connector.relay_parity.cp_retained ? (
                          /* Terminal by the E1 scope decision, not pending: the
                             device API cannot express rollback/readback, so the
                             proven control-plane path stays. Rendered neutral,
                             not warning — a warning says "act", and there is
                             nothing to act on. */
                          <>
                            <span className="font-medium">
                              {translateNow("source.cp.retained.e1par00006")}
                            </span>
                            {connector.relay_parity.scope_note ? (
                              <span className="mt-1 block text-xs text-muted-foreground">
                                {connector.relay_parity.scope_note}
                              </span>
                            ) : null}
                          </>
                        ) : (
                          <>
                            <span className="text-status-warning">
                              {translateNow("source.not.migrated.e1par00004")}
                            </span>
                            <ul className="mt-1 list-disc pl-4 text-xs text-muted-foreground">
                              {connector.relay_parity.missing.map((gate) => (
                                <li key={gate}>{gate}</li>
                              ))}
                            </ul>
                          </>
                        )}
                        {connector.relay_parity && connector.relay_parity.outstanding.length > 0 ? (
                          <span className="mt-1 block text-xs text-muted-foreground">
                            {translateNow("source.outstanding.gates.e1par00005")}{" "}
                            {connector.relay_parity.outstanding.join(", ")}
                          </span>
                        ) : null}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      )}

      {deliveries && (
        <section aria-labelledby="delivery-receipts-heading" className="grid gap-3 border-y border-border py-4">
          {/* D2: what the listeners are actually SERVING.
          Deliberately its own section rather than a column on the delivery
          receipts below. A receipt records what this control plane DID; these
          rows record what a handshake FOUND, and the two do not join reliably —
          an appliance probed by a relay has no delivery receipt at all, and
          hiding it inside one would make the only witness for appliances
          invisible. */}
          {/* B2: the migration view. Rendered whenever targets exist, including when
          NONE have migrated — an operator planning a custody migration needs to
          see the work remaining, and a panel that appeared only once the work
          was done would be a trophy rather than a tool. */}
          {keyCustody && (keyCustody.items?.length ?? 0) > 0 ? (
            <section aria-labelledby="endpoint-custody-heading" className="space-y-3">
              <div>
                <h2 id="endpoint-custody-heading" className="text-title font-semibold">
                  {translateNow("source.endpoint.key.custody.b2cus00001")}
                </h2>
                <p className="mt-1 max-w-4xl text-caption text-muted-foreground">{translateNow("source.endpoint.key.custody.help.b2cus00002")}</p>
                <p className="mt-2 text-caption text-muted-foreground">
                  {translateNow("source.endpoint.key.custody.summary.b2cus00003", {
                    value1: String(keyCustody.summary.host_generated),
                    value2: String(keyCustody.summary.targets),
                    value3: String(keyCustody.summary.migrated_percent),
                  })}
                </p>
              </div>
              <div className="ui-panel overflow-x-auto">
                <table className="ui-table min-w-[56rem]">
                  <caption className="sr-only">{translateNow("source.endpoint.key.custody.caption.b2cus00004")}</caption>
                  <thead>
                    <tr>
                      <th scope="col">{translateNow("source.target.b2cus00005")}</th>
                      <th scope="col">{translateNow("source.connector.b2cus00006")}</th>
                      <th scope="col">{translateNow("source.key.generated.by.b2cus00007")}</th>
                      <th scope="col">{translateNow("source.last.renewed.by.b2cus00012")}</th>
                      <th scope="col">{translateNow("source.status.920e413c7d")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(keyCustody.items ?? []).map((row) => (
                      <tr key={row.target_id} className="align-top">
                        <td className="font-mono text-xs">{row.name}</td>
                        <td className="text-xs text-muted-foreground">{row.connector}</td>
                        <td>
                          {row.executor === "agent" ? (
                            <span className="font-medium text-status-success">{translateNow("source.key.origin.host.agent.b2cus00008")}</span>
                          ) : (
                            /* Deliberately NOT styled as an error. A control-plane
                           key is the supported path today; painting a working
                           estate red teaches operators to ignore the colour. */
                            <span className="text-muted-foreground">{translateNow("source.key.origin.control.plane.b2cus00009")}</span>
                          )}
                          <span className="mt-1 block text-xs text-muted-foreground">{row.detail}</span>
                        </td>
                        {/* Who last DID it, not who is responsible for it. A
                            target is not bound to a named agent — claiming is by
                            role — so an assignment column here would imply a
                            guarantee this system does not make. */}
                        <td className="text-xs text-muted-foreground">
                          {row.last_executed_by_agent ? (
                            <>
                              <span className="font-mono">{row.last_executed_by_agent}</span>
                              {row.last_executed_at ? <span className="mt-1 block">{formatDateTime(row.last_executed_at)}</span> : null}
                            </>
                          ) : (
                            translateNow("source.not.observed.b2cus00013")
                          )}
                        </td>
                        <td className="text-xs text-muted-foreground">
                          {row.enabled ? translateNow("source.enabled.b2cus00010") : translateNow("source.disabled.b2cus00011")}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          ) : null}

          {endpointVerifications.length > 0 ? (
            <section aria-labelledby="endpoint-verification-heading" className="space-y-3">
              <div>
                <h2 id="endpoint-verification-heading" className="text-title font-semibold">
                  {translateNow("source.endpoint.verification.d2ver00001")}
                </h2>
                <p className="mt-1 max-w-4xl text-caption text-muted-foreground">{translateNow("source.endpoint.verification.help.d2ver00002")}</p>
              </div>
              <div className="ui-panel overflow-x-auto">
                <table className="ui-table min-w-[72rem]">
                  <caption className="sr-only">{translateNow("source.endpoint.verification.caption.d2ver00003")}</caption>
                  <thead>
                    <tr>
                      <th scope="col">{translateNow("source.endpoint.d2ver00004")}</th>
                      <th scope="col">{translateNow("source.vantage.d2ver00005")}</th>
                      <th scope="col">{translateNow("source.status.920e413c7d")}</th>
                      <th scope="col">{translateNow("source.checked.d2ver00006")}</th>
                      <th scope="col">{translateNow("source.last.good.d2ver00007")}</th>
                      <th scope="col">{translateNow("source.last.checked.d2ver00008")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {endpointVerifications.map((row) => (
                      <tr key={`${row.endpoint_id}:${row.vantage}`} className="align-top">
                        <td className="font-mono text-xs">{row.address}</td>
                        <td>{row.vantage === "local" ? translateNow("source.vantage.local.d2ver00009") : translateNow("source.vantage.relay.d2ver00010")}</td>
                        <td className="max-w-[24rem]">
                          {row.status === "verified" ? (
                            <span className="font-medium text-status-success">{translateNow("source.verified.d2ver00011")}</span>
                          ) : row.status === "unreachable" ? (
                            <span className="text-status-warning">{translateNow("source.unreachable.d2ver00012")}</span>
                          ) : (
                            <span className="font-medium text-destructive">
                              {row.mismatch
                                ? translateNow("source.diverged.class.d2ver00018", { value1: row.mismatch })
                                : translateNow("source.diverged.d2ver00013")}
                            </span>
                          )}
                          {row.detail ? <span className="mt-1 block text-xs text-muted-foreground">{row.detail}</span> : null}
                        </td>
                        {/* What was actually compared. A "verified" that only
                        matched a fingerprint is a narrower claim than one that
                        also checked the name set and chain, and the surface
                        says which rather than letting the reader assume. */}
                        <td className="text-xs text-muted-foreground">
                          {[
                            translateNow("source.checked.fingerprint.d2ver00014"),
                            row.checked_sans ? translateNow("source.checked.names.d2ver00015") : null,
                            row.checked_chain ? translateNow("source.checked.chain.d2ver00016") : null,
                          ]
                            .filter(Boolean)
                            .join(", ")}
                        </td>
                        {/* Never good is a much stronger statement than "not
                        recently", and it reads as one. */}
                        <td>
                          {row.last_good_at ? (
                            formatDateTimePolicy(row.last_good_at)
                          ) : (
                            <span className="font-medium text-destructive">{translateNow("source.never.verified.d2ver00017")}</span>
                          )}
                        </td>
                        <td className="text-muted-foreground">{row.last_checked_at ? formatDateTimePolicy(row.last_checked_at) : "-"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          ) : null}

          <div>
            <h2 id="delivery-receipts-heading" className="text-title font-semibold">
              {translateNow("source.recent.delivery.receipts.a9cb8f42a9")}
            </h2>
          </div>
          {deliveries.length === 0 ? (
            <EmptyState title={translateNow("source.no.connector.delivery.receipts.b8aaf68b4d")}>
              {translateNow("source.no.deploy.outbox.attempt.has.produced.a.re.6e3133a027")}
            </EmptyState>
          ) : (
            <>
              <div className="ui-panel overflow-x-auto">
                <table className="ui-table min-w-[80rem]">
                  <caption className="sr-only">{translateNow("source.recent.connector.delivery.receipts.3a2bf7db18")}</caption>
                  <thead>
                    <tr>
                      <th scope="col">{translateNow("source.status.920e413c7d")}</th>
                      <th scope="col">{translateNow("source.connector.8f0d706fff")}</th>
                      <th scope="col">{translateNow("source.destination.293d404a50")}</th>
                      <th scope="col">{translateNow("source.target.978354db0c")}</th>
                      <th scope="col">{translateNow("source.attempts.06e70139fc")}</th>
                      <th scope="col">{translateNow("source.fingerprint.ba7af0b704")}</th>
                      <th scope="col">{translateNow("source.reason.f81ab834de")}</th>
                      <th scope="col">{translateNow("source.rollback.c591f55749")}</th>
                      <th scope="col">{translateNow("source.actions.ff8059dc67")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {deliveries.map((receipt) => (
                      <tr key={receipt.id} className="align-top">
                        <td>
                          <StatusBadge value={receipt.status} vocabulary="delivery" tone={deliveryStatusTone(receipt.status)} />
                        </td>
                        <td>{receipt.connector}</td>
                        <td className="font-mono text-xs">{receipt.destination}</td>
                        <td>{receipt.target}</td>
                        <td>{receipt.attempts}</td>
                        <td className="break-all font-mono text-xs">{receipt.fingerprint || "-"}</td>
                        <td>{receipt.reason || receipt.detail || "-"}</td>
                        <td>{receipt.rollback_ref || "-"}</td>
                        <td>
                          <Button type="button" size="sm" variant="outline" onClick={() => setDeliveryDetail(receipt)}>
                            {t("parity.details_dc3dec")}
                          </Button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              {deliveriesCursor && (
                <div>
                  <Button type="button" size="sm" variant="outline" disabled={deliveriesLoadingMore} onClick={() => void loadMoreDeliveries()}>
                    {deliveriesLoadingMore ? translateNow("source.loading.more.receipts.967013adf8") : translateNow("source.load.more.receipts.8f4d8130d6")}
                  </Button>
                </div>
              )}
            </>
          )}
        </section>
      )}

      {circuits && (
        <section aria-labelledby="outbox-circuits-heading" className="grid gap-3 border-y border-border py-4">
          <div>
            <h2 id="outbox-circuits-heading" className="text-title font-semibold">
              {t("parity.outboxCircuitBreakers_278ec6")}
            </h2>
            <p className="text-sm text-muted-foreground">
              Per-destination outbox breaker state; open circuits pause external deliveries until the cool-off passes.
            </p>
          </div>
          {circuits.length === 0 ? (
            <EmptyState title={t("parity.noOutboxCircuitBreakers_b8a7be")}>{t("parity.noOutboxDestinationHasRecordedCircuit_1c248f")}</EmptyState>
          ) : (
            <div className="ui-panel overflow-x-auto">
              <table className="ui-table min-w-[48rem]">
                <caption className="sr-only">{t("parity.outboxCircuitBreakers_278ec6")}</caption>
                <thead>
                  <tr>
                    <th scope="col">{translateNow("source.destination.293d404a50")}</th>
                    <th scope="col">{translateNow("source.state.a3b50c4767")}</th>
                    <th scope="col">{t("parity.failures_3eec15")}</th>
                    <th scope="col">{t("parity.openUntil_5c3e00")}</th>
                    <th scope="col">{t("parity.lastError_5e4df8")}</th>
                    <th scope="col">{translateNow("source.updated.3a5ecca188")}</th>
                  </tr>
                </thead>
                <tbody>
                  {circuits.map((circuit) => (
                    <tr key={circuit.destination} className="align-top">
                      <td className="font-mono text-xs">{circuit.destination}</td>
                      <td>
                        <StatusBadge value={circuit.state} label={circuit.state} tone={circuitStateTone(circuit.state)} />
                      </td>
                      <td>{circuit.failures}</td>
                      <td>{circuit.open_until ? formatDateTime(circuit.open_until) : "-"}</td>
                      <td className="break-words">{circuit.last_error || "-"}</td>
                      <td>{formatDateTime(circuit.updated_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      )}

      {editTarget && (
        <Dialog
          open
          onClose={closeEdit}
          titleId="target-edit-heading"
          descriptionId="target-edit-description"
          initialFocusRef={editNameRef}
          className="fixed inset-0 z-50 flex items-center justify-center p-4"
          overlayClassName="absolute inset-0 bg-black/55"
          panelClassName="relative max-h-[calc(100vh-2rem)] w-full max-w-lg overflow-y-auto rounded-panel border border-border bg-card shadow-elevation2"
        >
          <header className="border-b border-border px-5 py-4">
            <h2 id="target-edit-heading" className="text-title font-semibold">
              {translateNow("source.edit.target.value1.28751a7b9e", { value1: editTarget.name })}
            </h2>
            <p id="target-edit-description" className="mt-1 text-sm text-muted-foreground">
              {t("parity.updateTheConnectorTargetNameConnector_1dafe2")}
            </p>
          </header>
          <form aria-label={t("parity.editConnectorTarget_6063fb")} className="grid gap-4 p-5" onSubmit={(event) => void submitEdit(event)}>
            <label className="grid gap-1 text-body font-medium">
              {t("parity.targetName_f2f724")}
              <input
                ref={editNameRef}
                className="min-h-9 rounded-control border border-border bg-background px-3 py-2 text-body"
                value={editName}
                onChange={(event) => setEditName(event.target.value)}
                required
              />
            </label>
            <label className="grid gap-1 text-body font-medium">
              {t("parity.targetConnector_99a265")}
              <select
                className="min-h-9 rounded-control border border-border bg-background px-3 py-2 text-body"
                value={editConnector}
                onChange={(event) => setEditConnector(event.target.value)}
              >
                {(connectorOptions.includes(editConnector) ? connectorOptions : [editConnector, ...connectorOptions]).map((name) => (
                  <option key={name} value={name}>
                    {name}
                  </option>
                ))}
              </select>
            </label>
            <label className="grid gap-1 text-body font-medium">
              {t("parity.targetConfigJson_68839a")}
              <textarea
                className="min-h-24 rounded-control border border-border bg-background px-3 py-2 font-mono text-xs"
                value={editConfig}
                onChange={(event) => setEditConfig(event.target.value)}
              />
            </label>
            {editError && (
              <p role="alert" className="text-sm text-destructive">
                {editError}
              </p>
            )}
            <div className="flex justify-end gap-2">
              <Button type="button" variant="outline" onClick={closeEdit}>
                {translateNow("source.cancel.19766ed6cc")}
              </Button>
              <Button type="submit" disabled={editBusy}>
                {t("parity.saveTarget_fa5df1")}
              </Button>
            </div>
          </form>
        </Dialog>
      )}

      {deleteTarget && (
        <Dialog
          open
          role="alertdialog"
          onClose={closeDelete}
          titleId="target-delete-heading"
          descriptionId="target-delete-description"
          initialFocusRef={deleteConfirmRef}
          className="fixed inset-0 z-50 flex items-center justify-center p-4"
          overlayClassName="absolute inset-0 bg-black/55"
          panelClassName="relative w-full max-w-md rounded-panel border border-destructive/40 bg-card p-4 shadow-elevation2"
        >
          <h2 id="target-delete-heading" className="text-title font-semibold text-destructive">
            {translateNow("source.delete.target.value1.e2c7d587e4", { value1: deleteTarget.name })}
          </h2>
          <p id="target-delete-description" className="mt-1 text-sm text-destructive">
            {translateNow("source.deleting.value1.removes.the.connector.targ.b3256fdde9", { value1: deleteTarget.name })}
          </p>
          <label className="mt-3 grid gap-1 text-body font-medium text-destructive">
            {t("parity.typeTargetNameToConfirm_aedaad")}
            <input
              ref={deleteConfirmRef}
              value={deleteConfirmName}
              onChange={(event) => setDeleteConfirmName(event.target.value)}
              placeholder={deleteTarget.name}
              className="min-h-9 rounded-control border border-destructive/40 bg-background px-3 py-2 text-body text-foreground"
            />
          </label>
          {deleteError && (
            <p role="alert" className="mt-2 text-sm text-destructive">
              {deleteError}
            </p>
          )}
          <div className="mt-3 flex gap-2">
            <Button
              type="button"
              size="sm"
              variant="destructive"
              loading={deleteBusy}
              disabled={deleteConfirmName.trim() !== deleteTarget.name}
              onClick={() => void confirmDelete()}
            >
              {t("parity.yesDeleteTarget_729269")}
            </Button>
            <Button type="button" size="sm" variant="ghost" onClick={closeDelete}>
              {translateNow("source.cancel.19766ed6cc")}
            </Button>
          </div>
        </Dialog>
      )}

      {deliveryDetail && (
        <Dialog
          open
          onClose={() => setDeliveryDetail(null)}
          titleId="delivery-detail-heading"
          descriptionId="delivery-detail-description"
          className="fixed inset-0 z-50 flex items-center justify-center p-4"
          overlayClassName="absolute inset-0 bg-black/55"
          panelClassName="relative max-h-[calc(100vh-2rem)] w-full max-w-2xl overflow-y-auto rounded-panel border border-border bg-card shadow-elevation2"
        >
          <header className="border-b border-border px-5 py-4">
            <h2 id="delivery-detail-heading" className="text-title font-semibold">
              {translateNow("source.delivery.receipt.value1.0b61c0292f", { value1: deliveryDetail.id })}
            </h2>
            <p id="delivery-detail-description" className="mt-1 text-sm text-muted-foreground">
              {t("parity.fullConnectorDeliveryReceiptEvidenceIncluding_080df5")}
            </p>
          </header>
          <dl className="grid gap-2 p-5 text-sm">
            <ConnectorDetailRow term="ID" mono>
              {deliveryDetail.id}
            </ConnectorDetailRow>
            <ConnectorDetailRow term="Status">
              <StatusBadge value={deliveryDetail.status} vocabulary="delivery" tone={deliveryStatusTone(deliveryDetail.status)} />
            </ConnectorDetailRow>
            <ConnectorDetailRow term="Connector">{deliveryDetail.connector}</ConnectorDetailRow>
            <ConnectorDetailRow term="Target">{deliveryDetail.target}</ConnectorDetailRow>
            <ConnectorDetailRow term="Destination" mono>
              {deliveryDetail.destination}
            </ConnectorDetailRow>
            <ConnectorDetailRow term="Attempts">{deliveryDetail.attempts}</ConnectorDetailRow>
            <ConnectorDetailRow term="Identity" mono>
              {deliveryDetail.identity_id || "-"}
            </ConnectorDetailRow>
            <ConnectorDetailRow term="Fingerprint" mono>
              {deliveryDetail.fingerprint || "-"}
            </ConnectorDetailRow>
            <ConnectorDetailRow term="Reason">{deliveryDetail.reason || "-"}</ConnectorDetailRow>
            <ConnectorDetailRow term="Detail">{deliveryDetail.detail || "-"}</ConnectorDetailRow>
            <ConnectorDetailRow term="Rollback ref" mono>
              {deliveryDetail.rollback_ref || "-"}
            </ConnectorDetailRow>
            <ConnectorDetailRow term="Idempotency key" mono>
              {deliveryDetail.idempotency_key || "-"}
            </ConnectorDetailRow>
            <ConnectorDetailRow term="Outbox ID">{deliveryDetail.outbox_id != null ? String(deliveryDetail.outbox_id) : "-"}</ConnectorDetailRow>
            <ConnectorDetailRow term="Tenant" mono>
              {deliveryDetail.tenant_id}
            </ConnectorDetailRow>
            <ConnectorDetailRow term="Created">{formatDateTime(deliveryDetail.created_at)}</ConnectorDetailRow>
            <ConnectorDetailRow term="Updated">{formatDateTime(deliveryDetail.updated_at)}</ConnectorDetailRow>
          </dl>
          <div className="flex justify-end border-t border-border px-5 py-4">
            <Button type="button" variant="outline" onClick={() => setDeliveryDetail(null)}>
              {translateNow("source.close.7d9eb7acb1")}
            </Button>
          </div>
        </Dialog>
      )}
    </section>
  );
}

function ConnectorDetailRow({ children, mono = false, term }: { term: string; children: ReactNode; mono?: boolean }) {
  return (
    <div className="grid gap-1 sm:grid-cols-[11rem_1fr] sm:gap-2">
      <dt className="font-medium text-muted-foreground">{term}</dt>
      <dd className={mono ? "break-all font-mono text-xs" : "break-words"}>{children}</dd>
    </div>
  );
}

// Tones come from the shared delivery vocabulary so the console cannot paint a
// status greener than the served claim (internal/servedstatus). Only `delivered`
// earns success here: config_validated never contacted the target and
// rollback_recorded never restored anything.
function deliveryStatusTone(status: ConnectorDelivery["status"]) {
  return describeStatus("delivery", status).tone;
}

function circuitStateTone(state: OutboxCircuit["state"]) {
  if (state === "closed") return "success";
  if (state === "open") return "critical";
  return "warning";
}
