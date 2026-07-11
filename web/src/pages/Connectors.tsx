import { type FormEvent, type ReactNode, useEffect, useMemo, useRef, useState } from "react";
import { Dialog } from "@/components/Dialog";
import { PageHeader } from "@/components/PageHeader";
import { EmptyState } from "@/components/EmptyState";
import { ErrorState, LoadingState } from "@/components/StatePrimitives";
import { StatusBadge } from "@/components/StatusBadge";
import { useToast } from "@/components/ToastProvider";
import { Button } from "@/components/ui/button";
import { formatDateTime } from "@/i18n/format";
import { api, type ConnectorCatalogItem, type ConnectorDelivery, type DeploymentTarget, type Identity, type OutboxCircuit } from "@/lib/api";
import { useTranslation } from "@/i18n/I18nProvider";

export function Connectors() {
  const { t } = useTranslation();
  const [catalog, setCatalog] = useState<ConnectorCatalogItem[] | null>(null);
  const [targets, setTargets] = useState<DeploymentTarget[] | null>(null);
  const [identities, setIdentities] = useState<Identity[]>([]);
  const [deliveries, setDeliveries] = useState<ConnectorDelivery[] | null>(null);
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
        title="Deployment connectors"
        description="Target setup, identity binding, delivery actions, and receipt evidence from the served connector API."
      />
      <h2 className="text-title font-semibold">{t("connectors.deliveryEvidence")}</h2>

      {error && <ErrorState title="Connector workflow failed">{error}</ErrorState>}
      {!catalog && !error && <LoadingState>Loading connector workflow...</LoadingState>}

      {catalog && targets && (
        <section aria-labelledby="target-setup-heading" className="grid gap-3 border-y border-border py-4">
          <div>
            <h2 id="target-setup-heading" className="text-title font-semibold">
              Connector targets
            </h2>
          </div>
          <form aria-label="Create connector target" className="ui-panel grid gap-3 md:grid-cols-[1fr_12rem] md:items-end" onSubmit={createTarget}>
            <label className="grid gap-1 text-sm">
              Target
              <input className="ui-input" value={targetName} onChange={(event) => setTargetName(event.target.value)} required />
            </label>
            <label className="grid gap-1 text-sm">
              Connector
              <select className="ui-input" value={connectorName} onChange={(event) => setConnectorName(event.target.value)}>
                {connectorOptions.map((name) => (
                  <option key={name} value={name}>
                    {name}
                  </option>
                ))}
              </select>
            </label>
            <label className="grid gap-1 text-sm md:col-span-2">
              Config JSON
              <textarea className="ui-input min-h-24 font-mono text-xs" value={targetConfig} onChange={(event) => setTargetConfig(event.target.value)} />
            </label>
            <button className="ui-button md:col-span-2" type="submit">
              Create target
            </button>
          </form>

          <form aria-label="Create endpoint binding" className="ui-panel grid gap-3 md:grid-cols-3 md:items-end" onSubmit={createEndpointBinding}>
            <label className="grid gap-1 text-sm">
              Owner ID
              <input className="ui-input font-mono text-xs" value={bindingOwnerID} onChange={(event) => setBindingOwnerID(event.target.value)} required />
            </label>
            <label className="grid gap-1 text-sm">
              Identity DNS name
              <input className="ui-input" value={bindingIdentityName} onChange={(event) => setBindingIdentityName(event.target.value)} required />
            </label>
            <button className="ui-button" type="submit">
              Bind and enroll
            </button>
          </form>

          {targets && targets.length === 0 ? (
            <EmptyState title="No connector targets">No tenant connector targets were returned.</EmptyState>
          ) : (
            targets && (
              <div className="ui-panel overflow-x-auto">
                <table className="ui-table min-w-[60rem]">
                  <caption className="sr-only">Connector targets</caption>
                  <thead>
                    <tr>
                      <th scope="col">Target</th>
                      <th scope="col">Connector</th>
                      <th scope="col">ID</th>
                      <th scope="col">Created</th>
                      <th scope="col">Actions</th>
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
                              {`Edit ${target.name}`}
                            </Button>
                            <Button type="button" size="sm" variant="destructive-outline" onClick={() => openDelete(target)}>
                              {`Delete ${target.name}`}
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
              Target actions
            </h2>
          </div>
          <div className="ui-panel grid gap-3 md:grid-cols-3">
            <label className="grid gap-1 text-sm">
              Target
              <select className="ui-input" value={selectedTarget} onChange={(event) => setSelectedTarget(event.target.value)}>
                <option value="">Select target</option>
                {targets.map((target) => (
                  <option key={target.id} value={target.id}>
                    {target.name}
                  </option>
                ))}
              </select>
            </label>
            <label className="grid gap-1 text-sm">
              Identity
              <select className="ui-input" value={selectedIdentity} onChange={(event) => setSelectedIdentity(event.target.value)}>
                <option value="">Select identity</option>
                {identities.map((identity) => (
                  <option key={identity.id} value={identity.id}>
                    {identity.name}
                  </option>
                ))}
              </select>
            </label>
            <label className="grid gap-1 text-sm">
              Reason
              <input className="ui-input" value={reason} onChange={(event) => setReason(event.target.value)} />
            </label>
            <div className="flex flex-wrap gap-2 md:col-span-3">
              <button className="ui-button" type="button" onClick={() => runTargetAction("bind")} disabled={!selectedTarget || !selectedIdentity}>
                Bind
              </button>
              <button className="ui-button" type="button" onClick={() => runTargetAction("test")} disabled={!selectedTarget}>
                Test
              </button>
              <button className="ui-button" type="button" onClick={() => runTargetAction("deploy")} disabled={!selectedTarget || !selectedIdentity}>
                Deploy
              </button>
              <button className="ui-button" type="button" onClick={() => runTargetAction("rollback")} disabled={!selectedTarget}>
                Rollback
              </button>
            </div>
            {actionResult && <output className="font-mono text-xs text-muted-foreground md:col-span-3">{actionResult}</output>}
          </div>
        </section>
      )}

      {catalog && (
        <section aria-labelledby="connectors-registry-heading" className="grid gap-3 border-y border-border py-4">
          <div>
            <h2 id="connectors-registry-heading" className="text-title font-semibold">
              Connector registry
            </h2>
          </div>
          {catalog.length === 0 ? (
            <EmptyState title="No connectors registered">No connector catalog rows were returned.</EmptyState>
          ) : (
            <div className="ui-panel overflow-x-auto">
              <table className="ui-table min-w-[54rem]">
                <caption className="sr-only">Connector registry</caption>
                <thead>
                  <tr>
                    <th scope="col">Connector</th>
                    <th scope="col">Kind</th>
                    <th scope="col">Delivery mode</th>
                    <th scope="col">Rollback evidence</th>
                  </tr>
                </thead>
                <tbody>
                  {catalog.map((connector) => (
                    <tr key={connector.name} className="align-top">
                      <td className="font-mono text-xs font-semibold">{connector.name}</td>
                      <td>{connector.kind}</td>
                      <td>{connector.delivery_mode}</td>
                      <td>{connector.rollback}</td>
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
          <div>
            <h2 id="delivery-receipts-heading" className="text-title font-semibold">
              Recent delivery receipts
            </h2>
          </div>
          {deliveries.length === 0 ? (
            <EmptyState title="No connector delivery receipts">No deploy outbox attempt has produced a receipt yet.</EmptyState>
          ) : (
            <>
              <div className="ui-panel overflow-x-auto">
                <table className="ui-table min-w-[80rem]">
                  <caption className="sr-only">Recent connector delivery receipts</caption>
                  <thead>
                    <tr>
                      <th scope="col">Status</th>
                      <th scope="col">Connector</th>
                      <th scope="col">Destination</th>
                      <th scope="col">Target</th>
                      <th scope="col">Attempts</th>
                      <th scope="col">Fingerprint</th>
                      <th scope="col">Reason</th>
                      <th scope="col">Rollback</th>
                      <th scope="col">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {deliveries.map((receipt) => (
                      <tr key={receipt.id} className="align-top">
                        <td>
                          <StatusBadge value={receipt.status} label={receipt.status} tone={deliveryStatusTone(receipt.status)} />
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
                    {deliveriesLoadingMore ? "Loading more receipts..." : "Load more receipts"}
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
                    <th scope="col">Destination</th>
                    <th scope="col">State</th>
                    <th scope="col">{t("parity.failures_3eec15")}</th>
                    <th scope="col">{t("parity.openUntil_5c3e00")}</th>
                    <th scope="col">{t("parity.lastError_5e4df8")}</th>
                    <th scope="col">Updated</th>
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
              {`Edit target ${editTarget.name}`}
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
                Cancel
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
            {`Delete target “${deleteTarget.name}”?`}
          </h2>
          <p id="target-delete-description" className="mt-1 text-sm text-destructive">
            {`Deleting “${deleteTarget.name}” removes the connector target from deployment routing. This cannot be undone.`}
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
              Cancel
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
              {`Delivery receipt ${deliveryDetail.id}`}
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
              <StatusBadge value={deliveryDetail.status} label={deliveryDetail.status} tone={deliveryStatusTone(deliveryDetail.status)} />
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
              Close
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

function deliveryStatusTone(status: ConnectorDelivery["status"]) {
  if (status === "delivered" || status === "test_succeeded") return "success";
  if (status === "failed") return "critical";
  if (status === "queued") return "warning";
  return "neutral";
}

function circuitStateTone(state: OutboxCircuit["state"]) {
  if (state === "closed") return "success";
  if (state === "open") return "critical";
  return "warning";
}
