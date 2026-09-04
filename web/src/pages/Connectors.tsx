import { type FormEvent, type ReactNode, useEffect, useMemo, useRef, useState } from "react";
import { Dialog } from "@/components/Dialog";
import { PageHeader } from "@/components/PageHeader";
import { EmptyState } from "@/components/EmptyState";
import { ErrorState, LoadingState } from "@/components/StatePrimitives";
import { StatusBadge } from "@/components/StatusBadge";
import { describeStatus, type StatusTone } from "@/lib/statusVocab";
import { useToast } from "@/components/ToastProvider";
import { Button } from "@/components/ui/button";
import { formatDateTime, formatDateTime as formatDateTimePolicy } from "@/i18n/format";
import {
  api,
  type ConnectorCatalogItem,
  type RelayPluginRuntime,
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
    return <span className="text-xs font-medium text-muted-foreground">{translateNow("source.vantage.host.a3vant0002")}</span>;
  }
  if (vantage === "network_relay") {
    return <span className="text-xs font-medium text-status-warning">{translateNow("source.vantage.relay.a3vant0003")}</span>;
  }
  return <span className="text-xs font-medium text-muted-foreground">{translateNow("source.vantage.control.plane.a3vant0004")}</span>;
}

export function Connectors() {
  const { t } = useTranslation();
  const [catalog, setCatalog] = useState<ConnectorCatalogItem[] | null>(null);
  const [relayPlugins, setRelayPlugins] = useState<RelayPluginRuntime[] | null>(null);
  const [relayPluginsCursor, setRelayPluginsCursor] = useState<string | undefined>(undefined);
  const [relayPluginsLoadingMore, setRelayPluginsLoadingMore] = useState(false);
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
  const [previewReceipt, setPreviewReceipt] = useState<ConnectorDelivery | null>(null);
  const [previewRefreshing, setPreviewRefreshing] = useState(false);
  const [recoveryReceipt, setRecoveryReceipt] = useState<ConnectorDelivery | null>(null);
  const [rollbackReviewOpen, setRollbackReviewOpen] = useState(false);
  const [targetActionBusy, setTargetActionBusy] = useState<"bind" | "test" | "deploy" | "rollback" | null>(null);
  const [targetName, setTargetName] = useState("edge/prod/payments");
  const [connectorName, setConnectorName] = useState("nginx");
  const [targetConfig, setTargetConfig] = useState('{"credential_ref":"connector-credential-ref","host":"edge-1.internal"}');
  const [selectedTarget, setSelectedTarget] = useState("");
  const [selectedIdentity, setSelectedIdentity] = useState("");
  const [bindingOwnerID, setBindingOwnerID] = useState("");
  const [bindingIdentityName, setBindingIdentityName] = useState("payments.example.test");
  const [reason, setReason] = useState("");
  const [targetEnabled, setTargetEnabled] = useState(false);
  const [circuits, setCircuits] = useState<OutboxCircuit[] | null>(null);
  const [deliveriesCursor, setDeliveriesCursor] = useState<string | undefined>(undefined);
  const [deliveriesLoadingMore, setDeliveriesLoadingMore] = useState(false);
  const [deliveryDetail, setDeliveryDetail] = useState<ConnectorDelivery | null>(null);
  const [editTarget, setEditTarget] = useState<DeploymentTarget | null>(null);
  const [editName, setEditName] = useState("");
  const [editConnector, setEditConnector] = useState("");
  const [editConfig, setEditConfig] = useState("{}");
  const [editEnabled, setEditEnabled] = useState(false);
  const [editError, setEditError] = useState<string | null>(null);
  const [editBusy, setEditBusy] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState<DeploymentTarget | null>(null);
  const [deleteConfirmName, setDeleteConfirmName] = useState("");
  const [deleteError, setDeleteError] = useState<string | null>(null);
  const [deleteBusy, setDeleteBusy] = useState(false);
  const [destinationOpen, setDestinationOpen] = useState(false);
  const [open, setOpen] = useState({ destinations: false, health: false, capabilities: false });
  const [destinationsLoading, setDestinationsLoading] = useState(false);
  const [destinationsError, setDestinationsError] = useState<string | null>(null);
  const [healthLoading, setHealthLoading] = useState(false);
  const [healthError, setHealthError] = useState<string | null>(null);
  const destinationNameRef = useRef<HTMLInputElement>(null);
  const editNameRef = useRef<HTMLInputElement>(null);
  const deleteConfirmRef = useRef<HTMLInputElement>(null);
  const { toast } = useToast();

  const loadSummary = async () => {
    const [catalogResult, targetResult, verificationResult] = await Promise.allSettled([
      api.connectorCatalog({ limit: 100 }),
      api.connectorTargets(),
      typeof api.endpointVerifications === "function" ? api.endpointVerifications() : Promise.resolve({ items: [] }),
    ]);
    if (catalogResult.status === "fulfilled") {
      setCatalog(catalogResult.value.items ?? []);
      setRelayPlugins(catalogResult.value.relay_plugins ?? []);
      setRelayPluginsCursor(catalogResult.value.relay_plugins_next_cursor);
      setConnectorName((current) => (catalogResult.value.items?.some((item) => item.name === current) ? current : catalogResult.value.items?.[0]?.name || ""));
    }
    if (targetResult.status === "fulfilled") {
      const loadedTargets = targetResult.value.items ?? [];
      setTargets(loadedTargets);
      setSelectedTarget((current) => (loadedTargets.some((target) => target.id === current) ? current : ""));
    }
    if (verificationResult.status === "fulfilled") setEndpointVerifications(verificationResult.value.items ?? []);
    if (catalogResult.status === "rejected" || targetResult.status === "rejected") {
      const failure = catalogResult.status === "rejected" ? catalogResult.reason : targetResult.status === "rejected" ? targetResult.reason : null;
      setError(failure instanceof Error ? failure.message : String(failure));
      return;
    }
    setError(null);
  };

  const loadDestinationEvidence = async () => {
    setDestinationsLoading(true);
    setDestinationsError(null);
    try {
      const loadedIdentities = await api.identities();
      setIdentities(loadedIdentities ?? []);
      setSelectedIdentity((current) => (loadedIdentities?.some((identity) => identity.id === current) ? current : ""));
    } catch (err) {
      setDestinationsError(err instanceof Error ? err.message : String(err));
    } finally {
      setDestinationsLoading(false);
    }
  };

  const loadHealthEvidence = async () => {
    setHealthLoading(true);
    setHealthError(null);
    const [deliveryResult, circuitResult, custodyResult, verificationResult] = await Promise.allSettled([
      api.connectorDeliveries({ limit: 20 }),
      api.outboxCircuits(),
      typeof api.endpointKeyCustody === "function"
        ? api.endpointKeyCustody()
        : Promise.resolve({ guidance: "", items: [], summary: { control_plane_generated: 0, host_generated: 0, targets: 0, migrated_percent: 0 } }),
      typeof api.endpointVerifications === "function" ? api.endpointVerifications() : Promise.resolve({ items: [] }),
    ]);
    if (deliveryResult.status === "fulfilled") {
      setDeliveries(deliveryResult.value.items ?? []);
      setDeliveriesCursor(deliveryResult.value.next_cursor);
    }
    if (circuitResult.status === "fulfilled") setCircuits(circuitResult.value.items ?? []);
    if (custodyResult.status === "fulfilled") setKeyCustody(custodyResult.value);
    if (verificationResult.status === "fulfilled") setEndpointVerifications(verificationResult.value.items ?? []);
    const failure = [deliveryResult, circuitResult, custodyResult, verificationResult].find((result) => result.status === "rejected");
    if (failure?.status === "rejected") setHealthError(failure.reason instanceof Error ? failure.reason.message : String(failure.reason));
    setHealthLoading(false);
  };

  const refresh = async () => {
    await loadSummary();
    if (open.destinations) await loadDestinationEvidence();
    if (open.health) await loadHealthEvidence();
  };

  const loadMoreRelayPlugins = async () => {
    if (!relayPluginsCursor || relayPluginsLoadingMore) return;
    setRelayPluginsLoadingMore(true);
    try {
      const next = await api.connectorCatalog({ limit: 100, cursor: relayPluginsCursor });
      setRelayPlugins((current) => [...(current ?? []), ...(next.relay_plugins ?? [])]);
      setRelayPluginsCursor(next.relay_plugins_next_cursor);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setRelayPluginsLoadingMore(false);
    }
  };

  useEffect(() => {
    let cancelled = false;
    loadSummary().catch((err) => {
      if (!cancelled) setError(err instanceof Error ? err.message : String(err));
    });
    return () => {
      cancelled = true;
    };
    // Initial route load is deliberately summary-only. Expert evidence is lazy.
  }, []);

  const connectorOptions = useMemo(() => (catalog ?? []).map((item) => item.name), [catalog]);
  const selectedTargetRecord = useMemo(() => (targets ?? []).find((target) => target.id === selectedTarget), [selectedTarget, targets]);
  const selectedConnectorRecord = useMemo(
    () => (catalog ?? []).find((connector) => connector.name === selectedTargetRecord?.connector),
    [catalog, selectedTargetRecord],
  );
  const selectedIdentityRecord = useMemo(() => identities.find((identity) => identity.id === selectedIdentity), [identities, selectedIdentity]);
  const intendedConnector = useMemo(() => {
    const value = selectedIdentityRecord?.attributes?.intended_connector;
    return typeof value === "string" ? value.trim() : "";
  }, [selectedIdentityRecord]);
  const connectorMismatch = Boolean(selectedTargetRecord && intendedConnector && intendedConnector !== selectedTargetRecord.connector);
  const targetActionBlocked = !selectedTargetRecord || !selectedTargetRecord.enabled;
  const identityActionBlocked = targetActionBlocked || !selectedIdentityRecord || connectorMismatch;
  const reasonActionBlocked = identityActionBlocked || !reason.trim();
  const actionSafetyMessage = !selectedTargetRecord
    ? null
    : !selectedTargetRecord.enabled
      ? t("connectors.targetReadiness.disabledHelp")
      : connectorMismatch
        ? t("connectors.targetReadiness.connectorMismatch", { intended: intendedConnector, connector: selectedTargetRecord.connector })
        : null;
  const selectedTargetTimeline = useMemo(() => {
    if (!selectedTargetRecord) return [];
    const receiptRows = (deliveries ?? [])
      .filter((receipt) => receipt.target === selectedTargetRecord.name)
      .map((receipt) => ({
        id: `delivery:${receipt.id}`,
        stage: receipt.destination,
        status: receipt.status,
        at: receipt.updated_at || receipt.created_at,
        detail: receipt.detail || receipt.reason || receipt.rollback_ref || "",
        actor: "",
      }));
    const verificationRows = endpointVerifications
      .filter((row) => row.endpoint_id === selectedTargetRecord.id)
      .map((row) => ({
        id: `verification:${row.endpoint_id}:${row.vantage}`,
        stage: "endpoint.verify",
        status: row.status,
        at: row.last_checked_at || "",
        detail: row.detail || row.mismatch || "",
        actor: row.agent_common_name || "",
      }));
    return [...receiptRows, ...verificationRows].sort((left, right) => Date.parse(right.at || "") - Date.parse(left.at || ""));
  }, [deliveries, endpointVerifications, selectedTargetRecord]);

  const createTarget = async (event: FormEvent) => {
    event.preventDefault();
    try {
      const config = JSON.parse(targetConfig) as Record<string, unknown>;
      const created = await api.createConnectorTarget({ name: targetName.trim(), connector: connectorName.trim(), config, enabled: targetEnabled });
      setActionResult(`target:${created.id}`);
      setSelectedTarget(created.id);
      await refresh();
      setDestinationOpen(false);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  const createEndpointBinding = async (event: FormEvent) => {
    event.preventDefault();
    try {
      const binding = await api.createEndpointBinding({
        owner_id: bindingOwnerID.trim(),
        identity_name: bindingIdentityName.trim(),
        reason: reason.trim(),
        target_id: selectedTarget,
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
    if (!selectedTarget || targetActionBlocked || targetActionBusy) return;
    if (action !== "test" && identityActionBlocked) return;
    if ((action === "deploy" || action === "rollback") && !reason.trim()) return;
    if (action === "rollback" && !selectedConnectorRecord?.executes_rollback) return;
    setTargetActionBusy(action);
    setError(null);
    try {
      if (action === "bind") {
        if (!selectedIdentity) return;
        const identity = await api.bindIdentityConnectorTarget(selectedIdentity, { target_id: selectedTarget });
        setActionResult(`bound:${identity.id}`);
      } else if (action === "test") {
        setPreviewReceipt(null);
        const receipt = await api.testConnectorTarget(selectedTarget);
        setPreviewReceipt(receipt);
        setActionResult(null);
      } else if (action === "deploy") {
        if (!selectedIdentity) return;
        const identity = await api.deployConnectorTarget(selectedTarget, { identity_id: selectedIdentity, reason: reason.trim() });
        setActionResult(`deploy:${identity.status}`);
      } else {
        setRecoveryReceipt(null);
        const receipt = await api.rollbackConnectorTarget(selectedTarget, { identity_id: selectedIdentity, reason: reason.trim() });
        setRecoveryReceipt(receipt);
        setRollbackReviewOpen(false);
        setActionResult(null);
      }
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setTargetActionBusy(null);
    }
  };

  const refreshPreviewResult = async () => {
    if (!selectedTargetRecord || !previewReceipt) return;
    setPreviewRefreshing(true);
    try {
      const page = await api.connectorDeliveries({ limit: 20 });
      const rows = page.items ?? [];
      setDeliveries(rows);
      setDeliveriesCursor(page.next_cursor);
      const resultKey = previewReceipt.idempotency_key ? `${previewReceipt.idempotency_key}:result` : "";
      const terminal = rows.find(
        (receipt) =>
          Boolean(resultKey) &&
          receipt.destination === "connector.test" &&
          receipt.target === selectedTargetRecord.name &&
          receipt.status !== "dry_run_queued" &&
          receipt.idempotency_key === resultKey,
      );
      if (terminal) setPreviewReceipt(terminal);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setPreviewRefreshing(false);
    }
  };

  const openEdit = (target: DeploymentTarget) => {
    setEditTarget(target);
    setEditName(target.name);
    setEditConnector(target.connector);
    setEditConfig(JSON.stringify(target.config ?? {}, null, 2));
    setEditEnabled(target.enabled);
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
      const updated = await api.updateConnectorTarget(editTarget.id, {
        name: editName.trim(),
        connector: editConnector.trim(),
        config,
        enabled: editEnabled,
      });
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

  const configuredTargetIDs = new Set((targets ?? []).map((target) => target.id));
  const configuredConnectorNames = new Set((targets ?? []).map((target) => target.connector));
  const verifiedTargetCount = new Set(
    endpointVerifications.filter((row) => row.status === "verified" && configuredTargetIDs.has(row.endpoint_id)).map((row) => row.endpoint_id),
  ).size;
  const rollbackConnectorCount = new Set(
    (catalog ?? []).filter((connector) => connector.executes_rollback && configuredConnectorNames.has(connector.name)).map((connector) => connector.name),
  ).size;

  return (
    <section aria-labelledby="connectors-heading" className="space-y-4">
      <PageHeader
        titleId="connectors-heading"
        title={t("connectors.design.title")}
        description={t("connectors.design.answer")}
        technicalDetails={t("connectors.design.technicalDetails")}
        actions={
          <Button type="button" onClick={() => setDestinationOpen(true)}>
            {t("connectors.design.add")}
          </Button>
        }
      />

      {error && <ErrorState title={translateNow("source.connector.workflow.failed.9b83125cd7")}>{error}</ErrorState>}
      {(!catalog || !targets) && !error ? (
        <LoadingState>{t("connectors.design.checking")}</LoadingState>
      ) : targets ? (
        <div className="ui-panel grid gap-2 p-comfortable" role="status" aria-live="polite">
          <h2 className="text-title font-semibold">
            {targets.length === 0
              ? t("connectors.design.statusEmpty")
              : targets.length === 1 && verifiedTargetCount === 1
                ? t("connectors.design.statusOneVerified")
                : verifiedTargetCount === targets.length
                  ? t("connectors.design.statusAllVerified", { targets: String(targets.length) })
                  : t("connectors.design.statusPartial", { verified: String(verifiedTargetCount), targets: String(targets.length) })}
          </h2>
          {targets.length === 0 ? (
            <p className="max-w-3xl text-sm text-muted-foreground">{t("connectors.design.statusEmptyBody")}</p>
          ) : (
            <div className="grid gap-1 text-sm text-muted-foreground">
              <p>
                {rollbackConnectorCount === 1
                  ? t("connectors.design.rollbackOne")
                  : t("connectors.design.rollbackMany", { connectors: String(rollbackConnectorCount) })}
              </p>
              {verifiedTargetCount < targets.length && <p>{t("connectors.design.verificationBoundary")}</p>}
            </div>
          )}
        </div>
      ) : null}

      <ConnectorDetails
        title={t("connectors.design.disclosure.destinations")}
        open={open.destinations}
        onToggle={(value) => {
          setOpen((current) => ({ ...current, destinations: value }));
          if (value) void loadDestinationEvidence();
        }}
      >
        <div className="grid gap-4">
          <p className="max-w-3xl text-sm text-muted-foreground">{t("connectors.design.destinationsHelp")}</p>
          {destinationsLoading && <LoadingState>{t("connectors.design.destinationsLoading")}</LoadingState>}
          {destinationsError && <ErrorState title={t("connectors.design.destinationsError")}>{destinationsError}</ErrorState>}

          {catalog && targets && (
            <section aria-labelledby="target-setup-heading" className="grid gap-3 border-y border-border py-4">
              <div>
                <h2 id="target-setup-heading" className="text-title font-semibold">
                  {t("connectors.design.configuredDestinations")}
                </h2>
              </div>
              <p className="max-w-3xl text-sm text-muted-foreground">{t("connectors.design.bindHelp")}</p>
              <form
                aria-label={translateNow("source.create.endpoint.binding.dd5b21a786")}
                className="ui-panel grid gap-3 md:grid-cols-5 md:items-end"
                onSubmit={createEndpointBinding}
              >
                <label className="grid gap-1 text-sm">
                  {t("connectors.targetReadiness.enrollmentDestination")}
                  <select className="ui-input" value={selectedTarget} onChange={(event) => setSelectedTarget(event.target.value)} required>
                    <option value="">{translateNow("source.select.target.adfbe7a33d")}</option>
                    {targets.map((target) => (
                      <option key={target.id} value={target.id}>
                        {target.name}
                        {target.enabled ? "" : t("connectors.targetReadiness.optionQualifier", { value: t("connectors.targetReadiness.disabledShort") })}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="grid gap-1 text-sm">
                  {translateNow("source.owner.id.1611f5e055")}
                  <input className="ui-input font-mono text-xs" value={bindingOwnerID} onChange={(event) => setBindingOwnerID(event.target.value)} required />
                </label>
                <label className="grid gap-1 text-sm">
                  {translateNow("source.identity.dns.name.c79a6b3b97")}
                  <input className="ui-input" value={bindingIdentityName} onChange={(event) => setBindingIdentityName(event.target.value)} required />
                </label>
                <label className="grid gap-1 text-sm">
                  {t("connectors.targetReadiness.enrollmentReason")}
                  <input className="ui-input" value={reason} onChange={(event) => setReason(event.target.value)} required />
                </label>
                <Button type="submit" disabled={targetActionBlocked || !bindingOwnerID.trim() || !bindingIdentityName.trim() || !reason.trim()}>
                  {translateNow("source.bind.and.enroll.5cb885780a")}
                </Button>
              </form>

              {targets && targets.length === 0 ? (
                <EmptyState title={translateNow("source.no.connector.targets.5a8adcf783")}>
                  {translateNow("source.no.tenant.connector.targets.were.returned.6c7baa9a8d")}
                </EmptyState>
              ) : (
                targets && (
                  <ScrollableTableRegion label={t("connectors.design.destinationsTable")}>
                    <table className="ui-table min-w-[60rem]">
                      <caption className="sr-only">{t("connectors.design.destinationsTable")}</caption>
                      <thead>
                        <tr>
                          <th scope="col">{translateNow("source.target.978354db0c")}</th>
                          <th scope="col">{translateNow("source.connector.8f0d706fff")}</th>
                          <th scope="col">{t("connectors.targetReadiness.state")}</th>
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
                            <td>
                              {target.enabled ? (
                                <span className="font-medium text-status-success">{t("connectors.targetReadiness.enabled")}</span>
                              ) : (
                                <span className="font-medium text-status-warning">{t("connectors.targetReadiness.disabledShort")}</span>
                              )}
                            </td>
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
                  </ScrollableTableRegion>
                )
              )}
            </section>
          )}

          {targets && (
            <section aria-labelledby="target-actions-heading" className="grid gap-3 border-y border-border py-4">
              <div>
                <h2 id="target-actions-heading" className="text-title font-semibold">
                  {t("connectors.actions.heading")}
                </h2>
                <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{t("connectors.actions.help")}</p>
              </div>
              <div className="ui-panel grid gap-3 md:grid-cols-3">
                <label className="grid gap-1 text-sm">
                  {translateNow("source.target.978354db0c")}
                  <select
                    className="ui-input"
                    value={selectedTarget}
                    onChange={(event) => {
                      setSelectedTarget(event.target.value);
                      setPreviewReceipt(null);
                      setRecoveryReceipt(null);
                      setRollbackReviewOpen(false);
                    }}
                  >
                    <option value="">{translateNow("source.select.target.adfbe7a33d")}</option>
                    {targets.map((target) => (
                      <option key={target.id} value={target.id}>
                        {target.name}
                        {target.enabled ? "" : t("connectors.targetReadiness.optionQualifier", { value: t("connectors.targetReadiness.disabledShort") })}
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
                        {typeof identity.attributes?.intended_connector === "string"
                          ? t("connectors.targetReadiness.optionQualifier", { value: identity.attributes.intended_connector })
                          : ""}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="grid gap-1 text-sm">
                  {translateNow("source.reason.f81ab834de")}
                  <input className="ui-input" value={reason} onChange={(event) => setReason(event.target.value)} />
                </label>
                {actionSafetyMessage ? (
                  <p
                    role="alert"
                    className="rounded-control border border-status-warning/40 bg-status-warning/10 px-3 py-2 text-sm text-foreground md:col-span-3"
                  >
                    {actionSafetyMessage}
                  </p>
                ) : null}
                <div className="flex flex-wrap gap-2 md:col-span-3">
                  <Button
                    type="button"
                    onClick={() => runTargetAction("bind")}
                    disabled={identityActionBlocked || Boolean(targetActionBusy)}
                    loading={targetActionBusy === "bind"}
                  >
                    {translateNow("source.bind.56b9b63d28")}
                  </Button>
                  <Button
                    type="button"
                    variant="outline"
                    onClick={() => runTargetAction("test")}
                    disabled={targetActionBlocked || Boolean(targetActionBusy)}
                    loading={targetActionBusy === "test"}
                  >
                    {t("connectors.preview.action")}
                  </Button>
                  <Button
                    type="button"
                    onClick={() => runTargetAction("deploy")}
                    disabled={reasonActionBlocked || Boolean(targetActionBusy)}
                    loading={targetActionBusy === "deploy"}
                  >
                    {translateNow("source.deploy.4c236daafb")}
                  </Button>
                  <Button
                    type="button"
                    variant="outline"
                    onClick={() => setRollbackReviewOpen(true)}
                    disabled={reasonActionBlocked || !selectedConnectorRecord?.executes_rollback || Boolean(targetActionBusy)}
                  >
                    {t("connectors.recovery.review")}
                  </Button>
                </div>
                {actionResult && <output className="font-mono text-xs text-muted-foreground md:col-span-3">{actionResult}</output>}
                {selectedTargetRecord && selectedConnectorRecord && !selectedConnectorRecord.executes_rollback ? (
                  <p className="text-sm text-muted-foreground md:col-span-3">{t("connectors.recovery.unavailable")}</p>
                ) : null}
                {previewReceipt ? (
                  <section
                    aria-labelledby="connector-preview-result-heading"
                    className="grid gap-2 rounded-control border border-border bg-muted/30 p-3 md:col-span-3"
                    role="status"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <h3 id="connector-preview-result-heading" className="font-semibold">
                        {previewReceipt.status === "dry_run_planned"
                          ? t("connectors.preview.ready")
                          : previewReceipt.status === "dry_run_blocked"
                            ? t("connectors.preview.blocked")
                            : previewReceipt.status === "dry_run_queued"
                              ? t("connectors.preview.queued")
                              : t("connectors.preview.localOnly")}
                      </h3>
                      <StatusBadge value={previewReceipt.status} vocabulary="delivery" tone={deliveryStatusTone(previewReceipt.status)} />
                    </div>
                    <p className="text-sm text-muted-foreground">{previewReceipt.detail || previewReceipt.reason || "-"}</p>
                    <p className="text-sm font-medium">{t("connectors.preview.zeroWriteBoundary")}</p>
                    {previewReceipt.status === "config_validated" ? (
                      <p className="text-sm text-status-warning">{t("connectors.preview.localOnlyWarning")}</p>
                    ) : null}
                    {previewReceipt.status === "dry_run_queued" && previewReceipt.idempotency_key ? (
                      <Button
                        type="button"
                        size="sm"
                        variant="outline"
                        className="justify-self-start"
                        loading={previewRefreshing}
                        onClick={() => void refreshPreviewResult()}
                      >
                        {t("connectors.preview.refresh")}
                      </Button>
                    ) : null}
                    {previewReceipt.status === "dry_run_queued" && !previewReceipt.idempotency_key ? (
                      <p className="text-sm text-status-warning">{t("connectors.preview.correlationUnavailable")}</p>
                    ) : null}
                  </section>
                ) : null}
                {recoveryReceipt ? (
                  <section
                    aria-labelledby="connector-recovery-result-heading"
                    className="grid gap-2 rounded-control border border-border bg-muted/30 p-3 md:col-span-3"
                    role="status"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <h3 id="connector-recovery-result-heading" className="font-semibold">
                        {recoveryReceipt.status === "rolled_back"
                          ? t("connectors.recovery.restored")
                          : recoveryReceipt.status === "rollback_queued"
                            ? t("connectors.recovery.queued")
                            : t("connectors.recovery.notExecuted")}
                      </h3>
                      <StatusBadge value={recoveryReceipt.status} vocabulary="delivery" tone={deliveryStatusTone(recoveryReceipt.status)} />
                    </div>
                    <p className="text-sm text-muted-foreground">{recoveryReceipt.detail || recoveryReceipt.reason || "-"}</p>
                  </section>
                ) : null}
              </div>
              {selectedTargetRecord ? (
                <section aria-labelledby="selected-target-timeline-heading" className="ui-panel grid gap-3">
                  <div>
                    <h3 id="selected-target-timeline-heading" className="font-semibold">
                      {translateNow("source.credential.activity.timeline.e03f707dcc")}
                    </h3>
                    <p className="mt-1 text-sm text-muted-foreground">
                      {translateNow("source.target.deploy.listener.verification.and.rollback.38783cea3d", { target: selectedTargetRecord.name })}
                    </p>
                  </div>
                  {selectedTargetTimeline.length === 0 ? (
                    <p className="text-sm text-muted-foreground">{translateNow("source.no.deployment.receipts.yet.439880ad78")}</p>
                  ) : (
                    <ol className="grid gap-2" data-testid="selected-target-timeline">
                      {selectedTargetTimeline.map((item) => (
                        <li key={item.id} className="grid gap-1 rounded-md border border-border p-3 sm:grid-cols-[10rem_8rem_1fr] sm:gap-3">
                          <div>
                            <p className="font-mono text-xs font-semibold">{item.stage}</p>
                            <p className="text-xs text-muted-foreground">{item.at ? formatDateTime(item.at) : "-"}</p>
                          </div>
                          <StatusBadge value={item.status} vocabulary="delivery" tone={targetTimelineStatusTone(item.stage, item.status)} />
                          <div className="text-xs text-muted-foreground">
                            {item.actor ? (
                              <p className="font-mono">
                                {translateNow("source.agent.11b39c9377")}: {item.actor}
                              </p>
                            ) : null}
                            <p>{item.detail || "-"}</p>
                          </div>
                        </li>
                      ))}
                    </ol>
                  )}
                </section>
              ) : null}
            </section>
          )}
        </div>
      </ConnectorDetails>

      <ConnectorDetails
        title={t("connectors.design.disclosure.capabilities")}
        open={open.capabilities}
        onToggle={(value) => setOpen((current) => ({ ...current, capabilities: value }))}
      >
        <div className="grid gap-4">
          <p className="max-w-3xl text-sm text-muted-foreground">{t("connectors.design.capabilitiesHelp")}</p>

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
                <ScrollableTableRegion label={t("connectors.design.capabilitiesTable")}>
                  <table className="ui-table min-w-[54rem]">
                    <caption className="sr-only">{t("connectors.design.capabilitiesTable")}</caption>
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
                              {connector.executes_rollback
                                ? translateNow("source.executes.rebind.d4rb000003")
                                : translateNow("source.manual.procedure.d4rb000004")}
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
                          {/* E1: all thirteen accepted families use the API's closed
                          disposition. The runtime executor census must never
                          decide which rows are visible: that was the AUD-33 bug. */}
                          <td className="max-w-[26rem]">
                            {!connector.relay_parity ? (
                              /* This connector is genuinely outside E1's thirteen,
                             not merely absent from the current relay binary. */
                              <span className="text-muted-foreground">{translateNow("source.parity.not.applicable.e1par00002")}</span>
                            ) : connector.relay_parity.disposition === "migrated" || connector.relay_parity.relay_migrated ? (
                              <span className="font-medium text-status-success">{translateNow("source.relay.migrated.e1par00003")}</span>
                            ) : connector.relay_parity.disposition === "architecture_exception" || connector.relay_parity.cp_retained ? (
                              <>
                                <span className="font-medium text-status-warning">{translateNow("source.cp.retained.e1par00006")}</span>
                                {connector.relay_parity.scope_note ? (
                                  <span className="mt-1 block text-xs text-muted-foreground">{connector.relay_parity.scope_note}</span>
                                ) : null}
                              </>
                            ) : (
                              <>
                                <span className="text-status-warning">{translateNow("source.not.migrated.e1par00004")}</span>
                                {connector.relay_parity.scope_note ? (
                                  <span className="mt-1 block text-xs text-muted-foreground">{connector.relay_parity.scope_note}</span>
                                ) : null}
                                <ul className="mt-1 list-disc pl-4 text-xs text-muted-foreground">
                                  {connector.relay_parity.missing.map((gate) => (
                                    <li key={gate}>{gate}</li>
                                  ))}
                                </ul>
                              </>
                            )}
                            {connector.relay_parity && connector.relay_parity.outstanding.length > 0 ? (
                              <span className="mt-1 block text-xs text-muted-foreground">
                                {translateNow("source.outstanding.gates.e1par00005")} {connector.relay_parity.outstanding.join(", ")}
                              </span>
                            ) : null}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </ScrollableTableRegion>
              )}
            </section>
          )}

          {relayPlugins && (
            <section aria-labelledby="relay-plugin-census-heading" className="grid gap-3 border-y border-border py-4">
              <div>
                <h2 id="relay-plugin-census-heading" className="text-title font-semibold">
                  {translateNow("connectors.relayPlugins.title")}
                </h2>
                <p className="mt-1 max-w-4xl text-caption text-muted-foreground">{translateNow("connectors.relayPlugins.help")}</p>
              </div>
              {relayPlugins.length === 0 ? (
                <EmptyState title={translateNow("connectors.relayPlugins.emptyTitle")}>{translateNow("connectors.relayPlugins.emptyBody")}</EmptyState>
              ) : (
                <ScrollableTableRegion label={translateNow("connectors.relayPlugins.title")}>
                  <table className="ui-table min-w-[76rem]">
                    <caption className="sr-only">{translateNow("connectors.relayPlugins.title")}</caption>
                    <thead>
                      <tr>
                        <th scope="col">{translateNow("connectors.relayPlugins.relay")}</th>
                        <th scope="col">{translateNow("connectors.relayPlugins.plugin")}</th>
                        <th scope="col">{translateNow("connectors.relayPlugins.provenance")}</th>
                        <th scope="col">{translateNow("connectors.relayPlugins.execution")}</th>
                        <th scope="col">{translateNow("connectors.relayPlugins.grant")}</th>
                        <th scope="col">{translateNow("connectors.relayPlugins.reported")}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {relayPlugins.flatMap((runtime) => {
                        // Older servers can serialize an empty Go slice as null even
                        // though the OpenAPI contract says this field is an array.
                        // Keep the evidence page usable while mixed versions upgrade.
                        const reportedPlugins = runtime.plugins ?? [];
                        const plugins = reportedPlugins.length > 0 ? reportedPlugins : [null];
                        return plugins.map((plugin) => (
                          <tr key={`${runtime.agent_id}:${plugin?.name ?? "empty"}`} className="align-top">
                            <td className="max-w-[18rem]">
                              <span className="font-mono text-xs font-semibold">{runtime.agent_name}</span>
                              <span className="mt-1 block break-all font-mono text-xs text-muted-foreground">{runtime.agent_id}</span>
                              <span className={`mt-1 block text-xs ${runtime.signature_verified ? "text-status-success" : "text-status-danger"}`}>
                                {runtime.signature_verified
                                  ? translateNow("connectors.relayPlugins.signatureVerified")
                                  : translateNow("connectors.relayPlugins.signatureUnverified")}
                              </span>
                              {runtime.metadata_only ? (
                                <span className="mt-1 block text-xs text-muted-foreground">{translateNow("connectors.relayPlugins.metadataOnly")}</span>
                              ) : null}
                              <span className="mt-1 block break-all font-mono text-xs text-muted-foreground">{runtime.signer_fingerprint}</span>
                            </td>
                            <td className="font-mono text-xs font-semibold">{plugin?.name ?? translateNow("connectors.relayPlugins.noLoadedPlugins")}</td>
                            <td className="max-w-[24rem]">
                              {plugin ? (
                                <>
                                  <span className="block break-all font-mono text-xs">{plugin.publisher}</span>
                                  <span className="mt-1 block break-all font-mono text-xs text-muted-foreground">{plugin.digest}</span>
                                </>
                              ) : null}
                            </td>
                            <td className="font-mono text-xs">{plugin?.execution_context ?? "—"}</td>
                            <td className="max-w-[22rem]">
                              {plugin?.grants.map((grant) => (
                                <span key={grant.capability} className="block text-xs">
                                  <span className="font-mono font-semibold">{grant.capability}</span>{" "}
                                  <span className="text-muted-foreground">
                                    {(grant.constraints ?? []).length > 0
                                      ? (grant.constraints ?? []).join(", ")
                                      : translateNow("connectors.relayPlugins.unrestricted")}
                                  </span>
                                </span>
                              ))}
                            </td>
                            <td className="text-xs text-muted-foreground">{formatDateTime(runtime.reported_at)}</td>
                          </tr>
                        ));
                      })}
                    </tbody>
                  </table>
                </ScrollableTableRegion>
              )}
              {relayPluginsCursor ? (
                <Button
                  type="button"
                  variant="outline"
                  className="justify-self-start"
                  disabled={relayPluginsLoadingMore}
                  onClick={() => void loadMoreRelayPlugins()}
                >
                  {relayPluginsLoadingMore ? translateNow("app.loading") : translateNow("connectors.relayPlugins.loadMore")}
                </Button>
              ) : null}
            </section>
          )}
        </div>
      </ConnectorDetails>

      <ConnectorDetails
        title={t("connectors.design.disclosure.health")}
        open={open.health}
        onToggle={(value) => {
          setOpen((current) => ({ ...current, health: value }));
          if (value) void loadHealthEvidence();
        }}
      >
        <div className="grid min-w-0 gap-4">
          <p className="max-w-3xl text-sm text-muted-foreground">{t("connectors.design.healthHelp")}</p>
          {healthLoading && <LoadingState>{t("connectors.design.healthLoading")}</LoadingState>}
          {healthError && <ErrorState title={t("connectors.design.healthError")}>{healthError}</ErrorState>}

          {deliveries && (
            <section aria-labelledby="delivery-receipts-heading" className="grid min-w-0 gap-3 border-y border-border py-4">
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
                  <ScrollableTableRegion label={translateNow("source.endpoint.key.custody.caption.b2cus00004")}>
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
                  </ScrollableTableRegion>
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
                  <ScrollableTableRegion label={translateNow("source.endpoint.verification.caption.d2ver00003")}>
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
                            <td>
                              {row.vantage === "local" ? translateNow("source.vantage.local.d2ver00009") : translateNow("source.vantage.relay.d2ver00010")}
                            </td>
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
                  </ScrollableTableRegion>
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
                  <ScrollableTableRegion label={translateNow("source.recent.connector.delivery.receipts.3a2bf7db18")}>
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
                  </ScrollableTableRegion>
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
                <ScrollableTableRegion label={t("parity.outboxCircuitBreakers_278ec6")}>
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
                </ScrollableTableRegion>
              )}
            </section>
          )}
        </div>
      </ConnectorDetails>

      <Dialog
        open={destinationOpen}
        onClose={() => setDestinationOpen(false)}
        titleId="add-destination-heading"
        descriptionId="add-destination-description"
        initialFocusRef={destinationNameRef}
        panelAnimation="none"
        panelClassName="fixed left-1/2 top-1/2 grid max-h-[calc(100dvh-2rem)] w-[min(94vw,44rem)] -translate-x-1/2 -translate-y-1/2 gap-4 overflow-y-auto overscroll-contain rounded-panel border border-border bg-card p-5 shadow-elevation3"
      >
        <form className="grid gap-4" onSubmit={(event) => void createTarget(event)}>
          <div>
            <h2 id="add-destination-heading" className="text-title font-semibold">
              {t("connectors.design.add")}
            </h2>
            <p id="add-destination-description" className="mt-1 max-w-3xl text-sm text-muted-foreground">
              {t("connectors.design.addHelp")}
            </p>
          </div>
          <label className="grid gap-1 text-sm font-medium">
            {t("connectors.design.destinationName")}
            <input
              ref={destinationNameRef}
              className="ui-input font-normal"
              value={targetName}
              onChange={(event) => setTargetName(event.target.value)}
              required
              autoComplete="off"
            />
          </label>
          <label className="grid gap-1 text-sm font-medium">
            {t("connectors.design.connectorType")}
            <select className="ui-input font-normal" value={connectorName} onChange={(event) => setConnectorName(event.target.value)}>
              {connectorOptions.map((name) => (
                <option key={name} value={name}>
                  {name}
                </option>
              ))}
            </select>
          </label>
          <label className="grid gap-1 text-sm font-medium">
            {t("connectors.design.configuration")}
            <textarea
              className="ui-input min-h-24 font-mono text-xs font-normal"
              value={targetConfig}
              onChange={(event) => setTargetConfig(event.target.value)}
              spellCheck={false}
            />
          </label>
          <label className="flex items-start gap-3 rounded-control border border-border bg-muted/30 p-3 text-sm" htmlFor="connector-target-enabled">
            <input
              id="connector-target-enabled"
              aria-label={t("connectors.targetReadiness.enableNow")}
              className="mt-1 size-4"
              type="checkbox"
              checked={targetEnabled}
              onChange={(event) => setTargetEnabled(event.target.checked)}
            />
            <span>
              <strong className="block">{t("connectors.targetReadiness.enableNow")}</strong>
              <span className="mt-1 block text-muted-foreground">{t("connectors.targetReadiness.enableNowHelp")}</span>
            </span>
          </label>
          <p className="text-sm text-muted-foreground">{t("connectors.design.configurationHelp")}</p>
          <div className="flex flex-wrap justify-end gap-2">
            <Button type="button" variant="ghost" onClick={() => setDestinationOpen(false)}>
              {translateNow("source.cancel.19766ed6cc")}
            </Button>
            <Button type="submit" disabled={!targetName.trim() || !connectorName.trim()}>
              {t("connectors.design.add")}
            </Button>
          </div>
        </form>
      </Dialog>

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
            <label className="flex items-start gap-3 rounded-control border border-border bg-muted/30 p-3 text-sm" htmlFor="connector-target-edit-enabled">
              <input
                id="connector-target-edit-enabled"
                aria-label={t("connectors.targetReadiness.enableNow")}
                className="mt-1 size-4"
                type="checkbox"
                checked={editEnabled}
                onChange={(event) => setEditEnabled(event.target.checked)}
              />
              <span>
                <strong className="block">{t("connectors.targetReadiness.enableNow")}</strong>
                <span className="mt-1 block text-muted-foreground">{t("connectors.targetReadiness.enableNowHelp")}</span>
              </span>
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

      {rollbackReviewOpen && selectedTargetRecord && selectedIdentityRecord && (
        <Dialog
          open
          onClose={() => setRollbackReviewOpen(false)}
          titleId="connector-rollback-review-heading"
          descriptionId="connector-rollback-review-description"
          className="fixed inset-0 z-50 flex items-center justify-center p-4"
          overlayClassName="absolute inset-0 bg-black/55"
          panelClassName="relative max-h-[calc(100dvh-2rem)] w-full max-w-xl overflow-y-auto overscroll-contain rounded-panel border border-border bg-card shadow-elevation2"
        >
          <header className="border-b border-border px-5 py-4">
            <h2 id="connector-rollback-review-heading" className="text-title font-semibold">
              {t("connectors.recovery.dialogTitle")}
            </h2>
            <p id="connector-rollback-review-description" className="mt-1 text-sm text-muted-foreground">
              {t("connectors.recovery.dialogHelp")}
            </p>
          </header>
          <dl className="grid gap-2 p-5 text-sm">
            <ConnectorDetailRow term={t("connectors.design.destinationName")}>{selectedTargetRecord.name}</ConnectorDetailRow>
            <ConnectorDetailRow term={translateNow("source.identity.999f23fcd7")}>{selectedIdentityRecord.name}</ConnectorDetailRow>
            <ConnectorDetailRow term={translateNow("source.reason.f81ab834de")}>{reason}</ConnectorDetailRow>
          </dl>
          <p className="mx-5 rounded-control border border-status-warning/40 bg-status-warning/10 px-3 py-2 text-sm">
            {t("connectors.recovery.dialogBoundary")}
          </p>
          <div className="flex flex-wrap justify-end gap-2 border-t border-border px-5 py-4">
            <Button type="button" variant="ghost" onClick={() => setRollbackReviewOpen(false)}>
              {translateNow("source.cancel.19766ed6cc")}
            </Button>
            <Button
              type="button"
              onClick={() => void runTargetAction("rollback")}
              disabled={Boolean(targetActionBusy)}
              loading={targetActionBusy === "rollback"}
            >
              {t("connectors.recovery.confirm")}
            </Button>
          </div>
        </Dialog>
      )}
    </section>
  );
}

function ConnectorDetails({ title, open, onToggle, children }: { title: string; open: boolean; onToggle: (open: boolean) => void; children: ReactNode }) {
  return (
    <details className="rounded-panel border border-border bg-card shadow-elevation1" open={open} onToggle={(event) => onToggle(event.currentTarget.open)}>
      <summary className="cursor-pointer px-4 py-3 font-semibold text-foreground">{title}</summary>
      <div className="border-t border-border p-4">{open ? children : null}</div>
    </details>
  );
}

/* eslint-disable jsx-a11y/no-noninteractive-tabindex -- A focusable labeled
   region is the WCAG keyboard path for a table whose columns overflow on a
   narrow viewport. The generic lint rule cannot see runtime overflow, while
   live axe explicitly requires this tab stop. */
function ScrollableTableRegion({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div
      className="ui-panel w-full min-w-0 max-w-full overflow-x-auto focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus focus-visible:ring-offset-2"
      role="region"
      aria-label={label}
      tabIndex={0}
    >
      {children}
    </div>
  );
}
/* eslint-enable jsx-a11y/no-noninteractive-tabindex */

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

function targetTimelineStatusTone(stage: string, status: string): StatusTone {
  if (stage !== "endpoint.verify") return describeStatus("delivery", status).tone;
  if (status === "verified") return "success";
  if (status === "diverged") return "critical";
  if (status === "unreachable") return "warning";
  return "neutral";
}

function circuitStateTone(state: OutboxCircuit["state"]) {
  if (state === "closed") return "success";
  if (state === "open") return "critical";
  return "warning";
}
