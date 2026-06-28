import { type FormEvent, useEffect, useMemo, useState } from "react";
import { PageHeader } from "@/components/PageHeader";
import { EmptyState } from "@/components/EmptyState";
import { ErrorState, LoadingState } from "@/components/StatePrimitives";
import { api, type ConnectorCatalogItem, type ConnectorDelivery, type DeploymentTarget, type Identity } from "@/lib/api";

export function Connectors() {
  const [catalog, setCatalog] = useState<ConnectorCatalogItem[] | null>(null);
  const [targets, setTargets] = useState<DeploymentTarget[] | null>(null);
  const [identities, setIdentities] = useState<Identity[]>([]);
  const [deliveries, setDeliveries] = useState<ConnectorDelivery[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [actionResult, setActionResult] = useState<string | null>(null);
  const [targetName, setTargetName] = useState("edge/prod/payments");
  const [connectorName, setConnectorName] = useState("nginx");
  const [targetConfig, setTargetConfig] = useState('{"credential_ref":"secret://connectors/nginx/edge","host":"edge-1.internal"}');
  const [selectedTarget, setSelectedTarget] = useState("");
  const [selectedIdentity, setSelectedIdentity] = useState("");
  const [reason, setReason] = useState("operator requested deployment");

  const refresh = () =>
    Promise.all([api.connectorCatalog(), api.connectorTargets(), api.identities(), api.connectorDeliveries({ limit: 20 })]).then(
      ([catalogResult, targetResult, identityResult, deliveryResult]) => {
        setCatalog(catalogResult.items ?? []);
        const loadedTargets = targetResult.items ?? [];
        setTargets(loadedTargets);
        setIdentities(identityResult ?? []);
        setDeliveries(deliveryResult.items ?? []);
        setSelectedTarget((current) => (loadedTargets.some((target) => target.id === current) ? current : loadedTargets[0]?.id || ""));
        setSelectedIdentity((current) => (identityResult?.some((identity) => identity.id === current) ? current : identityResult?.[0]?.id || ""));
        setError(null);
      },
    );

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

  return (
    <section aria-labelledby="connectors-heading" className="grid gap-6">
      <PageHeader
        titleId="connectors-heading"
        title="Deployment connectors"
        description="Target setup, identity binding, delivery actions, and receipt evidence from the served connector API."
      />

      {error && <ErrorState title="Connector workflow failed">{error}</ErrorState>}
      {!catalog && !error && <LoadingState>Loading connector workflow...</LoadingState>}

      {catalog && (
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

          {targets && targets.length === 0 ? (
            <EmptyState title="No connector targets">No tenant connector targets were returned.</EmptyState>
          ) : (
            targets && (
              <div className="ui-panel overflow-x-auto">
                <table className="ui-table min-w-[52rem]">
                  <caption className="sr-only">Connector targets</caption>
                  <thead>
                    <tr>
                      <th scope="col">Target</th>
                      <th scope="col">Connector</th>
                      <th scope="col">ID</th>
                      <th scope="col">Created</th>
                    </tr>
                  </thead>
                  <tbody>
                    {targets.map((target) => (
                      <tr key={target.id} className="align-top">
                        <td>{target.name}</td>
                        <td className="font-mono text-xs">{target.connector}</td>
                        <td className="break-all font-mono text-xs">{target.id}</td>
                        <td>{new Date(target.created_at).toLocaleString()}</td>
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
            <div className="ui-panel overflow-x-auto">
              <table className="ui-table min-w-[76rem]">
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
                  </tr>
                </thead>
                <tbody>
                  {deliveries.map((receipt) => (
                    <tr key={receipt.id} className="align-top">
                      <td className="font-mono text-xs">{receipt.status}</td>
                      <td>{receipt.connector}</td>
                      <td className="font-mono text-xs">{receipt.destination}</td>
                      <td>{receipt.target}</td>
                      <td>{receipt.attempts}</td>
                      <td className="break-all font-mono text-xs">{receipt.fingerprint || "-"}</td>
                      <td>{receipt.reason || receipt.detail || "-"}</td>
                      <td>{receipt.rollback_ref || "-"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      )}
    </section>
  );
}
