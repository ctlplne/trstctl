import { useEffect, useState } from "react";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { useTranslation } from "@/i18n/I18nProvider";
import { api, type Agent, type Owner } from "@/lib/api";

export type KubernetesDelivery = { clusterAgentID: string; ownerID: string; verifyAddress: string };

export const emptyKubernetesDelivery: KubernetesDelivery = { clusterAgentID: "", ownerID: "", verifyAddress: "" };

// kubernetesDeliveryConfig is the part of a Kubernetes TLS source's config that
// binds it to the agent running in the cluster. Without an agent the source only
// inventories what it finds, so the owner and verify address are not sent.
export function kubernetesDeliveryConfig(delivery: KubernetesDelivery): Record<string, string> {
  const agentID = delivery.clusterAgentID.trim();
  if (!agentID) return {};
  const verifyAddress = delivery.verifyAddress.trim();
  return { cluster_agent_id: agentID, owner_id: delivery.ownerID.trim(), ...(verifyAddress ? { verify_address: verifyAddress } : {}) };
}

// Only an enrolled host-role agent can write the Secret; the server refuses
// any other, so the picker does not offer them.
export function clusterAgentChoices(agents: Agent[]): Agent[] {
  return agents.filter((agent) => agent.roles.includes("host") && !agent.offboarded_at);
}

function clusterAgentLabel(agent: Agent): string {
  return `${agent.name} · ${agent.id.slice(0, 8)}`;
}

export function KubernetesDeliveryFields({ value, onChange }: { value: KubernetesDelivery; onChange: (value: KubernetesDelivery) => void }) {
  const { t } = useTranslation();
  const [agents, setAgents] = useState<Agent[]>([]);
  const [owners, setOwners] = useState<Owner[]>([]);
  const [loadFailed, setLoadFailed] = useState(false);
  useEffect(() => {
    let active = true;
    Promise.resolve()
      .then(() => Promise.all([api.agents(), api.owners()]))
      .then(([agentList, ownerList]) => {
        if (!active) return;
        setAgents(clusterAgentChoices(agentList ?? []));
        setOwners(ownerList ?? []);
      })
      .catch(() => {
        if (active) setLoadFailed(true);
      });
    return () => {
      active = false;
    };
  }, []);
  const bound = value.clusterAgentID.trim() !== "";
  return (
    <fieldset className="grid gap-3 rounded-panel border border-border p-4">
      <legend className="px-1 text-sm font-semibold">{t("discovery.k8sDelivery.title")}</legend>
      <p className="text-xs text-muted-foreground">{t("discovery.k8sDelivery.body")}</p>
      {loadFailed ? (
        <p role="alert" className="text-xs text-risk-critical">
          {t("discovery.k8sDelivery.loadFailed")}
        </p>
      ) : null}
      <Field label={t("discovery.k8sDelivery.agent")} description={t("discovery.k8sDelivery.agentHelp")}>
        {(control) => (
          <Select {...control} value={value.clusterAgentID} onChange={(event) => onChange({ ...value, clusterAgentID: event.target.value })}>
            <option value="">{t("discovery.k8sDelivery.inventoryOnly")}</option>
            {agents.map((agent) => (
              <option key={agent.id} value={agent.id}>
                {clusterAgentLabel(agent)}
              </option>
            ))}
          </Select>
        )}
      </Field>
      {bound ? (
        <>
          <Field label={t("discovery.k8sDelivery.owner")} description={t("discovery.k8sDelivery.ownerHelp")} required>
            {(control) => (
              <Select {...control} required value={value.ownerID} onChange={(event) => onChange({ ...value, ownerID: event.target.value })}>
                <option value="">{t("discovery.k8sDelivery.chooseOwner")}</option>
                {owners.map((owner) => (
                  <option key={owner.id} value={owner.id}>
                    {owner.name}
                  </option>
                ))}
              </Select>
            )}
          </Field>
          <Field label={t("discovery.k8sDelivery.verifyAddress")} description={t("discovery.k8sDelivery.verifyAddressHelp")}>
            {(control) => (
              <Input
                {...control}
                className="font-mono text-xs"
                value={value.verifyAddress}
                placeholder={t("discovery.k8sDelivery.verifyAddressPlaceholder")}
                onChange={(event) => onChange({ ...value, verifyAddress: event.target.value })}
              />
            )}
          </Field>
        </>
      ) : null}
    </fieldset>
  );
}
