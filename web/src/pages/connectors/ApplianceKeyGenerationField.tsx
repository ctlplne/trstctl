import { z } from "zod";
import { Field } from "@/components/ui/field";
import { Select } from "@/components/ui/select";
import { useTranslation } from "@/i18n/I18nProvider";
import { DestinationHostField } from "@/pages/connectors/DestinationHostField";

const configSchema = z.record(z.string(), z.unknown());

function configText(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

// Where an appliance destination's private key is made. Like the host field it
// edits the reviewed configuration itself: choosing the appliance writes
// key_generation=appliance and asks for the network relay that reaches the
// appliance; choosing the control plane removes the declaration and leaves any
// relay assignment as it was.
export function ApplianceKeyGenerationField({
  connector,
  config,
  onChange,
  required,
}: {
  connector: string;
  config: string;
  onChange: (value: string) => void;
  required: boolean;
}) {
  const { t } = useTranslation();
  let parsed: Record<string, unknown> | null = null;
  try {
    const result = configSchema.safeParse(JSON.parse(config));
    if (result.success) parsed = result.data;
  } catch {
    /* The configuration field keeps the invalid input. */
  }
  const onAppliance = parsed?.key_generation === "appliance";
  let note: string | undefined;
  if (onAppliance && connector === "paloalto" && (!configText(parsed?.ssl_tls_profile) || !configText(parsed?.commit_admin))) {
    note = t("connectors.keyGeneration.paloaltoProfile");
  } else if (onAppliance && connector === "f5" && configText(parsed?.peer_endpoint)) {
    note = t("connectors.keyGeneration.f5Pair");
  } else if (
    onAppliance &&
    connector === "cisco" &&
    (!configText(parsed?.node_hostname) || !Array.isArray(parsed?.certificate_roles) || parsed.certificate_roles.length === 0)
  ) {
    note = t("connectors.keyGeneration.ciscoNode");
  }
  return (
    <div className="grid gap-2">
      <Field
        label={t("connectors.keyGeneration.label")}
        description={t("connectors.keyGeneration.help")}
        error={!parsed ? t("connectors.host.invalidConfig") : note}
      >
        {(control) => (
          <Select
            {...control}
            value={onAppliance ? "appliance" : "control_plane"}
            disabled={!parsed}
            onChange={(event) => {
              if (!parsed) return;
              const next: Record<string, unknown> = { ...parsed };
              if (event.target.value === "appliance") next.key_generation = "appliance";
              else delete next.key_generation;
              onChange(JSON.stringify(next, null, 2));
            }}
          >
            <option value="control_plane">{t("connectors.keyGeneration.controlPlane")}</option>
            <option value="appliance">{t("connectors.keyGeneration.appliance")}</option>
          </Select>
        )}
      </Field>
      {onAppliance && <DestinationHostField agentRole="network" config={config} onChange={onChange} required={required} />}
    </div>
  );
}
