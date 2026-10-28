import { useFieldArray, type UseFormReturn } from "react-hook-form";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { useTranslation } from "@/i18n/I18nProvider";
import type { Agent, DiscoverySegmentCoverage } from "@/lib/api";
import type { SetupValues } from "./SourceSetup";

export function SSHCollectionFields({ form, segments, agents }: { form: UseFormReturn<SetupValues>; segments: DiscoverySegmentCoverage[]; agents: Agent[] }) {
  const { t } = useTranslation();
  const hosts = useFieldArray({ control: form.control, name: "sshHosts" });
  return (
    <div className="grid gap-4">
      <p className="text-sm text-muted-foreground">{t("discovery.setup.sshCollection.help")}</p>
      <Field label={t("discovery.setup.sshCollection.optIn")} error={form.formState.errors.sshEnabled?.message}>
        {(control) => <Checkbox {...control} {...form.register("sshEnabled")} />}
      </Field>
      <Field label={t("discovery.setup.sshCollection.scope")} error={form.formState.errors.segment?.message} required>
        {(control) => (
          <Select {...control} {...form.register("segment")}>
            <option value="" />
            {segments.map((segment) => (
              <option key={segment.name} value={segment.name}>
                {segment.name}
              </option>
            ))}
          </Select>
        )}
      </Field>
      <Field label={t("discovery.setup.sshCollection.relay")} error={form.formState.errors.relayAgentID?.message} required>
        {(control) => (
          <Select {...control} {...form.register("relayAgentID")}>
            <option value="" />
            {agents.map((agent) => (
              <option key={agent.id} value={agent.id}>
                {agent.name}
              </option>
            ))}
          </Select>
        )}
      </Field>
      {hosts.fields.map((host, index) => (
        <fieldset key={host.id} className="grid gap-3 border-y border-border py-3">
          <legend className="text-sm font-medium">{t("discovery.setup.sshCollection.hostNumber", { number: index + 1 })}</legend>
          {(["address", "username", "host_key_fingerprint", "credential_ref"] as const).map((key) => (
            <Field
              key={key}
              label={t(
                key === "address"
                  ? "discovery.setup.sshCollection.address"
                  : key === "username"
                    ? "discovery.setup.sshCollection.username"
                    : key === "host_key_fingerprint"
                      ? "discovery.setup.sshCollection.pin"
                      : "discovery.setup.sshCollection.credential",
              )}
              error={form.formState.errors.sshHosts?.[index]?.[key]?.message}
              required
            >
              {(control) => <Input {...control} {...form.register(`sshHosts.${index}.${key}`)} autoComplete="off" className="font-mono text-xs" />}
            </Field>
          ))}
          <Button type="button" variant="outline" disabled={hosts.fields.length === 1} onClick={() => hosts.remove(index)}>
            {t("discovery.setup.sshCollection.remove")}
          </Button>
        </fieldset>
      ))}
      <Button
        type="button"
        variant="outline"
        disabled={hosts.fields.length >= 100}
        onClick={() => hosts.append({ address: "", username: "trstctl_observe", host_key_fingerprint: "", credential_ref: "" })}
      >
        {t("discovery.setup.sshCollection.add")}
      </Button>
      <Field label={t("discovery.setup.sshCollection.private")}>{(control) => <Checkbox {...control} {...form.register("allowRFC1918")} />}</Field>
      <Field label={t("discovery.setup.sshCollection.loopback")}>{(control) => <Checkbox {...control} {...form.register("allowLoopback")} />}</Field>
    </div>
  );
}
