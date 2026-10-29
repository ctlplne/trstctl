import type { UseFormReturn } from "react-hook-form";
import type { Agent } from "@/lib/api";
import { Checkbox } from "@/components/ui/checkbox";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { translateNow, useTranslation } from "@/i18n/I18nProvider";
import type { SetupValues } from "./SourceSetup";

export function ADCSFields({ form, agents }: { form: UseFormReturn<SetupValues>; agents: Agent[] }) {
  const { t } = useTranslation();
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Field label={t("discovery.setup.directoryUrl")} error={form.formState.errors.adcsURL?.message} required>
        {(control) => <Input {...control} {...form.register("adcsURL")} className="font-mono text-xs" />}
      </Field>
      <Field label={t("discovery.setup.relay")} error={form.formState.errors.relayAgentID?.message}>
        {(control) => (
          <>
            <Input
              {...control}
              {...form.register("relayAgentID")}
              list="adcs-network-relays"
              className="font-mono text-xs"
              placeholder={t("discovery.setup.adcsRelayPlaceholder")}
            />
            <datalist id="adcs-network-relays">
              {agents.map((agent) => (
                <option key={agent.id} value={agent.id}>
                  {agent.name}
                </option>
              ))}
            </datalist>
          </>
        )}
      </Field>
      <Field label={t("discovery.setup.configurationDn")} error={form.formState.errors.configurationDN?.message} required>
        {(control) => (
          <Input {...control} {...form.register("configurationDN")} className="font-mono text-xs" placeholder="CN=Configuration,DC=corp,DC=example" />
        )}
      </Field>
      <Field label={t("discovery.setup.bindIdentity")} error={form.formState.errors.bindDN?.message} required>
        {(control) => (
          <Input
            {...control}
            {...form.register("bindDN")}
            className="font-mono text-xs"
            placeholder="CN=trstctl-reader,OU=Service Accounts,DC=corp,DC=example"
          />
        )}
      </Field>
      <Field
        label={t("discovery.setup.passwordRef")}
        description={t("discovery.setup.passwordRefDescription")}
        error={form.formState.errors.passwordRef?.message}
        required
      >
        {(control) => (
          <Input {...control} {...form.register("passwordRef")} className="font-mono text-xs" placeholder={t("discovery.setup.adcsPasswordExample")} />
        )}
      </Field>
      <label htmlFor="source-setup-adcs-membership" className="flex items-start gap-3 text-sm lg:col-span-2">
        <Checkbox {...form.register("adcsNestedGroups")} id="source-setup-adcs-membership" className="mt-0.5" />
        <span>
          <strong>{t("discovery.setup.adcsMembership.enabled")}</strong>
          <span className="mt-0.5 block text-muted-foreground">{t("discovery.setup.adcsMembership.help")}</span>
        </span>
      </label>
      {form.watch("adcsNestedGroups") ? (
        <Field
          label={t("discovery.setup.adcsMembership.domain")}
          description={t("discovery.setup.adcsMembership.domainHelp")}
          error={form.formState.errors.membershipDomainDN?.message}
          required
        >
          {(control) => <Input {...control} {...form.register("membershipDomainDN")} className="font-mono text-xs" placeholder="DC=corp,DC=example" />}
        </Field>
      ) : null}
      <label htmlFor="source-setup-adcs-probe" className="flex items-start gap-3 text-sm lg:col-span-2">
        <Checkbox {...form.register("adcsEndpointProbe")} id="source-setup-adcs-probe" className="mt-0.5" />
        <span>
          <strong>{t("discovery.setup.adcsProbe.enabled")}</strong>
          <span className="mt-0.5 block text-muted-foreground">{t("discovery.setup.adcsProbe.help")}</span>
        </span>
      </label>
      {form.watch("adcsEndpointProbe") ? (
        <Field
          label={t("discovery.setup.adcsProbe.suffixes")}
          description={t("discovery.setup.adcsProbe.suffixHelp")}
          error={form.formState.errors.adcsProbeSuffixes?.message}
          required
          className="lg:col-span-2"
        >
          {(control) => (
            <Textarea
              {...control}
              {...form.register("adcsProbeSuffixes")}
              className="min-h-16 font-mono text-xs"
              placeholder={t("discovery.setup.adcsProbe.suffixPlaceholder")}
            />
          )}
        </Field>
      ) : null}
      <details className="rounded-panel border border-border p-4 lg:col-span-2">
        <summary className="cursor-pointer font-medium">{t("discovery.setup.adcsAdvanced")}</summary>
        <div className="mt-4 grid gap-4">
          <Field
            label={t("discovery.setup.adcsEndpoints")}
            description={t("discovery.setup.adcsEndpointsDescription")}
            error={form.formState.errors.adcsEnrollmentEndpoints?.message}
          >
            {(control) => <Textarea {...control} {...form.register("adcsEnrollmentEndpoints")} className="min-h-24 font-mono text-xs" />}
          </Field>
          <label htmlFor="source-setup-adcs-private" className="flex items-start gap-3 text-sm">
            <Checkbox {...form.register("allowPrivateEndpoint")} id="source-setup-adcs-private" className="mt-0.5" />
            <span>
              <strong>{t("discovery.setup.allowPrivateEndpoint")}</strong>
              <span className="mt-0.5 block text-muted-foreground">{t("discovery.setup.allowPrivateEndpointDescription")}</span>
            </span>
          </label>
          {form.watch("allowPrivateEndpoint") ? (
            <Field label={t("discovery.setup.privateCidrs")} error={form.formState.errors.privateEgressCIDRs?.message} required>
              {(control) => <Textarea {...control} {...form.register("privateEgressCIDRs")} className="min-h-24 font-mono text-xs" />}
            </Field>
          ) : null}
        </div>
      </details>
    </div>
  );
}

export function parseADCSProbeSuffixes(raw: string): string[] {
  const values = raw
    .split(/[\n,]/)
    .map((value) => value.trim().toLowerCase().replace(/\.$/, ""))
    .filter(Boolean);
  if (
    values.length < 1 ||
    values.length > 32 ||
    values.some(
      (value) =>
        value.length > 253 || /^\d+\.\d+\.\d+\.\d+$/.test(value) || value.split(".").some((label) => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label)),
    )
  ) {
    throw new Error(translateNow("discovery.setup.adcsProbe.invalidSuffixes"));
  }
  return [...new Set(values)].sort();
}
