import type { UseFormReturn } from "react-hook-form";
import { z } from "zod";
import { Checkbox } from "@/components/ui/checkbox";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { translateNow, useTranslation } from "@/i18n/I18nProvider";
import type { SetupValues } from "./SourceSetup";

export const azureFieldPaths = [
  "azure_tenant_id",
  "subscription_id",
  "service_principal_ids",
  "graph_token_file_ref",
  "arm_token_file_ref",
  "read_beta_signins",
  "activity_lookback_days",
  "managed_identity_resources",
  "graph_endpoint",
  "arm_endpoint",
  "ca_pem",
  "allow_private_endpoint",
  "private_egress_cidrs",
] as const;
export const azureSchemaFields = {
  azureTenant: z.string().trim(),
  azureSubscription: z.string().trim(),
  azurePrincipals: z.string().trim(),
  azureGraphRef: z.string().trim(),
  azureARMRef: z.string().trim(),
  azureGraphEndpoint: z.string().trim(),
  azureARMEndpoint: z.string().trim(),
  azureBeta: z.boolean(),
  azureAuditDays: z.string().trim(),
  azureResources: z.string().trim(),
  azureCAPEM: z.string().max(65536),
};
export const azureDefaults = {
  azureTenant: "",
  azureSubscription: "",
  azurePrincipals: "",
  azureGraphRef: "",
  azureARMRef: "",
  azureGraphEndpoint: "",
  azureARMEndpoint: "",
  azureBeta: false,
  azureAuditDays: "30",
  azureResources: "",
  azureCAPEM: "",
};
const resourceMap = z.record(z.string(), z.string());
function resources(value: string) {
  try {
    return resourceMap.safeParse(JSON.parse(value || "{}"));
  } catch {
    return resourceMap.safeParse(null);
  }
}
export function buildAzureConfig(v: SetupValues): Record<string, unknown> {
  const parsed = resources(v.azureResources);
  return {
    azure_tenant_id: v.azureTenant,
    subscription_id: v.azureSubscription,
    service_principal_ids: v.azurePrincipals.split(/[\s,]+/).filter(Boolean),
    graph_token_file_ref: v.azureGraphRef,
    arm_token_file_ref: v.azureARMRef,
    read_beta_signins: v.azureBeta,
    activity_lookback_days: v.azureBeta ? Number(v.azureAuditDays) : 0,
    ...(v.azureResources && parsed.success ? { managed_identity_resources: parsed.data } : {}),
    ...(v.azureGraphEndpoint ? { graph_endpoint: v.azureGraphEndpoint } : {}),
    ...(v.azureARMEndpoint ? { arm_endpoint: v.azureARMEndpoint } : {}),
    ...(v.azureCAPEM ? { ca_pem: v.azureCAPEM } : {}),
    ...(v.allowPrivateEndpoint ? { allow_private_endpoint: true, private_egress_cidrs: v.privateEgressCIDRs.split(/[\s,]+/).filter(Boolean) } : {}),
  };
}
export function azureValidation(v: SetupValues): Array<[keyof SetupValues, string]> {
  const errors: Array<[keyof SetupValues, string]> = [];
  const invalid = translateNow("discovery.machine.invalidBinding");
  const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
  for (const name of ["azureTenant", "azureSubscription"] as const) if (!uuid.test(v[name])) errors.push([name, invalid]);
  for (const name of ["azureGraphRef", "azureARMRef"] as const) if (!/^env:[A-Za-z_][A-Za-z0-9_]{0,127}$/.test(v[name])) errors.push([name, invalid]);
  if (v.azureGraphRef === v.azureARMRef) errors.push(["azureARMRef", invalid]);
  const ids = v.azurePrincipals.split(/[\s,]+/).filter(Boolean);
  if (ids.length < 1 || ids.length > 64 || new Set(ids).size !== ids.length || ids.some((id) => !uuid.test(id))) errors.push(["azurePrincipals", invalid]);
  if (v.azureBeta && (!/^\d{1,2}$/.test(v.azureAuditDays) || Number(v.azureAuditDays) < 1 || Number(v.azureAuditDays) > 30))
    errors.push(["azureAuditDays", invalid]);
  const parsed = resources(v.azureResources);
  if (!parsed.success || Object.keys(parsed.data).length > 64 || Object.keys(parsed.data).some((id) => !ids.includes(id)))
    errors.push(["azureResources", invalid]);
  if (v.allowPrivateEndpoint && !v.privateEgressCIDRs.trim()) errors.push(["privateEgressCIDRs", invalid]);
  return errors;
}
export function AzureSourceFields({ form }: { form: UseFormReturn<SetupValues> }) {
  const { t } = useTranslation();
  const fields = [
    ["azureTenant", "discovery.azure.tenant"],
    ["azureSubscription", "discovery.azure.subscription"],
    ["azureGraphRef", "discovery.azure.graphRef"],
    ["azureARMRef", "discovery.azure.armRef"],
  ] as const;
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <p className="text-sm text-muted-foreground lg:col-span-2">{t("discovery.azure.help")}</p>
      {fields.map(([name, label]) => (
        <Field key={name} label={t(label)} error={form.formState.errors[name]?.message} required>
          {(control) => <Input {...control} {...form.register(name)} />}
        </Field>
      ))}
      <Field label={t("discovery.azure.principals")} error={form.formState.errors.azurePrincipals?.message} required>
        {(control) => <Textarea {...control} {...form.register("azurePrincipals")} rows={3} />}
      </Field>
      <Field label={t("discovery.azure.auditDays")} description={t("discovery.azure.betaHelp")} error={form.formState.errors.azureAuditDays?.message}>
        {(control) => <Input {...control} {...form.register("azureAuditDays")} type="number" min={1} max={30} />}
      </Field>
      <label className="flex items-start gap-3 text-sm lg:col-span-2">
        <Checkbox {...form.register("azureBeta")} />
        <span>{t("discovery.azure.betaOptIn")}</span>
      </label>
      <details className="lg:col-span-2">
        <summary>{t("discovery.machine.advanced")}</summary>
        <div className="mt-4 grid gap-4 lg:grid-cols-2">
          {(
            [
              ["azureGraphEndpoint", "discovery.azure.graphOrigin"],
              ["azureARMEndpoint", "discovery.azure.armOrigin"],
            ] as const
          ).map(([name, label]) => (
            <Field key={name} label={t(label)} error={form.formState.errors[name]?.message}>
              {(control) => <Input {...control} {...form.register(name)} />}
            </Field>
          ))}
          <Field label={t("discovery.azure.resources")} description={t("discovery.azure.resourcesHelp")} error={form.formState.errors.azureResources?.message}>
            {(control) => <Textarea {...control} {...form.register("azureResources")} rows={3} />}
          </Field>
          <Field label={t("discovery.machine.ca")} error={form.formState.errors.azureCAPEM?.message}>
            {(control) => <Textarea {...control} {...form.register("azureCAPEM")} rows={3} />}
          </Field>
          <Field label={t("discovery.setup.privateCidrs")} error={form.formState.errors.privateEgressCIDRs?.message}>
            {(control) => <Textarea {...control} {...form.register("privateEgressCIDRs")} rows={2} />}
          </Field>
          <label className="flex items-start gap-3 text-sm">
            <Checkbox {...form.register("allowPrivateEndpoint")} />
            <span>{t("discovery.setup.allowPrivateEndpoint")}</span>
          </label>
        </div>
      </details>
    </div>
  );
}
