import type { UseFormReturn } from "react-hook-form";
import { z } from "zod";
import { Checkbox } from "@/components/ui/checkbox";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { translateNow, useTranslation } from "@/i18n/I18nProvider";
import type { SetupValues } from "./SourceSetup";

export const gcpFieldPaths = [
  "project",
  "service_accounts",
  "token_file_ref",
  "activity_lookback_days",
  "iam_endpoint",
  "resource_manager_endpoint",
  "logging_endpoint",
  "ca_pem",
  "allow_private_endpoint",
  "private_egress_cidrs",
] as const;
export const gcpSchemaFields = {
  gcpAccounts: z.string().trim(),
  gcpIAMEndpoint: z.string().trim(),
  gcpResourceEndpoint: z.string().trim(),
  gcpLoggingEndpoint: z.string().trim(),
  gcpAuditDays: z.string().trim(),
  gcpCAPEM: z.string().max(65536),
};
export const gcpDefaults = { gcpAccounts: "", gcpIAMEndpoint: "", gcpResourceEndpoint: "", gcpLoggingEndpoint: "", gcpAuditDays: "30", gcpCAPEM: "" };
export function buildGCPConfig(values: SetupValues): Record<string, unknown> {
  return {
    project: values.project,
    service_accounts: values.gcpAccounts.split(/[\s,]+/).filter(Boolean),
    token_file_ref: values.tokenRef,
    activity_lookback_days: Number(values.gcpAuditDays || 0),
    ...(values.gcpIAMEndpoint ? { iam_endpoint: values.gcpIAMEndpoint } : {}),
    ...(values.gcpResourceEndpoint ? { resource_manager_endpoint: values.gcpResourceEndpoint } : {}),
    ...(values.gcpLoggingEndpoint ? { logging_endpoint: values.gcpLoggingEndpoint } : {}),
    ...(values.gcpCAPEM ? { ca_pem: values.gcpCAPEM } : {}),
    ...(values.allowPrivateEndpoint ? { allow_private_endpoint: true, private_egress_cidrs: values.privateEgressCIDRs.split(/[\s,]+/).filter(Boolean) } : {}),
  };
}
export function gcpValidation(values: SetupValues): Array<[keyof SetupValues, string]> {
  const errors: Array<[keyof SetupValues, string]> = [];
  const invalid = translateNow("discovery.machine.invalidBinding");
  if (!/^(?:[a-z][a-z0-9-]{4,28}[a-z0-9]|[0-9]{6,20})$/.test(values.project)) errors.push(["project", invalid]);
  if (!/^env:[A-Za-z_][A-Za-z0-9_]{0,127}$/.test(values.tokenRef)) errors.push(["tokenRef", invalid]);
  const accounts = values.gcpAccounts.split(/[\s,]+/).filter(Boolean);
  if (
    accounts.length < 1 ||
    accounts.length > 64 ||
    new Set(accounts).size !== accounts.length ||
    accounts.some((email) => !/^[a-z0-9][a-z0-9._-]{0,126}@[a-z0-9][a-z0-9.-]{0,190}\.gserviceaccount\.com$/.test(email))
  )
    errors.push(["gcpAccounts", invalid]);
  if (!/^\d{1,2}$/.test(values.gcpAuditDays) || Number(values.gcpAuditDays) > 90) errors.push(["gcpAuditDays", invalid]);
  if (values.allowPrivateEndpoint && !values.privateEgressCIDRs.trim()) errors.push(["privateEgressCIDRs", invalid]);
  return errors;
}
export function GCPSourceFields({ form }: { form: UseFormReturn<SetupValues> }) {
  const { t } = useTranslation();
  const endpoints = [
    ["gcpIAMEndpoint", "discovery.gcp.iamOrigin"],
    ["gcpResourceEndpoint", "discovery.gcp.resourceOrigin"],
    ["gcpLoggingEndpoint", "discovery.gcp.loggingOrigin"],
  ] as const;
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <p className="text-sm text-muted-foreground lg:col-span-2">{t("discovery.gcp.help")}</p>
      <Field label={t("discovery.gcp.project")} error={form.formState.errors.project?.message} required>
        {(control) => <Input {...control} {...form.register("project")} />}
      </Field>
      <Field label={t("discovery.gcp.tokenRef")} description={t("discovery.gcp.tokenHelp")} error={form.formState.errors.tokenRef?.message} required>
        {(control) => <Input {...control} {...form.register("tokenRef")} />}
      </Field>
      <Field label={t("discovery.gcp.accounts")} error={form.formState.errors.gcpAccounts?.message} required>
        {(control) => <Textarea {...control} {...form.register("gcpAccounts")} rows={3} />}
      </Field>
      <Field label={t("discovery.gcp.auditDays")} description={t("discovery.gcp.auditHelp")} error={form.formState.errors.gcpAuditDays?.message}>
        {(control) => <Input {...control} {...form.register("gcpAuditDays")} type="number" min={0} max={90} />}
      </Field>
      <details className="lg:col-span-2">
        <summary>{t("discovery.machine.advanced")}</summary>
        <div className="mt-4 grid gap-4 lg:grid-cols-2">
          {endpoints.map(([name, label]) => (
            <Field key={name} label={t(label)} error={form.formState.errors[name]?.message}>
              {(control) => <Input {...control} {...form.register(name)} />}
            </Field>
          ))}
          <Field label={t("discovery.machine.ca")} error={form.formState.errors.gcpCAPEM?.message}>
            {(control) => <Textarea {...control} {...form.register("gcpCAPEM")} rows={3} />}
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
