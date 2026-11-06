import type { UseFormReturn } from "react-hook-form";
import { z } from "zod";
import { Checkbox } from "@/components/ui/checkbox";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { translateNow, useTranslation } from "@/i18n/I18nProvider";
import type { SetupValues } from "./SourceSetup";

export const machineFieldPaths = [
  "session_file_ref",
  "principals",
  "assessment",
  "endpoint",
  "region",
  "ca_pem",
  "allow_private_endpoint",
  "private_egress_cidrs",
] as const;
export const machineSchemaFields = {
  machineKind: z.enum(["iam_user", "iam_role"]),
  machineName: z.string().trim(),
  machineARN: z.string().trim(),
  machineAction: z.string().trim(),
  machineResource: z.string().trim(),
  machineResourceAccount: z.string().trim(),
  machineSessionFileRef: z.string().trim(),
  machineContext: z.string().max(32768),
  machineContextComplete: z.boolean(),
  machinePolicies: z.string().max(400000),
  machineActivity: z.string().max(400000),
  machineCAPEM: z.string().max(65536),
};
export const machineDefaults = {
  machineKind: "iam_user" as const,
  machineName: "",
  machineARN: "",
  machineAction: "s3:GetObject",
  machineResource: "",
  machineResourceAccount: "",
  machineSessionFileRef: "",
  machineContext: "{}",
  machineContextComplete: false,
  machinePolicies: "[]",
  machineActivity: "{}",
  machineCAPEM: "",
};

export function buildMachineConfig(values: SetupValues): Record<string, unknown> {
  const context: unknown = JSON.parse(values.machineContext || "{}");
  const policies: unknown = JSON.parse(values.machinePolicies || "[]");
  const activity: unknown = JSON.parse(values.machineActivity || "{}");
  if (
    !context ||
    typeof context !== "object" ||
    Array.isArray(context) ||
    !Object.values(context).every((entry) => Array.isArray(entry) && entry.every((item) => typeof item === "string")) ||
    !Array.isArray(policies) ||
    !activity ||
    typeof activity !== "object" ||
    Array.isArray(activity)
  )
    throw new Error(translateNow("discovery.machine.jsonError"));
  return {
    session_file_ref: values.machineSessionFileRef,
    principals: [{ kind: values.machineKind, name: values.machineName }],
    assessment: {
      checks: [
        {
          principal_arn: values.machineARN,
          action: values.machineAction,
          resource: values.machineResource,
          resource_account_id: values.machineResourceAccount,
          context: { values: context, complete: values.machineContextComplete },
        },
      ],
      recorded_policy_evidence: policies,
      recorded_activity_evidence: activity,
    },
    ...(values.endpoint ? { endpoint: values.endpoint } : {}),
    ...(values.region ? { region: values.region } : {}),
    ...(values.machineCAPEM ? { ca_pem: values.machineCAPEM } : {}),
    ...(values.allowPrivateEndpoint ? { allow_private_endpoint: true, private_egress_cidrs: values.privateEgressCIDRs.split(/[\s,]+/).filter(Boolean) } : {}),
  };
}
export function machineValidation(values: SetupValues): Array<[keyof SetupValues, string]> {
  const errors: Array<[keyof SetupValues, string]> = [];
  const invalid = translateNow("discovery.machine.invalidBinding");
  if (!/^env:[A-Za-z_][A-Za-z0-9_]*$/.test(values.machineSessionFileRef)) errors.push(["machineSessionFileRef", invalid]);
  if (!/^[A-Za-z0-9+=,.@_-]{1,128}$/.test(values.machineName)) errors.push(["machineName", invalid]);
  if (
    !/^arn:(aws|aws-us-gov|aws-cn):iam::\d{12}:(user|role)\/.+/.test(values.machineARN) ||
    !values.machineARN.includes(`:${values.machineKind === "iam_user" ? "user" : "role"}/`) ||
    !values.machineARN.endsWith(`/${values.machineName}`)
  )
    errors.push(["machineARN", invalid]);
  if (!/^[A-Za-z0-9-]+:[A-Za-z0-9-]+$/.test(values.machineAction)) errors.push(["machineAction", invalid]);
  if (values.machineResource !== "*" && !values.machineResource.startsWith("arn:")) errors.push(["machineResource", invalid]);
  if (!/^\d{12}$/.test(values.machineResourceAccount)) errors.push(["machineResourceAccount", invalid]);
  if (values.allowPrivateEndpoint && !values.privateEgressCIDRs.trim()) errors.push(["privateEgressCIDRs", invalid]);
  try {
    buildMachineConfig(values);
  } catch {
    errors.push(["machineContext", translateNow("discovery.machine.jsonError")]);
  }
  return errors;
}

export function MachineSourceFields({ form }: { form: UseFormReturn<SetupValues> }) {
  const { t } = useTranslation();
  const inputs = [
    ["machineName", "discovery.machine.name", "workload"],
    ["machineARN", "discovery.machine.arn", "arn:aws:iam::111122223333:user/workload"],
    ["machineSessionFileRef", "discovery.machine.sessionRef", "env:TRSTCTL_AWS_READER_SESSION_PATH"],
    ["machineAction", "discovery.machine.action", "s3:GetObject"],
    ["machineResource", "discovery.machine.resource", "arn:aws:s3:::owned/report"],
    ["machineResourceAccount", "discovery.machine.account", "111122223333"],
  ] as const;
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <p className="text-sm text-muted-foreground lg:col-span-2">{t("discovery.machine.help")}</p>
      <Field label={t("discovery.machine.kind")} required>
        {(control) => (
          <Select {...control} {...form.register("machineKind")}>
            <option value="iam_user">{t("discovery.machine.user")}</option>
            <option value="iam_role">{t("discovery.machine.role")}</option>
          </Select>
        )}
      </Field>
      {inputs.map(([name, label, placeholder]) => (
        <Field key={name} label={t(label)} error={form.formState.errors[name]?.message} required>
          {(control) => <Input {...control} {...form.register(name)} placeholder={placeholder} className="font-mono text-xs" />}
        </Field>
      ))}
      <Field label={t("discovery.machine.context")} error={form.formState.errors.machineContext?.message}>
        {(control) => <Textarea {...control} {...form.register("machineContext")} rows={3} className="font-mono text-xs" />}
      </Field>
      <label className="flex items-start gap-3 text-sm lg:col-span-2">
        <Checkbox {...form.register("machineContextComplete")} />
        <span>{t("discovery.machine.completeContext")}</span>
      </label>
      <details className="lg:col-span-2">
        <summary className="cursor-pointer text-sm font-medium">{t("discovery.machine.advanced")}</summary>
        <div className="mt-4 grid gap-4 lg:grid-cols-2">
          <Field label={t("discovery.setup.endpoint")}>
            {(control) => <Input {...control} {...form.register("endpoint")} placeholder={t("discovery.machine.endpointExample")} />}
          </Field>
          <Field label={t("discovery.setup.region")}>
            {(control) => <Input {...control} {...form.register("region")} placeholder={t("discovery.machine.regionExample")} />}
          </Field>
          <Field
            label={t("discovery.machine.policies")}
            description={t("discovery.machine.recordedHelp")}
            error={form.formState.errors.machinePolicies?.message}
          >
            {(control) => <Textarea {...control} {...form.register("machinePolicies")} rows={4} className="font-mono text-xs" />}
          </Field>
          <Field
            label={t("discovery.machine.activity")}
            description={t("discovery.machine.recordedHelp")}
            error={form.formState.errors.machineActivity?.message}
          >
            {(control) => <Textarea {...control} {...form.register("machineActivity")} rows={4} className="font-mono text-xs" />}
          </Field>
          <Field label={t("discovery.machine.ca")}>
            {(control) => <Textarea {...control} {...form.register("machineCAPEM")} rows={3} className="font-mono text-xs" />}
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
