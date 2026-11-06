import { z } from "zod";
import type { DiscoveryFinding } from "@/lib/api";
import { CredentialChip } from "@/components/CredentialChip";
import { ErrorState } from "@/components/StatePrimitives";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { useTranslation } from "@/i18n/I18nProvider";
const schema = z.object({
  version: z.literal(1),
  provider: z.literal("gcp-iam"),
  collected_at: z.string(),
  identity: z.object({ email: z.string(), uniqueId: z.string(), projectId: z.string(), disabled: z.boolean() }),
  keys_coverage: z.string(),
  trust_coverage: z.string(),
  policy_coverage: z.string(),
  activity_coverage: z.string(),
  keys: z
    .array(
      z.object({
        name: z.string(),
        validAfterTime: z.string(),
        validBeforeTime: z.string(),
        disabled: z.boolean(),
        long_lived: z.boolean(),
        last_observed_use_at: z.string().optional(),
        last_use_coverage: z.string(),
      }),
    )
    .nullable(),
  policy_bindings: z
    .array(
      z.object({
        scope: z.string(),
        role: z.string(),
        condition: z.object({ expression: z.string().optional() }).nullable().optional(),
        permissions: z.array(z.string()).nullable(),
        permission_coverage: z.string(),
      }),
    )
    .nullable(),
  trust_policy: z.object({ bindings: z.array(z.object({ role: z.string(), members: z.array(z.string()) })).nullable() }),
  limitations: z.array(z.string()).nullable(),
});
export function GCPMachineFindingParts({ finding }: { finding: DiscoveryFinding }) {
  const { t } = useTranslation();
  if (finding.kind !== "gcp_machine_identity") return null;
  const parsed = schema.safeParse(finding.metadata);
  if (!parsed.success) return <ErrorState title={t("discovery.machine.evidenceUnavailable")}>{t("discovery.machine.rescan")}</ErrorState>;
  const v = parsed.data;
  return (
    <Card>
      <CardHeader>
        <CardTitle>{t("discovery.gcp.findingHeading")}</CardTitle>
      </CardHeader>
      <CardContent className="grid gap-4">
        <CredentialChip value={v.identity.email} fullValue />
        <p>
          {t("discovery.gcp.snapshot", {
            at: v.collected_at,
            project: v.identity.projectId,
            state: v.identity.disabled ? t("discovery.gcp.disabled") : t("discovery.gcp.enabled"),
          })}
        </p>
        <p className="text-sm text-muted-foreground">{t("discovery.gcp.help")}</p>
        <details>
          <summary>{t("discovery.gcp.coverage")}</summary>
          <pre className="overflow-x-auto whitespace-pre-wrap break-all text-xs">
            {JSON.stringify({ keys: v.keys_coverage, trust: v.trust_coverage, project_policy: v.policy_coverage, audit: v.activity_coverage }, null, 2)}
          </pre>
        </details>
        {(v.keys ?? []).map((key) => (
          <section key={key.name} className="grid gap-2 border-t pt-3 text-sm">
            <CredentialChip value={key.name} fullValue />
            <p>
              {t("discovery.gcp.keyDates", {
                created: key.validAfterTime,
                expires: key.validBeforeTime,
                disabled: String(key.disabled),
                long: String(key.long_lived),
              })}
            </p>
            <p>{key.last_observed_use_at ? t("discovery.gcp.observedUse", { at: key.last_observed_use_at }) : t("discovery.gcp.useUnknown")}</p>
          </section>
        ))}
        {(v.policy_bindings ?? []).map((binding, index) => (
          <section key={index} className="grid gap-1 border-t pt-3 text-sm">
            <p>{binding.role}</p>
            <p>{t("discovery.gcp.bindingScope", { scope: binding.scope })}</p>
            {binding.condition?.expression && <pre className="overflow-x-auto whitespace-pre-wrap break-all">{binding.condition.expression}</pre>}
            <p>{binding.permission_coverage === "unavailable" ? t("discovery.gcp.permissionsUnknown") : (binding.permissions ?? []).join(", ")}</p>
          </section>
        ))}
        <details>
          <summary>{t("discovery.gcp.trustPolicy")}</summary>
          <pre className="overflow-x-auto whitespace-pre-wrap break-all text-xs">{JSON.stringify(v.trust_policy.bindings ?? [], null, 2)}</pre>
        </details>
        <ul className="list-disc pl-5 text-sm text-muted-foreground">
          {(v.limitations ?? []).map((item, index) => (
            <li key={index}>{item}</li>
          ))}
        </ul>
      </CardContent>
    </Card>
  );
}
