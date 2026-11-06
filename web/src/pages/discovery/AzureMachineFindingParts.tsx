import { z } from "zod";
import type { DiscoveryFinding } from "@/lib/api";
import { CredentialChip } from "@/components/CredentialChip";
import { ErrorState } from "@/components/StatePrimitives";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { useTranslation } from "@/i18n/I18nProvider";
const credential = z.object({
  keyId: z.string(),
  startDateTime: z.string(),
  endDateTime: z.string(),
  kind: z.string(),
  long_lived: z.boolean(),
  last_observed_use_at: z.string().optional(),
  last_use_coverage: z.string(),
});
const schema = z.object({
  version: z.literal(1),
  provider: z.literal("azure-entra"),
  azure_tenant_id: z.string(),
  subscription_id: z.string(),
  collected_at: z.string(),
  identity: z.object({
    id: z.string(),
    appId: z.string(),
    displayName: z.string(),
    servicePrincipalType: z.string(),
    accountEnabled: z.boolean(),
    keyCredentials: z.array(credential).nullable(),
    passwordCredentials: z.array(credential).nullable(),
  }),
  app_role_coverage: z.string(),
  federation_coverage: z.string(),
  rbac_coverage: z.string(),
  managed_identity_coverage: z.string(),
  activity_coverage: z.string(),
  app_roles: z
    .array(z.object({ id: z.string(), resourceId: z.string(), appRoleId: z.string(), value: z.string().optional(), definition_coverage: z.string() }))
    .nullable(),
  rbac: z
    .array(
      z.object({
        id: z.string(),
        properties: z.object({ scope: z.string(), roleDefinitionId: z.string(), condition: z.string(), conditionVersion: z.string() }),
        permissions: z
          .array(
            z.object({
              actions: z.array(z.string()).nullable(),
              notActions: z.array(z.string()).nullable(),
              dataActions: z.array(z.string()).nullable(),
              notDataActions: z.array(z.string()).nullable(),
            }),
          )
          .nullable(),
        definition_coverage: z.string(),
      }),
    )
    .nullable(),
  federation: z.array(z.object({ id: z.string(), issuer: z.string(), subject: z.string(), audiences: z.array(z.string()).nullable() })).nullable(),
  limitations: z.array(z.string()).nullable(),
});
export function AzureMachineFindingParts({ finding }: { finding: DiscoveryFinding }) {
  const { t } = useTranslation();
  if (finding.kind !== "azure_machine_identity") return null;
  const parsed = schema.safeParse(finding.metadata);
  if (!parsed.success) return <ErrorState title={t("discovery.azure.evidenceUnavailable")}>{t("discovery.azure.rescan")}</ErrorState>;
  const v = parsed.data;
  return (
    <Card>
      <CardHeader>
        <CardTitle>{t("discovery.azure.findingHeading")}</CardTitle>
      </CardHeader>
      <CardContent className="grid gap-4">
        <CredentialChip value={v.identity.id} fullValue />
        <p>
          {v.identity.displayName} · {v.identity.servicePrincipalType}
        </p>
        <p>{t("discovery.azure.snapshot", { at: v.collected_at, tenant: v.azure_tenant_id, subscription: v.subscription_id })}</p>
        <p className="text-sm text-muted-foreground">{t("discovery.azure.help")}</p>
        <details>
          <summary>{t("discovery.gcp.coverage")}</summary>
          <pre className="overflow-x-auto whitespace-pre-wrap break-all text-xs">
            {JSON.stringify(
              {
                app_roles: v.app_role_coverage,
                federation: v.federation_coverage,
                rbac: v.rbac_coverage,
                managed_identity: v.managed_identity_coverage,
                activity: v.activity_coverage,
              },
              null,
              2,
            )}
          </pre>
        </details>
        {[...(v.identity.keyCredentials ?? []), ...(v.identity.passwordCredentials ?? [])].map((key) => (
          <section key={key.keyId} className="grid gap-2 border-t pt-3 text-sm">
            <CredentialChip value={key.keyId} fullValue />
            <p>{key.kind}</p>
            <p>{t("discovery.azure.keyDates", { created: key.startDateTime, expires: key.endDateTime, long: String(key.long_lived) })}</p>
            <p>{key.last_observed_use_at ? t("discovery.gcp.observedUse", { at: key.last_observed_use_at }) : t("discovery.azure.useUnknown")}</p>
          </section>
        ))}
        {(v.app_roles ?? []).map((role) => (
          <section key={role.id} className="grid gap-1 border-t pt-3 text-sm">
            <p>{role.value ?? role.appRoleId}</p>
            <p>{role.resourceId}</p>
            <p>{role.definition_coverage}</p>
          </section>
        ))}
        {(v.rbac ?? []).map((role) => (
          <section key={role.id} className="grid gap-1 border-t pt-3 text-sm">
            <p>{role.properties.roleDefinitionId}</p>
            <p>{t("discovery.azure.bindingScope", { scope: role.properties.scope })}</p>
            <pre className="overflow-x-auto whitespace-pre-wrap break-all text-xs">
              {JSON.stringify(
                {
                  condition: role.properties.condition,
                  condition_version: role.properties.conditionVersion,
                  permissions: role.permissions,
                  coverage: role.definition_coverage,
                },
                null,
                2,
              )}
            </pre>
          </section>
        ))}
        <details>
          <summary>{t("discovery.azure.federation")}</summary>
          <pre className="overflow-x-auto whitespace-pre-wrap break-all text-xs">{JSON.stringify(v.federation ?? [], null, 2)}</pre>
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
