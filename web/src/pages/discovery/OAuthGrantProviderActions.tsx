import { useState } from "react";
import { Button } from "@/components/ui/button";
import { useTranslation } from "@/i18n/I18nProvider";
import type { DiscoveryFinding } from "@/lib/api";

export type OAuthProviderAction = "revoke" | "block" | "unblock";

type ProviderActionState = { status?: string; detail?: string; provider?: string };

const graphProviders = new Set(["microsoft", "entra", "azuread", "azure-ad", "microsoft365", "m365", "graph"]);
const blockable = new Set(["okta", ...graphProviders]);

function text(value: unknown): string {
  return typeof value === "string" ? value : "";
}

// A170/A171: an OAuth grant finding can be acted on at the provider — the
// user's grant revoked, or the application blocked so no one can grant it
// again — through the admin connection its source names. The section shows
// what was asked of the provider and what the provider confirmed.
export function OAuthGrantProviderActions({
  finding,
  busy,
  onAction,
}: {
  finding: DiscoveryFinding;
  busy: boolean;
  onAction: (action: OAuthProviderAction) => Promise<void>;
}) {
  const { t } = useTranslation();
  const [confirm, setConfirm] = useState<OAuthProviderAction | null>(null);
  if (finding.kind !== "oauth_grant" && finding.kind !== "oauth_grant_abuse") return null;
  const meta = (finding.metadata ?? {}) as Record<string, unknown>;
  const provider = text(meta.provider);
  const app = text(meta.app_id);
  const user = text(meta.principal);
  const actions = (meta.provider_actions ?? {}) as Record<string, ProviderActionState>;
  const canBlock = blockable.has(provider.toLowerCase());
  // A170-L1: Microsoft Graph's admin consent for every user names no user
  // and is revoked as the tenant's grant; each user's own grant stays.
  const tenantWide = !user && graphProviders.has(provider.toLowerCase()) && text(meta.consent_type).toLowerCase() === "allprincipals";
  const states: [string, ProviderActionState | undefined][] = [
    [t("discovery.findings.oauthProvider.revokeLabel"), actions.revoke_grant],
    [t("discovery.findings.oauthProvider.blockLabel"), actions.block_app],
    [t("discovery.findings.oauthProvider.unblockLabel"), actions.unblock_app],
  ];
  // A171-L1: an app blocked at the provider can be unblocked there.
  const blocked = canBlock && actions.block_app?.status === "confirmed";

  async function run(action: OAuthProviderAction) {
    await onAction(action);
    setConfirm(null);
  }

  return (
    <section aria-labelledby="oauth-provider-heading" className="rounded-control border border-border p-3 text-sm">
      <h3 id="oauth-provider-heading" className="font-medium">
        {t("discovery.findings.oauthProvider.heading", { provider: provider || "-" })}
      </h3>
      <p className="mt-1 text-muted-foreground">
        {tenantWide
          ? t("discovery.findings.oauthProvider.helpTenantWide", { app: app || "-" })
          : t("discovery.findings.oauthProvider.help", { app: app || "-", user: user || "-" })}
      </p>
      <ul className="mt-2 grid gap-1">
        {states
          .filter(([, state]) => state?.status)
          .map(([label, state]) => (
            <li key={label}>{t("discovery.findings.oauthProvider.state", { action: label, status: state?.status ?? "", detail: state?.detail ?? "" })}</li>
          ))}
      </ul>
      {confirm ? (
        <div className="mt-3 grid gap-2">
          <p>
            {confirm === "block"
              ? t("discovery.findings.oauthProvider.blockConfirm", { app: app || "-" })
              : confirm === "unblock"
                ? t("discovery.findings.oauthProvider.unblockConfirm", { app: app || "-" })
                : tenantWide
                  ? t("discovery.findings.oauthProvider.revokeTenantWideConfirm", { app: app || "-" })
                  : t("discovery.findings.oauthProvider.revokeConfirm", { app: app || "-", user: user || "-" })}
          </p>
          <div className="flex flex-wrap gap-2">
            <Button type="button" size="sm" variant="destructive" disabled={busy} onClick={() => void run(confirm)}>
              {t("discovery.findings.oauthProvider.confirm")}
            </Button>
            <Button type="button" size="sm" variant="ghost" disabled={busy} onClick={() => setConfirm(null)}>
              {t("discovery.findings.oauthProvider.cancel")}
            </Button>
          </div>
        </div>
      ) : (
        <div className="mt-3 flex flex-wrap gap-2">
          <Button type="button" size="sm" variant="destructive-outline" disabled={busy || (!user && !tenantWide)} onClick={() => setConfirm("revoke")}>
            {tenantWide ? t("discovery.findings.oauthProvider.revokeTenantWide") : t("discovery.findings.oauthProvider.revoke")}
          </Button>
          {canBlock ? (
            <Button type="button" size="sm" variant="destructive-outline" disabled={busy} onClick={() => setConfirm("block")}>
              {t("discovery.findings.oauthProvider.block")}
            </Button>
          ) : (
            <span className="text-muted-foreground">{t("discovery.findings.oauthProvider.blockUnsupported")}</span>
          )}
          {blocked && (
            <Button type="button" size="sm" variant="outline" disabled={busy} onClick={() => setConfirm("unblock")}>
              {t("discovery.findings.oauthProvider.unblock")}
            </Button>
          )}
        </div>
      )}
    </section>
  );
}
