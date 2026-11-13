import { useState } from "react";
import { Button } from "@/components/ui/button";
import { useTranslation } from "@/i18n/I18nProvider";
import type { DiscoveryFinding, DynamicSecretConfiguredProvider } from "@/lib/api";

type ProviderActionState = { status?: string; detail?: string };

const awsLeaseTypes = new Set(["aws-sts", "aws-iam"]);

function text(value: unknown): string {
  return typeof value === "string" ? value : "";
}

// isAWSKeyFinding is a discovered AWS IAM user key, the only cloud key the
// replacement acts on.
export function isAWSKeyFinding(finding: DiscoveryFinding | null): boolean {
  return finding?.kind === "cloud_access_key" && text((finding.metadata ?? {}).provider) === "aws-iam";
}

// M3-L4: an AWS IAM user key discovery found can give way to a dynamic-secret
// role's short-lived credentials. trstctl sets the key Inactive through the
// source's own IAM connection (never a deletion) and records the role as the
// replacement; the section shows what IAM confirmed.
export function CloudKeyReplacement({
  finding,
  providers,
  busy,
  onReplace,
}: {
  finding: DiscoveryFinding;
  providers: DynamicSecretConfiguredProvider[] | null;
  busy: boolean;
  onReplace: (provider: string, role: string) => Promise<void>;
}) {
  const { t } = useTranslation();
  const [provider, setProvider] = useState("");
  const [role, setRole] = useState("");
  const [confirm, setConfirm] = useState(false);
  if (!isAWSKeyFinding(finding)) return null;
  const meta = (finding.metadata ?? {}) as Record<string, unknown>;
  const user = text(meta.user);
  const keyID = text(meta.access_key_id);
  const active = text(meta.status).toLowerCase() === "active";
  const action = ((meta.provider_actions ?? {}) as Record<string, ProviderActionState>).deactivate_key;
  const replacedBy = text(meta.replaced_by);
  const awsProviders = (providers ?? []).filter((item) => awsLeaseTypes.has(item.type) && item.ready);
  const chosen = awsProviders.find((item) => item.id === provider) ?? null;
  const roles = chosen?.allowed_roles ?? [];

  async function run() {
    await onReplace(provider, role);
    setConfirm(false);
  }

  return (
    <section aria-labelledby="cloud-key-heading" className="rounded-control border border-border p-3 text-sm">
      <h3 id="cloud-key-heading" className="font-medium">
        {t("discovery.findings.cloudKey.heading")}
      </h3>
      <p className="mt-1 text-muted-foreground">{t("discovery.findings.cloudKey.help", { key: keyID || "-", user: user || "-" })}</p>
      {action?.status && <p className="mt-2">{t("discovery.findings.cloudKey.state", { status: action.status, detail: action.detail ?? "" })}</p>}
      {replacedBy && <p className="mt-1">{t("discovery.findings.cloudKey.replacedBy", { replacement: replacedBy })}</p>}
      {!active ? null : providers === null ? (
        <p className="mt-2 text-muted-foreground">{t("discovery.findings.cloudKey.loading")}</p>
      ) : awsProviders.length === 0 ? (
        <p className="mt-2 text-muted-foreground">{t("discovery.findings.cloudKey.noProvider")}</p>
      ) : confirm ? (
        <div className="mt-3 grid gap-2">
          <p>{t("discovery.findings.cloudKey.confirmText", { key: keyID || "-", user: user || "-", provider, role })}</p>
          <div className="flex flex-wrap gap-2">
            <Button type="button" size="sm" variant="destructive" disabled={busy} onClick={() => void run()}>
              {t("discovery.findings.cloudKey.confirm")}
            </Button>
            <Button type="button" size="sm" variant="ghost" disabled={busy} onClick={() => setConfirm(false)}>
              {t("discovery.findings.cloudKey.cancel")}
            </Button>
          </div>
        </div>
      ) : (
        <div className="mt-3 flex flex-wrap items-end gap-2">
          <label className="grid gap-1">
            <span>{t("discovery.findings.cloudKey.provider")}</span>
            <select
              className="rounded-control border border-border bg-background px-2 py-1"
              value={provider}
              onChange={(event) => {
                setProvider(event.target.value);
                setRole("");
              }}
            >
              <option value="">{t("discovery.findings.cloudKey.choose")}</option>
              {awsProviders.map((item) => (
                <option key={item.id} value={item.id}>
                  {item.label || item.id}
                </option>
              ))}
            </select>
          </label>
          <label className="grid gap-1">
            <span>{t("discovery.findings.cloudKey.role")}</span>
            <select
              className="rounded-control border border-border bg-background px-2 py-1"
              value={role}
              disabled={!chosen}
              onChange={(event) => setRole(event.target.value)}
            >
              <option value="">{t("discovery.findings.cloudKey.choose")}</option>
              {roles.map((item) => (
                <option key={item} value={item}>
                  {item}
                </option>
              ))}
            </select>
          </label>
          <Button type="button" size="sm" variant="destructive-outline" disabled={busy || !provider || !role} onClick={() => setConfirm(true)}>
            {t("discovery.findings.cloudKey.replace")}
          </Button>
        </div>
      )}
    </section>
  );
}
