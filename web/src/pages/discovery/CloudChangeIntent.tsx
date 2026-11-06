import { CredentialChip } from "@/components/CredentialChip";
import { useTranslation } from "@/i18n/I18nProvider";
import type { CloudMachineChange } from "@/lib/api-types.gen";

// Both requester and reviewer see the same immutable, server-bound intent.
export function CloudChangeIntent({ plan }: { plan: CloudMachineChange }) {
  const { t } = useTranslation();
  let document = "";
  try {
    document = plan.intent.policy_document ? atob(plan.intent.policy_document) : "";
  } catch {
    document = t("discovery.machine.evidenceUnavailable");
  }
  return (
    <details open>
      <summary>{t("discovery.machine.exactIntent")}</summary>
      <p className="my-2 text-muted-foreground">
        {t(plan.intent.action === "replace_key" ? "discovery.machine.replacementHelp" : "discovery.machine.effectHelp")}
      </p>
      <pre className="overflow-x-auto whitespace-pre-wrap break-all text-xs">{JSON.stringify(plan.intent, null, 2)}</pre>
      {document && <pre className="mt-2 overflow-x-auto whitespace-pre-wrap break-all text-xs">{document}</pre>}
      <CredentialChip value={plan.intent_digest} fullValue />
    </details>
  );
}
