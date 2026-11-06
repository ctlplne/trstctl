import type { CloudMachineChange } from "@/lib/api-types.gen";
import { useTranslation } from "@/i18n/I18nProvider";

export function CloudReplacementRendererConfig({ plan }: { plan: CloudMachineChange }) {
  const { t } = useTranslation();
  const i = plan.intent;
  if (i.action !== "replace_key" || !i.replacement_provider_id || !i.replacement_role || !i.consumer) return null;
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(i.replacement_provider_id) || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(i.replacement_role))
    return <p>{t("discovery.machine.customConsumerConfig")}</p>;
  const quote = (value: string) => JSON.stringify(value);
  const configuration = [
    `consumer: ${quote(i.consumer)}`,
    "templates:",
    "  - name: workload",
    "    destination: /run/workload/aws.json",
    `    template: ${quote('{{ lease "' + i.replacement_provider_id + "/" + i.replacement_role + '" }}')}`,
    `    lease_ttl: ${i.replacement_ttl_seconds ?? 900}s`,
    "    replacement:",
    `      change_id: ${quote(plan.id)}`,
    `      provider: ${quote(i.replacement_provider_id)}`,
    `      role: ${quote(i.replacement_role)}`,
    "    verify:",
    "      url: http://127.0.0.1:9080/credential-check",
    "      expect_status: 200",
  ].join("\n");
  return (
    <details>
      <summary>{t("discovery.machine.rendererConfig")}</summary>
      <p>{t("discovery.machine.rendererConfigHelp")}</p>
      <pre aria-label={t("discovery.machine.rendererConfig")} className="overflow-x-auto whitespace-pre-wrap break-all text-xs">
        {configuration}
      </pre>
    </details>
  );
}
