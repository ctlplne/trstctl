import { CheckCircle2, MinusCircle, XCircle } from "lucide-react";
import type { Ref } from "react";
import { StatusBadge } from "@/components/StatusBadge";
import { useTranslation, translateNow } from "@/i18n/I18nProvider";
import type { ACMEDNS01Preflight } from "@/lib/api";
import { DNS01CAAPolicyPanel } from "@/pages/protocols/DNS01CAAPolicyPanel";

export function DNS01PreflightResultPanel({ result, sectionRef }: { result: ACMEDNS01Preflight; sectionRef?: Ref<HTMLElement> }) {
  const { t } = useTranslation();
  return (
    <section
      ref={sectionRef}
      tabIndex={-1}
      role="status"
      aria-label={translateNow("source.preflight.result.for.value1.b75b62525f", { value1: result.domain })}
      className="grid gap-3 rounded-control border border-border p-3 text-sm"
    >
      <div className="flex flex-wrap items-center gap-2">
        <StatusBadge value={result.ready ? "ready" : "not-ready"} tone={result.ready ? "success" : "critical"} label={result.ready ? "Ready" : "Not ready"} />
        <span className="font-medium">{result.domain}</span>
        {result.wildcard && (
          <span className="rounded-control border border-border px-2 py-0.5 text-caption text-muted-foreground">{t("parity.wildcard_08654e")}</span>
        )}
      </div>
      <dl className="grid gap-3 sm:grid-cols-2">
        <div>
          <dt className="text-caption text-muted-foreground">{t("parity.selectedMethod_9ad9ca")}</dt>
          <dd className="font-mono text-xs">{result.selected_method}</dd>
        </div>
        <div>
          <dt className="text-caption text-muted-foreground">{t("parity.challengeRecord_320513")}</dt>
          <dd className="break-all font-mono text-xs">{result.record_name}</dd>
        </div>
      </dl>
      {result.method_rationale && <p className="text-sm text-muted-foreground">{result.method_rationale}</p>}
      <DNS01CAAPolicyPanel policy={result.caa_policy} />
      <ul className="grid gap-2">
        {result.checks.map((check) => (
          <li
            key={check.name}
            className={
              check.status === "fail"
                ? "flex items-start gap-2 rounded-control border border-destructive/40 bg-destructive/10 p-2"
                : "flex items-start gap-2 rounded-control border border-border p-2"
            }
          >
            <PreflightCheckIcon status={check.status} />
            <div className="min-w-0">
              <p className={check.status === "fail" ? "font-medium text-destructive" : "font-medium"}>
                {check.name}
                <span className="sr-only">{translateNow("source.value1.eff53e36f5", { value1: check.status })}</span>
              </p>
              <p className={check.status === "fail" ? "text-sm text-destructive/90" : "text-sm text-muted-foreground"}>{check.detail}</p>
            </div>
          </li>
        ))}
      </ul>
      {result.failed_checks.length > 0 && (
        <p className="text-sm font-medium text-destructive">
          {translateNow("source.failed.checks.890e88faab")} {result.failed_checks.join(", ")}
        </p>
      )}
    </section>
  );
}

function PreflightCheckIcon({ status }: { status: "pass" | "fail" | "skipped" }) {
  if (status === "pass") return <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-status-success" aria-hidden="true" />;
  if (status === "fail") return <XCircle className="mt-0.5 h-4 w-4 shrink-0 text-destructive" aria-hidden="true" />;
  return <MinusCircle className="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />;
}
