import { useTranslation } from "@/i18n/I18nProvider";
import type { DiscoveryFinding } from "@/lib/api";

type ResidueLocation = { commit?: string; file?: string; line?: number };

// P6-L6: once a moved leak's finding closes, the history commits that still
// hold the rotated value are their own finding. The section names the secret
// the value moved into, the finding it came from and the commits, and says
// what closes it: a scan that finds no commit still holding the value.
export function FindingHistoryResidue({ finding }: { finding: DiscoveryFinding }) {
  const { t } = useTranslation();
  if (finding.kind !== "secret_history_residue") return null;
  const meta = (finding.metadata ?? {}) as Record<string, unknown>;
  const residue = (Array.isArray(meta.history_residue) ? meta.history_residue : []) as ResidueLocation[];
  const secretName = typeof meta.secret_name === "string" ? meta.secret_name : "";
  const movedFinding = typeof meta.moved_finding_id === "string" ? meta.moved_finding_id : "";
  return (
    <section aria-labelledby="finding-history-residue-heading" className="rounded-control border border-border p-3 text-sm">
      <h3 id="finding-history-residue-heading" className="font-medium">
        {t("discovery.findings.historyResidue.heading")}
      </h3>
      <p className="mt-1 text-muted-foreground">{t("discovery.findings.historyResidue.what", { secret: secretName, finding: movedFinding })}</p>
      <ul className="mt-2 list-disc pl-5" aria-label={t("discovery.findings.secretMove.residueList")}>
        {residue.map((loc) => (
          <li key={`${loc.commit}:${loc.file}:${loc.line}`} className="font-mono text-xs">
            {t("discovery.findings.secretMove.residueItem", { commit: (loc.commit ?? "").slice(0, 12), file: loc.file ?? "", line: loc.line ?? 0 })}
          </li>
        ))}
      </ul>
      <p className="mt-2 text-muted-foreground">{t("discovery.findings.historyResidue.closes")}</p>
    </section>
  );
}
