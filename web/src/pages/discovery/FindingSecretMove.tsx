import { useTranslation } from "@/i18n/I18nProvider";
import type { DiscoveryFinding } from "@/lib/api";

// P6, P6-L5: a leaked secret moved into the vault names the secret that now
// holds its value, the history commits that still held it, and when a later
// scan of the repository last looked at that history (and which run).
export function FindingSecretMove({ finding }: { finding: DiscoveryFinding }) {
  const { t, formatDateTime } = useTranslation();
  const move = finding.secret_move;
  if (!move) return null;
  const residue = move.history_residue ?? [];
  return (
    <section aria-labelledby="finding-secret-move-heading" className="rounded-control border border-border p-3 text-sm">
      <h3 id="finding-secret-move-heading" className="font-medium">
        {t("discovery.findings.secretMove.heading")}
      </h3>
      <p className="mt-1 text-muted-foreground">{t("discovery.findings.secretMove.where", { reference: move.reference, version: move.secret_version })}</p>
      <p className="mt-2">{t("discovery.findings.secretMove.residue", { count: residue.length })}</p>
      {residue.length > 0 ? (
        <ul className="mt-1 list-disc pl-5" aria-label={t("discovery.findings.secretMove.residueList")}>
          {residue.map((loc) => (
            <li key={`${loc.commit}:${loc.file}:${loc.line}`} className="font-mono text-xs">
              {t("discovery.findings.secretMove.residueItem", { commit: loc.commit.slice(0, 12), file: loc.file, line: loc.line })}
            </li>
          ))}
        </ul>
      ) : null}
      <p className="mt-2 text-muted-foreground">
        {move.history_residue_checked_at
          ? t("discovery.findings.secretMove.checked", {
              time: formatDateTime(move.history_residue_checked_at),
              run: move.history_residue_run_id ?? "",
            })
          : t("discovery.findings.secretMove.notChecked")}
      </p>
    </section>
  );
}
