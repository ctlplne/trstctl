// SPDX-License-Identifier: BUSL-1.1

import { useState } from "react";
import { Download } from "lucide-react";
import { Button } from "@/components/ui/button";
import { StatTile } from "@/components/charts";
import { DashboardGrid, SectionCard, AttentionList, AttentionRow } from "@/components/dashboard";
import { StatusBadge } from "@/components/StatusBadge";
import { translateNow } from "@/i18n/I18nProvider";
import { api, type ValidityReadinessCertificate, type ValidityReadinessExport, type ValidityReadinessReport } from "@/lib/api";
import { useApiQuery } from "@/lib/query";
import { cn } from "@/lib/utils";
import type { StatusTone } from "@/lib/statusVocab";

// A178: the server evaluates every active certificate and profile under each
// dated step of the CA/Browser Forum's maximum validity, from the scheduler's
// own view of what renews it. The console reads that report; it does not model
// the fleet itself.
export function ValidityReadinessPanel() {
  const readiness = useApiQuery(["validity-readiness"], api.validityReadiness);
  const [selected, setSelected] = useState<string | null>(null);
  const [exporting, setExporting] = useState(false);
  const [exportError, setExportError] = useState<string | null>(null);
  const report = readiness.data;
  const steps = report?.steps ?? [];
  const step = steps.find((candidate) => candidate.effective === selected) ?? steps.find((candidate) => candidate.in_effect) ?? steps[0];

  async function download() {
    setExporting(true);
    setExportError(null);
    try {
      saveExport(await api.validityReadinessExport());
    } catch (error) {
      setExportError(error instanceof Error ? error.message : String(error));
    } finally {
      setExporting(false);
    }
  }

  return (
    <SectionCard
      title={translateNow("certificates.validityReadiness.title")}
      description={
        report
          ? translateNow("certificates.validityReadiness.requirements", {
              version: report.requirements.version,
              published: report.requirements.published,
              section: report.requirements.section,
            })
          : undefined
      }
      actions={
        <Button type="button" variant="outline" size="sm" disabled={!report || exporting} onClick={() => void download()}>
          <Download className="h-4 w-4" aria-hidden="true" />
          {translateNow("certificates.validityReadiness.download")}
        </Button>
      }
    >
      {readiness.error ? (
        <p className="text-caption text-status-danger">{readiness.error}</p>
      ) : !report || !step ? (
        <p className="text-caption text-muted-foreground">{translateNow("app.loading")}</p>
      ) : (
        <>
          <div role="group" aria-label={translateNow("certificates.validityReadiness.steps")} className="flex flex-wrap gap-2">
            {steps.map((candidate) => (
              <button
                key={candidate.effective}
                type="button"
                aria-pressed={candidate.effective === step.effective}
                onClick={() => setSelected(candidate.effective)}
                className={cn(
                  "min-h-9 rounded-control border px-3 text-body",
                  candidate.effective === step.effective ? "border-primary bg-primary text-primary-foreground" : "border-border bg-background",
                )}
              >
                {translateNow(candidate.in_effect ? "certificates.validityReadiness.stepInEffect" : "certificates.validityReadiness.step", {
                  date: candidate.effective,
                  days: candidate.max_days,
                })}
              </button>
            ))}
          </div>
          <DashboardGrid className="mt-3">
            <StatTile label={translateNow("certificates.validityReadiness.renews")} value={step.renews} tone={step.renews ? "success" : undefined} />
            <StatTile label={translateNow("certificates.validityReadiness.atRisk")} value={step.at_risk} tone={step.at_risk ? "warning" : undefined} />
            <StatTile label={translateNow("certificates.validityReadiness.manual")} value={step.manual} tone={step.manual ? "critical" : undefined} />
            <StatTile
              label={translateNow("certificates.validityReadiness.manualRenewals")}
              value={step.manual_renewals_per_year}
              hint={translateNow("certificates.validityReadiness.manualRenewalsHint", { count: step.public_tls_manual })}
              tone={step.manual_renewals_per_year ? "warning" : undefined}
            />
            <StatTile
              label={translateNow("certificates.validityReadiness.flaggedProfiles")}
              value={step.flagged_profiles}
              tone={step.flagged_profiles ? "critical" : undefined}
            />
          </DashboardGrid>
          <FlaggedProfiles report={report} effective={step.effective} />
          <CertificatesNeedingWork certificates={report.certificates} effective={step.effective} />
          <p className="mt-3 text-caption text-muted-foreground">
            {report.scheduler.enabled
              ? translateNow("certificates.validityReadiness.scheduler", { lead: report.scheduler.renew_before })
              : translateNow("certificates.validityReadiness.schedulerDisabled")}
          </p>
          {report.truncated ? (
            <p className="mt-1 text-caption text-status-warning">{translateNow("certificates.validityReadiness.truncated", { limit: report.limit })}</p>
          ) : null}
        </>
      )}
      {exportError ? <p className="mt-2 text-caption text-status-danger">{exportError}</p> : null}
    </SectionCard>
  );
}

function FlaggedProfiles({ report, effective }: { report: ValidityReadinessReport; effective: string }) {
  const flagged = report.profiles.flatMap((profile) =>
    profile.steps.filter((step) => step.effective === effective && step.flagged).map((step) => ({ profile, step })),
  );
  if (flagged.length === 0) {
    return <p className="mt-3 text-caption text-muted-foreground">{translateNow("certificates.validityReadiness.noFlaggedProfiles")}</p>;
  }
  return (
    <AttentionList ariaLabel={translateNow("certificates.validityReadiness.flaggedProfilesList")}>
      {flagged.map(({ profile, step }) => (
        <AttentionRow key={profile.name}>
          <span className="flex-1 truncate font-medium">
            {profile.name} v{profile.version}
          </span>
          <span className="text-caption text-muted-foreground">
            {step.reason === "no_validity_ceiling"
              ? translateNow("certificates.validityReadiness.profileNoCeiling", { max: step.max_days })
              : translateNow("certificates.validityReadiness.profileTooLong", { requested: profile.requested_days, max: step.max_days })}
          </span>
        </AttentionRow>
      ))}
    </AttentionList>
  );
}

const verdictTone: Record<string, StatusTone> = { renews: "success", at_risk: "warning", manual: "critical" };

function CertificatesNeedingWork({ certificates, effective }: { certificates: ValidityReadinessCertificate[]; effective: string }) {
  const needing = certificates
    .map((certificate) => ({ certificate, step: certificate.steps.find((step) => step.effective === effective) }))
    .filter((row) => row.step && row.step.verdict !== "renews");
  if (needing.length === 0) {
    return null;
  }
  return (
    <AttentionList ariaLabel={translateNow("certificates.validityReadiness.needingWork")}>
      {needing.slice(0, 8).map(({ certificate, step }) => (
        <AttentionRow key={certificate.certificate_id}>
          <span className="flex-1 truncate font-mono text-caption">{certificate.subject}</span>
          <span className="hidden w-64 truncate text-caption text-muted-foreground md:inline">
            {step!.reasons.map((reason) => translateNow(`certificates.validityReadiness.reason.${reason}`)).join("; ")}
          </span>
          <StatusBadge
            value={step!.verdict}
            label={translateNow(`certificates.validityReadiness.verdict.${step!.verdict}`)}
            tone={verdictTone[step!.verdict]}
          />
        </AttentionRow>
      ))}
    </AttentionList>
  );
}

function saveExport(file: ValidityReadinessExport) {
  const url = URL.createObjectURL(new Blob([file.csv], { type: `${file.content_type};charset=utf-8` }));
  const link = document.createElement("a");
  link.href = url;
  link.download = file.filename;
  link.click();
  URL.revokeObjectURL(url);
}
