// SPDX-License-Identifier: BUSL-1.1

import { useState } from "react";
import { Download, ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import { translateNow } from "@/i18n/I18nProvider";
import { api, type AssuranceRecord, type CertificateAssuranceRecord } from "@/lib/api";

type Stage = AssuranceRecord["absent"][number];

// A179: one certificate's signed lifecycle assurance record. The server joins
// every stage with its evidence and signs it with the audit-evidence key; the
// console shows which stages were independently observed and saves the signed
// file for offline verification. It is built on request: each build is a
// signing operation.
export function AssuranceRecordPanel({ certificateId }: { certificateId: string }) {
  const [signed, setSigned] = useState<CertificateAssuranceRecord | null>(null);
  const [building, setBuilding] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function build() {
    setBuilding(true);
    setError(null);
    try {
      setSigned(await api.certificateAssuranceRecord(certificateId));
    } catch {
      setError(translateNow("certificates.assurance.failed"));
    } finally {
      setBuilding(false);
    }
  }

  const record = signed?.record;
  return (
    <div className="space-y-2 text-sm">
      {!record ? (
        <Button type="button" variant="outline" size="sm" disabled={building} onClick={() => void build()}>
          <ShieldCheck className="h-4 w-4" aria-hidden="true" />
          {translateNow(building ? "certificates.assurance.building" : "certificates.assurance.build")}
        </Button>
      ) : (
        <>
          <StageLine label="certificates.assurance.observed" stages={record.independently_observed} tone="text-status-success" />
          <StageLine label="certificates.assurance.recorded" stages={record.recorded_only} tone="text-muted-foreground" />
          <StageLine label="certificates.assurance.absent" stages={record.absent} tone="text-status-warning" />
          <p className="text-xs text-muted-foreground">{translateNow("certificates.assurance.signed", { digest: signed.record_sha256 })}</p>
          <Button type="button" variant="outline" size="sm" onClick={() => saveRecord(signed, certificateId)}>
            <Download className="h-4 w-4" aria-hidden="true" />
            {translateNow("certificates.assurance.download")}
          </Button>
          <p className="text-xs text-muted-foreground">{translateNow("certificates.assurance.verifyHint")}</p>
        </>
      )}
      {error ? <p className="text-caption text-status-danger">{error}</p> : null}
    </div>
  );
}

function StageLine({ label, stages, tone }: { label: string; stages: Stage[]; tone: string }) {
  const names = stages.map((stage) => translateNow(`certificates.assurance.stage.${stage}`));
  return (
    <p className={tone}>
      {translateNow(label as "certificates.assurance.observed", { stages: names.length ? names.join(", ") : translateNow("certificates.assurance.none") })}
    </p>
  );
}

function saveRecord(signed: CertificateAssuranceRecord, certificateId: string) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(signed, null, 2) + "\n"], { type: "application/json" }));
  const link = document.createElement("a");
  link.href = url;
  link.download = `assurance-record-${certificateId}.json`;
  link.click();
  URL.revokeObjectURL(url);
}
