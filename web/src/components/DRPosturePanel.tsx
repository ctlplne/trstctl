// SPDX-License-Identifier: BUSL-1.1

import { StatusBadge } from "@/components/StatusBadge";
import { CredentialChip } from "@/components/CredentialChip";
import { DataGrid, type DataGridColumn } from "@/components/DataGrid";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { translateNow } from "@/i18n/I18nProvider";
import { formatDateTime, type FormatPolicy } from "@/i18n/format";
import type { DRDrill, DRPosture } from "@/lib/api";
import type { StatusTone } from "@/lib/statusVocab";

// J2: backup and disaster-recovery posture.
//
// Its own component rather than another section inside Platform.tsx, which was
// already at the served-file line budget — the budget exists so a page that
// accumulates panels gets split instead of growing until nobody reads it whole.
//
// The panel leads with when the backup was last VERIFIED rather than when one
// was last taken, because a nightly job that writes a corrupt artifact runs
// perfectly and reports success every morning.
export function DRPosturePanel({ posture, error, formatPolicy }: { posture: DRPosture | null; error: string | null; formatPolicy: FormatPolicy }) {
  const drPosture = posture;
  const drError = error;
  const history = drPosture?.drill_history ?? [];
  const historyColumns: Array<DataGridColumn<DRDrill>> = [
    {
      id: "completed",
      header: translateNow("platform.dr.history.completed"),
      cell: (drill) => formatDateTime(drill.completed_at ?? drill.ran_at, formatPolicy),
    },
    {
      id: "outcome",
      header: translateNow("source.outcome.j2dr000011"),
      cell: (drill) => (
        <StatusBadge
          value={drill.outcome}
          tone={(drill.outcome === "restored" ? "success" : drill.outcome === "skipped" ? "neutral" : "danger") as StatusTone}
          label={drill.outcome}
        />
      ),
    },
    { id: "rpo", header: translateNow("source.rpo.j2dr000013"), cell: (drill) => <span className="font-mono tabular-nums">{drill.rpo_seconds}s</span> },
    { id: "rto", header: translateNow("source.rto.floor.j2dr000014"), cell: (drill) => <span className="font-mono tabular-nums">{drill.rto_seconds}s</span> },
    {
      id: "signer",
      header: translateNow("platform.dr.history.signer"),
      cell: (drill) => (
        <div className="flex flex-col items-start gap-1">
          <StatusBadge
            value={drill.signature_verified ? "verified" : "unverified"}
            tone={(drill.signature_verified ? "success" : "danger") as StatusTone}
            label={drill.signature_verified ? translateNow("platform.dr.history.signed") : translateNow("source.not.verified.j2dr000008")}
          />
          {drill.signer_key_id ? <CredentialChip value={drill.signer_key_id} label={translateNow("platform.dr.history.signer")} /> : null}
        </div>
      ),
    },
    {
      id: "evidence",
      header: translateNow("platform.dr.history.download"),
      cell: (drill) => (
        <Button type="button" variant="outline" size="sm" disabled={!drill.signed_evidence} onClick={() => downloadDrillEvidence(drill)}>
          {translateNow("platform.dr.history.download")}
        </Button>
      ),
    },
  ];
  return (
    <Card aria-labelledby="dr-posture-heading">
      <CardHeader>
        <CardTitle id="dr-posture-heading">{translateNow("source.dr.posture.j2dr000001")}</CardTitle>
      </CardHeader>
      <CardContent>
        {drError ? (
          <p className="mt-2 text-caption text-status-danger">{drError}</p>
        ) : !drPosture ? (
          <p className="mt-2 text-caption text-muted-foreground">{translateNow("source.loading.4f9d1e0e3a")}</p>
        ) : !drPosture.backup_configured ? (
          /* Not a fault. Plenty of deployments back up through infrastructure
           this product cannot see, and painting that red would be a false
           alarm on every one of them. */
          <p className="mt-2 max-w-3xl text-caption text-muted-foreground">{drPosture.detail}</p>
        ) : (
          <>
            <dl className="mt-4 grid gap-4 sm:grid-cols-3">
              <div>
                <dt className="text-caption font-medium text-muted-foreground">{translateNow("source.last.verified.j2dr000002")}</dt>
                <dd className="text-title font-semibold">
                  {drPosture.last_verified_at ? formatDateTime(drPosture.last_verified_at, formatPolicy) : translateNow("source.never.j2dr000003")}
                </dd>
              </div>
              <div>
                <dt className="text-caption font-medium text-muted-foreground">{translateNow("source.artifacts.checked.j2dr000004")}</dt>
                {/* Both numbers, always. "Verified" across two of eleven
                  artifacts is not the claim "verified" across eleven, and
                  showing only the first is how it becomes one. */}
                <dd className="text-title font-semibold tabular-nums">{drPosture.artifacts_checked}</dd>
                {drPosture.artifacts_unverifiable > 0 ? (
                  <span className="mt-1 block text-xs text-status-warning">
                    {drPosture.artifacts_unverifiable} {translateNow("source.unverifiable.j2dr000005")}
                  </span>
                ) : null}
              </div>
              <div>
                <dt className="text-caption font-medium text-muted-foreground">{translateNow("source.verification.j2dr000006")}</dt>
                <dd>
                  <StatusBadge
                    value={drPosture.verified ? "verified" : "unverified"}
                    tone={(drPosture.verified ? "success" : "danger") as StatusTone}
                    label={drPosture.verified ? translateNow("source.verified.j2dr000007") : translateNow("source.not.verified.j2dr000008")}
                  />
                </dd>
              </div>
            </dl>
            {drPosture.failures && drPosture.failures.length > 0 ? (
              <ul className="mt-3 list-disc pl-5 text-caption text-status-danger">
                {drPosture.failures.map((failure) => (
                  <li key={failure.name}>
                    {failure.name}: {failure.detail}
                  </li>
                ))}
              </ul>
            ) : null}
            {/* The drill. Absent is its own state and is shown as such: a
              deployment that has never drilled must not read like one whose
              drills pass. */}
            <div className="mt-4 border-t border-border pt-4">
              <h3 className="text-body font-medium">{translateNow("source.restore.drill.j2dr000009")}</h3>
              {!drPosture.last_drill ? (
                <p className="mt-1 max-w-3xl text-caption text-muted-foreground">{translateNow("source.no.drill.yet.j2dr000010")}</p>
              ) : (
                <>
                  <dl className="mt-3 grid gap-4 sm:grid-cols-5">
                    <div>
                      <dt className="text-caption font-medium text-muted-foreground">{translateNow("source.outcome.j2dr000011")}</dt>
                      <dd>
                        <StatusBadge
                          value={drPosture.last_drill.outcome}
                          tone={
                            (drPosture.last_drill.outcome === "restored"
                              ? "success"
                              : drPosture.last_drill.outcome === "skipped"
                                ? "neutral"
                                : "danger") as StatusTone
                          }
                          label={drPosture.last_drill.outcome}
                        />
                      </dd>
                    </div>
                    <div>
                      <dt className="text-caption font-medium text-muted-foreground">{translateNow("source.events.restored.j2dr000012")}</dt>
                      <dd className="text-title font-semibold tabular-nums">{drPosture.last_drill.events_restored}</dd>
                    </div>
                    <div>
                      <dt className="text-caption font-medium text-muted-foreground">{translateNow("source.rpo.j2dr000013")}</dt>
                      <dd className="text-title font-semibold tabular-nums">{drPosture.last_drill.rpo_seconds}s</dd>
                    </div>
                    <div>
                      <dt className="text-caption font-medium text-muted-foreground">{translateNow("source.rto.floor.j2dr000014")}</dt>
                      {/* Labeled a FLOOR here and not just in the
                        attestation. A drill on an idle machine is not a
                        measurement of a bad afternoon, and this number is
                        the one an operator would otherwise quote. */}
                      <dd className="text-title font-semibold tabular-nums">{drPosture.last_drill.rto_seconds}s</dd>
                    </div>
                    <div>
                      <dt className="text-caption font-medium text-muted-foreground">{translateNow("source.postgresql.cc52d03280")}</dt>
                      <dd className="text-title font-semibold tabular-nums">{drPosture.last_drill.postgres_records_restored}</dd>
                    </div>
                  </dl>
                  {/* The signed detail names the exact full-set and recovered
                    health predicate. Rendering it matters: a green badge by
                    itself cannot tell an operator whether only events replayed. */}
                  <p className="mt-3 max-w-4xl text-caption text-muted-foreground">{drPosture.last_drill.detail}</p>
                  {(drPosture.last_drill.artifacts_restored ?? []).length > 0 ? (
                    <p className="mt-2 break-words font-mono text-xs text-muted-foreground">{(drPosture.last_drill.artifacts_restored ?? []).join(" · ")}</p>
                  ) : null}
                  {(drPosture.last_drill.limitations ?? []).length > 0 ? (
                    <ul className="mt-3 list-disc pl-5 text-xs text-muted-foreground">
                      {(drPosture.last_drill.limitations ?? []).map((limitation) => (
                        <li key={limitation}>{limitation}</li>
                      ))}
                    </ul>
                  ) : null}
                </>
              )}
            </div>
          </>
        )}
        {drPosture ? (
          <div className="mt-4 border-t border-border pt-4">
            <h3 className="text-body font-medium">{translateNow("platform.dr.history.title")}</h3>
            <div className="mt-3">
              <DataGrid
                ariaLabel={translateNow("platform.dr.history.aria")}
                rows={history}
                columns={historyColumns}
                getRowId={(drill) => drill.id ?? drill.signature ?? drill.ran_at}
                state={history.length === 0 ? "empty" : "ready"}
                stateMessage={translateNow("source.no.drill.yet.j2dr000010")}
                virtualization={false}
              />
            </div>
          </div>
        ) : null}
        <p className="mt-4 max-w-3xl text-xs text-muted-foreground">{drPosture?.guidance}</p>
      </CardContent>
    </Card>
  );
}

function downloadDrillEvidence(drill: DRDrill) {
  if (!drill.signed_evidence) return;
  const blob = new Blob([JSON.stringify(drill.signed_evidence, null, 2) + "\n"], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `trstctl-restore-drill-${drill.id ?? drill.ran_at}.json`;
  link.click();
  URL.revokeObjectURL(url);
}
