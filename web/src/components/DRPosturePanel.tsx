// SPDX-License-Identifier: MPL-2.0

import { StatusBadge } from "@/components/StatusBadge";
import { translateNow } from "@/i18n/I18nProvider";
import { formatDateTime, type FormatPolicy } from "@/i18n/format";
import type { DRPosture } from "@/lib/api";
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
export function DRPosturePanel({
  posture,
  error,
  formatPolicy,
}: {
  posture: DRPosture | null;
  error: string | null;
  formatPolicy: FormatPolicy;
}) {
  const drPosture = posture;
  const drError = error;
  return (
    <section className="ui-panel p-comfortable" aria-labelledby="dr-posture-heading">
      <h2 id="dr-posture-heading" className="text-title font-semibold">
        {translateNow("source.dr.posture.j2dr000001")}
      </h2>
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
                <dl className="mt-3 grid gap-4 sm:grid-cols-4">
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
                    {/* Labelled a FLOOR here and not just in the
                        attestation. A drill on an idle machine is not a
                        measurement of a bad afternoon, and this number is
                        the one an operator would otherwise quote. */}
                    <dd className="text-title font-semibold tabular-nums">{drPosture.last_drill.rto_seconds}s</dd>
                  </div>
                </dl>
                {drPosture.last_drill.limitations.length > 0 ? (
                  <ul className="mt-3 list-disc pl-5 text-xs text-muted-foreground">
                    {drPosture.last_drill.limitations.map((limitation) => (
                      <li key={limitation}>{limitation}</li>
                    ))}
                  </ul>
                ) : null}
              </>
            )}
          </div>
        </>
      )}
      <p className="mt-4 max-w-3xl text-xs text-muted-foreground">{drPosture?.guidance}</p>
    </section>
  );
}
