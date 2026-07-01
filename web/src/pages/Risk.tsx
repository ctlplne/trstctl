import { useEffect, useMemo, useState, type FormEvent } from "react";
import { Info } from "lucide-react";
import { useSearchParams } from "react-router-dom";
import {
  api,
  type ContextualRiskPriorities,
  type CredentialRisk,
  type NHIExposurePosture,
  type NHIOverPrivilegePosture,
  type NHIPolicyCompliance,
  type NHIStaticPosture,
  type NHIStalePosture,
  type RiskQuery,
} from "@/lib/api";
import { DataGrid, type DataGridColumn, type DataGridSort } from "@/components/DataGrid";
import { DataGridToolbar } from "@/components/DataGridToolbar";
import { Button } from "@/components/ui/button";
import { StatusBadge } from "@/components/StatusBadge";
import { UnavailableState } from "@/components/StatePrimitives";
import { PageHeader } from "@/components/PageHeader";
import { RiskPosture } from "@/components/risk/posture";
import { riskBand } from "@/lib/statusVocab";
import { formatDate as formatDatePolicy } from "@/i18n/format";
import { useTranslation } from "@/i18n/I18nProvider";

const privilegeLabel = ["Low", "Standard", "High", "Critical"];
const sensitivityLabel = ["Public", "Internal", "Confidential", "Restricted"];
const factorKeys = ["age", "rotation", "privilege", "exposure", "owner", "sensitivity"] as const;
const riskThresholds = [
  { value: "critical", label: "90-100" },
  { value: "high", label: "70-89" },
  { value: "medium", label: "40-69" },
  { value: "low", label: "1-39" },
  { value: "none", label: "0" },
] as const;

type RiskFactor = (typeof factorKeys)[number];
type RiskSortColumn = "score" | "expires_at";

const factorLabels: Record<RiskFactor, string> = {
  age: "Age",
  rotation: "Rotation",
  privilege: "Privilege",
  exposure: "Exposure",
  owner: "Owner",
  sensitivity: "Sensitivity",
};

export function Risk() {
  const [searchParams] = useSearchParams();
  const initialSort = searchParams.get("sort") === "expiry" ? "expiry" : "score";
  const [data, setData] = useState<CredentialRisk[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState<RiskQuery>({ sort: initialSort });
  const [sort, setSort] = useState<DataGridSort>({
    columnId: initialSort === "expiry" ? "expires_at" : "score",
    direction: "desc",
  });
  const [minScore, setMinScore] = useState("");
  const [privilege, setPrivilege] = useState("");
  const [owner, setOwner] = useState(searchParams.get("owner") ?? "");
  const [search, setSearch] = useState(searchParams.get("q") ?? "");
  const [expanded, setExpanded] = useState<string | null>(null);
  const [nhiPosture, setNHIPosture] = useState<NHIOverPrivilegePosture | null>(null);
  const [nhiPostureLoading, setNHIPostureLoading] = useState(true);
  const [nhiPostureError, setNHIPostureError] = useState<string | null>(null);
  const [nhiPolicyCompliance, setNHIPolicyCompliance] = useState<NHIPolicyCompliance | null>(null);
  const [nhiPolicyComplianceLoading, setNHIPolicyComplianceLoading] = useState(true);
  const [nhiPolicyComplianceError, setNHIPolicyComplianceError] = useState<string | null>(null);
  const [nhiStalePosture, setNHIStalePosture] = useState<NHIStalePosture | null>(null);
  const [nhiStalePostureLoading, setNHIStalePostureLoading] = useState(true);
  const [nhiStalePostureError, setNHIStalePostureError] = useState<string | null>(null);
  const [nhiStaticPosture, setNHIStaticPosture] = useState<NHIStaticPosture | null>(null);
  const [nhiStaticPostureLoading, setNHIStaticPostureLoading] = useState(true);
  const [nhiStaticPostureError, setNHIStaticPostureError] = useState<string | null>(null);
  const [nhiExposurePosture, setNHIExposurePosture] = useState<NHIExposurePosture | null>(null);
  const [nhiExposurePostureLoading, setNHIExposurePostureLoading] = useState(true);
  const [nhiExposurePostureError, setNHIExposurePostureError] = useState<string | null>(null);
  const [contextualRisk, setContextualRisk] = useState<ContextualRiskPriorities | null>(null);
  const [contextualRiskLoading, setContextualRiskLoading] = useState(true);
  const [contextualRiskError, setContextualRiskError] = useState<string | null>(null);
  const certRows = useMemo(() => (data ?? []).filter(isCertificateRisk), [data]);
  const rows = useMemo(() => {
    const needle = search.trim().toLowerCase();
    if (!needle) return certRows;
    return certRows.filter((row) =>
      [row.subject, row.credential_id, row.kind, row.owner_active ? "active" : "orphaned"].join(" ").toLowerCase().includes(needle),
    );
  }, [certRows, search]);
  const expandedRisk = useMemo(() => certRows.find((row) => row.credential_id === expanded) ?? null, [certRows, expanded]);

  useEffect(() => {
    let active = true;
    setLoading(true);
    setError(null);
    api
      .risk(query)
      .then((risk) => {
        if (!active) return;
        setData(risk);
      })
      .catch((err) => {
        if (!active) return;
        setData(null);
        setError(err instanceof Error ? err.message : String(err));
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [query]);

  useEffect(() => {
    let active = true;
    setNHIPostureLoading(true);
    setNHIPostureError(null);
    api
      .nhiOverPrivilegePosture()
      .then((posture) => {
        if (!active) return;
        setNHIPosture(posture);
      })
      .catch((err) => {
        if (!active) return;
        setNHIPosture(null);
        setNHIPostureError(err instanceof Error ? err.message : String(err));
      })
      .finally(() => {
        if (active) setNHIPostureLoading(false);
      });
    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    let active = true;
    setNHIPolicyComplianceLoading(true);
    setNHIPolicyComplianceError(null);
    api
      .nhiPolicyCompliance()
      .then((posture) => {
        if (!active) return;
        setNHIPolicyCompliance(posture);
      })
      .catch((err) => {
        if (!active) return;
        setNHIPolicyCompliance(null);
        setNHIPolicyComplianceError(err instanceof Error ? err.message : String(err));
      })
      .finally(() => {
        if (active) setNHIPolicyComplianceLoading(false);
      });
    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    let active = true;
    setContextualRiskLoading(true);
    setContextualRiskError(null);
    api
      .contextualRiskPriorities()
      .then((priorities) => {
        if (!active) return;
        setContextualRisk(priorities);
      })
      .catch((err) => {
        if (!active) return;
        setContextualRisk(null);
        setContextualRiskError(err instanceof Error ? err.message : String(err));
      })
      .finally(() => {
        if (active) setContextualRiskLoading(false);
      });
    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    let active = true;
    setNHIStaticPostureLoading(true);
    setNHIStaticPostureError(null);
    api
      .nhiStaticPosture()
      .then((posture) => {
        if (!active) return;
        setNHIStaticPosture(posture);
      })
      .catch((err) => {
        if (!active) return;
        setNHIStaticPosture(null);
        setNHIStaticPostureError(err instanceof Error ? err.message : String(err));
      })
      .finally(() => {
        if (active) setNHIStaticPostureLoading(false);
      });
    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    let active = true;
    setNHIStalePostureLoading(true);
    setNHIStalePostureError(null);
    api
      .nhiStalePosture()
      .then((posture) => {
        if (!active) return;
        setNHIStalePosture(posture);
      })
      .catch((err) => {
        if (!active) return;
        setNHIStalePosture(null);
        setNHIStalePostureError(err instanceof Error ? err.message : String(err));
      })
      .finally(() => {
        if (active) setNHIStalePostureLoading(false);
      });
    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    let active = true;
    setNHIExposurePostureLoading(true);
    setNHIExposurePostureError(null);
    api
      .nhiExposurePosture()
      .then((posture) => {
        if (!active) return;
        setNHIExposurePosture(posture);
      })
      .catch((err) => {
        if (!active) return;
        setNHIExposurePosture(null);
        setNHIExposurePostureError(err instanceof Error ? err.message : String(err));
      })
      .finally(() => {
        if (active) setNHIExposurePostureLoading(false);
      });
    return () => {
      active = false;
    };
  }, []);

  function applySort(next: DataGridSort) {
    const columnId = next.columnId as RiskSortColumn;
    const serverSort = columnId === "expires_at" ? "expiry" : "score";
    setSort(next);
    setQuery((current) => ({ ...current, sort: serverSort }));
  }

  function applyFilters(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const parsedMinScore = Number(minScore);
    const parsedPrivilege = Number(privilege);
    setQuery((current) => ({
      ...current,
      minScore: minScore.trim() && Number.isFinite(parsedMinScore) ? parsedMinScore : undefined,
      privilege: privilege !== "" && Number.isFinite(parsedPrivilege) ? parsedPrivilege : undefined,
      owner: owner.trim() || undefined,
    }));
  }

  const columns = useMemo<Array<DataGridColumn<CredentialRisk>>>(
    () => [
      { id: "subject", header: "Credential", cell: (risk) => <span data-testid="risk-subject">{risk.subject}</span> },
      {
        id: "score",
        header: "Score",
        sortable: true,
        cell: (risk) => (
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-medium">{Math.round(risk.score)}</span>
            <StatusBadge vocabulary="risk" value={riskBand(risk.score)} />
          </div>
        ),
      },
      { id: "top_factor", header: "Top factor", cell: (risk) => formatTopFactor(risk) },
      { id: "expires_at", header: "Expires", sortable: true, cell: (risk) => formatDate(risk.expires_at) },
      {
        id: "privilege",
        header: "Privilege",
        cell: (risk) => <RiskScaleLabel label={scaleLabel(privilegeLabel, risk.privilege)} raw={risk.privilege} name="privilege" />,
      },
      {
        id: "sensitivity",
        header: "Sensitivity",
        cell: (risk) => <RiskScaleLabel label={scaleLabel(sensitivityLabel, risk.sensitivity)} raw={risk.sensitivity} name="sensitivity" />,
      },
      { id: "owner", header: "Owner", cell: (risk) => (risk.owner_active ? "active" : "orphaned") },
      {
        id: "actions",
        header: "Actions",
        cell: (risk) => {
          const isExpanded = expanded === risk.credential_id;
          return (
            <Button type="button" size="sm" variant="outline" onClick={() => setExpanded(isExpanded ? null : risk.credential_id)}>
              {isExpanded ? "Hide factors" : "Show factors"}
            </Button>
          );
        },
      },
    ],
    [expanded],
  );

  return (
    <section aria-labelledby="risk-heading">
      <PageHeader
        titleId="risk-heading"
        title="Credential risk"
        description="A ranked list of individual credentials by urgency — what to rotate first. For fleet-wide crypto hygiene like configuration drift and post-quantum readiness, see Crypto posture."
      />

      <RiskPosture risks={data ?? []} />
      <ContextualRiskPanel priorities={contextualRisk} loading={contextualRiskLoading} error={contextualRiskError} />
      <NHIPolicyCompliancePanel posture={nhiPolicyCompliance} loading={nhiPolicyComplianceLoading} error={nhiPolicyComplianceError} />
      <NHIOverPrivilegePanel posture={nhiPosture} loading={nhiPostureLoading} error={nhiPostureError} />
      <NHIStalePanel posture={nhiStalePosture} loading={nhiStalePostureLoading} error={nhiStalePostureError} />
      <NHIStaticPanel posture={nhiStaticPosture} loading={nhiStaticPostureLoading} error={nhiStaticPostureError} />
      <NHIExposurePanel posture={nhiExposurePosture} loading={nhiExposurePostureLoading} error={nhiExposurePostureError} />

      <RiskLegend />

      <DataGrid
        ariaLabel="Certificate risk scores"
        rows={rows}
        columns={columns}
        getRowId={(risk) => risk.credential_id}
        state={loading ? "loading" : error ? "error" : rows.length === 0 ? "empty" : "ready"}
        stateTitle={error ? "Could not load risk scores" : "No matching certificate rows"}
        stateMessage={error ?? "No certificate risk scores match the current filter."}
        sort={sort}
        onSort={applySort}
        showColumnChooser
        toolbar={({ columnChooser }) => (
          <DataGridToolbar
            searchLabel="Search credential risk rows"
            searchPlaceholder="Search credential or owner state"
            searchValue={search}
            onSearchChange={setSearch}
            filters={
              <RiskFilterForm
                minScore={minScore}
                privilege={privilege}
                owner={owner}
                onMinScore={setMinScore}
                onPrivilege={setPrivilege}
                onOwner={setOwner}
                onSubmit={applyFilters}
              />
            }
            columnChooser={columnChooser}
          />
        )}
      />

      {expandedRisk && (
        <section aria-labelledby="risk-detail-heading" className="mt-4 rounded-panel border border-border bg-card p-4 shadow-elevation1">
          <h2 id="risk-detail-heading" className="mb-2 text-title font-semibold">
            Six-factor breakdown for {expandedRisk.subject}
          </h2>
          <RiskDetail risk={expandedRisk} activeFactor={topFactor(expandedRisk)} />
        </section>
      )}
    </section>
  );
}

function ContextualRiskPanel({ priorities, loading, error }: { priorities: ContextualRiskPriorities | null; loading: boolean; error: string | null }) {
  const { t } = useTranslation();
  const topPriorities = priorities?.priorities?.slice(0, 5) ?? [];
  return (
    <section aria-labelledby="contextual-risk-heading" className="mb-4 border-b border-border pb-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 id="contextual-risk-heading" className="text-title font-semibold">
            {t("risk.contextual.heading")}
          </h2>
          {priorities && (
            <p className="mt-1 text-sm text-muted-foreground">
              {t("risk.contextual.summary", {
                priorities: priorities.summary.priorities,
                total: priorities.summary.total_analyzed,
                highBlast: priorities.summary.high_blast_radius,
                weakCrypto: priorities.summary.weak_crypto_context,
              })}
            </p>
          )}
        </div>
        {priorities && (
          <StatusBadge
            vocabulary="risk"
            value={priorities.summary.critical > 0 ? "critical" : priorities.summary.high > 0 ? "high" : priorities.summary.medium > 0 ? "medium" : "low"}
          />
        )}
      </div>

      {loading && <p className="mt-3 text-sm text-muted-foreground">{t("risk.contextual.loading")}</p>}
      {error && (
        <div className="mt-3">
          <UnavailableState title={t("risk.contextual.unavailableTitle")}>{error}</UnavailableState>
        </div>
      )}
      {!loading && !error && priorities && topPriorities.length === 0 && (
        <p className="mt-3 text-sm text-muted-foreground">{t("risk.contextual.empty")}</p>
      )}
      {!loading && !error && topPriorities.length > 0 && (
        <div className="mt-3 overflow-x-auto">
          <table className="ui-table min-w-[58rem]">
            <caption className="sr-only">{t("risk.contextual.caption")}</caption>
            <thead>
              <tr>
                <th scope="col">{t("risk.contextual.credential")}</th>
                <th scope="col">{t("risk.contextual.priority")}</th>
                <th scope="col">{t("risk.contextual.blastRadius")}</th>
                <th scope="col">{t("risk.contextual.action")}</th>
              </tr>
            </thead>
            <tbody>
              {topPriorities.map((priority) => (
                <tr key={priority.credential_id}>
                  <td>
                    <p className="font-medium">{priority.subject}</p>
                    <p className="text-caption text-muted-foreground">#{priority.rank} · {priority.credential_id}</p>
                  </td>
                  <td>
                    <div className="flex flex-wrap items-center gap-2">
                      <StatusBadge vocabulary="risk" value={priority.severity} />
                      <span>
                        {t("risk.contextual.scoreValue", {
                          contextual: priority.contextual_score.toFixed(1),
                          base: priority.base_score.toFixed(1),
                        })}
                      </span>
                    </div>
                    <p className="mt-1 text-caption text-muted-foreground">{priority.priority_reasons.join(", ")}</p>
                  </td>
                  <td>
                    {t("risk.contextual.blastValue", {
                      total: priority.blast_radius,
                      resources: priority.resource_blast_radius,
                      cryptoAssets: priority.crypto_asset_blast_radius,
                    })}
                  </td>
                  <td>{priority.recommended_action}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

function NHIPolicyCompliancePanel({ posture, loading, error }: { posture: NHIPolicyCompliance | null; loading: boolean; error: string | null }) {
  const { t } = useTranslation();
  const topFindings = posture?.findings?.slice(0, 5) ?? [];
  return (
    <section aria-labelledby="nhi-policy-heading" className="mb-4 border-y border-border py-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 id="nhi-policy-heading" className="text-title font-semibold">
            {t("risk.nhiPolicy.heading")}
          </h2>
          {posture && (
            <p className="mt-1 text-sm text-muted-foreground">
              {t("risk.nhiPolicy.summary", {
                violations: posture.summary.violations,
                total: posture.summary.total_analyzed,
                rotation: posture.summary.rotation_violations,
                scope: posture.summary.scope_violations,
                geo: posture.summary.geo_violations,
                expiry: posture.summary.expiry_violations,
                purpose: posture.summary.business_purpose_missing,
              })}
            </p>
          )}
        </div>
        {posture && <StatusBadge vocabulary="risk" value={posture.summary.critical > 0 ? "critical" : posture.summary.high > 0 ? "high" : posture.summary.medium > 0 ? "medium" : "low"} />}
      </div>

      {loading && <p className="mt-3 text-sm text-muted-foreground">{t("risk.nhiPolicy.loading")}</p>}
      {error && (
        <div className="mt-3">
          <UnavailableState title={t("risk.nhiPolicy.unavailableTitle")}>{error}</UnavailableState>
        </div>
      )}
      {!loading && !error && posture && topFindings.length === 0 && (
        <p className="mt-3 text-sm text-muted-foreground">{t("risk.nhiPolicy.empty")}</p>
      )}
      {!loading && !error && topFindings.length > 0 && (
        <div className="mt-3 overflow-x-auto">
          <table className="ui-table min-w-[62rem]">
            <caption className="sr-only">{t("risk.nhiPolicy.caption")}</caption>
            <thead>
              <tr>
                <th scope="col">{t("risk.nhiPolicy.nhi")}</th>
                <th scope="col">{t("risk.nhiPolicy.violations")}</th>
                <th scope="col">{t("risk.nhiPolicy.envelope")}</th>
                <th scope="col">{t("risk.nhiPolicy.recommendation")}</th>
              </tr>
            </thead>
            <tbody>
              {topFindings.map((finding) => (
                <tr key={finding.inventory_id}>
                  <td>
                    <p className="font-medium">{finding.display_name}</p>
                    <p className="text-caption text-muted-foreground">
                      {finding.kind} · {finding.source}
                    </p>
                  </td>
                  <td>
                    <div className="flex flex-wrap items-center gap-2">
                      <StatusBadge vocabulary="risk" value={finding.severity} />
                      <span>{finding.violation_types.join(", ")}</span>
                    </div>
                  </td>
                  <td>
                    {t("risk.nhiPolicy.envelopeValue", {
                      scopes: finding.disallowed_scopes?.join(", ") || t("risk.nhiPolicy.none"),
                      geos: finding.disallowed_geos?.join(", ") || t("risk.nhiPolicy.none"),
                    })}
                  </td>
                  <td>{finding.recommendation}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

function NHIStaticPanel({ posture, loading, error }: { posture: NHIStaticPosture | null; loading: boolean; error: string | null }) {
  const { t } = useTranslation();
  const topFindings = posture?.findings?.slice(0, 5) ?? [];
  return (
    <section aria-labelledby="nhi-static-heading" className="mb-4 border-b border-border pb-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 id="nhi-static-heading" className="text-title font-semibold">
            {t("risk.nhiStatic.heading")}
          </h2>
          {posture && (
            <p className="mt-1 text-sm text-muted-foreground">
              {t("risk.nhiStatic.summary", {
                findings: posture.summary.findings,
                total: posture.summary.total_analyzed,
                longLived: posture.summary.long_lived,
                staticCredentials: posture.summary.static_credentials,
              })}
            </p>
          )}
        </div>
        {posture && <StatusBadge vocabulary="risk" value={posture.summary.critical > 0 ? "critical" : posture.summary.high > 0 ? "high" : posture.summary.medium > 0 ? "medium" : "low"} />}
      </div>

      {loading && <p className="mt-3 text-sm text-muted-foreground">{t("risk.nhiStatic.loading")}</p>}
      {error && (
        <div className="mt-3">
          <UnavailableState title={t("risk.nhiStatic.unavailableTitle")}>{error}</UnavailableState>
        </div>
      )}
      {!loading && !error && posture && topFindings.length === 0 && (
        <p className="mt-3 text-sm text-muted-foreground">{t("risk.nhiStatic.empty")}</p>
      )}
      {!loading && !error && topFindings.length > 0 && (
        <div className="mt-3 overflow-x-auto">
          <table className="ui-table min-w-[56rem]">
            <caption className="sr-only">{t("risk.nhiStatic.caption")}</caption>
            <thead>
              <tr>
                <th scope="col">{t("risk.nhiStatic.nhi")}</th>
                <th scope="col">{t("risk.nhiStatic.finding")}</th>
                <th scope="col">{t("risk.nhiStatic.lifetime")}</th>
                <th scope="col">{t("risk.nhiStatic.recommendation")}</th>
              </tr>
            </thead>
            <tbody>
              {topFindings.map((finding) => (
                <tr key={finding.inventory_id}>
                  <td>
                    <p className="font-medium">{finding.display_name}</p>
                    <p className="text-caption text-muted-foreground">
                      {finding.kind} · {finding.source}
                    </p>
                  </td>
                  <td>
                    <div className="flex flex-wrap items-center gap-2">
                      <StatusBadge vocabulary="risk" value={finding.severity} />
                      <span>{finding.finding_types.join(", ")}</span>
                    </div>
                  </td>
                  <td>
                    {t("risk.nhiStatic.lifetimeValue", {
                      age: finding.credential_age_days,
                      ttl: finding.ttl_days,
                      rotation: finding.rotation_age_days,
                    })}
                  </td>
                  <td>{finding.recommendation}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

function NHIExposurePanel({ posture, loading, error }: { posture: NHIExposurePosture | null; loading: boolean; error: string | null }) {
  const { t } = useTranslation();
  const topFindings = posture?.findings?.slice(0, 5) ?? [];
  return (
    <section aria-labelledby="nhi-exposure-heading" className="mb-4 border-b border-border pb-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 id="nhi-exposure-heading" className="text-title font-semibold">
            {t("risk.nhiExposure.heading")}
          </h2>
          {posture && (
            <p className="mt-1 text-sm text-muted-foreground">
              {t("risk.nhiExposure.summary", {
                findings: posture.summary.findings,
                total: posture.summary.total_analyzed,
                exposed: posture.summary.internet_exposed,
                weakAuth: posture.summary.weak_authentication,
                insecureTransport: posture.summary.insecure_transport,
              })}
            </p>
          )}
        </div>
        {posture && <StatusBadge vocabulary="risk" value={posture.summary.critical > 0 ? "critical" : posture.summary.high > 0 ? "high" : posture.summary.medium > 0 ? "medium" : "low"} />}
      </div>

      {loading && <p className="mt-3 text-sm text-muted-foreground">{t("risk.nhiExposure.loading")}</p>}
      {error && (
        <div className="mt-3">
          <UnavailableState title={t("risk.nhiExposure.unavailableTitle")}>{error}</UnavailableState>
        </div>
      )}
      {!loading && !error && posture && topFindings.length === 0 && (
        <p className="mt-3 text-sm text-muted-foreground">{t("risk.nhiExposure.empty")}</p>
      )}
      {!loading && !error && topFindings.length > 0 && (
        <div className="mt-3 overflow-x-auto">
          <table className="ui-table min-w-[62rem]">
            <caption className="sr-only">{t("risk.nhiExposure.caption")}</caption>
            <thead>
              <tr>
                <th scope="col">{t("risk.nhiExposure.nhi")}</th>
                <th scope="col">{t("risk.nhiExposure.finding")}</th>
                <th scope="col">{t("risk.nhiExposure.exposure")}</th>
                <th scope="col">{t("risk.nhiExposure.recommendation")}</th>
              </tr>
            </thead>
            <tbody>
              {topFindings.map((finding) => (
                <tr key={finding.inventory_id}>
                  <td>
                    <p className="font-medium">{finding.display_name}</p>
                    <p className="text-caption text-muted-foreground">
                      {finding.kind} · {finding.source}
                    </p>
                  </td>
                  <td>
                    <div className="flex flex-wrap items-center gap-2">
                      <StatusBadge vocabulary="risk" value={finding.severity} />
                      <span>{finding.finding_types.join(", ")}</span>
                    </div>
                  </td>
                  <td>
                    {t("risk.nhiExposure.exposureValue", {
                      level: finding.exposure_level || t("risk.nhiExposure.unknown"),
                      auth: finding.auth_mode || t("risk.nhiExposure.unknown"),
                      transport: finding.transport_security || t("risk.nhiExposure.unknown"),
                    })}
                  </td>
                  <td>{finding.recommendation}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

function NHIStalePanel({ posture, loading, error }: { posture: NHIStalePosture | null; loading: boolean; error: string | null }) {
  const { t } = useTranslation();
  const topFindings = posture?.findings?.slice(0, 5) ?? [];
  return (
    <section aria-labelledby="nhi-stale-heading" className="mb-4 border-b border-border pb-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 id="nhi-stale-heading" className="text-title font-semibold">
            {t("risk.nhiStale.heading")}
          </h2>
          {posture && (
            <p className="mt-1 text-sm text-muted-foreground">
              {t("risk.nhiStale.summary", {
                findings: posture.summary.findings,
                total: posture.summary.total_analyzed,
                dormant: posture.summary.dormant,
                orphaned: posture.summary.orphaned,
              })}
            </p>
          )}
        </div>
        {posture && <StatusBadge vocabulary="risk" value={posture.summary.critical > 0 ? "critical" : posture.summary.high > 0 ? "high" : posture.summary.medium > 0 ? "medium" : "low"} />}
      </div>

      {loading && <p className="mt-3 text-sm text-muted-foreground">{t("risk.nhiStale.loading")}</p>}
      {error && (
        <div className="mt-3">
          <UnavailableState title={t("risk.nhiStale.unavailableTitle")}>{error}</UnavailableState>
        </div>
      )}
      {!loading && !error && posture && topFindings.length === 0 && (
        <p className="mt-3 text-sm text-muted-foreground">{t("risk.nhiStale.empty")}</p>
      )}
      {!loading && !error && topFindings.length > 0 && (
        <div className="mt-3 overflow-x-auto">
          <table className="ui-table min-w-[56rem]">
            <caption className="sr-only">{t("risk.nhiStale.caption")}</caption>
            <thead>
              <tr>
                <th scope="col">{t("risk.nhiStale.nhi")}</th>
                <th scope="col">{t("risk.nhiStale.finding")}</th>
                <th scope="col">{t("risk.nhiStale.age")}</th>
                <th scope="col">{t("risk.nhiStale.recommendation")}</th>
              </tr>
            </thead>
            <tbody>
              {topFindings.map((finding) => (
                <tr key={finding.inventory_id}>
                  <td>
                    <p className="font-medium">{finding.display_name}</p>
                    <p className="text-caption text-muted-foreground">
                      {finding.kind} · {finding.owner_status}
                    </p>
                  </td>
                  <td>
                    <div className="flex flex-wrap items-center gap-2">
                      <StatusBadge vocabulary="risk" value={finding.severity} />
                      <span>{finding.finding_types.join(", ")}</span>
                    </div>
                  </td>
                  <td>
                    {t("risk.nhiStale.ageValue", {
                      activity: finding.activity_age_days,
                      created: finding.created_age_days,
                    })}
                  </td>
                  <td>{finding.recommendation}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

function NHIOverPrivilegePanel({ posture, loading, error }: { posture: NHIOverPrivilegePosture | null; loading: boolean; error: string | null }) {
  const { t } = useTranslation();
  const topFindings = posture?.findings?.slice(0, 5) ?? [];
  return (
    <section aria-labelledby="nhi-overprivilege-heading" className="mb-4 border-y border-border py-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 id="nhi-overprivilege-heading" className="text-title font-semibold">
            {t("risk.nhiOverprivilege.heading")}
          </h2>
          {posture && (
            <p className="mt-1 text-sm text-muted-foreground">
              {t("risk.nhiOverprivilege.summary", {
                overprivileged: posture.summary.overprivileged,
                total: posture.summary.total_analyzed,
                unused: posture.summary.unused_grants,
              })}
            </p>
          )}
        </div>
        {posture && <StatusBadge vocabulary="risk" value={posture.summary.critical > 0 ? "critical" : posture.summary.high > 0 ? "high" : "low"} />}
      </div>

      {loading && <p className="mt-3 text-sm text-muted-foreground">{t("risk.nhiOverprivilege.loading")}</p>}
      {error && (
        <div className="mt-3">
          <UnavailableState title={t("risk.nhiOverprivilege.unavailableTitle")}>{error}</UnavailableState>
        </div>
      )}
      {!loading && !error && posture && topFindings.length === 0 && (
        <p className="mt-3 text-sm text-muted-foreground">{t("risk.nhiOverprivilege.empty")}</p>
      )}
      {!loading && !error && topFindings.length > 0 && (
        <div className="mt-3 overflow-x-auto">
          <table className="ui-table min-w-[56rem]">
            <caption className="sr-only">{t("risk.nhiOverprivilege.caption")}</caption>
            <thead>
              <tr>
                <th scope="col">{t("risk.nhiOverprivilege.nhi")}</th>
                <th scope="col">{t("risk.nhiOverprivilege.severity")}</th>
                <th scope="col">{t("risk.nhiOverprivilege.unusedGrants")}</th>
                <th scope="col">{t("risk.nhiOverprivilege.recommendation")}</th>
              </tr>
            </thead>
            <tbody>
              {topFindings.map((finding) => (
                <tr key={finding.inventory_id}>
                  <td>
                    <p className="font-medium">{finding.display_name}</p>
                    <p className="text-caption text-muted-foreground">
                      {finding.kind} · {finding.source}
                    </p>
                  </td>
                  <td>
                    <StatusBadge vocabulary="risk" value={finding.severity} />
                  </td>
                  <td>{finding.unused_scopes.join(", ")}</td>
                  <td>{finding.recommendation}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

function RiskFilterForm({
  minScore,
  privilege,
  owner,
  onMinScore,
  onPrivilege,
  onOwner,
  onSubmit,
}: {
  minScore: string;
  privilege: string;
  owner: string;
  onMinScore: (value: string) => void;
  onPrivilege: (value: string) => void;
  onOwner: (value: string) => void;
  onSubmit: (event: FormEvent<HTMLFormElement>) => void;
}) {
  return (
    <form className="flex flex-wrap items-end gap-2" onSubmit={onSubmit}>
      <label className="grid gap-1 text-sm font-medium">
        Minimum score
        <input
          className="min-h-9 w-28 rounded-control border border-input bg-background px-2 text-sm"
          type="number"
          min={0}
          max={100}
          value={minScore}
          onChange={(event) => onMinScore(event.target.value)}
        />
      </label>
      <label className="grid gap-1 text-sm font-medium">
        Privilege
        <select
          className="min-h-9 rounded-control border border-input bg-background px-2 text-sm"
          value={privilege}
          onChange={(event) => onPrivilege(event.target.value)}
        >
          <option value="">Any privilege</option>
          {privilegeLabel.map((label, index) => (
            <option key={label} value={index}>
              {label}
            </option>
          ))}
        </select>
      </label>
      <label className="grid gap-1 text-sm font-medium">
        Owner
        <input
          className="min-h-9 w-36 rounded-control border border-input bg-background px-2 text-sm"
          value={owner}
          onChange={(event) => onOwner(event.target.value)}
          placeholder="owner id"
        />
      </label>
      <Button type="submit" size="sm" variant="outline">
        Apply risk filters
      </Button>
    </form>
  );
}

function RiskDetail({ risk, activeFactor }: { risk: CredentialRisk; activeFactor: RiskFactor }) {
  const encodedCredential = encodeURIComponent(risk.credential_id);
  const graphNode = encodeURIComponent(`cert:${risk.credential_id}`);
  return (
    <div className="grid gap-4 lg:grid-cols-[1fr_16rem]">
      <div>
        <h2 className="mb-2 text-sm font-semibold">Six-factor breakdown</h2>
        <div className="grid gap-2 md:grid-cols-2">
          {factorKeys.map((factor) => (
            <FactorBar key={factor} factor={factor} value={risk.components[factor]} active={factor === activeFactor} />
          ))}
        </div>
        <dl className="mt-4 grid gap-2 text-sm md:grid-cols-2">
          <div className="rounded-md border border-border p-2">
            <dt className="font-medium text-muted-foreground">Privilege label</dt>
            <dd>
              {scaleLabel(privilegeLabel, risk.privilege)} <span className="text-muted-foreground">(raw {risk.privilege})</span>
            </dd>
          </div>
          <div className="rounded-md border border-border p-2">
            <dt className="font-medium text-muted-foreground">Sensitivity label</dt>
            <dd>
              {scaleLabel(sensitivityLabel, risk.sensitivity)} <span className="text-muted-foreground">(raw {risk.sensitivity})</span>
            </dd>
          </div>
        </dl>
      </div>
      <div>
        <h2 className="mb-2 text-sm font-semibold">Drilldown links</h2>
        <ul className="space-y-1">
          <li>
            <a className="text-primary underline" href={`/certificates?credential=${encodedCredential}`}>
              Credential detail
            </a>
          </li>
          <li>
            <a className="text-primary underline" href={`/owners?status=${risk.owner_active ? "active" : "orphaned"}`}>
              Owner status {risk.owner_active ? "active" : "orphaned"}
            </a>
          </li>
          <li>
            <a className="text-primary underline" href={`/graph?node=${graphNode}`}>
              Graph blast radius
            </a>
          </li>
          <li>
            <a className="text-primary underline" href={`/audit?credential=${encodedCredential}`}>
              Audit evidence
            </a>
          </li>
        </ul>
      </div>
    </div>
  );
}

function RiskLegend() {
  const description = riskThresholds.map((band) => `${riskBandLabel(band.value)} ${band.label}`).join(", ");

  return (
    <div className="group relative mb-4 inline-flex">
      <Button type="button" size="sm" variant="outline" aria-describedby="risk-band-tooltip" title={description}>
        <Info className="h-4 w-4" aria-hidden="true" />
        Risk bands
      </Button>
      <div
        id="risk-band-tooltip"
        role="tooltip"
        className="pointer-events-none absolute start-0 top-full z-20 mt-2 w-72 rounded-panel border border-border bg-card p-3 text-sm opacity-0 shadow-elevation2 transition-opacity group-focus-within:opacity-100 group-hover:opacity-100"
      >
        <p className="mb-2 font-medium">Risk band thresholds</p>
        <div className="flex flex-wrap gap-2">
          {riskThresholds.map((band) => (
            <span key={band.value} className="inline-flex items-center gap-2 rounded-control border border-border px-2 py-1">
              <StatusBadge vocabulary="risk" value={band.value} />
              <span className="text-muted-foreground">{band.label}</span>
            </span>
          ))}
        </div>
      </div>
    </div>
  );
}

function riskBandLabel(value: (typeof riskThresholds)[number]["value"]): string {
  return value.charAt(0).toUpperCase() + value.slice(1);
}

function RiskScaleLabel({ label, raw, name }: { label: string; raw: number; name: string }) {
  return (
    <span title={`Raw ${name} value ${raw}`}>
      {label}
      <span className="sr-only">, raw {raw}</span>
    </span>
  );
}

function FactorBar({ factor, value, active }: { factor: RiskFactor; value: number; active: boolean }) {
  const pct = factorPercent(value);
  return (
    <div data-testid={`risk-factor-${factor}`} className={active ? "rounded-md border border-primary p-2" : "rounded-md border border-border p-2"}>
      <div className="mb-1 flex items-center justify-between gap-2">
        <span className="font-medium">{factorLabels[factor]}</span>
        <span>{pct}</span>
      </div>
      <div className="h-2 rounded-full bg-background" aria-label={`${factorLabels[factor]} risk ${pct}`}>
        <div className="h-2 rounded-full bg-primary" style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}

function isCertificateRisk(risk: CredentialRisk): boolean {
  return risk.kind === "certificate" || risk.kind === "x509_certificate";
}

function factorPercent(value: number): number {
  const normalized = value <= 1 ? value * 100 : value;
  return Math.max(0, Math.min(100, Math.round(normalized)));
}

function formatTopFactor(risk: CredentialRisk): string {
  const factor = topFactor(risk);
  return `${factorLabels[factor]} ${factorPercent(risk.components[factor])}`;
}

function scaleLabel(labels: string[], value: number): string {
  return labels[value] ?? `Unknown ${value}`;
}

function formatDate(value?: string): string {
  return formatDatePolicy(value);
}

function topFactor(risk: CredentialRisk): RiskFactor {
  return factorKeys.reduce((best, next) => (factorPercent(risk.components[next]) > factorPercent(risk.components[best]) ? next : best));
}

export { privilegeLabel, sensitivityLabel };
