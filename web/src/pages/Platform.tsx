import { useEffect, useMemo, useState, type FormEvent } from "react";
import { Navigate, useSearchParams } from "react-router-dom";
import { Building2, Gauge, Headphones, Network, Plus } from "lucide-react";
import { useAuth } from "@/auth/AuthProvider";
import { AdminHeaderActions } from "@/components/AdminHeaderActions";
import { PageHeader } from "@/components/PageHeader";
import { StatusBadge } from "@/components/StatusBadge";
import { DRPosturePanel } from "@/components/DRPosturePanel";
import { IdempotencyResultProtectionPanel, TenantKeyDomainPanel, UsageEvidencePanel } from "@/components/TenantCustodyPanels";
import { Button } from "@/components/ui/button";
import { useTranslation, translateNow } from "@/i18n/I18nProvider";
import { formatCurrency as formatCurrencyPolicy, formatDateTime, formatNumber as formatNumberPolicy, type FormatPolicy } from "@/i18n/format";
import {
  api,
  type ActiveActiveIssuancePlan,
  type EditionsInfo,
  type EnterpriseSupportStatus,
  type ManagedOfferingStatus,
  type ManagedTenant,
  type ManagedTenantProvisionRequest,
  type PlatformDistributionStatus,
  type ScaleOrchestrationPlan,
  type SystemReadout,
  type DRPosture,
} from "@/lib/api";
import { optionalApiCall } from "@/lib/optionalApi";

export { AdminAccess } from "@/pages/AdminAccess";

function browserTransport(): { label: string; detail: string; warning?: string } {
  if (typeof window === "undefined") {
    return { label: translateNow("source.unknown.b764cdc0ea"), detail: translateNow("source.browser.transport.is.evaluated.at.runtime.94214a825a") };
  }
  if (window.location.protocol === "https:") {
    return {
      label: translateNow("source.https.observed.50a13e2b41"),
      detail: translateNow("source.the.console.is.currently.loaded.over.an.en.4e9bab4e91"),
    };
  }
  return {
    label: translateNow("source.local.preview.http.957e66ac19"),
    detail: translateNow("source.the.local.vite.preview.is.http.production.7f2e105c44"),
    warning: translateNow("source.plaintext.local.preview.no.private.cert.ke.e5059d6667"),
  };
}

const defaultPackaging: NonNullable<EditionsInfo["packaging"]> = {
  category_label: "Machine Identity Security Control Plane",
  positioning: "One control plane for machine credentials, secrets, SSH certificates, X.509, API tokens, and SPIFFE workload identities.",
  billable_unit: "control_plane_deployment",
  provider_billing_unit: "managed_customer_band",
  no_per_certificate_billing: true,
  no_ephemeral_identity_billing: true,
  certificate_counters_classification: "operational_telemetry",
  managed_boundary:
    "Provider/MSP normally runs one shared control plane with multiple customer tenants, with dedicated customer deployments available when its security posture requires them.",
  pricing_posture:
    "Free is the self-hosted MPL core. Enterprise reference list is USD 15,000/year Standard or USD 30,000/year Plus per production control-plane deployment. Provider/MSP reference bands start at USD 12,000/year.",
  bundled_non_production_deployments: 3,
  non_production_support_posture: "Three bound non-production control planes are included with no production SLA.",
  reference_price_bands: [
    { id: "enterprise-standard", label: "", annual_usd: 15000, unit: "production control plane" },
    { id: "enterprise-plus", label: "", annual_usd: 30000, unit: "HA production control plane" },
    { id: "provider-1-10", label: "", annual_usd: 12000, unit: "managed customer band" },
    { id: "provider-11-50", label: "", annual_usd: 30000, unit: "managed customer band" },
    { id: "provider-51-250", label: "", annual_usd: 72000, unit: "managed customer band" },
  ],
  evidence_rail: ["live eval receipts", "served NHI route coverage", "OWASP NHI mapping", "current limitations"],
  editions: [
    { id: "community", name: "Free", column: "Free", buyer_fit: "", license_boundary: "", billing: "", included: [] },
    { id: "enterprise", name: "Enterprise self-host", column: "Enterprise", buyer_fit: "", license_boundary: "", billing: "", included: [] },
    { id: "provider", name: "Provider / MSP", column: "Provider / MSP", buyer_fit: "", license_boundary: "", billing: "", included: [] },
  ],
  meters: [],
};

const priceBandLabelKeys = {
  "enterprise-standard": "platform.editions.enterpriseStandard",
  "enterprise-plus": "platform.editions.enterprisePlus",
  "provider-1-10": "platform.editions.provider1To10",
  "provider-11-50": "platform.editions.provider11To50",
  "provider-51-250": "platform.editions.provider51To250",
} as const;

/** C-A1 (07-closeout plan): the /platform tab grab-bag became three real
 * routes — /admin/access, /admin/system, /admin/editions — each deep-linkable
 * and individually fetch-scoped. /platform stays registered forever as a
 * redirector so historical deep links, docs, and muscle memory keep working. */
export function PlatformRedirect() {
  const [searchParams] = useSearchParams();
  const tab = searchParams.get("tab");
  if (tab === "posture") return <Navigate to="/admin/system" replace />;
  if (tab === "editions") return <Navigate to="/admin/editions" replace />;
  return <Navigate to="/admin/access" replace />;
}

export function AdminSystem() {
  const { user, preview } = useAuth();
  const { locale, timeZone, t } = useTranslation();
  const formatPolicy = useMemo<FormatPolicy>(() => ({ locale, timeZone }), [locale, timeZone]);
  const transport = browserTransport();
  const csrfPresent = typeof document !== "undefined" && document.cookie.includes("trstctl_csrf=");
  const [editions, setEditions] = useState<EditionsInfo | null>(null);
  const [enterpriseSupport, setEnterpriseSupport] = useState<EnterpriseSupportStatus | null>(null);
  const [managedOffering, setManagedOffering] = useState<ManagedOfferingStatus | null>(null);
  const [scaleOrchestration, setScaleOrchestration] = useState<ScaleOrchestrationPlan | null>(null);
  const [systemReadout, setSystemReadout] = useState<SystemReadout | null>(null);
  // J2: DR posture is fetched separately from the system readout because it can
  // fail on its own — an unreadable backup directory is a real finding, and
  // folding it into the readout would either hide that or take the whole panel
  // down with it.
  const [drPosture, setDRPosture] = useState<DRPosture | null>(null);
  const [drError, setDRError] = useState<string | null>(null);
  const [protectionLoading, setProtectionLoading] = useState(true);
  const [protectionError, setProtectionError] = useState<string | null>(null);
  const [lastManagedTenant, setLastManagedTenant] = useState<ManagedTenant | null>(null);
  const [systemBusy, setSystemBusy] = useState(false);
  const [systemError, setSystemError] = useState<string | null>(null);
  const [systemNotice, setSystemNotice] = useState<string | null>(null);
  const [hostedTenantID, setHostedTenantID] = useState("");
  const [hostedTenantName, setHostedTenantName] = useState("");
  const [hostedRegion, setHostedRegion] = useState("us-east-1");
  const [hostedResidency, setHostedResidency] = useState("US");
  const [hostedPlan, setHostedPlan] = useState("enterprise");
  const [hostedSupportTier, setHostedSupportTier] = useState("24x7");
  const [hostedSLOTier, setHostedSLOTier] = useState("99.95");
  const packaging = editions?.packaging ?? defaultPackaging;

  useEffect(() => {
    let active = true;
    Promise.all([api.editions(), api.enterpriseSupportStatus(), api.managedOfferingStatus(), api.scaleOrchestration()])
      .then(([editionInfo, supportStatus, managedStatus, scaleStatus]) => {
        if (!active) return;
        setEditions(editionInfo);
        setEnterpriseSupport(supportStatus);
        setManagedOffering(managedStatus);
        setScaleOrchestration(scaleStatus);
      })
      .catch((err) => {
        if (active) setSystemError(err instanceof Error ? err.message : String(err));
      });
    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    let active = true;
    setProtectionLoading(true);
    api
      .platformSystem()
      .then((readout) => {
        if (!active) return;
        setSystemReadout(readout);
        setProtectionError(null);
      })
      .catch((err) => {
        if (!active) return;
        setProtectionError(err instanceof Error ? err.message : String(err));
      })
      .finally(() => {
        if (active) setProtectionLoading(false);
      });
    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    let active = true;
    // Optional-method guard (see lib/optionalApi): a client without this method
    // must leave the panel absent, not blank the Platform page.
    optionalApiCall<DRPosture | null>("drPosture", null)
      .then((posture) => {
        if (!active) return;
        setDRPosture(posture);
        setDRError(null);
      })
      .catch((err) => {
        if (!active) return;
        setDRError(err instanceof Error ? err.message : String(err));
      });
    return () => {
      active = false;
    };
  }, []);

  async function provisionHostedTenant(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSystemBusy(true);
    setSystemError(null);
    setSystemNotice(null);
    try {
      const input: ManagedTenantProvisionRequest = {
        tenant_id: hostedTenantID.trim(),
        name: hostedTenantName.trim(),
        ...(hostedRegion.trim() ? { region: hostedRegion.trim() } : {}),
        ...(hostedResidency.trim() ? { data_residency: hostedResidency.trim() } : {}),
        ...(hostedPlan.trim() ? { plan: hostedPlan.trim() } : {}),
        ...(hostedSupportTier.trim() ? { support_tier: hostedSupportTier.trim() } : {}),
        ...(hostedSLOTier.trim() ? { slo_tier: hostedSLOTier.trim() } : {}),
      };
      const created = await api.provisionManagedTenant(input);
      setLastManagedTenant(created);
      setSystemNotice(`Provisioned managed tenant ${created.name}`);
      setHostedTenantID("");
      setHostedTenantName("");
    } catch (err) {
      setSystemError(err instanceof Error ? err.message : String(err));
    } finally {
      setSystemBusy(false);
    }
  }

  return (
    <section aria-labelledby="admin-system-heading" className="grid gap-6">
      <PageHeader
        titleId="admin-system-heading"
        title={t("platform.tabs.posture")}
        description={t("admin.system.description")}
        actions={<AdminHeaderActions />}
      />
      {systemError && (
        <p role="alert" className="rounded-control border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm text-destructive">
          {systemError}
        </p>
      )}
      {systemNotice && (
        <p role="status" className="rounded-control border border-status-success/30 bg-status-success/10 px-3 py-2 text-sm text-status-success">
          {systemNotice}
        </p>
      )}
      <div className="grid gap-6">
        <TenantKeyDomainPanel canWrite={Boolean(user?.permissions?.includes("keys:write"))} />
        <IdempotencyResultProtectionPanel readout={systemReadout} loading={protectionLoading} requestError={protectionError} />
        <UsageEvidencePanel />

        <DRPosturePanel posture={drPosture} error={drError} formatPolicy={formatPolicy} />

        {/* D3: issued / delivered / verified.
            Delivered is this pipeline's account of what it did; verified is
            what a client actually gets. Only a TLS handshake establishes the
            second, so they are counted separately and the panel leads with the
            one that is not self-reported. */}
        {systemReadout?.deployment && systemReadout.deployment.delivered > 0 ? (
          <section className="ui-panel p-comfortable" aria-labelledby="deployment-truth-heading">
            <h2 id="deployment-truth-heading" className="text-title font-semibold">
              {translateNow("source.deployment.truth.d3tri00001")}
            </h2>
            <p className="mt-1 max-w-3xl text-caption text-muted-foreground">{translateNow("source.deployment.truth.help.d3tri00002")}</p>
            <dl className="mt-4 grid gap-4 sm:grid-cols-4">
              <div>
                <dt className="text-caption font-medium text-muted-foreground">{translateNow("source.delivered.d3tri00003")}</dt>
                <dd className="text-title font-semibold tabular-nums">{systemReadout.deployment.delivered}</dd>
              </div>
              <div>
                <dt className="text-caption font-medium text-muted-foreground">{translateNow("source.verified.serving.d3tri00004")}</dt>
                <dd className="text-title font-semibold tabular-nums text-status-success">
                  {systemReadout.deployment.verified}
                  <span className="ml-1 text-body font-normal text-muted-foreground">({systemReadout.deployment.verified_percent}%)</span>
                </dd>
              </div>
              <div>
                <dt className="text-caption font-medium text-muted-foreground">{translateNow("source.serving.something.else.d3tri00005")}</dt>
                <dd
                  className={
                    systemReadout.deployment.verify_failed > 0
                      ? "text-title font-semibold tabular-nums text-destructive"
                      : "text-title font-semibold tabular-nums"
                  }
                >
                  {systemReadout.deployment.verify_failed}
                </dd>
              </div>
              {/* Unverified is the honest middle: not a failure, not a pass.
                  Nobody has looked. On a fresh install every target is here. */}
              <div>
                <dt className="text-caption font-medium text-muted-foreground">{translateNow("source.not.checked.d3tri00006")}</dt>
                <dd className="text-title font-semibold tabular-nums text-muted-foreground">{systemReadout.deployment.unverified}</dd>
              </div>
            </dl>
          </section>
        ) : null}

        <div className="grid gap-4 lg:grid-cols-4">
          <section className="ui-panel p-comfortable" aria-labelledby="packaging-heading">
            <h2 id="packaging-heading" className="text-title font-semibold">
              {translateNow("source.packaging.0d62bb01df")}
            </h2>
            <dl className="mt-3 grid gap-2 text-sm">
              <div>
                <dt className="font-medium text-muted-foreground">{translateNow("source.category.292c06f004")}</dt>
                <dd>{packaging.category_label}</dd>
              </div>
              <div>
                <dt className="font-medium text-muted-foreground">{translateNow("source.billable.unit.2373d1d5f8")}</dt>
                <dd className="font-mono text-xs">{packaging.billable_unit}</dd>
              </div>
              <div>
                <dt className="font-medium text-muted-foreground">{translateNow("source.provider.unit.7e58335a9f")}</dt>
                <dd className="font-mono text-xs">{packaging.provider_billing_unit}</dd>
              </div>
            </dl>
            <p className="mt-3 text-sm text-muted-foreground">
              {translateNow("source.no.per.certificate.or.ephemeral.identity.b.c797515fce")} {packaging.certificate_counters_classification}.
            </p>
          </section>

          <section className="ui-panel p-comfortable" aria-labelledby="tenant-heading">
            <h2 id="tenant-heading" className="text-title font-semibold">
              {translateNow("source.tenant.boundary.4b458df962")}
            </h2>
            <dl className="mt-3 grid gap-2 text-sm">
              <div>
                <dt className="font-medium text-muted-foreground">{translateNow("source.subject.6897128384")}</dt>
                <dd>{user?.email || user?.subject || "-"}</dd>
              </div>
              <div>
                <dt className="font-medium text-muted-foreground">{translateNow("source.tenant.id.from.session.fb2bbbb246")}</dt>
                <dd className="break-all font-mono text-xs">{user?.tenant_id || "-"}</dd>
              </div>
            </dl>
            <p className="mt-3 text-sm text-muted-foreground">{translateNow("source.the.browser.never.chooses.a.tenant.id.thro.091c4e9bb3")}</p>
          </section>

          <section className="ui-panel p-comfortable" aria-labelledby="transport-heading">
            <h2 id="transport-heading" className="text-title font-semibold">
              {translateNow("source.transport.aaead4abf5")}
            </h2>
            <p className="mt-3 text-sm font-medium">{transport.label}</p>
            <p className="mt-1 text-sm text-muted-foreground">{transport.detail}</p>
            {transport.warning && <p className="mt-2 text-sm font-medium text-status-warning">{transport.warning}</p>}
          </section>

          <section className="ui-panel p-comfortable" aria-labelledby="auth-heading">
            <h2 id="auth-heading" className="text-title font-semibold">
              {translateNow("source.auth.session.0e46f553a4")}
            </h2>
            <dl className="mt-3 grid gap-2 text-sm">
              <div>
                <dt className="font-medium text-muted-foreground">{translateNow("source.mode.visible.to.ui.8520f90032")}</dt>
                <dd>{preview ? translateNow("source.local.preview.session.04a12d6877") : translateNow("source.authenticated.session.e651c7182d")}</dd>
              </div>
              <div>
                <dt className="font-medium text-muted-foreground">{translateNow("source.csrf.cookie.04ee351267")}</dt>
                <dd>
                  {csrfPresent
                    ? translateNow("source.present.for.browser.mutations.f21c11a696")
                    : translateNow("source.not.visible.in.this.browser.context.09390ab73b")}
                </dd>
              </div>
            </dl>
            <p className="mt-3 text-sm text-muted-foreground">{translateNow("source.oidc.mapping.status.and.api.token.administ.565d8d27fd")}</p>
          </section>
        </div>

        <section className="ui-panel p-comfortable" aria-labelledby="scale-orchestration-heading">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="flex items-center gap-2">
              <Gauge className="h-4 w-4 text-status-success" aria-hidden="true" />
              <h2 id="scale-orchestration-heading" className="text-title font-semibold">
                {t("platform.scale.heading")}
              </h2>
            </div>
            <span className={scaleServedClass(scaleOrchestration?.served)}>
              {scaleOrchestration?.served ? t("platform.scale.served") : t("platform.scale.unavailable")}
            </span>
          </div>
          <div className="mt-4 grid gap-4 xl:grid-cols-[minmax(18rem,0.5fr)_minmax(0,1fr)]">
            <dl className="grid content-start gap-2 text-sm">
              <div>
                <dt className="font-medium text-muted-foreground">{t("platform.scale.selectedTier")}</dt>
                <dd>
                  {scaleOrchestration?.selected_capacity_tier?.id ?? "-"} ·{" "}
                  {t("platform.scale.credentialsCount", {
                    count: formatOptionalNumber(scaleOrchestration?.selected_capacity_tier?.managed_credentials, formatPolicy),
                  })}
                </dd>
              </div>
              <div>
                <dt className="font-medium text-muted-foreground">{t("platform.scale.eventsPerDay")}</dt>
                <dd>{formatOptionalNumber(scaleOrchestration?.estimated_daily_event_load, formatPolicy)}</dd>
              </div>
              <div>
                <dt className="font-medium text-muted-foreground">{t("platform.scale.monthlyCost")}</dt>
                <dd>{formatOptionalCurrency(scaleOrchestration?.estimated_monthly_cost_usd, formatPolicy)}</dd>
              </div>
              <div>
                <dt className="font-medium text-muted-foreground">{t("platform.scale.unitCost")}</dt>
                <dd>
                  {formatOptionalUnitCost(
                    scaleOrchestration?.unit_economics?.estimated_cost_per_credential_usd,
                    t("platform.scale.credentialUnit"),
                    formatPolicy,
                  )}
                </dd>
              </div>
              <div>
                <dt className="font-medium text-muted-foreground">{t("platform.scale.signerModel")}</dt>
                <dd>{scaleOrchestration?.signer?.process_model ?? "-"}</dd>
              </div>
              <div>
                <dt className="font-medium text-muted-foreground">{t("platform.scale.projectionFloor")}</dt>
                <dd>
                  {t("platform.scale.projectionFloorValue", {
                    rate: formatOptionalNumber(scaleOrchestration?.projection_replay?.replay_floor_events_per_second, formatPolicy),
                    lag: formatOptionalNumber(scaleOrchestration?.projection_replay?.max_lag_events, formatPolicy),
                  })}
                </dd>
              </div>
            </dl>
            <div className="grid gap-4">
              <div className="overflow-x-auto rounded-panel border border-border">
                <table className="ui-table min-w-[44rem]">
                  <caption className="sr-only">{t("platform.scale.executionCaption")}</caption>
                  <thead>
                    <tr>
                      <th scope="col">{t("platform.scale.lane")}</th>
                      <th scope="col">{t("platform.scale.bulkhead")}</th>
                      <th scope="col">{t("platform.scale.signal")}</th>
                      <th scope="col">{t("platform.scale.slo")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(scaleOrchestration?.execution_lanes ?? []).slice(0, 6).map((lane) => (
                      <tr key={lane.id} className="align-top">
                        <td>
                          <span className="font-medium">{lane.subsystem}</span>
                          <span className="mt-1 block font-mono text-xs text-muted-foreground">{lane.id}</span>
                        </td>
                        <td className="font-mono text-xs">{lane.bulkhead_env.join(", ")}</td>
                        <td>{lane.backpressure_signal}</td>
                        <td>{lane.hot_path_slo}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <div className="grid gap-4 xl:grid-cols-2">
                <div className="overflow-x-auto rounded-panel border border-border">
                  <table className="ui-table min-w-[28rem]">
                    <caption className="sr-only">{t("platform.scale.releaseCaption")}</caption>
                    <thead>
                      <tr>
                        <th scope="col">{t("platform.scale.gate")}</th>
                        <th scope="col">{t("platform.scale.artifact")}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(scaleOrchestration?.release_gates ?? []).map((gate) => (
                        <tr key={gate.id}>
                          <td className="font-medium">{gate.id}</td>
                          <td className="font-mono text-xs">{gate.artifact}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                <div className="overflow-x-auto rounded-panel border border-border">
                  <table className="ui-table min-w-[28rem]">
                    <caption className="sr-only">{t("platform.scale.bandCaption")}</caption>
                    <thead>
                      <tr>
                        <th scope="col">{t("platform.scale.band")}</th>
                        <th scope="col">{t("platform.scale.tier")}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(scaleOrchestration?.target_credential_bands ?? []).map((band) => (
                        <tr key={band.id}>
                          <td>
                            <span className="font-medium">{band.managed_credential}</span>
                            <span className="mt-1 block font-mono text-xs text-muted-foreground">{band.id}</span>
                          </td>
                          <td>{band.capacity_tier}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
              <div className="grid gap-2 text-sm md:grid-cols-2">
                {(scaleOrchestration?.residuals ?? []).slice(0, 2).map((residual) => (
                  <p key={residual} className="rounded-panel border border-border bg-muted/40 p-3 text-muted-foreground">
                    {residual}
                  </p>
                ))}
              </div>
            </div>
          </div>
        </section>

        <section className="ui-panel p-comfortable" aria-labelledby="enterprise-support-heading">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="flex items-center gap-2">
              <Headphones className="h-4 w-4 text-status-success" aria-hidden="true" />
              <h2 id="enterprise-support-heading" className="text-title font-semibold">
                {translateNow("source.enterprise.support.b31b42b62d")}
              </h2>
            </div>
            <span className={supportModeClass(enterpriseSupport?.support_mode)}>{supportModeLabel(enterpriseSupport?.support_mode)}</span>
          </div>
          <div className="mt-4 grid gap-4 xl:grid-cols-[minmax(16rem,0.45fr)_minmax(0,1fr)]">
            <dl className="grid content-start gap-2 text-sm">
              <div>
                <dt className="font-medium text-muted-foreground">{translateNow("source.capability.5faf58a69d")}</dt>
                <dd>{enterpriseSupport?.capability ?? translateNow("source.cap.model.04.d945df90f4")}</dd>
              </div>
              <div>
                <dt className="font-medium text-muted-foreground">{translateNow("source.license.feature.de93785a58")}</dt>
                <dd className="font-mono text-xs">{enterpriseSupport?.license_feature ?? translateNow("source.ha.support.6fd6a7fc16")}</dd>
              </div>
              <div>
                <dt className="font-medium text-muted-foreground">{translateNow("source.license.tier.0c9a751553")}</dt>
                <dd>{enterpriseSupport?.tier ?? editions?.tier ?? translateNow("source.community.f354ee99e2")}</dd>
              </div>
              <div>
                <dt className="font-medium text-muted-foreground">{translateNow("source.contract.boundary.67a4070e64")}</dt>
                <dd>{enterpriseSupport?.contract_boundary ?? translateNow("source.commercial.support.terms.control.legal.sla.dd90f4015f")}</dd>
              </div>
            </dl>
            <div className="grid gap-4">
              <div className="overflow-x-auto rounded-panel border border-border">
                <table className="ui-table min-w-[44rem]">
                  <caption className="sr-only">{translateNow("source.enterprise.support.tier.table.0b375fcc18")}</caption>
                  <thead>
                    <tr>
                      <th scope="col">{translateNow("source.tier.cb9e8664ed")}</th>
                      <th scope="col">{translateNow("source.coverage.523487a5de")}</th>
                      <th scope="col">{translateNow("source.initial.sla.ee9124e35d")}</th>
                      <th scope="col">{translateNow("source.updates.22e2bada8f")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(enterpriseSupport?.support_tiers ?? []).map((tier) => (
                      <tr key={tier.id}>
                        <td>
                          <span className="font-medium">{tier.name}</span>
                          <span className="mt-1 block font-mono text-xs text-muted-foreground">{tier.id}</span>
                        </td>
                        <td>{tier.coverage}</td>
                        <td>{tier.initial_response_sla}</td>
                        <td>{tier.update_cadence_sla}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <div className="overflow-x-auto rounded-panel border border-border">
                <table className="ui-table min-w-[44rem]">
                  <caption className="sr-only">{translateNow("source.enterprise.sla.target.table.dfd20c29f8")}</caption>
                  <thead>
                    <tr>
                      <th scope="col">{translateNow("source.severity.5e9f98120d")}</th>
                      <th scope="col">{translateNow("source.applies.to.6687458bee")}</th>
                      <th scope="col">{translateNow("source.response.9061383b8e")}</th>
                      <th scope="col">{translateNow("source.escalation.35615b8245")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(enterpriseSupport?.sla_targets ?? []).map((target) => (
                      <tr key={target.severity}>
                        <td className="font-semibold">{target.severity}</td>
                        <td>{target.applies_to}</td>
                        <td>{target.initial_response_sla}</td>
                        <td>{target.escalation}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <div className="overflow-x-auto rounded-panel border border-border">
                <table className="ui-table min-w-[44rem]">
                  <caption className="sr-only">{translateNow("source.professional.services.package.table.60626ecbca")}</caption>
                  <thead>
                    <tr>
                      <th scope="col">{translateNow("source.service.d677190e0a")}</th>
                      <th scope="col">{translateNow("source.model.5e2c614c23")}</th>
                      <th scope="col">{translateNow("source.deliverables.c7ec4b92c2")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(enterpriseSupport?.professional_services ?? []).map((service) => (
                      <tr key={service.id}>
                        <td>
                          <span className="font-medium">{service.name}</span>
                          <span className="mt-1 block font-mono text-xs text-muted-foreground">{service.id}</span>
                        </td>
                        <td>{service.engagement_model}</td>
                        <td>{service.deliverables.join("; ")}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </section>

        <section className="ui-panel p-comfortable" aria-labelledby="managed-offering-heading">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="flex items-center gap-2">
              <Building2 className="h-4 w-4 text-status-success" aria-hidden="true" />
              <h2 id="managed-offering-heading" className="text-title font-semibold">
                {translateNow("source.managed.offering.f4e80765ae")}
              </h2>
            </div>
            <span className={providerPlaneClass(managedOffering?.provider_plane_mode)}>{providerPlaneLabel(managedOffering?.provider_plane_mode)}</span>
          </div>
          <div className="mt-4 grid gap-4 xl:grid-cols-[minmax(0,0.75fr)_minmax(22rem,1fr)]">
            <dl className="grid content-start gap-2 text-sm">
              <div>
                <dt className="font-medium text-muted-foreground">{translateNow("source.deployment.model.48b995f6f0")}</dt>
                <dd>{managedOffering?.deployment_model ?? "-"}</dd>
              </div>
              <div>
                <dt className="font-medium text-muted-foreground">{translateNow("source.provider.plane.47b8ba879c")}</dt>
                <dd>{managedOffering?.provider_plane_mode ?? translateNow("source.off.b4dc66dde8")}</dd>
              </div>
              <div>
                <dt className="font-medium text-muted-foreground">{translateNow("source.license.tier.0c9a751553")}</dt>
                <dd>{managedOffering?.tier ?? editions?.tier ?? translateNow("source.community.f354ee99e2")}</dd>
              </div>
              <div>
                <dt className="font-medium text-muted-foreground">{t("platform.editions.billingUnit")}</dt>
                <dd>{managedOffering?.billing_unit ?? packaging.provider_billing_unit}</dd>
              </div>
              {(managedOffering?.tier ?? editions?.tier) === "provider" ? (
                <div>
                  <dt className="font-medium text-muted-foreground">{t("platform.editions.managedCustomerBand")}</dt>
                  <dd>
                    {managedOffering?.managed_customer_band
                      ? formatNumberPolicy(managedOffering.managed_customer_band, formatPolicy)
                      : translateNow("source.negotiated.unlimited.9939fd4cf1")}
                  </dd>
                </div>
              ) : null}
              <div>
                <dt className="font-medium text-muted-foreground">{translateNow("source.event.source.60dbb37270")}</dt>
                <dd>{managedOffering?.event_type ?? translateNow("source.tenant.registered.62865a2986")}</dd>
              </div>
              <div>
                <dt className="font-medium text-muted-foreground">{translateNow("source.mutation.idempotency.e5fe0e928c")}</dt>
                <dd>{managedOffering?.idempotency_required ? translateNow("source.required.d0a3630555") : "-"}</dd>
              </div>
              {lastManagedTenant && (
                <div>
                  <dt className="font-medium text-muted-foreground">{translateNow("source.last.hosted.tenant.ddd9f6cf68")}</dt>
                  <dd className="break-all">
                    {lastManagedTenant.name} · {lastManagedTenant.tenant_id}
                  </dd>
                </div>
              )}
            </dl>
            <form onSubmit={(event) => void provisionHostedTenant(event)} className="grid gap-3">
              <div className="grid gap-3 md:grid-cols-2">
                <label className="grid gap-1 text-sm">
                  <span className="font-medium text-muted-foreground">{translateNow("source.hosted.id.16f3dc88ea")}</span>
                  <input className="ui-input" value={hostedTenantID} onChange={(event) => setHostedTenantID(event.target.value)} required />
                </label>
                <label className="grid gap-1 text-sm">
                  <span className="font-medium text-muted-foreground">{translateNow("source.hosted.name.af1e0d31be")}</span>
                  <input className="ui-input" value={hostedTenantName} onChange={(event) => setHostedTenantName(event.target.value)} required />
                </label>
                <label className="grid gap-1 text-sm">
                  <span className="font-medium text-muted-foreground">{translateNow("source.region.d3a008ef13")}</span>
                  <input className="ui-input" value={hostedRegion} onChange={(event) => setHostedRegion(event.target.value)} />
                </label>
                <label className="grid gap-1 text-sm">
                  <span className="font-medium text-muted-foreground">{translateNow("source.data.residency.4ab08acdfa")}</span>
                  <input className="ui-input" value={hostedResidency} onChange={(event) => setHostedResidency(event.target.value)} />
                </label>
                <label className="grid gap-1 text-sm">
                  <span className="font-medium text-muted-foreground">{translateNow("source.plan.fa8ed0bdab")}</span>
                  <input className="ui-input" value={hostedPlan} onChange={(event) => setHostedPlan(event.target.value)} />
                </label>
                <label className="grid gap-1 text-sm">
                  <span className="font-medium text-muted-foreground">{translateNow("source.support.tier.2dfba0f890")}</span>
                  <input className="ui-input" value={hostedSupportTier} onChange={(event) => setHostedSupportTier(event.target.value)} />
                </label>
              </div>
              <label className="grid gap-1 text-sm">
                <span className="font-medium text-muted-foreground">{translateNow("source.slo.tier.9d31a12006")}</span>
                <input className="ui-input" value={hostedSLOTier} onChange={(event) => setHostedSLOTier(event.target.value)} />
              </label>
              <Button
                type="submit"
                disabled={systemBusy || !hostedTenantID.trim() || !hostedTenantName.trim() || managedOffering?.provider_plane_mode !== "enabled"}
              >
                <Plus className="h-4 w-4" aria-hidden="true" />
                {translateNow("source.provision.tenant.e6e411f04c")}
              </Button>
            </form>
          </div>
        </section>
      </div>
    </section>
  );
}

/** /admin/editions — the console's one commercial surface (S-A3/DA-26):
 * offline license state, edition/feature rows, FIPS, distribution, and the
 * regional issuance posture. */
export function AdminEditions() {
  const { locale, timeZone, t } = useTranslation();
  const formatPolicy = useMemo<FormatPolicy>(() => ({ locale, timeZone }), [locale, timeZone]);
  const [editions, setEditions] = useState<EditionsInfo | null>(null);
  const [activeActiveIssuance, setActiveActiveIssuance] = useState<ActiveActiveIssuancePlan | null>(null);
  const [distribution, setDistribution] = useState<PlatformDistributionStatus | null>(null);
  const [editionsError, setEditionsError] = useState<string | null>(null);
  const packaging = editions?.packaging ?? defaultPackaging;

  useEffect(() => {
    let active = true;
    Promise.all([api.editions(), api.activeActiveIssuance()])
      .then(([editionInfo, haIssuanceStatus]) => {
        if (!active) return;
        setEditions(editionInfo);
        setActiveActiveIssuance(haIssuanceStatus);
      })
      .catch((err) => {
        if (active) setEditionsError(err instanceof Error ? err.message : String(err));
      });
    Promise.resolve()
      .then(() => api.platformDistribution())
      .then((status) => {
        if (active) setDistribution(status);
      })
      .catch(() => null);
    return () => {
      active = false;
    };
  }, []);

  return (
    <section aria-labelledby="admin-editions-heading" className="grid gap-6">
      <PageHeader
        titleId="admin-editions-heading"
        title={t("platform.tabs.editions")}
        description={t("admin.editions.description")}
        actions={<AdminHeaderActions />}
      />
      {editionsError && (
        <p role="alert" className="rounded-control border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm text-destructive">
          {editionsError}
        </p>
      )}
      <div className="grid gap-6">
        <section className="ui-panel p-comfortable" aria-labelledby="editions-heading">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <h2 id="editions-heading" className="text-title font-semibold">
                {translateNow("source.editions.c6a48dcca4")}
              </h2>
              <p className="mt-1 text-sm text-muted-foreground">{translateNow("source.offline.license.state.feature.rows.and.the.ee22ad090c")}</p>
            </div>
            <span className={editionStateClass(editions?.state)}>{editionStateLabel(editions?.state)}</span>
          </div>
          <div className="mt-4 grid gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(18rem,0.6fr)]">
            <div className="grid gap-4">
              <div className="overflow-x-auto rounded-panel border border-border">
                <table className="ui-table min-w-[42rem]">
                  <caption className="sr-only">{translateNow("source.packaging.edition.matrix.265d443ef4")}</caption>
                  <thead>
                    <tr>
                      {packaging.editions.map((edition) => (
                        <th scope="col" key={edition.id}>
                          {edition.column}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    <tr>
                      {packaging.editions.map((edition) => (
                        <td key={edition.id}>{edition.name}</td>
                      ))}
                    </tr>
                  </tbody>
                </table>
              </div>
              <div className="overflow-x-auto rounded-panel border border-border">
                <table className="ui-table min-w-[36rem]">
                  <caption>{t("platform.editions.referencePrices")}</caption>
                  <thead>
                    <tr>
                      <th scope="col">{t("platform.editions.priceBand")}</th>
                      <th scope="col">{t("platform.editions.annualPrice")}</th>
                      <th scope="col">{t("platform.editions.unit")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {packaging.reference_price_bands.map((band) => {
                      const labelKey = priceBandLabelKeys[band.id as keyof typeof priceBandLabelKeys];
                      return (
                        <tr key={band.id}>
                          <td>{labelKey ? t(labelKey) : band.label}</td>
                          <td>{formatCurrencyPolicy(band.annual_usd, formatPolicy, { maximumFractionDigits: 0 })}</td>
                          <td>{band.unit}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
                <p className="px-3 pb-3 text-sm text-muted-foreground">{packaging.non_production_support_posture}</p>
              </div>
              <div className="overflow-x-auto rounded-panel border border-border">
                <table className="ui-table min-w-[32rem]">
                  <caption className="sr-only">{translateNow("source.edition.feature.table.9690596a9d")}</caption>
                  <thead>
                    <tr>
                      <th scope="col">{translateNow("source.feature.3d377ae910")}</th>
                      <th scope="col">{translateNow("source.tier.cb9e8664ed")}</th>
                      <th scope="col">{translateNow("source.state.a3b50c4767")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(editions?.features ?? []).map((feature) => (
                      <tr key={feature.name}>
                        <td className="font-mono text-xs">{feature.name}</td>
                        <td>{feature.tier}</td>
                        <td>{featureStateLabel(feature.licensed, feature.mode)}</td>
                      </tr>
                    ))}
                    {editions && editions.features.length === 0 ? (
                      <tr>
                        <td colSpan={3} className="text-muted-foreground">
                          {translateNow("source.no.commercial.feature.rows.825b068dda")}
                        </td>
                      </tr>
                    ) : null}
                  </tbody>
                </table>
              </div>
            </div>
            <dl className="grid gap-2 text-sm">
              <div>
                <dt className="font-medium text-muted-foreground">{translateNow("source.tier.cb9e8664ed")}</dt>
                <dd className="text-base font-semibold">{(editions?.tier ?? "community").toUpperCase()}</dd>
              </div>
              <div>
                <dt className="font-medium text-muted-foreground">{translateNow("source.customer.bf3763383a")}</dt>
                <dd>{editions?.customer ?? translateNow("source.community.core.9de2dc1902")}</dd>
              </div>
              <div>
                <dt className="font-medium text-muted-foreground">{translateNow("source.expiry.6956d81401")}</dt>
                <dd>{formatOptionalDate(editions?.expires_at, formatPolicy)}</dd>
              </div>
              {editions?.deployment_entitlement ? (
                <>
                  <div>
                    <dt className="font-medium text-muted-foreground">{t("platform.editions.environment")}</dt>
                    <dd>
                      {editions.deployment_entitlement.environment === "non_production"
                        ? t("platform.editions.nonProduction")
                        : t("platform.editions.production")}
                    </dd>
                  </div>
                  <div>
                    <dt className="font-medium text-muted-foreground">{t("platform.editions.deploymentId")}</dt>
                    <dd className="font-mono text-xs">{editions.deployment_entitlement.deployment_id || "-"}</dd>
                  </div>
                  <div>
                    <dt className="font-medium text-muted-foreground">{t("platform.editions.billingUnit")}</dt>
                    <dd>{t("platform.editions.productionUnits", { count: editions.deployment_entitlement.production_units_consumed })}</dd>
                  </div>
                  <div>
                    <dt className="font-medium text-muted-foreground">{t("platform.editions.nonProduction")}</dt>
                    <dd>
                      {t("platform.editions.nonProductionSlots", {
                        remaining: editions.deployment_entitlement.non_production_slots_remaining,
                        total: editions.deployment_entitlement.bundled_non_production_deployments,
                      })}
                    </dd>
                  </div>
                </>
              ) : null}
              <div>
                <dt className="font-medium text-muted-foreground">{t("platform.editions.useRights")}</dt>
                <dd>{(editions?.rights ?? ["self_host"]).map((right) => right.replaceAll("_", " ")).join(", ")}</dd>
              </div>
              {editions?.tier === "provider" ? (
                <div>
                  <dt className="font-medium text-muted-foreground">{t("platform.editions.managedCustomerBand")}</dt>
                  <dd>
                    {editions.managed_customer_band
                      ? formatNumberPolicy(editions.managed_customer_band, formatPolicy)
                      : translateNow("source.negotiated.unlimited.9939fd4cf1")}
                  </dd>
                </div>
              ) : null}
              <div>
                <dt className="font-medium text-muted-foreground">{translateNow("source.fips.posture.4051e94687")}</dt>
                <dd className="grid gap-1">
                  <span>
                    {editions?.fips?.module_active
                      ? translateNow("source.fips.module.active.76cb6077b6")
                      : translateNow("source.fips.module.inactive.fac8ddb35b")}
                    {editions?.fips?.required ? translateNow("source.required.cdc2689fe2") : ""}
                    {editions?.fips?.self_test_passed
                      ? translateNow("source.self.test.passed.c28b5c9b12")
                      : translateNow("source.self.test.not.confirmed.03a528b202")}
                  </span>
                  {editions?.fips?.validated_module_path ? (
                    <span>
                      {editions.fips.standard ?? translateNow("source.fips.140.3.b95c3c39f5")} ·{" "}
                      {editions.fips.module ?? translateNow("source.go.cryptographic.module.0acf566e1e")} ·{" "}
                      {editions.fips.build_target ?? translateNow("source.make.fips.build.ce51354815")}
                    </span>
                  ) : null}
                  {editions?.fips?.ci_gate ? <span>{editions.fips.ci_gate}</span> : null}
                  {editions?.fips?.product_certification_residual ? (
                    <span className="text-muted-foreground">{editions.fips.product_certification_residual}</span>
                  ) : null}
                </dd>
              </div>
            </dl>
          </div>
        </section>

        <div className="grid gap-4 xl:grid-cols-2">
          <section className="ui-panel grid content-start gap-3 p-comfortable" aria-labelledby="platform-region-heading">
            <h2 id="platform-region-heading" className="text-title font-semibold">
              {translateNow("source.multi.region.posture.e57c514674")}
            </h2>
            <p className="text-sm text-muted-foreground">{translateNow("source.passive.read.state.model.projections.can.b.9f2d6a2da6")}</p>
            <p className="text-sm text-muted-foreground">{translateNow("source.background.jobs.perform.access.token.revoc.5f46484521")}</p>
            {/* TRACE-014 source anchor: served worker */}
          </section>
          {distribution && (
            <section className="ui-panel grid content-start gap-3 p-comfortable" aria-labelledby="distribution-posture-heading">
              <h2 id="distribution-posture-heading" className="text-title font-semibold">
                {t("parity.distributionPosture_10c8b4")}
              </h2>
              <dl className="grid gap-2 text-sm">
                <div>
                  <dt className="font-medium text-muted-foreground">{t("parity.productionMode_1737a4")}</dt>
                  <dd>{humanizeToken(distribution.production_mode)}</dd>
                </div>
                <div>
                  <dt className="font-medium text-muted-foreground">{t("parity.controlPlaneLineage_513399")}</dt>
                  <dd>{humanizeToken(distribution.control_plane_lineage)}</dd>
                </div>
                <div>
                  <dt className="font-medium text-muted-foreground">{t("parity.builtInGuarantees_21db16")}</dt>
                  <dd className="flex flex-wrap gap-2">
                    <StatusBadge
                      value={distribution.offline_license_verifier ? "included" : "absent"}
                      label={distribution.offline_license_verifier ? "Licenses verified offline" : "No offline license verifier"}
                      tone={distribution.offline_license_verifier ? "success" : "neutral"}
                    />
                    <StatusBadge
                      value={distribution.core_audit_and_export ? "included" : "absent"}
                      label={distribution.core_audit_and_export ? "Audit log and export in core" : "Audit and export not in core"}
                      tone={distribution.core_audit_and_export ? "success" : "neutral"}
                    />
                  </dd>
                </div>
                <div>
                  <dt className="font-medium text-muted-foreground">{t("parity.runModes_6fced8")}</dt>
                  <dd className="grid gap-1">
                    {(distribution.run_modes ?? []).map((mode) => (
                      <span key={mode.id}>
                        <span className="font-medium">{mode.label}</span>
                        <span className="text-muted-foreground"> — {mode.intended_use}</span>
                      </span>
                    ))}
                    {(distribution.run_modes ?? []).length === 0 && <span className="text-muted-foreground">-</span>}
                  </dd>
                </div>
                <div>
                  <dt className="font-medium text-muted-foreground">{t("parity.supportedHostArchives_38c6c0")}</dt>
                  <dd className="grid gap-1">
                    {(distribution.supported_host_archives ?? []).map((archive) => (
                      <span key={`${archive.os_arch}-${archive.postgres_version}`} className="font-mono text-xs">
                        {archive.os_arch} {translateNow("source.postgresql.17197ea102")} {archive.postgres_version}
                        {archive.evaluation_only ? translateNow("source.evaluation.only.7e42530821") : ""}
                      </span>
                    ))}
                    {(distribution.supported_host_archives ?? []).length === 0 && <span className="text-muted-foreground">-</span>}
                  </dd>
                </div>
                <div>
                  <dt className="font-medium text-muted-foreground">{t("parity.airGap_a0134a")}</dt>
                  <dd>{airGapSummary(distribution.air_gap)}</dd>
                </div>
              </dl>
            </section>
          )}
        </div>

        <section className="ui-panel p-comfortable" aria-labelledby="regional-issuance-heading">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="flex items-center gap-2">
              <Network className="h-4 w-4 text-status-success" aria-hidden="true" />
              <h2 id="regional-issuance-heading" className="text-title font-semibold">
                {t("platform.ha.heading")}
              </h2>
            </div>
            <span className={scaleServedClass(activeActiveIssuance?.served)}>
              {activeActiveIssuance?.served ? t("platform.ha.active") : t("platform.ha.unavailable")}
            </span>
          </div>
          <p className="mt-3 text-sm text-muted-foreground">{t("platform.ha.description")}</p>
          <div className="mt-4 grid gap-4 xl:grid-cols-[minmax(18rem,0.45fr)_minmax(0,1fr)]">
            <dl className="grid content-start gap-2 text-sm">
              <div>
                <dt className="font-medium text-muted-foreground">{t("platform.ha.topology")}</dt>
                <dd>{activeActiveIssuance?.topology ?? "-"}</dd>
              </div>
              <div>
                <dt className="font-medium text-muted-foreground">{t("platform.ha.writeModel")}</dt>
                <dd>{activeActiveIssuance?.write_model ?? "-"}</dd>
              </div>
              <div>
                <dt className="font-medium text-muted-foreground">{t("platform.ha.rpoRto")}</dt>
                <dd>
                  {t("platform.ha.rpoRtoValue", {
                    rpo: formatOptionalNumber(activeActiveIssuance?.rpo_seconds, formatPolicy),
                    rto: formatOptionalNumber(activeActiveIssuance?.rto_seconds, formatPolicy),
                  })}
                </dd>
              </div>
              <div>
                <dt className="font-medium text-muted-foreground">{t("platform.ha.invariants")}</dt>
                <dd className="font-mono text-xs">{(activeActiveIssuance?.architecture_invariants ?? []).join(", ") || "-"}</dd>
              </div>
            </dl>
            <div className="grid gap-4">
              <div className="overflow-x-auto rounded-panel border border-border">
                <table className="ui-table min-w-[44rem]">
                  <caption className="sr-only">{t("platform.ha.regionCaption")}</caption>
                  <thead>
                    <tr>
                      <th scope="col">{t("platform.ha.region")}</th>
                      <th scope="col">{t("platform.ha.role")}</th>
                      <th scope="col">{t("platform.ha.writeScope")}</th>
                      <th scope="col">{t("platform.ha.health")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(activeActiveIssuance?.regions ?? []).slice(0, 3).map((region) => (
                      <tr key={region.id} className="align-top">
                        <td>
                          <span className="font-medium">{region.region}</span>
                          <span className="mt-1 block font-mono text-xs text-muted-foreground">{region.id}</span>
                        </td>
                        <td>{region.role}</td>
                        <td>{region.writable_scope}</td>
                        <td>{region.health_signal}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <div className="grid gap-4 xl:grid-cols-2">
                <div className="overflow-x-auto rounded-panel border border-border">
                  <table className="ui-table min-w-[34rem]">
                    <caption className="sr-only">{t("platform.ha.fenceCaption")}</caption>
                    <thead>
                      <tr>
                        <th scope="col">{t("platform.ha.fence")}</th>
                        <th scope="col">{t("platform.ha.scope")}</th>
                        <th scope="col">{t("platform.ha.mechanism")}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(activeActiveIssuance?.tenant_write_fences ?? []).map((fence) => (
                        <tr key={fence.id} className="align-top">
                          <td className="font-medium">{fence.id}</td>
                          <td>{fence.scope}</td>
                          <td>{fence.mechanism}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                <div className="overflow-x-auto rounded-panel border border-border">
                  <table className="ui-table min-w-[28rem]">
                    <caption className="sr-only">{t("platform.ha.failoverCaption")}</caption>
                    <thead>
                      <tr>
                        <th scope="col">{t("platform.ha.step")}</th>
                        <th scope="col">{t("platform.ha.action")}</th>
                        <th scope="col">{t("platform.ha.gate")}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(activeActiveIssuance?.failover_runbook ?? []).map((step) => (
                        <tr key={step.id} className="align-top">
                          <td className="font-medium">{step.id}</td>
                          <td>{step.action}</td>
                          <td>{step.gate}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
              <div className="flex flex-wrap gap-2">
                {(activeActiveIssuance?.release_gates ?? []).map((gate) => (
                  <span key={gate.id} className="rounded-control border border-border bg-muted px-2 py-1 font-mono text-xs">
                    {gate.id}
                  </span>
                ))}
              </div>
              <div className="grid gap-2 text-sm md:grid-cols-2">
                {(activeActiveIssuance?.residuals ?? []).slice(0, 2).map((residual) => (
                  <p key={residual} className="rounded-panel border border-border bg-muted/40 p-3 text-muted-foreground">
                    {residual}
                  </p>
                ))}
              </div>
            </div>
          </div>
        </section>
      </div>
    </section>
  );
}

function formatOptionalNumber(value: number | undefined, policy: FormatPolicy): string {
  if (value == null || Number.isNaN(value)) return "-";
  return formatNumberPolicy(value, policy);
}

function formatOptionalDate(value: string | undefined, policy: FormatPolicy): string {
  if (!value) return "-";
  return formatDateTime(value, policy);
}

function formatOptionalCurrency(value: number | undefined, policy: FormatPolicy): string {
  if (value == null || Number.isNaN(value)) return "-";
  return formatCurrencyPolicy(value, policy, { maximumFractionDigits: 0 });
}

function formatOptionalUnitCost(value: number | undefined, unitLabel: string, policy: FormatPolicy): string {
  if (value == null || Number.isNaN(value)) return "-";
  const formatted = formatCurrencyPolicy(value, policy, {
    minimumFractionDigits: 4,
    maximumFractionDigits: 4,
  });
  return `${formatted} / ${unitLabel}`;
}

function editionStateLabel(state?: EditionsInfo["state"]): string {
  switch (state) {
    case "active":
      return "active";
    case "grace":
      return "expired, grace";
    case "read_only":
      return "read-only";
    default:
      return "community";
  }
}

function editionStateClass(state?: EditionsInfo["state"]): string {
  const base = "rounded-control border px-2 py-1 text-xs font-medium";
  switch (state) {
    case "active":
      return `${base} border-status-success/30 bg-status-success/10 text-status-success`;
    case "grace":
      return `${base} border-status-warning/30 bg-status-warning/10 text-status-warning`;
    case "read_only":
      return `${base} border-destructive/30 bg-destructive/10 text-destructive`;
    default:
      return `${base} border-border bg-muted text-muted-foreground`;
  }
}

function featureStateLabel(licensed: boolean, mode: EditionsInfo["features"][number]["mode"]): string {
  if (!licensed) return "Not licensed";
  if (mode === "read_only") return "Read-only";
  return "Enabled";
}

function supportModeLabel(mode?: EnterpriseSupportStatus["support_mode"]): string {
  if (mode === "enabled") return "support enabled";
  if (mode === "read_only") return "support read-only";
  return "support off";
}

function supportModeClass(mode?: EnterpriseSupportStatus["support_mode"]): string {
  const base = "rounded-control border px-2 py-1 text-xs font-medium";
  if (mode === "enabled") return `${base} border-status-success/30 bg-status-success/10 text-status-success`;
  if (mode === "read_only") return `${base} border-status-warning/30 bg-status-warning/10 text-status-warning`;
  return `${base} border-border bg-muted text-muted-foreground`;
}

function providerPlaneLabel(mode?: ManagedOfferingStatus["provider_plane_mode"]): string {
  if (mode === "enabled") return "provider plane enabled";
  if (mode === "read_only") return "provider plane read-only";
  return "provider plane off";
}

function providerPlaneClass(mode?: ManagedOfferingStatus["provider_plane_mode"]): string {
  const base = "rounded-control border px-2 py-1 text-xs font-medium";
  if (mode === "enabled") return `${base} border-status-success/30 bg-status-success/10 text-status-success`;
  if (mode === "read_only") return `${base} border-status-warning/30 bg-status-warning/10 text-status-warning`;
  return `${base} border-border bg-muted text-muted-foreground`;
}

function scaleServedClass(served?: boolean): string {
  const base = "rounded-control border px-2 py-1 text-xs font-medium";
  return served ? `${base} border-status-success/30 bg-status-success/10 text-status-success` : `${base} border-border bg-muted text-muted-foreground`;
}

function humanizeToken(value: string): string {
  return value ? value.replace(/[_-]+/g, " ") : "-";
}

function airGapSummary(airGap: PlatformDistributionStatus["air_gap"] | undefined): string {
  if (!airGap) return "No air-gap protections reported.";
  const protections = [
    airGap.no_phone_home_default ? "no phone-home by default" : null,
    airGap.public_telemetry_fail_closed ? "public telemetry fails closed" : null,
    airGap.cloud_ai_fail_closed ? "cloud AI fails closed" : null,
    airGap.runtime_egress_guard ? "runtime egress guard" : null,
  ].filter((item): item is string => item != null);
  if (protections.length === 0) return "No air-gap protections reported.";
  return `${airGap.served ? "Served" : "Not served"} · ${protections.join(" · ")}`;
}
