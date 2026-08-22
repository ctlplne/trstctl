import { useEffect, useMemo, useRef, useState, type FormEvent, type ReactNode } from "react";
import { Navigate, useSearchParams } from "react-router-dom";
import { Building2, ChevronDown, Gauge, Headphones, Network, Plus } from "lucide-react";
import { useAuth } from "@/auth/AuthProvider";
import { AdminHeaderActions } from "@/components/AdminHeaderActions";
import { PageHeader } from "@/components/PageHeader";
import { DRPosturePanel } from "@/components/DRPosturePanel";
import { DetailDrawer } from "@/components/DetailDrawer";
import { IdempotencyResultProtectionPanel, TenantKeyDomainPanel, UsageEvidencePanel } from "@/components/TenantCustodyPanels";
import { Eyebrow } from "@/components/typography";
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
  const [systemAttempt, setSystemAttempt] = useState(0);
  const [open, setOpen] = useState({ checks: true, configuration: false, dependencies: false, exceptions: false });
  const packaging = editions?.packaging ?? defaultPackaging;

  useEffect(() => {
    if (!open.exceptions) return;
    let active = true;
    Promise.all([api.editions(), api.enterpriseSupportStatus(), api.managedOfferingStatus()])
      .then(([editionInfo, supportStatus, managedStatus]) => {
        if (!active) return;
        setEditions(editionInfo);
        setEnterpriseSupport(supportStatus);
        setManagedOffering(managedStatus);
      })
      .catch(() => {
        if (active) setSystemError(translateNow("admin.system.detailReadFailed"));
      });
    return () => {
      active = false;
    };
  }, [open.exceptions]);

  useEffect(() => {
    if (!open.dependencies) return;
    let active = true;
    api
      .scaleOrchestration()
      .then((scaleStatus) => {
        if (active) setScaleOrchestration(scaleStatus);
      })
      .catch(() => {
        if (active) setSystemError(translateNow("admin.system.detailReadFailed"));
      });
    return () => {
      active = false;
    };
  }, [open.dependencies]);

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
      .catch(() => {
        if (!active) return;
        setProtectionError(translateNow("admin.system.healthReadFailed"));
      })
      .finally(() => {
        if (active) setProtectionLoading(false);
      });
    return () => {
      active = false;
    };
  }, [systemAttempt]);

  useEffect(() => {
    if (!open.dependencies) return;
    let active = true;
    // Optional-method guard (see lib/optionalApi): a client without this method
    // must leave the panel absent, not blank the Platform page.
    optionalApiCall<DRPosture | null>("drPosture", null)
      .then((posture) => {
        if (!active) return;
        setDRPosture(posture);
        setDRError(null);
      })
      .catch(() => {
        if (!active) return;
        setDRError(translateNow("admin.system.detailReadFailed"));
      });
    return () => {
      active = false;
    };
  }, [open.dependencies]);

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
    } catch {
      setSystemError(t("admin.system.provisionFailed"));
    } finally {
      setSystemBusy(false);
    }
  }

  const dependencies = systemReadout?.dependencies ?? [];
  const dependencyIssues = dependencies.filter((dependency) => !dependency.ready);
  const resultProtectionState = systemReadout?.idempotency_results?.state;
  const resultProtectionNeedsWork = Boolean(systemReadout && resultProtectionState !== "complete");
  const deliveryIssues = systemReadout?.deployment?.verify_failed ?? 0;
  const issueCount = dependencyIssues.length + (resultProtectionNeedsWork ? 1 : 0) + deliveryIssues;
  const healthTitle = protectionLoading
    ? t("admin.system.healthChecking")
    : protectionError
      ? t("admin.system.healthUnknown")
      : issueCount === 0
        ? t("admin.system.healthReady")
        : issueCount === 1
          ? t("admin.system.healthIssueOne")
          : t("admin.system.healthIssues", { count: String(issueCount) });
  const healthBody = protectionLoading
    ? t("admin.system.healthCheckingBody")
    : protectionError
      ? t("admin.system.healthUnknownBody")
      : issueCount === 0
        ? t("admin.system.healthReadyBody")
        : t("admin.system.healthIssuesBody");

  function openFirstIssue() {
    const target = protectionError ? "checks" : dependencyIssues.length > 0 || deliveryIssues > 0 ? "dependencies" : "configuration";
    setOpen((current) => ({ ...current, [target]: true }));
    window.setTimeout(() => document.getElementById(`admin-system-${target}-summary`)?.focus(), 0);
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
      <section className="ui-panel grid gap-4 border-s-4 border-s-brand-accent p-comfortable" aria-labelledby="system-health-answer-heading" aria-live="polite">
        <div className="grid gap-1">
          <Eyebrow as="p">{t("admin.system.currentAnswer")}</Eyebrow>
          <h2 id="system-health-answer-heading" className="text-heading font-semibold">
            {healthTitle}
          </h2>
          <p className="max-w-3xl text-sm text-muted-foreground">{healthBody}</p>
        </div>
        <div>
          <Button type="button" onClick={openFirstIssue}>
            {t("admin.system.fixFirstIssue")}
          </Button>
        </div>
      </section>

      <div className="grid gap-3">
        <SystemDisclosure
          summaryId="admin-system-checks-summary"
          title={t("admin.system.checks")}
          description={t("admin.system.checksDescription")}
          open={open.checks}
          onToggle={(value) => setOpen((current) => ({ ...current, checks: value }))}
        >
          <div className="grid gap-4">
            {protectionLoading ? (
              <p role="status" className="text-sm text-muted-foreground">
                {t("admin.system.healthCheckingBody")}
              </p>
            ) : null}
            {protectionError ? (
              <div role="alert" className="rounded-control border border-destructive/30 bg-destructive/10 p-3 text-sm">
                <p className="font-semibold text-destructive">{t("admin.system.healthUnknown")}</p>
                <p className="mt-1 text-muted-foreground">{t("admin.system.healthUnknownBody")}</p>
                <Button type="button" variant="outline" className="mt-3" onClick={() => setSystemAttempt((attempt) => attempt + 1)}>
                  {t("admin.system.tryAgain")}
                </Button>
              </div>
            ) : null}
            {systemReadout ? (
              <dl className="grid gap-3 text-sm sm:grid-cols-2 xl:grid-cols-4">
                <SystemCheck
                  label={t("admin.system.dependenciesCheck")}
                  value={t("admin.system.dependenciesReady", {
                    ready: String(dependencies.length - dependencyIssues.length),
                    total: String(dependencies.length),
                  })}
                  issue={dependencyIssues.length > 0}
                />
                <SystemCheck label={t("admin.system.signerCheck")} value={systemReadout.signer_mode} issue={systemReadout.signer_mode === "none"} />
                <SystemCheck
                  label={t("admin.system.retryProtectionCheck")}
                  value={resultProtectionState ? resultProtectionState.replaceAll("_", " ") : t("platform.idempotency.stateUnavailable")}
                  issue={resultProtectionNeedsWork}
                />
                <SystemCheck
                  label={t("admin.system.deliveryCheck")}
                  value={t("admin.system.deliveryFailures", { count: String(deliveryIssues) })}
                  issue={deliveryIssues > 0}
                />
              </dl>
            ) : null}
          </div>
        </SystemDisclosure>

        <SystemDisclosure
          summaryId="admin-system-configuration-summary"
          title={t("admin.system.configurationEvidence")}
          description={t("admin.system.configurationDescription")}
          open={open.configuration}
          onToggle={(value) => setOpen((current) => ({ ...current, configuration: value }))}
        >
          <div className="grid gap-6">
            <TenantKeyDomainPanel canWrite={Boolean(user?.permissions?.includes("keys:write"))} />
            <IdempotencyResultProtectionPanel readout={systemReadout} loading={protectionLoading} requestError={protectionError} />
            <UsageEvidencePanel />
          </div>
        </SystemDisclosure>

        <SystemDisclosure
          summaryId="admin-system-dependencies-summary"
          title={t("admin.system.dependencyHealth")}
          description={t("admin.system.dependencyDescription")}
          open={open.dependencies}
          onToggle={(value) => setOpen((current) => ({ ...current, dependencies: value }))}
        >
          <div className="grid gap-6">
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
                  <SystemTableRegion label={t("platform.scale.executionCaption")}>
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
                  </SystemTableRegion>
                  <div className="grid gap-4 xl:grid-cols-2">
                    <SystemTableRegion label={t("platform.scale.releaseCaption")}>
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
                    </SystemTableRegion>
                    <SystemTableRegion label={t("platform.scale.bandCaption")}>
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
                    </SystemTableRegion>
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
          </div>
        </SystemDisclosure>

        <SystemDisclosure
          summaryId="admin-system-exceptions-summary"
          title={t("admin.system.exceptions")}
          description={t("admin.system.exceptionsDescription")}
          open={open.exceptions}
          onToggle={(value) => setOpen((current) => ({ ...current, exceptions: value }))}
        >
          <div className="grid gap-6">
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
                  <SystemTableRegion label={translateNow("source.enterprise.support.tier.table.0b375fcc18")}>
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
                  </SystemTableRegion>
                  <SystemTableRegion label={translateNow("source.enterprise.sla.target.table.dfd20c29f8")}>
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
                  </SystemTableRegion>
                  <SystemTableRegion label={translateNow("source.professional.services.package.table.60626ecbca")}>
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
                  </SystemTableRegion>
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
        </SystemDisclosure>
      </div>
    </section>
  );
}

function SystemDisclosure({
  summaryId,
  title,
  description,
  open,
  onToggle,
  children,
}: {
  summaryId: string;
  title: string;
  description: string;
  open: boolean;
  onToggle: (open: boolean) => void;
  children: ReactNode;
}) {
  return (
    <details
      className="group min-w-0 rounded-panel border border-border bg-card shadow-elevation1"
      open={open}
      onToggle={(event) => onToggle(event.currentTarget.open)}
    >
      <summary id={summaryId} className="flex cursor-pointer list-none items-start justify-between gap-4 p-comfortable marker:hidden">
        <span>
          <span className="block text-body font-semibold">{title}</span>
          <span className="mt-1 block max-w-3xl text-sm text-muted-foreground">{description}</span>
        </span>
        <ChevronDown className="mt-1 h-4 w-4 shrink-0 text-muted-foreground transition-transform group-open:rotate-180" aria-hidden="true" />
      </summary>
      <div className="border-t border-border p-comfortable">{open ? children : null}</div>
    </details>
  );
}

function SystemCheck({ label, value, issue }: { label: string; value: string; issue: boolean }) {
  return (
    <div className="rounded-control border border-border bg-background p-3">
      <dt className="font-medium text-muted-foreground">{label}</dt>
      <dd className={issue ? "mt-1 font-semibold text-status-warning" : "mt-1 font-semibold text-status-success"}>{value}</dd>
    </div>
  );
}

/* eslint-disable jsx-a11y/no-noninteractive-tabindex -- Narrow viewports need
   a named keyboard stop for horizontally scrollable expert evidence. */
function SystemTableRegion({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div
      className="min-w-0 max-w-full overflow-x-auto rounded-panel border border-border focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus focus-visible:ring-offset-2"
      role="region"
      aria-label={label}
      tabIndex={0}
    >
      {children}
    </div>
  );
}
/* eslint-enable jsx-a11y/no-noninteractive-tabindex */

/** /admin/editions — the console's one commercial surface (S-A3/DA-26).
 * DESIGN-ROUTE-042 makes the verified plan/expiry answer the default read,
 * then keeps signature, feature, entitlement, packaging, and deployment
 * architecture evidence behind explicit disclosures. The only default API
 * read is /editions; HA and distribution evidence are not fetched until the
 * operator opens the nested architecture proof. */
export function AdminEditions() {
  const { locale, timeZone, t } = useTranslation();
  const formatPolicy = useMemo<FormatPolicy>(() => ({ locale, timeZone }), [locale, timeZone]);
  const [editions, setEditions] = useState<EditionsInfo | null>(null);
  const [activeActiveIssuance, setActiveActiveIssuance] = useState<ActiveActiveIssuancePlan | null>(null);
  const [distribution, setDistribution] = useState<PlatformDistributionStatus | null>(null);
  const [editionsError, setEditionsError] = useState<string | null>(null);
  const [architectureError, setArchitectureError] = useState<string | null>(null);
  const [licenseAttempt, setLicenseAttempt] = useState(0);
  const [architectureAttempt, setArchitectureAttempt] = useState(0);
  const [architectureOpen, setArchitectureOpen] = useState(false);
  const [guideOpen, setGuideOpen] = useState(false);
  const [open, setOpen] = useState({ signature: false, features: false, entitlements: false });
  const addLicenseRef = useRef<HTMLButtonElement>(null);
  const packaging = editions?.packaging ?? defaultPackaging;
  const licensedFeatures = editions?.features.filter((feature) => feature.licensed && feature.mode !== "off").length ?? 0;

  useEffect(() => {
    let active = true;
    setEditionsError(null);
    api
      .editions()
      .then((editionInfo) => {
        if (!active) return;
        setEditions(editionInfo);
      })
      .catch(() => {
        if (!active) return;
        setEditions(null);
        setEditionsError(translateNow("admin.editions.readFailed"));
      });
    return () => {
      active = false;
    };
  }, [licenseAttempt, locale]);

  useEffect(() => {
    if (!architectureOpen) return;
    let active = true;
    setArchitectureError(null);
    Promise.allSettled([api.platformDistribution(), api.activeActiveIssuance()]).then(([distributionResult, issuanceResult]) => {
      if (!active) return;
      if (distributionResult.status === "fulfilled") setDistribution(distributionResult.value);
      if (issuanceResult.status === "fulfilled") setActiveActiveIssuance(issuanceResult.value);
      if (distributionResult.status === "rejected" || issuanceResult.status === "rejected") {
        setArchitectureError(translateNow("admin.editions.architectureReadFailed"));
      }
    });
    return () => {
      active = false;
    };
  }, [architectureAttempt, architectureOpen, locale]);

  const retryLicense = () => {
    setEditions(null);
    setLicenseAttempt((attempt) => attempt + 1);
  };

  const planToken = humanizeToken(editions?.tier ?? "community");
  const planName = `${planToken.charAt(0).toUpperCase()}${planToken.slice(1)}`;
  const answer = editions ? licenseAnswer(editions, planName, t) : t("admin.editions.unavailableAnswer");
  const signatureSummary = editions?.state === "community" ? t("admin.editions.noSignedLicense") : t("admin.editions.signatureVerified");

  return (
    <section aria-labelledby="admin-editions-heading" className="grid gap-6">
      <PageHeader
        titleId="admin-editions-heading"
        title={t("platform.tabs.editions")}
        description={t("admin.editions.description")}
        technicalDetails={t("admin.editions.technical")}
        actions={
          <>
            <Button ref={addLicenseRef} type="button" onClick={() => setGuideOpen(true)}>
              <Plus className="h-4 w-4" aria-hidden="true" />
              {t("admin.editions.addLicense")}
            </Button>
            <AdminHeaderActions />
          </>
        }
      />
      <section className="ui-panel p-comfortable" aria-labelledby="license-answer-heading" aria-busy={!editions && !editionsError}>
        {!editions && !editionsError ? (
          <>
            <Eyebrow as="p">{t("admin.system.currentAnswer")}</Eyebrow>
            <h2 id="license-answer-heading" className="mt-2 text-title font-semibold">
              {t("admin.editions.loading")}
            </h2>
          </>
        ) : (
          <>
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div>
                <Eyebrow as="p">{t("admin.system.currentAnswer")}</Eyebrow>
                <h2 id="license-answer-heading" className="mt-2 text-title font-semibold">
                  {answer}
                </h2>
                {editions ? <p className="mt-2 text-sm text-muted-foreground">{signatureSummary}</p> : null}
              </div>
              {editions ? <span className={editionStateClass(editions.state)}>{editionStateLabel(editions.state)}</span> : null}
            </div>
            {editionsError ? (
              <div className="mt-4 grid justify-items-start gap-3">
                <p role="alert" className="rounded-control border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm text-destructive">
                  {editionsError}
                </p>
                <Button type="button" variant="outline" onClick={retryLicense}>
                  {t("admin.system.tryAgain")}
                </Button>
              </div>
            ) : null}
            {editions ? (
              <dl className="mt-5 grid gap-3 sm:grid-cols-3">
                <div className="rounded-control border border-border bg-background p-3">
                  <dt className="text-sm text-muted-foreground">{t("source.plan.fa8ed0bdab")}</dt>
                  <dd className="mt-1 font-semibold">{planName}</dd>
                </div>
                <div className="rounded-control border border-border bg-background p-3">
                  <dt className="text-sm text-muted-foreground">{t("admin.editions.featuresEnabled")}</dt>
                  <dd className="mt-1 font-semibold">{t("admin.editions.featureCount", { enabled: licensedFeatures, total: editions.features.length })}</dd>
                </div>
                <div className="rounded-control border border-border bg-background p-3">
                  <dt className="text-sm text-muted-foreground">{t("admin.access.expires")}</dt>
                  <dd className="mt-1 font-semibold">
                    {editions.expires_at ? formatDateTime(editions.expires_at, formatPolicy) : t("admin.editions.noExpiry")}
                  </dd>
                </div>
              </dl>
            ) : null}
          </>
        )}
      </section>

      <div className="grid gap-3">
        <SystemDisclosure
          summaryId="license-signature-summary"
          title={t("admin.editions.signature")}
          description={t("admin.editions.signatureDescription")}
          open={open.signature}
          onToggle={(signature) => setOpen((current) => ({ ...current, signature }))}
        >
          {editions ? (
            <div className="grid gap-3">
              <dl className="grid gap-3 text-sm sm:grid-cols-2 xl:grid-cols-4">
                <LicenseFact label={t("source.verification.j2dr000006")} value={signatureSummary} />
                <LicenseFact label={t("secrets.sessions.method")} value={t("admin.editions.methodValue")} />
                <LicenseFact label={t("admin.editions.licenseId")} value={editions.license_id || t("protocols.ari.notApplicable")} mono />
                <LicenseFact
                  label={t("admin.editions.readOnlyAfter")}
                  value={editions.read_only_at ? formatDateTime(editions.read_only_at, formatPolicy) : t("protocols.ari.notApplicable")}
                />
              </dl>
              <p className="text-sm text-muted-foreground">{t("admin.editions.failClosedBoundary")}</p>
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">{t("admin.editions.evidenceUnavailable")}</p>
          )}
        </SystemDisclosure>

        <SystemDisclosure
          summaryId="license-feature-summary"
          title={t("admin.editions.featureTable")}
          description={t("admin.editions.featureDescription")}
          open={open.features}
          onToggle={(features) => setOpen((current) => ({ ...current, features }))}
        >
          {editions ? (
            <SystemTableRegion label={t("admin.editions.featureTable")}>
              <table className="ui-table min-w-[34rem]">
                <caption className="sr-only">{t("admin.editions.featureTable")}</caption>
                <thead>
                  <tr>
                    <th scope="col">{t("source.license.feature.de93785a58")}</th>
                    <th scope="col">{t("source.license.tier.0c9a751553")}</th>
                    <th scope="col">{t("caHierarchy.externalIssue.stateLabel")}</th>
                  </tr>
                </thead>
                <tbody>
                  {editions.features.map((feature) => (
                    <tr key={feature.name}>
                      <td>
                        <span className="font-medium">{humanizeToken(feature.name)}</span>
                        <span className="mt-1 block font-mono text-xs text-muted-foreground">{feature.name}</span>
                      </td>
                      <td>{humanizeToken(feature.tier)}</td>
                      <td>{featureStateLabel(feature.licensed, feature.mode)}</td>
                    </tr>
                  ))}
                  {editions.features.length === 0 ? (
                    <tr>
                      <td colSpan={3} className="text-muted-foreground">
                        {t("source.no.commercial.feature.rows.825b068dda")}
                      </td>
                    </tr>
                  ) : null}
                </tbody>
              </table>
            </SystemTableRegion>
          ) : (
            <p className="text-sm text-muted-foreground">{t("admin.editions.evidenceUnavailable")}</p>
          )}
        </SystemDisclosure>

        <SystemDisclosure
          summaryId="license-entitlement-summary"
          title={t("admin.editions.entitlementEvidence")}
          description={t("admin.editions.entitlementDescription")}
          open={open.entitlements}
          onToggle={(entitlements) => setOpen((current) => ({ ...current, entitlements }))}
        >
          {editions ? (
            <div className="grid gap-4">
              <dl className="grid gap-3 text-sm sm:grid-cols-2 xl:grid-cols-4">
                <LicenseFact
                  label={t("source.provider.col.name.l3prov0013")}
                  value={editions.customer || (editions.tier === "community" ? planName : t("protocols.ari.notApplicable"))}
                />
                <LicenseFact
                  label={t("platform.editions.environment")}
                  value={
                    editions.deployment_entitlement?.environment === "non_production"
                      ? t("platform.editions.nonProduction")
                      : editions.deployment_entitlement?.environment === "production"
                        ? t("platform.editions.production")
                        : t("protocols.ari.notApplicable")
                  }
                />
                <LicenseFact
                  label={t("platform.editions.deploymentId")}
                  value={editions.deployment_entitlement?.deployment_id || t("protocols.ari.notApplicable")}
                  mono
                />
                <LicenseFact label={t("platform.editions.useRights")} value={(editions.rights ?? ["self_host"]).map(humanizeToken).join(", ")} />
                {editions.deployment_entitlement ? (
                  <>
                    <LicenseFact
                      label={t("platform.editions.billingUnit")}
                      value={t("platform.editions.productionUnits", { count: editions.deployment_entitlement.production_units_consumed })}
                    />
                    <LicenseFact
                      label={t("platform.editions.nonProduction")}
                      value={t("platform.editions.nonProductionSlots", {
                        remaining: editions.deployment_entitlement.non_production_slots_remaining,
                        total: editions.deployment_entitlement.bundled_non_production_deployments,
                      })}
                    />
                  </>
                ) : null}
                {editions.tier === "provider" ? (
                  <LicenseFact
                    label={t("platform.editions.managedCustomerBand")}
                    value={editions.managed_customer_band ? formatNumberPolicy(editions.managed_customer_band, formatPolicy) : t("admin.editions.negotiated")}
                  />
                ) : null}
                <LicenseFact
                  label={t("source.fips.posture.4051e94687")}
                  value={`${t(editions.fips?.module_active ? "source.fips.module.active.76cb6077b6" : "source.fips.module.inactive.fac8ddb35b")} ${
                    editions.fips?.module_active
                      ? ""
                      : t(editions.fips?.self_test_passed ? "source.self.test.passed.c28b5c9b12" : "source.self.test.not.confirmed.03a528b202")
                  }`.trim()}
                />
              </dl>

              <details className="min-w-0 rounded-panel border border-border bg-background p-3">
                <summary className="cursor-pointer font-semibold">{t("source.packaging.edition.matrix.265d443ef4")}</summary>
                <div className="mt-4 grid gap-4">
                  <SystemTableRegion label={t("source.packaging.edition.matrix.265d443ef4")}>
                    <table className="ui-table min-w-[36rem]">
                      <caption className="sr-only">{t("source.packaging.edition.matrix.265d443ef4")}</caption>
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
                  </SystemTableRegion>
                  <SystemTableRegion label={t("platform.editions.referencePrices")}>
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
                  </SystemTableRegion>
                  <p className="text-sm text-muted-foreground">{packaging.non_production_support_posture}</p>
                </div>
              </details>

              <details
                className="min-w-0 rounded-panel border border-border bg-background p-3"
                open={architectureOpen}
                onToggle={(event) => setArchitectureOpen(event.currentTarget.open)}
              >
                <summary className="cursor-pointer font-semibold">{t("admin.editions.architectureEvidence")}</summary>
                <div className="mt-4 grid gap-4">
                  {!distribution && !activeActiveIssuance && !architectureError ? <p>{t("app.loading")}</p> : null}
                  {architectureError ? (
                    <div className="grid justify-items-start gap-3">
                      <p role="alert" className="text-sm text-destructive">
                        {architectureError}
                      </p>
                      <Button type="button" variant="outline" onClick={() => setArchitectureAttempt((attempt) => attempt + 1)}>
                        {t("admin.system.tryAgain")}
                      </Button>
                    </div>
                  ) : null}
                  {distribution ? <DistributionEvidence status={distribution} /> : null}
                  {activeActiveIssuance ? <RegionalIssuanceEvidence plan={activeActiveIssuance} formatPolicy={formatPolicy} /> : null}
                </div>
              </details>
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">{t("admin.editions.evidenceUnavailable")}</p>
          )}
        </SystemDisclosure>
      </div>

      <DetailDrawer
        open={guideOpen}
        onClose={() => setGuideOpen(false)}
        returnFocusRef={addLicenseRef}
        title={t("admin.editions.addLicense")}
        description={t("admin.editions.guideVerify")}
      >
        <div className="grid gap-5 text-sm">
          <ol className="grid list-decimal gap-3 ps-5">
            <li>{t("admin.editions.guideStepFile")}</li>
            <li>{t("admin.editions.guideStepIdentity")}</li>
            <li>{t("admin.editions.guideStepRestart")}</li>
          </ol>
          <div className="grid gap-2 rounded-panel border border-border bg-muted/40 p-3">
            {licenseRuntimeBindings.map((binding) => (
              <code key={binding}>{binding}</code>
            ))}
          </div>
          <p className="rounded-control border border-status-info/30 bg-status-info/10 p-3 text-muted-foreground">{t("admin.editions.guideBrowserBoundary")}</p>
          <p className="text-muted-foreground">{t("admin.editions.guideRecovery")}</p>
        </div>
      </DetailDrawer>
    </section>
  );
}

const licenseRuntimeBindings = ["TRSTCTL_LICENSE_FILE", "TRSTCTL_LICENSE_DEPLOYMENT_ID", "TRSTCTL_LICENSE_ENVIRONMENT"] as const;

function LicenseFact({ label, value, mono = false }: { label: string; value: ReactNode; mono?: boolean }) {
  return (
    <div className="rounded-control border border-border bg-background p-3">
      <dt className="text-muted-foreground">{label}</dt>
      <dd className={mono ? "mt-1 break-all font-mono text-xs" : "mt-1 font-medium"}>{value}</dd>
    </div>
  );
}

function licenseAnswer(editions: EditionsInfo, planName: string, t: ReturnType<typeof useTranslation>["t"]): string {
  if (editions.state === "active") return t("admin.editions.activeAnswer", { plan: planName });
  if (editions.state === "grace") return t("admin.editions.graceAnswer", { plan: planName });
  if (editions.state === "read_only") return t("admin.editions.readOnlyAnswer", { plan: planName });
  return t("admin.editions.communityAnswer");
}

function DistributionEvidence({ status }: { status: PlatformDistributionStatus }) {
  const { t } = useTranslation();
  return (
    <section className="rounded-panel border border-border p-3" aria-labelledby="distribution-posture-heading">
      <h3 id="distribution-posture-heading" className="text-body font-semibold">
        {t("parity.distributionPosture_10c8b4")}
      </h3>
      <dl className="mt-3 grid gap-3 text-sm sm:grid-cols-2">
        <LicenseFact label={t("parity.productionMode_1737a4")} value={humanizeToken(status.production_mode)} />
        <LicenseFact label={t("parity.controlPlaneLineage_513399")} value={humanizeToken(status.control_plane_lineage)} />
        <LicenseFact
          label={t("parity.builtInGuarantees_21db16")}
          value={
            status.offline_license_verifier && status.core_audit_and_export
              ? t("admin.editions.coreGuaranteesPresent")
              : t("admin.editions.coreGuaranteesIncomplete")
          }
        />
        <LicenseFact label={t("parity.airGap_a0134a")} value={airGapSummary(status.air_gap)} />
      </dl>
    </section>
  );
}

function RegionalIssuanceEvidence({ plan, formatPolicy }: { plan: ActiveActiveIssuancePlan; formatPolicy: FormatPolicy }) {
  const { t } = useTranslation();
  return (
    <section className="rounded-panel border border-border p-3" aria-labelledby="regional-issuance-heading">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="flex items-center gap-2">
          <Network className="h-4 w-4 text-status-success" aria-hidden="true" />
          <h3 id="regional-issuance-heading" className="text-body font-semibold">
            {t("platform.ha.heading")}
          </h3>
        </div>
        <span className={scaleServedClass(plan.served)}>{plan.served ? t("platform.ha.active") : t("platform.ha.unavailable")}</span>
      </div>
      <p className="mt-2 text-sm text-muted-foreground">{t("platform.ha.description")}</p>
      <dl className="mt-3 grid gap-3 text-sm sm:grid-cols-2">
        <LicenseFact label={t("platform.ha.topology")} value={plan.topology ?? "-"} />
        <LicenseFact label={t("platform.ha.writeModel")} value={plan.write_model ?? "-"} />
        <LicenseFact
          label={t("platform.ha.rpoRto")}
          value={t("platform.ha.rpoRtoValue", {
            rpo: formatOptionalNumber(plan.rpo_seconds, formatPolicy),
            rto: formatOptionalNumber(plan.rto_seconds, formatPolicy),
          })}
        />
        <LicenseFact label={t("platform.ha.invariants")} value={(plan.architecture_invariants ?? []).join(", ") || "-"} mono />
      </dl>
      {(plan.regions ?? []).length > 0 ? (
        <div className="mt-4">
          <SystemTableRegion label={t("platform.ha.regionCaption")}>
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
                {plan.regions.slice(0, 3).map((region) => (
                  <tr key={region.id}>
                    <td>
                      {region.region}
                      <span className="block font-mono text-xs text-muted-foreground">{region.id}</span>
                    </td>
                    <td>{region.role}</td>
                    <td>{region.writable_scope}</td>
                    <td>{region.health_signal}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </SystemTableRegion>
        </div>
      ) : null}
      <div className="mt-4 flex flex-wrap gap-2">
        {(plan.tenant_write_fences ?? []).map((fence) => (
          <span key={fence.id} className="rounded-control border border-border bg-muted px-2 py-1 font-mono text-xs">
            {fence.id}
          </span>
        ))}
        {(plan.release_gates ?? []).map((gate) => (
          <span key={gate.id} className="rounded-control border border-border bg-muted px-2 py-1 font-mono text-xs">
            {gate.id}
          </span>
        ))}
      </div>
    </section>
  );
}

function formatOptionalNumber(value: number | undefined, policy: FormatPolicy): string {
  if (value == null || Number.isNaN(value)) return "-";
  return formatNumberPolicy(value, policy);
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
