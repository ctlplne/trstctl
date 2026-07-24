import { useEffect, useMemo, useState, type FormEvent, type ReactNode } from "react";
import { Link, Navigate, useSearchParams } from "react-router-dom";
import { Building2, Gauge, Headphones, KeyRound, Loader2, Network, Plus, RefreshCw, ShieldCheck, UserMinus } from "lucide-react";
import { useAuth } from "@/auth/AuthProvider";
import { DataGrid, type DataGridColumn } from "@/components/DataGrid";
import { Dialog } from "@/components/Dialog";
import { PageHeader } from "@/components/PageHeader";
import { StatusBadge } from "@/components/StatusBadge";
import { Button } from "@/components/ui/button";
import { useTranslation, translateNow } from "@/i18n/I18nProvider";
import { formatCurrency as formatCurrencyPolicy, formatDateTime, formatNumber as formatNumberPolicy, type FormatPolicy } from "@/i18n/format";
import {
  api,
  type ActiveActiveIssuancePlan,
  type APIToken,
  type EditionsInfo,
  type EnterpriseSupportStatus,
  type ManagedOfferingStatus,
  type ManagedTenant,
  type ManagedTenantProvisionRequest,
  type Member,
  type OIDCMappingStatus,
  type PAMSession,
  type PAMSessionRequest,
  type PlatformDistributionStatus,
  type RoleList,
  type ScaleOrchestrationPlan,
} from "@/lib/api";
import type { StatusTone } from "@/lib/statusVocab";

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
    warning: "Plaintext local preview. No private cert/key bytes are exposed in this browser view.",
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
    "Free is the self-hosted MPL core. Enterprise bills per control-plane deployment. Provider/MSP wholesale pricing uses negotiable managed-customer bands and includes managed-service and resale rights for the commercial feature set; each MSP controls its own downstream hosting, support, and customer pricing. Credentials and rotations are never billing units.",
  evidence_rail: ["live eval receipts", "served NHI route coverage", "OWASP NHI mapping", "current limitations"],
  editions: [
    { id: "community", name: "Free", column: "Free", buyer_fit: "", license_boundary: "", billing: "", included: [] },
    { id: "enterprise", name: "Enterprise self-host", column: "Enterprise", buyer_fit: "", license_boundary: "", billing: "", included: [] },
    { id: "provider", name: "Provider / MSP", column: "Provider / MSP", buyer_fit: "", license_boundary: "", billing: "", included: [] },
  ],
  meters: [],
};

type PAMSessionFormState = {
  target_type: PAMSessionRequest["target_type"];
  target_id: string;
  role: string;
  method: string;
  payload_base64: string;
  reason: string;
  ttl_seconds: string;
  ssh_principal: string;
  ssh_public_key: string;
};

const defaultPAMSessionForm: PAMSessionFormState = {
  target_type: "postgres",
  target_id: "",
  role: "",
  method: "",
  payload_base64: "",
  reason: "",
  ttl_seconds: "",
  ssh_principal: "",
  ssh_public_key: "",
};

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

/** Shared header quick links (Privacy / Integrate) for the three admin pages. */
function AdminHeaderActions() {
  const { t } = useTranslation();
  return (
    <>
      <Link
        to="/privacy"
        className="inline-flex min-h-10 items-center justify-center gap-2 rounded-md border border-border bg-background px-3 py-2 text-sm font-medium hover:border-brand-accent/40 hover:bg-muted/60"
      >
        <ShieldCheck className="h-4 w-4" aria-hidden="true" />
        {t("nav.item.privacy")}
      </Link>
      <Link
        to="/integrate"
        className="inline-flex min-h-10 items-center justify-center gap-2 rounded-md border border-border bg-background px-3 py-2 text-sm font-medium hover:border-brand-accent/40 hover:bg-muted/60"
      >
        <Network className="h-4 w-4" aria-hidden="true" />
        {t("nav.item.integrate")}
      </Link>
    </>
  );
}

/** /admin/system — read-only posture disclosures plus the managed-offering
 * provisioning flow. Fetches only what this page renders. */
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
                <dd>{preview ? "local preview session" : "authenticated session"}</dd>
              </div>
              <div>
                <dt className="font-medium text-muted-foreground">{translateNow("source.csrf.cookie.04ee351267")}</dt>
                <dd>{csrfPresent ? "present for browser mutations" : "not visible in this browser context"}</dd>
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
                <dd>{enterpriseSupport?.capability ?? "CAP-MODEL-04"}</dd>
              </div>
              <div>
                <dt className="font-medium text-muted-foreground">{translateNow("source.license.feature.de93785a58")}</dt>
                <dd className="font-mono text-xs">{enterpriseSupport?.license_feature ?? "ha_support"}</dd>
              </div>
              <div>
                <dt className="font-medium text-muted-foreground">{translateNow("source.license.tier.0c9a751553")}</dt>
                <dd>{enterpriseSupport?.tier ?? editions?.tier ?? "community"}</dd>
              </div>
              <div>
                <dt className="font-medium text-muted-foreground">{translateNow("source.contract.boundary.67a4070e64")}</dt>
                <dd>{enterpriseSupport?.contract_boundary ?? "Commercial support terms control legal SLA credits and named contacts."}</dd>
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
                <dd>{managedOffering?.provider_plane_mode ?? "off"}</dd>
              </div>
              <div>
                <dt className="font-medium text-muted-foreground">{translateNow("source.license.tier.0c9a751553")}</dt>
                <dd>{managedOffering?.tier ?? editions?.tier ?? "community"}</dd>
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
                      : "Negotiated / unlimited"}
                  </dd>
                </div>
              ) : null}
              <div>
                <dt className="font-medium text-muted-foreground">{translateNow("source.event.source.60dbb37270")}</dt>
                <dd>{managedOffering?.event_type ?? "tenant.registered"}</dd>
              </div>
              <div>
                <dt className="font-medium text-muted-foreground">{translateNow("source.mutation.idempotency.e5fe0e928c")}</dt>
                <dd>{managedOffering?.idempotency_required ? "required" : "-"}</dd>
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
                <dd>{editions?.customer ?? "community core"}</dd>
              </div>
              <div>
                <dt className="font-medium text-muted-foreground">{translateNow("source.expiry.6956d81401")}</dt>
                <dd>{formatOptionalDate(editions?.expires_at, formatPolicy)}</dd>
              </div>
              <div>
                <dt className="font-medium text-muted-foreground">{t("platform.editions.useRights")}</dt>
                <dd>{(editions?.rights ?? ["self_host"]).map((right) => right.replaceAll("_", " ")).join(", ")}</dd>
              </div>
              {editions?.tier === "provider" ? (
                <div>
                  <dt className="font-medium text-muted-foreground">{t("platform.editions.managedCustomerBand")}</dt>
                  <dd>{editions.managed_customer_band ? formatNumberPolicy(editions.managed_customer_band, formatPolicy) : "Negotiated / unlimited"}</dd>
                </div>
              ) : null}
              <div>
                <dt className="font-medium text-muted-foreground">{translateNow("source.fips.posture.4051e94687")}</dt>
                <dd className="grid gap-1">
                  <span>
                    {editions?.fips?.module_active ? "FIPS module active" : "FIPS module inactive"}
                    {editions?.fips?.required ? " · required" : ""}
                    {editions?.fips?.self_test_passed ? " · self-test passed" : " · self-test not confirmed"}
                  </span>
                  {editions?.fips?.validated_module_path ? (
                    <span>
                      {editions.fips.standard ?? "FIPS 140-3"} · {editions.fips.module ?? "Go Cryptographic Module"} ·{" "}
                      {editions.fips.build_target ?? "make fips-build"}
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
                        {archive.evaluation_only ? " · evaluation only" : ""}
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

/** /admin/access — the tenant's operational access surface: membership, API
 * tokens, offboarding, and JIT privileged sessions. */
export function AdminAccess() {
  const { locale, timeZone, t } = useTranslation();
  const formatPolicy = useMemo<FormatPolicy>(() => ({ locale, timeZone }), [locale, timeZone]);
  const [roles, setRoles] = useState<RoleList | null>(null);
  const [oidc, setOIDC] = useState<OIDCMappingStatus | null>(null);
  const [members, setMembers] = useState<Member[]>([]);
  const [tokens, setTokens] = useState<APIToken[]>([]);
  const [accessLoading, setAccessLoading] = useState(true);
  const [accessBusy, setAccessBusy] = useState(false);
  const [accessError, setAccessError] = useState<string | null>(null);
  const [accessNotice, setAccessNotice] = useState<string | null>(null);
  const [revealedToken, setRevealedToken] = useState<string | null>(null);
  const [memberSubject, setMemberSubject] = useState("");
  const [memberDisplayName, setMemberDisplayName] = useState("");
  const [memberEmail, setMemberEmail] = useState("");
  const [memberRoles, setMemberRoles] = useState("operator");
  const [tokenSubject, setTokenSubject] = useState("");
  const [tokenScopes, setTokenScopes] = useState("access:read");
  const [offboardSubject, setOffboardSubject] = useState("");
  const [offboardReason, setOffboardReason] = useState("");
  const [pamRows, setPAMRows] = useState<PAMSession[] | null>(null);
  const [pamCursor, setPAMCursor] = useState<string | undefined>(undefined);
  const [pamLoadingMore, setPAMLoadingMore] = useState(false);
  const [pamDetail, setPAMDetail] = useState<PAMSession | null>(null);
  const [pamFormOpen, setPAMFormOpen] = useState(false);
  const [pamForm, setPAMForm] = useState<PAMSessionFormState>(defaultPAMSessionForm);
  const [pamBusy, setPAMBusy] = useState(false);
  const [pamFormError, setPAMFormError] = useState<string | null>(null);
  const [pamCreated, setPAMCreated] = useState<PAMSession | null>(null);
  const [pamCopied, setPAMCopied] = useState(false);
  const roleRows = useMemo(() => roles?.items ?? [], [roles]);
  const pamColumns = useMemo<DataGridColumn<PAMSession>[]>(
    () => [
      { id: "started", header: "Started", cell: (session) => formatOptionalDate(session.started_at, formatPolicy) },
      {
        id: "subject",
        header: "Subject",
        cell: (session) => <span className="break-all font-mono text-xs">{session.subject}</span>,
      },
      { id: "role", header: "Role", cell: (session) => session.role },
      {
        id: "target",
        header: "Target",
        cell: (session) => (
          <div className="grid gap-1">
            <span>{session.target_type}</span>
            <span className="break-all font-mono text-xs text-muted-foreground">{session.target_id}</span>
          </div>
        ),
      },
      {
        id: "status",
        header: "Status",
        cell: (session) => <StatusBadge value={session.status} label={session.status} tone={pamStatusTone(session.status)} />,
      },
      { id: "expires", header: "Expires", cell: (session) => formatOptionalDate(session.expires_at, formatPolicy) },
    ],
    [formatPolicy],
  );

  async function loadAccessAdmin() {
    setAccessLoading(true);
    setAccessError(null);
    try {
      const [roleCatalog, oidcStatus, memberPage, tokenPage] = await Promise.all([
        api.accessRoles(),
        api.oidcMappingStatus(),
        api.members({ includeOffboarded: true, limit: 50 }),
        api.apiTokens({ includeRevoked: true, limit: 50 }),
      ]);
      setRoles(roleCatalog);
      setOIDC(oidcStatus);
      setMembers(memberPage.items ?? []);
      setTokens(tokenPage.items ?? []);
    } catch (err) {
      setAccessError(err instanceof Error ? err.message : String(err));
    } finally {
      setAccessLoading(false);
    }
  }

  useEffect(() => {
    void loadAccessAdmin();
  }, []);

  useEffect(() => {
    let active = true;
    Promise.resolve()
      .then(() => api.pamSessions({ limit: 20 }))
      .then((page) => {
        if (!active) return;
        setPAMRows(page.items ?? []);
        setPAMCursor(page.next_cursor);
      })
      .catch(() => null);
    return () => {
      active = false;
    };
  }, []);

  async function loadMorePAMSessions() {
    if (!pamCursor) return;
    setPAMLoadingMore(true);
    try {
      const page = await api.pamSessions({ limit: 20, cursor: pamCursor });
      setPAMRows((current) => [...(current ?? []), ...(page.items ?? [])]);
      setPAMCursor(page.next_cursor);
    } catch (err) {
      setAccessError(err instanceof Error ? err.message : String(err));
    } finally {
      setPAMLoadingMore(false);
    }
  }

  function closePAMDialog() {
    setPAMFormOpen(false);
    setPAMFormError(null);
    setPAMCreated(null);
    setPAMCopied(false);
  }

  async function openPrivilegedSession(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setPAMBusy(true);
    setPAMFormError(null);
    try {
      const ttl = Number(pamForm.ttl_seconds.trim());
      const input: PAMSessionRequest = {
        method: pamForm.method.trim(),
        payload_base64: pamForm.payload_base64.trim(),
        role: pamForm.role.trim(),
        target_id: pamForm.target_id.trim(),
        target_type: pamForm.target_type,
        ...(pamForm.reason.trim() ? { reason: pamForm.reason.trim() } : {}),
        ...(pamForm.ttl_seconds.trim() && Number.isFinite(ttl) && ttl > 0 ? { ttl_seconds: Math.floor(ttl) } : {}),
        ...(pamForm.target_type === "ssh" && pamForm.ssh_principal.trim() ? { ssh_principal: pamForm.ssh_principal.trim() } : {}),
        ...(pamForm.target_type === "ssh" && pamForm.ssh_public_key.trim() ? { ssh_public_key: pamForm.ssh_public_key.trim() } : {}),
      };
      const created = await api.openPAMSession(input);
      setPAMCreated(created);
      setPAMRows((current) => [created, ...(current ?? []).filter((item) => item.id !== created.id)]);
      setPAMForm(defaultPAMSessionForm);
    } catch (err) {
      setPAMFormError(err instanceof Error ? err.message : String(err));
    } finally {
      setPAMBusy(false);
    }
  }

  async function copyPAMSessionID(id: string) {
    try {
      await navigator.clipboard.writeText(id);
      setPAMCopied(true);
    } catch {
      setPAMCopied(false);
    }
  }

  async function onboardMember(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setAccessBusy(true);
    setAccessError(null);
    setAccessNotice(null);
    try {
      await api.upsertMember(memberSubject.trim(), {
        display_name: memberDisplayName.trim(),
        email: memberEmail.trim(),
        roles: csvList(memberRoles),
        source: "manual",
      });
      setAccessNotice(`Onboarded ${memberSubject.trim()}`);
      setMemberSubject("");
      setMemberDisplayName("");
      setMemberEmail("");
      await loadAccessAdmin();
    } catch (err) {
      setAccessError(err instanceof Error ? err.message : String(err));
    } finally {
      setAccessBusy(false);
    }
  }

  async function mintToken(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setAccessBusy(true);
    setAccessError(null);
    setAccessNotice(null);
    setRevealedToken(null);
    try {
      const created = await api.createAPIToken({ subject: tokenSubject.trim(), scopes: csvList(tokenScopes) });
      setRevealedToken(created.token);
      setAccessNotice(`Minted API token for ${created.subject}`);
      setTokenSubject("");
      await loadAccessAdmin();
    } catch (err) {
      setAccessError(err instanceof Error ? err.message : String(err));
    } finally {
      setAccessBusy(false);
    }
  }

  async function offboardMember(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setAccessBusy(true);
    setAccessError(null);
    setAccessNotice(null);
    setRevealedToken(null);
    try {
      const result = await api.offboardMember(offboardSubject.trim(), { reason: offboardReason.trim() });
      setAccessNotice(`Offboarded ${result.member.subject}; revoked ${result.revoked_token_count} token(s)`);
      setOffboardSubject("");
      setOffboardReason("");
      await loadAccessAdmin();
    } catch (err) {
      setAccessError(err instanceof Error ? err.message : String(err));
    } finally {
      setAccessBusy(false);
    }
  }

  return (
    <section aria-labelledby="admin-access-heading" className="grid gap-6">
      <PageHeader
        titleId="admin-access-heading"
        title={t("platform.tabs.access")}
        description={t("admin.access.description")}
        actions={<AdminHeaderActions />}
      />
      <div className="grid gap-6">
        {/* The page H1 above already says "Access administration" (naming
              parity), so this block only carries the refresh affordance. */}
        <div>
          <div className="mb-3 flex flex-wrap items-center justify-end gap-3">
            <Button type="button" size="sm" variant="outline" onClick={() => void loadAccessAdmin()} disabled={accessLoading}>
              {accessLoading ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <RefreshCw className="h-4 w-4" aria-hidden="true" />}
              {translateNow("source.refresh.0e91610117")}
            </Button>
          </div>
          {accessError && (
            <p role="alert" className="mb-3 rounded-control border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm text-destructive">
              {accessError}
            </p>
          )}
          {accessNotice && (
            <p role="status" className="mb-3 rounded-control border border-status-success/30 bg-status-success/10 px-3 py-2 text-sm text-status-success">
              {accessNotice}
            </p>
          )}
          {revealedToken && (
            <div className="mb-3 rounded-panel border border-status-warning/40 bg-status-warning/10 p-3 text-sm">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <p className="font-medium">{translateNow("source.reveal.once.api.token.8cfd65d574")}</p>
                <Button type="button" size="sm" variant="ghost" onClick={() => setRevealedToken(null)}>
                  {translateNow("source.dismiss.48845bff33")}
                </Button>
              </div>
              <code className="mt-2 block break-all rounded bg-background px-2 py-1 text-xs">{revealedToken}</code>
            </div>
          )}
          <div className="mb-4 grid gap-3 xl:grid-cols-3">
            <form onSubmit={(event) => void onboardMember(event)} className="ui-panel grid gap-3 p-comfortable">
              <div className="flex items-center gap-2">
                <ShieldCheck className="h-4 w-4 text-status-success" aria-hidden="true" />
                <h2 className="text-body font-semibold">{translateNow("source.onboard.member.a6dfe12142")}</h2>
              </div>
              <label className="grid gap-1 text-sm">
                <span className="font-medium text-muted-foreground">{translateNow("source.subject.6897128384")}</span>
                <input className="ui-input" value={memberSubject} onChange={(event) => setMemberSubject(event.target.value)} required />
              </label>
              <label className="grid gap-1 text-sm">
                <span className="font-medium text-muted-foreground">{translateNow("source.display.name.2b7f6a84de")}</span>
                <input className="ui-input" value={memberDisplayName} onChange={(event) => setMemberDisplayName(event.target.value)} />
              </label>
              <label className="grid gap-1 text-sm">
                <span className="font-medium text-muted-foreground">{translateNow("source.email.969ccbd3cf")}</span>
                <input className="ui-input" value={memberEmail} onChange={(event) => setMemberEmail(event.target.value)} />
              </label>
              <label className="grid gap-1 text-sm">
                <span className="font-medium text-muted-foreground">{translateNow("source.roles.c253370554")}</span>
                <input className="ui-input" value={memberRoles} onChange={(event) => setMemberRoles(event.target.value)} required />
              </label>
              <Button type="submit" disabled={accessBusy || !memberSubject.trim()}>
                <Plus className="h-4 w-4" aria-hidden="true" />
                {translateNow("source.save.1509f561f2")}
              </Button>
            </form>
            <form onSubmit={(event) => void mintToken(event)} className="ui-panel grid gap-3 p-comfortable">
              <div className="flex items-center gap-2">
                <KeyRound className="h-4 w-4 text-status-warning" aria-hidden="true" />
                <h2 className="text-body font-semibold">{translateNow("source.mint.api.token.f6cf0efff0")}</h2>
              </div>
              <label className="grid gap-1 text-sm">
                <span className="font-medium text-muted-foreground">{translateNow("source.subject.6897128384")}</span>
                <input className="ui-input" value={tokenSubject} onChange={(event) => setTokenSubject(event.target.value)} required />
              </label>
              <label className="grid gap-1 text-sm">
                <span className="font-medium text-muted-foreground">{translateNow("source.scopes.0d5644ff52")}</span>
                <input className="ui-input" value={tokenScopes} onChange={(event) => setTokenScopes(event.target.value)} required />
              </label>
              <Button type="submit" disabled={accessBusy || !tokenSubject.trim()}>
                <KeyRound className="h-4 w-4" aria-hidden="true" />
                {translateNow("source.mint.ced97cc4a3")}
              </Button>
            </form>
            <form onSubmit={(event) => void offboardMember(event)} className="ui-panel grid gap-3 p-comfortable">
              <div className="flex items-center gap-2">
                <UserMinus className="h-4 w-4 text-destructive" aria-hidden="true" />
                <h2 className="text-body font-semibold">{translateNow("source.offboard.member.8a27787595")}</h2>
              </div>
              <label className="grid gap-1 text-sm">
                <span className="font-medium text-muted-foreground">{translateNow("source.subject.6897128384")}</span>
                {/* Autocomplete from the loaded member roster — no copy-pasting
                  subjects out of the table above. */}
                <input
                  className="ui-input"
                  value={offboardSubject}
                  onChange={(event) => setOffboardSubject(event.target.value)}
                  list="member-subject-options"
                  required
                />
                <datalist id="member-subject-options">
                  {members.map((member) => (
                    <option key={member.subject} value={member.subject}>
                      {member.email ?? member.subject}
                    </option>
                  ))}
                </datalist>
              </label>
              <label className="grid gap-1 text-sm">
                <span className="font-medium text-muted-foreground">{translateNow("source.reason.f81ab834de")}</span>
                <input className="ui-input" value={offboardReason} onChange={(event) => setOffboardReason(event.target.value)} />
              </label>
              <Button type="submit" variant="destructive" loading={accessBusy} disabled={!offboardSubject.trim()}>
                <UserMinus className="h-4 w-4" aria-hidden="true" />
                {translateNow("source.offboard.9053e68ef6")}
              </Button>
            </form>
          </div>
          {pamRows && (
            <div className="ui-panel mb-4 grid gap-3 p-comfortable">
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div>
                  <h2 className="text-body font-semibold">{t("parity.privilegedAccessSessions_368da5")}</h2>
                  <p className="mt-1 text-sm text-muted-foreground">{t("parity.justInTimeOperatorSessionsBrokered_df233f")}</p>
                </div>
                <Button type="button" size="sm" onClick={() => setPAMFormOpen(true)}>
                  <KeyRound className="h-4 w-4" aria-hidden="true" />
                  {t("parity.openSession_73b3ca")}
                </Button>
              </div>
              <DataGrid
                ariaLabel="Privileged access sessions"
                rows={pamRows}
                columns={pamColumns}
                getRowId={(session) => session.id}
                onRowOpen={(session) => setPAMDetail(session)}
                rowActionLabel={() => "Details"}
                pagination={
                  pamCursor ? (
                    <div>
                      <Button type="button" size="sm" variant="outline" disabled={pamLoadingMore} onClick={() => void loadMorePAMSessions()}>
                        {pamLoadingMore ? "Loading more sessions..." : "Load more sessions"}
                      </Button>
                    </div>
                  ) : undefined
                }
              />
            </div>
          )}
          <div className="mb-4 grid gap-4 xl:grid-cols-2">
            <div className="overflow-x-auto rounded-panel border border-border">
              <table className="ui-table min-w-[34rem]">
                <caption className="sr-only">{translateNow("source.role.catalog.d2bfa0ab0e")}</caption>
                <thead>
                  <tr>
                    <th scope="col">{translateNow("source.role.14736a2eb9")}</th>
                    <th scope="col">{translateNow("source.permissions.abccc78cc9")}</th>
                  </tr>
                </thead>
                <tbody>
                  {roleRows.map((role) => (
                    <tr key={role.name} className="align-top">
                      <td className="font-medium">{role.name}</td>
                      <td className="font-mono text-xs">{role.permissions.join(", ")}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="ui-panel p-comfortable text-sm">
              <h2 className="font-semibold">{translateNow("source.oidc.mapping.status.358515bade")}</h2>
              <dl className="mt-3 grid gap-2">
                <div>
                  <dt className="font-medium text-muted-foreground">{translateNow("source.enabled.92c1cdfdf4")}</dt>
                  <dd>{oidc?.enabled ? "yes" : "no"}</dd>
                </div>
                <div>
                  <dt className="font-medium text-muted-foreground">{translateNow("source.claims.1c85c12229")}</dt>
                  <dd>{[oidc?.tenant_claim || "no tenant claim", oidc?.groups_claim || "no groups claim"].join(" · ")}</dd>
                </div>
                <div>
                  <dt className="font-medium text-muted-foreground">{translateNow("source.mappings.f64ec16b0d")}</dt>
                  <dd>{oidc?.tenant_mappings?.length ? oidc.tenant_mappings.map((m) => m.group || m.subject || m.claim).join(", ") : "none"}</dd>
                </div>
              </dl>
            </div>
          </div>
          <div className="mb-4 grid gap-4 xl:grid-cols-2">
            <div className="overflow-x-auto rounded-panel border border-border">
              <table className="ui-table min-w-[44rem]">
                <caption className="sr-only">{translateNow("source.tenant.members.7c3b607c20")}</caption>
                <thead>
                  <tr>
                    <th scope="col">{translateNow("source.subject.6897128384")}</th>
                    <th scope="col">{translateNow("source.roles.c253370554")}</th>
                    <th scope="col">{translateNow("source.status.920e413c7d")}</th>
                    <th scope="col">{translateNow("source.updated.3a5ecca188")}</th>
                  </tr>
                </thead>
                <tbody>
                  {members.map((member) => (
                    <tr key={member.subject} className="align-top">
                      <td className="font-medium">{member.subject}</td>
                      <td className="font-mono text-xs">{member.roles.join(", ")}</td>
                      <td>{member.status}</td>
                      <td>{formatOptionalDate(member.updated_at, formatPolicy)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="overflow-x-auto rounded-panel border border-border">
              <table className="ui-table min-w-[48rem]">
                <caption className="sr-only">{translateNow("source.api.token.metadata.d3e4dba811")}</caption>
                <thead>
                  <tr>
                    <th scope="col">{translateNow("source.subject.6897128384")}</th>
                    <th scope="col">{translateNow("source.scopes.0d5644ff52")}</th>
                    <th scope="col">{translateNow("source.status.920e413c7d")}</th>
                    <th scope="col">{translateNow("source.created.d70b9e24bc")}</th>
                  </tr>
                </thead>
                <tbody>
                  {tokens.map((token) => (
                    <tr key={token.id} className="align-top">
                      <td className="font-medium">{token.subject}</td>
                      <td className="font-mono text-xs">{token.scopes.join(", ")}</td>
                      <td>{token.revoked_at ? "revoked" : "active"}</td>
                      <td>{formatOptionalDate(token.created_at, formatPolicy)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        {pamDetail && (
          <Dialog
            open
            onClose={() => setPAMDetail(null)}
            titleId="pam-session-detail-heading"
            descriptionId="pam-session-detail-description"
            className="fixed inset-0 z-50 flex items-center justify-center p-4"
            overlayClassName="absolute inset-0 bg-black/55"
            panelClassName="relative max-h-[calc(100vh-2rem)] w-full max-w-2xl overflow-y-auto rounded-panel border border-border bg-card shadow-elevation2"
          >
            <header className="border-b border-border px-5 py-4">
              <h2 id="pam-session-detail-heading" className="text-title font-semibold">
                {`Privileged session ${pamDetail.id}`}
              </h2>
              <p id="pam-session-detail-description" className="mt-1 text-sm text-muted-foreground">
                {t("parity.brokerEvidenceForThisJustIn_44ca48")}
              </p>
            </header>
            <dl className="grid gap-2 p-5 text-sm">
              <PlatformDetailRow term="ID" mono>
                {pamDetail.id}
              </PlatformDetailRow>
              <PlatformDetailRow term="Status">
                <StatusBadge value={pamDetail.status} label={pamDetail.status} tone={pamStatusTone(pamDetail.status)} />
              </PlatformDetailRow>
              <PlatformDetailRow term="Subject" mono>
                {pamDetail.subject}
              </PlatformDetailRow>
              <PlatformDetailRow term="Requested by" mono>
                {pamDetail.requested_by}
              </PlatformDetailRow>
              <PlatformDetailRow term="Role">{pamDetail.role}</PlatformDetailRow>
              <PlatformDetailRow term="Target" mono>
                {`${pamDetail.target_type} · ${pamDetail.target_id}`}
              </PlatformDetailRow>
              <PlatformDetailRow term="Reason">{pamDetail.reason || "-"}</PlatformDetailRow>
              <PlatformDetailRow term="Started">{formatOptionalDate(pamDetail.started_at, formatPolicy)}</PlatformDetailRow>
              <PlatformDetailRow term="Expires">{formatOptionalDate(pamDetail.expires_at, formatPolicy)}</PlatformDetailRow>
              <PlatformDetailRow term="Ended">{formatOptionalDate(pamDetail.ended_at, formatPolicy)}</PlatformDetailRow>
              {pamDetail.attestation ? (
                <PlatformDetailRow term="Attestation">
                  <JSONBlock value={pamDetail.attestation} />
                </PlatformDetailRow>
              ) : null}
              {pamDetail.audit ? (
                <PlatformDetailRow term="Audit">
                  <JSONBlock value={pamDetail.audit} />
                </PlatformDetailRow>
              ) : null}
              {pamDetail.postgres ? (
                <PlatformDetailRow term="PostgreSQL credential">
                  <JSONBlock value={pamDetail.postgres} />
                </PlatformDetailRow>
              ) : null}
              {pamDetail.ssh ? (
                <PlatformDetailRow term="SSH credential">
                  <JSONBlock value={pamDetail.ssh} />
                </PlatformDetailRow>
              ) : null}
            </dl>
            <div className="flex justify-end border-t border-border px-5 py-4">
              <Button type="button" variant="outline" onClick={() => setPAMDetail(null)}>
                {translateNow("source.close.7d9eb7acb1")}
              </Button>
            </div>
          </Dialog>
        )}

        {pamFormOpen && (
          <Dialog
            open
            onClose={closePAMDialog}
            titleId="pam-open-heading"
            descriptionId="pam-open-description"
            className="fixed inset-0 z-50 flex items-center justify-center p-4"
            overlayClassName="absolute inset-0 bg-black/55"
            panelClassName="relative max-h-[calc(100vh-2rem)] w-full max-w-xl overflow-y-auto rounded-panel border border-border bg-card shadow-elevation2"
          >
            <header className="border-b border-border px-5 py-4">
              <h2 id="pam-open-heading" className="text-title font-semibold">
                {t("parity.openPrivilegedSession_78a445")}
              </h2>
              <p id="pam-open-description" className="mt-1 text-sm text-muted-foreground">
                Broker short-lived access to a PostgreSQL role or SSH principal; the session and its evidence land in the audit trail.
              </p>
            </header>
            {pamCreated ? (
              <div className="grid gap-3 p-5 text-sm">
                <p role="status" className="rounded-control border border-status-success/30 bg-status-success/10 px-3 py-2 text-status-success">
                  {t("parity.sessionOpened_368838")}
                </p>
                <dl className="grid gap-2">
                  <PlatformDetailRow term="Session ID">
                    <span className="inline-flex flex-wrap items-center gap-2">
                      <span className="break-all font-mono text-xs">{pamCreated.id}</span>
                      <Button type="button" size="sm" variant="outline" onClick={() => void copyPAMSessionID(pamCreated.id)}>
                        {pamCopied ? "Copied" : "Copy ID"}
                      </Button>
                    </span>
                  </PlatformDetailRow>
                  <PlatformDetailRow term="Status">
                    <StatusBadge value={pamCreated.status} label={pamCreated.status} tone={pamStatusTone(pamCreated.status)} />
                  </PlatformDetailRow>
                  <PlatformDetailRow term="Expires">{formatOptionalDate(pamCreated.expires_at, formatPolicy)}</PlatformDetailRow>
                </dl>
                <div className="flex justify-end">
                  <Button type="button" variant="outline" onClick={closePAMDialog}>
                    {translateNow("source.close.7d9eb7acb1")}
                  </Button>
                </div>
              </div>
            ) : (
              <form onSubmit={(event) => void openPrivilegedSession(event)} className="grid gap-3 p-5">
                {pamFormError && (
                  <p role="alert" className="rounded-control border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm text-destructive">
                    {pamFormError}
                  </p>
                )}
                <div className="grid gap-3 md:grid-cols-2">
                  <label className="grid gap-1 text-body font-medium">
                    {t("parity.targetType_a45f80")}
                    <select
                      className="min-h-9 rounded-control border border-border bg-background px-3 py-2 text-body"
                      value={pamForm.target_type}
                      onChange={(event) => setPAMForm({ ...pamForm, target_type: event.target.value as PAMSessionRequest["target_type"] })}
                    >
                      <option value="postgres">{t("parity.postgres_afc848")}</option>
                      <option value="ssh">{t("parity.ssh_e8b9f6")}</option>
                    </select>
                  </label>
                  <label className="grid gap-1 text-body font-medium">
                    {t("parity.targetId_00960a")}
                    <input
                      className="min-h-9 rounded-control border border-border bg-background px-3 py-2 text-body"
                      value={pamForm.target_id}
                      onChange={(event) => setPAMForm({ ...pamForm, target_id: event.target.value })}
                      required
                    />
                  </label>
                  <label className="grid gap-1 text-body font-medium">
                    {translateNow("source.role.14736a2eb9")}
                    <input
                      className="min-h-9 rounded-control border border-border bg-background px-3 py-2 text-body"
                      value={pamForm.role}
                      onChange={(event) => setPAMForm({ ...pamForm, role: event.target.value })}
                      required
                    />
                  </label>
                  <label className="grid gap-1 text-body font-medium">
                    {translateNow("source.method.52a0f9b65b")}
                    <input
                      className="min-h-9 rounded-control border border-border bg-background px-3 py-2 text-body"
                      value={pamForm.method}
                      onChange={(event) => setPAMForm({ ...pamForm, method: event.target.value })}
                      required
                    />
                  </label>
                  {pamForm.target_type === "ssh" && (
                    <label className="grid gap-1 text-body font-medium">
                      {t("parity.sshPrincipal_8d0a6c")}
                      <input
                        className="min-h-9 rounded-control border border-border bg-background px-3 py-2 text-body"
                        value={pamForm.ssh_principal}
                        onChange={(event) => setPAMForm({ ...pamForm, ssh_principal: event.target.value })}
                      />
                    </label>
                  )}
                  <label className="grid gap-1 text-body font-medium">
                    {translateNow("source.reason.f81ab834de")}
                    <input
                      className="min-h-9 rounded-control border border-border bg-background px-3 py-2 text-body"
                      value={pamForm.reason}
                      onChange={(event) => setPAMForm({ ...pamForm, reason: event.target.value })}
                    />
                  </label>
                  <label className="grid gap-1 text-body font-medium">
                    {translateNow("source.ttl.seconds.862d08de5a")}
                    <input
                      className="min-h-9 rounded-control border border-border bg-background px-3 py-2 text-body"
                      type="number"
                      min={1}
                      value={pamForm.ttl_seconds}
                      onChange={(event) => setPAMForm({ ...pamForm, ttl_seconds: event.target.value })}
                      placeholder={translateNow("source.optional.ec91fdd925")}
                    />
                  </label>
                </div>
                {pamForm.target_type === "ssh" && (
                  <label className="grid gap-1 text-body font-medium">
                    {translateNow("source.ssh.public.key.c9be6a369e")}
                    <textarea
                      className="min-h-24 rounded-control border border-border bg-background px-3 py-2 font-mono text-xs"
                      value={pamForm.ssh_public_key}
                      onChange={(event) => setPAMForm({ ...pamForm, ssh_public_key: event.target.value })}
                    />
                  </label>
                )}
                <label className="grid gap-1 text-body font-medium">
                  {t("parity.payloadBase64_738cc4")}
                  <textarea
                    className="min-h-24 rounded-control border border-border bg-background px-3 py-2 font-mono text-xs"
                    value={pamForm.payload_base64}
                    onChange={(event) => setPAMForm({ ...pamForm, payload_base64: event.target.value })}
                    required
                  />
                </label>
                <div className="flex justify-end gap-2">
                  <Button type="button" variant="ghost" onClick={closePAMDialog}>
                    {translateNow("source.cancel.19766ed6cc")}
                  </Button>
                  <Button
                    type="submit"
                    disabled={pamBusy || !pamForm.target_id.trim() || !pamForm.role.trim() || !pamForm.method.trim() || !pamForm.payload_base64.trim()}
                  >
                    {pamBusy ? "Opening..." : "Open session"}
                  </Button>
                </div>
              </form>
            )}
          </Dialog>
        )}
      </div>
    </section>
  );
}

function csvList(value: string): string[] {
  return value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function formatOptionalDate(value: string | undefined, policy: FormatPolicy): string {
  if (!value) return "-";
  return formatDateTime(value, policy);
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

function pamStatusTone(status: string): StatusTone {
  if (status === "open" || status === "active") return "success";
  if (status === "expired" || status === "pending") return "warning";
  if (status === "revoked" || status === "failed") return "critical";
  return "neutral";
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

function PlatformDetailRow({ term, children, mono = false }: { term: string; children: ReactNode; mono?: boolean }) {
  return (
    <div className="grid gap-1 sm:grid-cols-[11rem_1fr] sm:gap-2">
      <dt className="font-medium text-muted-foreground">{term}</dt>
      <dd className={mono ? "break-all font-mono text-xs" : "break-words"}>{children}</dd>
    </div>
  );
}

function JSONBlock({ value }: { value: unknown }) {
  let text: string;
  try {
    text = JSON.stringify(value, null, 2);
  } catch {
    text = String(value);
  }
  return <pre className="max-h-48 overflow-auto rounded-control border border-border bg-muted/40 p-2 font-mono text-xs">{text}</pre>;
}
