import { useEffect, useMemo, useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { Building2, Gauge, Headphones, KeyRound, Loader2, Network, Plus, RefreshCw, ShieldCheck, UserMinus } from "lucide-react";
import { useAuth } from "@/auth/AuthProvider";
import { PageHeader } from "@/components/PageHeader";
import { Button } from "@/components/ui/button";
import { useTranslation } from "@/i18n/I18nProvider";
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
  type RoleList,
  type ScaleOrchestrationPlan,
} from "@/lib/api";

function browserTransport(): { label: string; detail: string; warning?: string } {
  if (typeof window === "undefined") {
    return { label: "Unknown", detail: "Browser transport is evaluated at runtime." };
  }
  if (window.location.protocol === "https:") {
    return {
      label: "HTTPS observed",
      detail: "The console is currently loaded over an encrypted browser connection.",
    };
  }
  return {
    label: "Local preview HTTP",
    detail: "The local Vite preview is HTTP. Production should be HTTPS or mTLS-terminated before operators use it.",
    warning: "Plaintext local preview. No private cert/key bytes are exposed in this browser view.",
  };
}

export function Platform() {
  const { user, preview } = useAuth();
  const { t } = useTranslation();
  const transport = browserTransport();
  const csrfPresent = typeof document !== "undefined" && document.cookie.includes("trstctl_csrf=");
  const [roles, setRoles] = useState<RoleList | null>(null);
  const [oidc, setOIDC] = useState<OIDCMappingStatus | null>(null);
  const [editions, setEditions] = useState<EditionsInfo | null>(null);
  const [enterpriseSupport, setEnterpriseSupport] = useState<EnterpriseSupportStatus | null>(null);
  const [managedOffering, setManagedOffering] = useState<ManagedOfferingStatus | null>(null);
  const [scaleOrchestration, setScaleOrchestration] = useState<ScaleOrchestrationPlan | null>(null);
  const [activeActiveIssuance, setActiveActiveIssuance] = useState<ActiveActiveIssuancePlan | null>(null);
  const [lastManagedTenant, setLastManagedTenant] = useState<ManagedTenant | null>(null);
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
  const [hostedTenantID, setHostedTenantID] = useState("");
  const [hostedTenantName, setHostedTenantName] = useState("");
  const [hostedRegion, setHostedRegion] = useState("us-east-1");
  const [hostedResidency, setHostedResidency] = useState("US");
  const [hostedPlan, setHostedPlan] = useState("enterprise");
  const [hostedSupportTier, setHostedSupportTier] = useState("24x7");
  const [hostedSLOTier, setHostedSLOTier] = useState("99.95");
  const roleRows = useMemo(() => roles?.items ?? [], [roles]);

  async function loadAccessAdmin() {
    setAccessLoading(true);
    setAccessError(null);
    try {
      const [roleCatalog, oidcStatus, memberPage, tokenPage, editionInfo, supportStatus, managedStatus, scaleStatus, haIssuanceStatus] = await Promise.all([
        api.accessRoles(),
        api.oidcMappingStatus(),
        api.members({ includeOffboarded: true, limit: 50 }),
        api.apiTokens({ includeRevoked: true, limit: 50 }),
        api.editions(),
        api.enterpriseSupportStatus(),
        api.managedOfferingStatus(),
        api.scaleOrchestration(),
        api.activeActiveIssuance(),
      ]);
      setRoles(roleCatalog);
      setOIDC(oidcStatus);
      setEditions(editionInfo);
      setEnterpriseSupport(supportStatus);
      setManagedOffering(managedStatus);
      setScaleOrchestration(scaleStatus);
      setActiveActiveIssuance(haIssuanceStatus);
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

  async function provisionHostedTenant(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setAccessBusy(true);
    setAccessError(null);
    setAccessNotice(null);
    setRevealedToken(null);
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
      setAccessNotice(`Provisioned managed tenant ${created.name}`);
      setHostedTenantID("");
      setHostedTenantName("");
      await loadAccessAdmin();
    } catch (err) {
      setAccessError(err instanceof Error ? err.message : String(err));
    } finally {
      setAccessBusy(false);
    }
  }

  return (
    <section aria-labelledby="platform-heading" className="grid gap-6">
      <PageHeader
        titleId="platform-heading"
        title="Platform"
        description="Tenant context, access-control evidence, browser transport posture, and auth status."
        actions={
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
        }
      />

      <div className="grid gap-4 lg:grid-cols-3">
        <section className="ui-panel p-comfortable" aria-labelledby="tenant-heading">
          <h2 id="tenant-heading" className="text-title font-semibold">
            Tenant boundary
          </h2>
          <dl className="mt-3 grid gap-2 text-sm">
            <div>
              <dt className="font-medium text-muted-foreground">Subject</dt>
              <dd>{user?.email || user?.subject || "-"}</dd>
            </div>
            <div>
              <dt className="font-medium text-muted-foreground">Tenant ID from session</dt>
              <dd className="break-all font-mono text-xs">{user?.tenant_id || "-"}</dd>
            </div>
          </dl>
          <p className="mt-3 text-sm text-muted-foreground">
            The browser never chooses a tenant id through a route, query string, or form field. The backend session or API token supplies it, and PostgreSQL RLS
            enforces it below the API.
          </p>
        </section>

        <section className="ui-panel p-comfortable" aria-labelledby="transport-heading">
          <h2 id="transport-heading" className="text-title font-semibold">
            Transport
          </h2>
          <p className="mt-3 text-sm font-medium">{transport.label}</p>
          <p className="mt-1 text-sm text-muted-foreground">{transport.detail}</p>
          {transport.warning && <p className="mt-2 text-sm font-medium text-status-warning">{transport.warning}</p>}
        </section>

        <section className="ui-panel p-comfortable" aria-labelledby="auth-heading">
          <h2 id="auth-heading" className="text-title font-semibold">
            Auth session
          </h2>
          <dl className="mt-3 grid gap-2 text-sm">
            <div>
              <dt className="font-medium text-muted-foreground">Mode visible to UI</dt>
              <dd>{preview ? "local preview session" : "authenticated session"}</dd>
            </div>
            <div>
              <dt className="font-medium text-muted-foreground">CSRF cookie</dt>
              <dd>{csrfPresent ? "present for browser mutations" : "not visible in this browser context"}</dd>
            </div>
          </dl>
          <p className="mt-3 text-sm text-muted-foreground">
            OIDC mapping status and API-token administration are shown in Access administration below. This card only reflects the browser session and CSRF
            posture.
          </p>
        </section>
      </div>

      <section className="ui-panel p-comfortable" aria-labelledby="editions-heading">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h2 id="editions-heading" className="text-title font-semibold">
              Editions
            </h2>
            <p className="mt-1 text-sm text-muted-foreground">Offline license state, feature rows, and the live crypto posture.</p>
          </div>
          <span className={editionStateClass(editions?.state)}>{editionStateLabel(editions?.state)}</span>
        </div>
        <div className="mt-4 grid gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(18rem,0.6fr)]">
          <div className="overflow-x-auto rounded-panel border border-border">
            <table className="ui-table min-w-[32rem]">
              <caption className="sr-only">Edition feature table</caption>
              <thead>
                <tr>
                  <th scope="col">Feature</th>
                  <th scope="col">Tier</th>
                  <th scope="col">State</th>
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
                      No commercial feature rows.
                    </td>
                  </tr>
                ) : null}
              </tbody>
            </table>
          </div>
          <dl className="grid gap-2 text-sm">
            <div>
              <dt className="font-medium text-muted-foreground">Tier</dt>
              <dd className="text-base font-semibold">{(editions?.tier ?? "community").toUpperCase()}</dd>
            </div>
            <div>
              <dt className="font-medium text-muted-foreground">Customer</dt>
              <dd>{editions?.customer ?? "community core"}</dd>
            </div>
            <div>
              <dt className="font-medium text-muted-foreground">Expiry</dt>
              <dd>{formatDate(editions?.expires_at)}</dd>
            </div>
            <div>
              <dt className="font-medium text-muted-foreground">FIPS posture</dt>
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

      <section className="ui-panel grid gap-3 p-comfortable" aria-labelledby="platform-region-heading">
        <h2 id="platform-region-heading" className="text-title font-semibold">
          Multi-region posture
        </h2>
        <p className="text-sm text-muted-foreground">
          Passive-read-state model: projections can be read from follower regions while the write path stays on one writable region per tenant.
        </p>
        <p className="text-sm text-muted-foreground">
          Background jobs perform access-token revocation and audit projection work while write promotion remains an operator-controlled runbook.
        </p>
        {/* TRACE-014 source anchor: served worker */}
      </section>

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
                  rpo: formatNumber(activeActiveIssuance?.rpo_seconds),
                  rto: formatNumber(activeActiveIssuance?.rto_seconds),
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
                {t("platform.scale.credentialsCount", { count: formatNumber(scaleOrchestration?.selected_capacity_tier?.managed_credentials) })}
              </dd>
            </div>
            <div>
              <dt className="font-medium text-muted-foreground">{t("platform.scale.eventsPerDay")}</dt>
              <dd>{formatNumber(scaleOrchestration?.estimated_daily_event_load)}</dd>
            </div>
            <div>
              <dt className="font-medium text-muted-foreground">{t("platform.scale.monthlyCost")}</dt>
              <dd>{formatCurrency(scaleOrchestration?.estimated_monthly_cost_usd)}</dd>
            </div>
            <div>
              <dt className="font-medium text-muted-foreground">{t("platform.scale.unitCost")}</dt>
              <dd>{formatUnitCost(scaleOrchestration?.unit_economics?.estimated_cost_per_credential_usd, t("platform.scale.credentialUnit"))}</dd>
            </div>
            <div>
              <dt className="font-medium text-muted-foreground">{t("platform.scale.signerModel")}</dt>
              <dd>{scaleOrchestration?.signer?.process_model ?? "-"}</dd>
            </div>
            <div>
              <dt className="font-medium text-muted-foreground">{t("platform.scale.projectionFloor")}</dt>
              <dd>
                {t("platform.scale.projectionFloorValue", {
                  rate: formatNumber(scaleOrchestration?.projection_replay?.replay_floor_events_per_second),
                  lag: formatNumber(scaleOrchestration?.projection_replay?.max_lag_events),
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
              Enterprise support
            </h2>
          </div>
          <span className={supportModeClass(enterpriseSupport?.support_mode)}>{supportModeLabel(enterpriseSupport?.support_mode)}</span>
        </div>
        <div className="mt-4 grid gap-4 xl:grid-cols-[minmax(16rem,0.45fr)_minmax(0,1fr)]">
          <dl className="grid content-start gap-2 text-sm">
            <div>
              <dt className="font-medium text-muted-foreground">Capability</dt>
              <dd>{enterpriseSupport?.capability ?? "CAP-MODEL-04"}</dd>
            </div>
            <div>
              <dt className="font-medium text-muted-foreground">License feature</dt>
              <dd className="font-mono text-xs">{enterpriseSupport?.license_feature ?? "ha_support"}</dd>
            </div>
            <div>
              <dt className="font-medium text-muted-foreground">License tier</dt>
              <dd>{enterpriseSupport?.tier ?? editions?.tier ?? "community"}</dd>
            </div>
            <div>
              <dt className="font-medium text-muted-foreground">Contract boundary</dt>
              <dd>{enterpriseSupport?.contract_boundary ?? "Commercial support terms control legal SLA credits and named contacts."}</dd>
            </div>
          </dl>
          <div className="grid gap-4">
            <div className="overflow-x-auto rounded-panel border border-border">
              <table className="ui-table min-w-[44rem]">
                <caption className="sr-only">Enterprise support tier table</caption>
                <thead>
                  <tr>
                    <th scope="col">Tier</th>
                    <th scope="col">Coverage</th>
                    <th scope="col">Initial SLA</th>
                    <th scope="col">Updates</th>
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
                <caption className="sr-only">Enterprise SLA target table</caption>
                <thead>
                  <tr>
                    <th scope="col">Severity</th>
                    <th scope="col">Applies to</th>
                    <th scope="col">Response</th>
                    <th scope="col">Escalation</th>
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
                <caption className="sr-only">Professional services package table</caption>
                <thead>
                  <tr>
                    <th scope="col">Service</th>
                    <th scope="col">Model</th>
                    <th scope="col">Deliverables</th>
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
              Managed offering
            </h2>
          </div>
          <span className={providerPlaneClass(managedOffering?.provider_plane_mode)}>{providerPlaneLabel(managedOffering?.provider_plane_mode)}</span>
        </div>
        <div className="mt-4 grid gap-4 xl:grid-cols-[minmax(0,0.75fr)_minmax(22rem,1fr)]">
          <dl className="grid content-start gap-2 text-sm">
            <div>
              <dt className="font-medium text-muted-foreground">Deployment model</dt>
              <dd>{managedOffering?.deployment_model ?? "-"}</dd>
            </div>
            <div>
              <dt className="font-medium text-muted-foreground">Provider plane</dt>
              <dd>{managedOffering?.provider_plane_mode ?? "off"}</dd>
            </div>
            <div>
              <dt className="font-medium text-muted-foreground">License tier</dt>
              <dd>{managedOffering?.tier ?? editions?.tier ?? "community"}</dd>
            </div>
            <div>
              <dt className="font-medium text-muted-foreground">Event source</dt>
              <dd>{managedOffering?.event_type ?? "tenant.registered"}</dd>
            </div>
            <div>
              <dt className="font-medium text-muted-foreground">Mutation idempotency</dt>
              <dd>{managedOffering?.idempotency_required ? "required" : "-"}</dd>
            </div>
            {lastManagedTenant && (
              <div>
                <dt className="font-medium text-muted-foreground">Last hosted tenant</dt>
                <dd className="break-all">
                  {lastManagedTenant.name} · {lastManagedTenant.tenant_id}
                </dd>
              </div>
            )}
          </dl>
          <form onSubmit={(event) => void provisionHostedTenant(event)} className="grid gap-3">
            <div className="grid gap-3 md:grid-cols-2">
              <label className="grid gap-1 text-sm">
                <span className="font-medium text-muted-foreground">Hosted ID</span>
                <input className="ui-input" value={hostedTenantID} onChange={(event) => setHostedTenantID(event.target.value)} required />
              </label>
              <label className="grid gap-1 text-sm">
                <span className="font-medium text-muted-foreground">Hosted name</span>
                <input className="ui-input" value={hostedTenantName} onChange={(event) => setHostedTenantName(event.target.value)} required />
              </label>
              <label className="grid gap-1 text-sm">
                <span className="font-medium text-muted-foreground">Region</span>
                <input className="ui-input" value={hostedRegion} onChange={(event) => setHostedRegion(event.target.value)} />
              </label>
              <label className="grid gap-1 text-sm">
                <span className="font-medium text-muted-foreground">Data residency</span>
                <input className="ui-input" value={hostedResidency} onChange={(event) => setHostedResidency(event.target.value)} />
              </label>
              <label className="grid gap-1 text-sm">
                <span className="font-medium text-muted-foreground">Plan</span>
                <input className="ui-input" value={hostedPlan} onChange={(event) => setHostedPlan(event.target.value)} />
              </label>
              <label className="grid gap-1 text-sm">
                <span className="font-medium text-muted-foreground">Support tier</span>
                <input className="ui-input" value={hostedSupportTier} onChange={(event) => setHostedSupportTier(event.target.value)} />
              </label>
            </div>
            <label className="grid gap-1 text-sm">
              <span className="font-medium text-muted-foreground">SLO tier</span>
              <input className="ui-input" value={hostedSLOTier} onChange={(event) => setHostedSLOTier(event.target.value)} />
            </label>
            <Button
              type="submit"
              disabled={accessBusy || !hostedTenantID.trim() || !hostedTenantName.trim() || managedOffering?.provider_plane_mode !== "enabled"}
            >
              <Plus className="h-4 w-4" aria-hidden="true" />
              Provision tenant
            </Button>
          </form>
        </div>
      </section>

      <section aria-labelledby="access-heading">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
          <h2 id="access-heading" className="text-title font-semibold">
            Access administration
          </h2>
          <Button type="button" size="sm" variant="outline" onClick={() => void loadAccessAdmin()} disabled={accessLoading}>
            {accessLoading ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <RefreshCw className="h-4 w-4" aria-hidden="true" />}
            Refresh
          </Button>
        </div>
        {accessError && (
          <p role="alert" className="mb-3 rounded-control border border-status-danger/30 bg-status-danger/10 px-3 py-2 text-sm text-status-danger">
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
              <p className="font-medium">Reveal-once API token</p>
              <Button type="button" size="sm" variant="ghost" onClick={() => setRevealedToken(null)}>
                Dismiss
              </Button>
            </div>
            <code className="mt-2 block break-all rounded bg-background px-2 py-1 text-xs">{revealedToken}</code>
          </div>
        )}
        <div className="mb-4 grid gap-3 xl:grid-cols-3">
          <form onSubmit={(event) => void onboardMember(event)} className="ui-panel grid gap-3 p-comfortable">
            <div className="flex items-center gap-2">
              <ShieldCheck className="h-4 w-4 text-status-success" aria-hidden="true" />
              <h3 className="text-body font-semibold">Onboard member</h3>
            </div>
            <label className="grid gap-1 text-sm">
              <span className="font-medium text-muted-foreground">Subject</span>
              <input className="ui-input" value={memberSubject} onChange={(event) => setMemberSubject(event.target.value)} required />
            </label>
            <label className="grid gap-1 text-sm">
              <span className="font-medium text-muted-foreground">Display name</span>
              <input className="ui-input" value={memberDisplayName} onChange={(event) => setMemberDisplayName(event.target.value)} />
            </label>
            <label className="grid gap-1 text-sm">
              <span className="font-medium text-muted-foreground">Email</span>
              <input className="ui-input" value={memberEmail} onChange={(event) => setMemberEmail(event.target.value)} />
            </label>
            <label className="grid gap-1 text-sm">
              <span className="font-medium text-muted-foreground">Roles</span>
              <input className="ui-input" value={memberRoles} onChange={(event) => setMemberRoles(event.target.value)} required />
            </label>
            <Button type="submit" disabled={accessBusy || !memberSubject.trim()}>
              <Plus className="h-4 w-4" aria-hidden="true" />
              Save
            </Button>
          </form>
          <form onSubmit={(event) => void mintToken(event)} className="ui-panel grid gap-3 p-comfortable">
            <div className="flex items-center gap-2">
              <KeyRound className="h-4 w-4 text-status-warning" aria-hidden="true" />
              <h3 className="text-body font-semibold">Mint API token</h3>
            </div>
            <label className="grid gap-1 text-sm">
              <span className="font-medium text-muted-foreground">Subject</span>
              <input className="ui-input" value={tokenSubject} onChange={(event) => setTokenSubject(event.target.value)} required />
            </label>
            <label className="grid gap-1 text-sm">
              <span className="font-medium text-muted-foreground">Scopes</span>
              <input className="ui-input" value={tokenScopes} onChange={(event) => setTokenScopes(event.target.value)} required />
            </label>
            <Button type="submit" disabled={accessBusy || !tokenSubject.trim()}>
              <KeyRound className="h-4 w-4" aria-hidden="true" />
              Mint
            </Button>
          </form>
          <form onSubmit={(event) => void offboardMember(event)} className="ui-panel grid gap-3 p-comfortable">
            <div className="flex items-center gap-2">
              <UserMinus className="h-4 w-4 text-status-danger" aria-hidden="true" />
              <h3 className="text-body font-semibold">Offboard member</h3>
            </div>
            <label className="grid gap-1 text-sm">
              <span className="font-medium text-muted-foreground">Subject</span>
              <input className="ui-input" value={offboardSubject} onChange={(event) => setOffboardSubject(event.target.value)} required />
            </label>
            <label className="grid gap-1 text-sm">
              <span className="font-medium text-muted-foreground">Reason</span>
              <input className="ui-input" value={offboardReason} onChange={(event) => setOffboardReason(event.target.value)} />
            </label>
            <Button type="submit" variant="outline" className="text-status-danger" disabled={accessBusy || !offboardSubject.trim()}>
              <UserMinus className="h-4 w-4" aria-hidden="true" />
              Offboard
            </Button>
          </form>
        </div>
        <div className="mb-4 grid gap-4 xl:grid-cols-2">
          <div className="overflow-x-auto rounded-panel border border-border">
            <table className="ui-table min-w-[34rem]">
              <caption className="sr-only">Role catalog</caption>
              <thead>
                <tr>
                  <th scope="col">Role</th>
                  <th scope="col">Permissions</th>
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
            <h3 className="font-semibold">OIDC mapping status</h3>
            <dl className="mt-3 grid gap-2">
              <div>
                <dt className="font-medium text-muted-foreground">Enabled</dt>
                <dd>{oidc?.enabled ? "yes" : "no"}</dd>
              </div>
              <div>
                <dt className="font-medium text-muted-foreground">Claims</dt>
                <dd>{[oidc?.tenant_claim || "no tenant claim", oidc?.groups_claim || "no groups claim"].join(" · ")}</dd>
              </div>
              <div>
                <dt className="font-medium text-muted-foreground">Mappings</dt>
                <dd>{oidc?.tenant_mappings?.length ? oidc.tenant_mappings.map((m) => m.group || m.subject || m.claim).join(", ") : "none"}</dd>
              </div>
            </dl>
          </div>
        </div>
        <div className="mb-4 grid gap-4 xl:grid-cols-2">
          <div className="overflow-x-auto rounded-panel border border-border">
            <table className="ui-table min-w-[44rem]">
              <caption className="sr-only">Tenant members</caption>
              <thead>
                <tr>
                  <th scope="col">Subject</th>
                  <th scope="col">Roles</th>
                  <th scope="col">Status</th>
                  <th scope="col">Updated</th>
                </tr>
              </thead>
              <tbody>
                {members.map((member) => (
                  <tr key={member.subject} className="align-top">
                    <td className="font-medium">{member.subject}</td>
                    <td className="font-mono text-xs">{member.roles.join(", ")}</td>
                    <td>{member.status}</td>
                    <td>{formatDate(member.updated_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="overflow-x-auto rounded-panel border border-border">
            <table className="ui-table min-w-[48rem]">
              <caption className="sr-only">API token metadata</caption>
              <thead>
                <tr>
                  <th scope="col">Subject</th>
                  <th scope="col">Scopes</th>
                  <th scope="col">Status</th>
                  <th scope="col">Created</th>
                </tr>
              </thead>
              <tbody>
                {tokens.map((token) => (
                  <tr key={token.id} className="align-top">
                    <td className="font-medium">{token.subject}</td>
                    <td className="font-mono text-xs">{token.scopes.join(", ")}</td>
                    <td>{token.revoked_at ? "revoked" : "active"}</td>
                    <td>{formatDate(token.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </section>
    </section>
  );
}

function csvList(value: string): string[] {
  return value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function formatDate(value?: string): string {
  if (!value) return "-";
  const parsed = Date.parse(value);
  if (Number.isNaN(parsed)) return value;
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(parsed);
}

function formatNumber(value?: number): string {
  if (value == null || Number.isNaN(value)) return "-";
  return new Intl.NumberFormat().format(value);
}

function formatCurrency(value?: number): string {
  if (value == null || Number.isNaN(value)) return "-";
  return new Intl.NumberFormat(undefined, { style: "currency", currency: "USD", maximumFractionDigits: 0 }).format(value);
}

function formatUnitCost(value: number | undefined, unitLabel: string): string {
  if (value == null || Number.isNaN(value)) return "-";
  const formatted = new Intl.NumberFormat(undefined, {
    style: "currency",
    currency: "USD",
    minimumFractionDigits: 4,
    maximumFractionDigits: 4,
  }).format(value);
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
      return `${base} border-status-danger/30 bg-status-danger/10 text-status-danger`;
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
