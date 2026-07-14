import { useEffect, useMemo, useState, type FormEvent, type ReactNode } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { Building2, Gauge, Headphones, KeyRound, Loader2, Network, Plus, RefreshCw, ShieldCheck, UserMinus } from "lucide-react";
import { useAuth } from "@/auth/AuthProvider";
import { DataGrid, type DataGridColumn } from "@/components/DataGrid";
import { Dialog } from "@/components/Dialog";
import { PageHeader } from "@/components/PageHeader";
import { PageTabs, tabPanelProps } from "@/components/PageTabs";
import { StatusBadge } from "@/components/StatusBadge";
import { Button } from "@/components/ui/button";
import { useTranslation } from "@/i18n/I18nProvider";
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

const defaultPackaging: NonNullable<EditionsInfo["packaging"]> = {
  category_label: "Machine Identity Security Control Plane",
  positioning: "One control plane for machine credentials, secrets, SSH certificates, X.509, API tokens, and SPIFFE workload identities.",
  billable_unit: "control_plane_deployment",
  provider_billing_unit: "managed_customer_band",
  no_per_certificate_billing: true,
  no_ephemeral_identity_billing: true,
  certificate_counters_classification: "operational_telemetry",
  managed_boundary: "Provider/MSP normally runs one shared control plane with multiple customer tenants, with dedicated customer deployments available when its security posture requires them.",
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

/** Access administration is the page's one operational surface, so it renders
 * as the default tab; the read-only posture panels live behind "System
 * posture" (audit P0: Access was buried under six disclosure panels). */
type PlatformTab = "access" | "posture";

function platformTabFromSearchParam(value: string | null): PlatformTab {
  return value === "posture" ? "posture" : "access";
}

export function Platform() {
  const { user, preview } = useAuth();
  const { locale, timeZone, t } = useTranslation();
  const [searchParams, setSearchParams] = useSearchParams();
  const [tab, setTab] = useState<PlatformTab>(() => platformTabFromSearchParam(searchParams.get("tab")));

  function selectTab(next: string) {
    const value = platformTabFromSearchParam(next);
    setTab(value);
    setSearchParams(
      (current) => {
        const nextParams = new URLSearchParams(current);
        if (value === "access") {
          nextParams.delete("tab");
        } else {
          nextParams.set("tab", value);
        }
        return nextParams;
      },
      { replace: true },
    );
  }

  const formatPolicy = useMemo<FormatPolicy>(() => ({ locale, timeZone }), [locale, timeZone]);
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
  const [distribution, setDistribution] = useState<PlatformDistributionStatus | null>(null);
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
  const packaging = editions?.packaging ?? defaultPackaging;
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
        description="Self-hosted NHI management / Machine IAM packaging, tenant boundary, access evidence, browser transport, and auth status."
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

      <PageTabs
        idPrefix="platform"
        ariaLabel="Platform workspaces"
        active={tab}
        onChange={selectTab}
        className="mb-0"
        tabs={[
          { id: "access", label: t("platform.tabs.access") },
          { id: "posture", label: t("platform.tabs.posture") },
        ]}
      />

      {tab === "posture" && (
        <div {...tabPanelProps("platform", "posture")} className="grid gap-6">
          <div className="grid gap-4 lg:grid-cols-4">
            <section className="ui-panel p-comfortable" aria-labelledby="packaging-heading">
              <h2 id="packaging-heading" className="text-title font-semibold">
                Packaging
              </h2>
              <dl className="mt-3 grid gap-2 text-sm">
                <div>
                  <dt className="font-medium text-muted-foreground">Category</dt>
                  <dd>{packaging.category_label}</dd>
                </div>
                <div>
                  <dt className="font-medium text-muted-foreground">Billable unit</dt>
                  <dd className="font-mono text-xs">{packaging.billable_unit}</dd>
                </div>
                <div>
                  <dt className="font-medium text-muted-foreground">Provider unit</dt>
                  <dd className="font-mono text-xs">{packaging.provider_billing_unit}</dd>
                </div>
              </dl>
              <p className="mt-3 text-sm text-muted-foreground">
                No per-certificate or ephemeral-identity billing. Certificate counters are {packaging.certificate_counters_classification}.
              </p>
            </section>

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
                The browser never chooses a tenant id through a route, query string, or form field. The backend session or API token supplies it, and PostgreSQL
                RLS enforces it below the API.
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
              <div className="grid gap-4">
                <div className="overflow-x-auto rounded-panel border border-border">
                  <table className="ui-table min-w-[42rem]">
                    <caption className="sr-only">Packaging edition matrix</caption>
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

          <div className="grid gap-4 xl:grid-cols-2">
            <section className="ui-panel grid content-start gap-3 p-comfortable" aria-labelledby="platform-region-heading">
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
                      {distribution.run_modes.map((mode) => (
                        <span key={mode.id}>
                          <span className="font-medium">{mode.label}</span>
                          <span className="text-muted-foreground"> — {mode.intended_use}</span>
                        </span>
                      ))}
                      {distribution.run_modes.length === 0 && <span className="text-muted-foreground">-</span>}
                    </dd>
                  </div>
                  <div>
                    <dt className="font-medium text-muted-foreground">{t("parity.supportedHostArchives_38c6c0")}</dt>
                    <dd className="grid gap-1">
                      {distribution.supported_host_archives.map((archive) => (
                        <span key={`${archive.os_arch}-${archive.postgres_version}`} className="font-mono text-xs">
                          {archive.os_arch} · PostgreSQL {archive.postgres_version}
                          {archive.evaluation_only ? " · evaluation only" : ""}
                        </span>
                      ))}
                      {distribution.supported_host_archives.length === 0 && <span className="text-muted-foreground">-</span>}
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
        </div>
      )}

      {tab === "access" && (
        <div {...tabPanelProps("platform", "access")} className="grid gap-6">
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
                  <UserMinus className="h-4 w-4 text-destructive" aria-hidden="true" />
                  <h3 className="text-body font-semibold">Offboard member</h3>
                </div>
                <label className="grid gap-1 text-sm">
                  <span className="font-medium text-muted-foreground">Subject</span>
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
                  <span className="font-medium text-muted-foreground">Reason</span>
                  <input className="ui-input" value={offboardReason} onChange={(event) => setOffboardReason(event.target.value)} />
                </label>
                <Button type="submit" variant="destructive" loading={accessBusy} disabled={!offboardSubject.trim()}>
                  <UserMinus className="h-4 w-4" aria-hidden="true" />
                  Offboard
                </Button>
              </form>
            </div>
            {pamRows && (
              <div className="ui-panel mb-4 grid gap-3 p-comfortable">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <h3 className="text-body font-semibold">{t("parity.privilegedAccessSessions_368da5")}</h3>
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
                        <td>{formatOptionalDate(member.updated_at, formatPolicy)}</td>
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
                        <td>{formatOptionalDate(token.created_at, formatPolicy)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </section>

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
                  Close
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
                      Close
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
                      Role
                      <input
                        className="min-h-9 rounded-control border border-border bg-background px-3 py-2 text-body"
                        value={pamForm.role}
                        onChange={(event) => setPAMForm({ ...pamForm, role: event.target.value })}
                        required
                      />
                    </label>
                    <label className="grid gap-1 text-body font-medium">
                      Method
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
                      Reason
                      <input
                        className="min-h-9 rounded-control border border-border bg-background px-3 py-2 text-body"
                        value={pamForm.reason}
                        onChange={(event) => setPAMForm({ ...pamForm, reason: event.target.value })}
                      />
                    </label>
                    <label className="grid gap-1 text-body font-medium">
                      TTL seconds
                      <input
                        className="min-h-9 rounded-control border border-border bg-background px-3 py-2 text-body"
                        type="number"
                        min={1}
                        value={pamForm.ttl_seconds}
                        onChange={(event) => setPAMForm({ ...pamForm, ttl_seconds: event.target.value })}
                        placeholder="optional"
                      />
                    </label>
                  </div>
                  {pamForm.target_type === "ssh" && (
                    <label className="grid gap-1 text-body font-medium">
                      SSH public key
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
                      Cancel
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
      )}
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

function airGapSummary(airGap: PlatformDistributionStatus["air_gap"]): string {
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
