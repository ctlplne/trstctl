import { useEffect, useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { PageHeader } from "@/components/PageHeader";
import { ErrorState, LoadingState } from "@/components/StatePrimitives";
import { Button } from "@/components/ui/button";
import { useTranslation } from "@/i18n/I18nProvider";
import type { MessageKey } from "@/i18n/messages";
import {
  api,
  ApiError,
  type ComplianceEvidencePack,
  type ComplianceInventoryReport,
  type ComplianceReportSchedule,
  type ComplianceReportScheduleRequest,
  type NHIComplianceReport,
  type NHIReviewCampaign,
  type NHIReviewDecisionRequest,
  type NHIReviewItem,
  type PolicyDryRun,
  type PolicyDryRunRequest,
} from "@/lib/api";

type ComplianceFramework = ComplianceEvidencePack["framework"];
type ComplianceReportType = ComplianceReportScheduleRequest["report_type"];
type PolicyDryRunKind = "lifecycle" | "abac";

const complianceFrameworks: Array<{ id: ComplianceFramework; label?: string; labelKey?: MessageKey }> = [
  { id: "pci-dss", label: "PCI DSS" },
  { id: "hipaa", label: "HIPAA" },
  { id: "soc2", label: "SOC 2" },
  { id: "fedramp", label: "FedRAMP" },
  { id: "cnsa-2.0", label: "CNSA 2.0" },
  { id: "fips-140", labelKey: "policy.framework.fips140" },
  { id: "common-criteria", labelKey: "policy.framework.commonCriteria" },
  { id: "cabf-br", labelKey: "policy.framework.cabfBR" },
  { id: "webtrust", label: "WebTrust" },
  { id: "etsi", label: "ETSI" },
];

const complianceReportTypes: Array<{ id: ComplianceReportType; labelKey: MessageKey }> = [
  { id: "inventory_snapshot", labelKey: "policy.reportType.inventorySnapshot" },
  { id: "framework_evidence_pack", labelKey: "policy.reportType.frameworkEvidencePack" },
  { id: "cbom_posture", labelKey: "policy.reportType.cbomPosture" },
  { id: "audit_summary", labelKey: "policy.reportType.auditSummary" },
  { id: "nhi_compliance_mapping", labelKey: "policy.reportType.nhiComplianceMapping" },
];

interface ComplianceControl {
  id?: string;
  title?: string;
  status?: string;
  evidence?: string[];
}

interface ComplianceManifest {
  controls?: ComplianceControl[];
  posture?: {
    total_crypto_assets?: number;
    quantum_vulnerable?: number;
    post_quantum?: number;
  };
  product_evidences?: string[];
  operator_attests?: string[];
}

const lifecycleDryRunModule = `package trstctl.policy

default allow := false
default reason := ""

allow if {
  input.action == "issue"
  input.profile == "server-tls"
}

allow if {
  input.action == "revoke"
}

reason := "issuance requires the server-tls profile" if {
  input.action == "issue"
  input.profile != "server-tls"
}
`;

const lifecycleDryRunInput = JSON.stringify(
  {
    action: "issue",
    profile: "server-tls",
    subject: "svc-payments-api",
  },
  null,
  2,
);

const abacDryRunModule = `package trstctl.abac

default deny := false
default reason := ""

deny if {
  input.permission == "certs:issue"
  input.actor_attrs.emergency != "true"
}

reason := "cert issuance requires emergency attribute" if {
  input.permission == "certs:issue"
  input.actor_attrs.emergency != "true"
}
`;

const abacDryRunInput = JSON.stringify(
  {
    permission: "certs:issue",
    action: "issue",
    subject: "svc-payments-api",
    actor_attrs: { emergency: "false" },
  },
  null,
  2,
);

export function Policy() {
  const { formatDate, t } = useTranslation();
  const [selectedFramework, setSelectedFramework] = useState<ComplianceFramework>("soc2");
  const [evidencePack, setEvidencePack] = useState<ComplianceEvidencePack | null>(null);
  const [evidencePackError, setEvidencePackError] = useState<string | null>(null);
  const [evidencePackLoading, setEvidencePackLoading] = useState(true);
  const [inventoryReport, setInventoryReport] = useState<ComplianceInventoryReport | null>(null);
  const [nhiComplianceReport, setNHIComplianceReport] = useState<NHIComplianceReport | null>(null);
  const [reportSchedules, setReportSchedules] = useState<ComplianceReportSchedule[]>([]);
  const [reportLoading, setReportLoading] = useState(true);
  const [reportError, setReportError] = useState<string | null>(null);
  const [reportNotice, setReportNotice] = useState<string | null>(null);
  const [scheduleAction, setScheduleAction] = useState(false);
  const [evidenceBundle, setEvidenceBundle] = useState<string | null>(null);
  const [evidenceError, setEvidenceError] = useState<string | null>(null);
  const [exporting, setExporting] = useState(false);
  const [reviewCampaigns, setReviewCampaigns] = useState<NHIReviewCampaign[]>([]);
  const [activeReview, setActiveReview] = useState<NHIReviewCampaign | null>(null);
  const [reviewError, setReviewError] = useState<string | null>(null);
  const [reviewNotice, setReviewNotice] = useState<string | null>(null);
  const [reviewLoading, setReviewLoading] = useState(true);
  const [reviewAction, setReviewAction] = useState<string | null>(null);
  const [decisionReasons, setDecisionReasons] = useState<Record<string, string>>({});
  const [reviewForm, setReviewForm] = useState({
    name: "Quarterly NHI access certification",
    reviewer: "",
    nhiId: "svc-payments-api",
    displayName: "Payments API workload",
    resource: "k8s://prod/payments",
    entitlement: "secret:payments/db/read",
    evidenceRefs: "audit:nhi-discovery/latest",
    risk: "medium",
  });
  const [scheduleForm, setScheduleForm] = useState({
    name: "Quarterly SOC 2 inventory",
    framework: "soc2" as ComplianceFramework,
    reportType: "inventory_snapshot" as ComplianceReportType,
    intervalDays: "90",
    recipientRef: "audit-vault",
  });
  const [dryRunKind, setDryRunKind] = useState<PolicyDryRunKind>("lifecycle");
  const [dryRunModule, setDryRunModule] = useState(lifecycleDryRunModule);
  const [dryRunInput, setDryRunInput] = useState(lifecycleDryRunInput);
  const [dryRunResult, setDryRunResult] = useState<PolicyDryRun | null>(null);
  const [dryRunError, setDryRunError] = useState<string | null>(null);
  const [dryRunBusy, setDryRunBusy] = useState(false);

  useEffect(() => {
    let active = true;
    setEvidencePackLoading(true);
    setEvidencePackError(null);
    setEvidencePack(null);
    api
      .complianceEvidencePack(selectedFramework)
      .then((pack) => {
        if (active) setEvidencePack(pack);
      })
      .catch((err: unknown) => {
        if (active) setEvidencePackError(describePolicyError(err, "evidence pack unavailable"));
      })
      .finally(() => {
        if (active) setEvidencePackLoading(false);
      });
    return () => {
      active = false;
    };
  }, [selectedFramework]);

  useEffect(() => {
    let active = true;
    setReportLoading(true);
    setReportError(null);
    Promise.all([api.complianceInventoryReport(), api.nhiComplianceReport(), api.complianceReportSchedules({ limit: 5 })])
      .then(([report, nhiReport, schedules]) => {
        if (!active) return;
        setInventoryReport(report);
        setNHIComplianceReport(nhiReport);
        setReportSchedules(schedules.items ?? []);
      })
      .catch((err: unknown) => {
        if (active) setReportError(describePolicyError(err, "compliance reporting unavailable"));
      })
      .finally(() => {
        if (active) setReportLoading(false);
      });
    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    let active = true;
    setReviewLoading(true);
    setReviewError(null);
    api
      .nhiReviewCampaigns({ limit: 5 })
      .then(async (page) => {
        if (!active) return;
        const campaigns = page.items ?? [];
        setReviewCampaigns(campaigns);
        if (campaigns.length === 0) {
          setActiveReview(null);
          return;
        }
        const detailed = await api.getNHIReviewCampaign(campaigns[0].id);
        if (active) setActiveReview(detailed);
      })
      .catch((err: unknown) => {
        if (active) setReviewError(describePolicyError(err, "NHI access reviews unavailable"));
      })
      .finally(() => {
        if (active) setReviewLoading(false);
      });
    return () => {
      active = false;
    };
  }, []);

  async function exportComplianceEvidence() {
    setExporting(true);
    setEvidenceError(null);
    setEvidenceBundle(null);
    try {
      const bundle = await api.exportAudit({ limit: 500 });
      setEvidenceBundle(`${bundle.format}: ${bundle.bundle}`);
    } catch (err) {
      setEvidenceError(`Could not export audit evidence: ${describePolicyError(err, "export failed")}`);
    } finally {
      setExporting(false);
    }
  }

  async function refreshComplianceReporting() {
    setReportLoading(true);
    setReportError(null);
    try {
      const [report, nhiReport, schedules] = await Promise.all([api.complianceInventoryReport(), api.nhiComplianceReport(), api.complianceReportSchedules({ limit: 5 })]);
      setInventoryReport(report);
      setNHIComplianceReport(nhiReport);
      setReportSchedules(schedules.items ?? []);
    } catch (err) {
      setReportError(describePolicyError(err, "compliance reporting unavailable"));
    } finally {
      setReportLoading(false);
    }
  }

  async function createReportSchedule(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setScheduleAction(true);
    setReportError(null);
    setReportNotice(null);
    const intervalDays = Number.parseInt(scheduleForm.intervalDays, 10);
    if (!Number.isFinite(intervalDays) || intervalDays < 1) {
      setReportError("interval days must be a positive integer");
      setScheduleAction(false);
      return;
    }
    try {
      const schedule = await api.createComplianceReportSchedule({
        name: scheduleForm.name.trim(),
        framework: scheduleForm.framework,
        report_type: scheduleForm.reportType,
        interval_seconds: intervalDays * 24 * 60 * 60,
        enabled: true,
        delivery: "audit_export",
        recipient_ref: optionalText(scheduleForm.recipientRef),
      });
      setReportNotice(`${schedule.name} scheduled for ${formatDate(schedule.next_run_at)}.`);
      await refreshComplianceReporting();
    } catch (err) {
      setReportError(describePolicyError(err, "report schedule create failed"));
    } finally {
      setScheduleAction(false);
    }
  }

  async function refreshNHIReviews(preferredID?: string) {
    setReviewLoading(true);
    setReviewError(null);
    try {
      const page = await api.nhiReviewCampaigns({ limit: 5 });
      const campaigns = page.items ?? [];
      setReviewCampaigns(campaigns);
      const id = preferredID ?? activeReview?.id ?? campaigns[0]?.id;
      if (id) {
        setActiveReview(await api.getNHIReviewCampaign(id));
      } else {
        setActiveReview(null);
      }
    } catch (err) {
      setReviewError(describePolicyError(err, "NHI access reviews unavailable"));
    } finally {
      setReviewLoading(false);
    }
  }

  async function startNHIReviewCampaign(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setReviewAction("start");
    setReviewError(null);
    setReviewNotice(null);
    try {
      const campaign = await api.startNHIReviewCampaign({
        name: reviewForm.name.trim(),
        reviewer_subject: optionalText(reviewForm.reviewer),
        scope: "quarterly_access",
        items: [
          {
            nhi_id: reviewForm.nhiId.trim(),
            nhi_kind: "workload",
            display_name: optionalText(reviewForm.displayName),
            resource: reviewForm.resource.trim(),
            entitlement: reviewForm.entitlement.trim(),
            risk: optionalText(reviewForm.risk),
            evidence_refs: splitRefs(reviewForm.evidenceRefs),
          },
        ],
      });
      setActiveReview(campaign);
      setDecisionReasons({});
      setReviewNotice(`${campaign.name} started with ${campaign.item_count} ${plural(campaign.item_count, "item")}.`);
      await refreshNHIReviews(campaign.id);
    } catch (err) {
      setReviewError(describePolicyError(err, "NHI access review start failed"));
    } finally {
      setReviewAction(null);
    }
  }

  async function selectNHIReviewCampaign(id: string) {
    setReviewLoading(true);
    setReviewError(null);
    try {
      setActiveReview(await api.getNHIReviewCampaign(id));
    } catch (err) {
      setReviewError(describePolicyError(err, "NHI access review unavailable"));
    } finally {
      setReviewLoading(false);
    }
  }

  async function decideNHIReviewItem(item: NHIReviewItem, decision: NHIReviewDecisionRequest["decision"]) {
    if (!activeReview) return;
    const action = `${item.item_id}:${decision}`;
    setReviewAction(action);
    setReviewError(null);
    setReviewNotice(null);
    try {
      const campaign = await api.decideNHIReviewItem(activeReview.id, item.item_id, {
        decision,
        reviewer_subject: optionalText(reviewForm.reviewer),
        reason: optionalText(decisionReasons[item.item_id]),
        decision_evidence_refs: splitRefs(reviewForm.evidenceRefs),
      });
      setActiveReview(campaign);
      setReviewNotice(`${item.display_name} marked ${decision}.`);
      await refreshNHIReviews(campaign.id);
    } catch (err) {
      setReviewError(describePolicyError(err, "NHI access review decision failed"));
    } finally {
      setReviewAction(null);
    }
  }

  function selectDryRunKind(kind: PolicyDryRunKind) {
    setDryRunKind(kind);
    setDryRunResult(null);
    setDryRunError(null);
    setDryRunModule(kind === "lifecycle" ? lifecycleDryRunModule : abacDryRunModule);
    setDryRunInput(kind === "lifecycle" ? lifecycleDryRunInput : abacDryRunInput);
  }

  async function runPolicyDryRun(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setDryRunBusy(true);
    setDryRunError(null);
    setDryRunResult(null);
    try {
      const parsed = JSON.parse(dryRunInput) as unknown;
      if (!isRecord(parsed)) {
        throw new Error(t("policy.dryRun.invalidInput"));
      }
      const request: PolicyDryRunRequest = {
        kind: dryRunKind,
        module: dryRunModule,
        input: parsed,
        trace_limit: 80,
      };
      setDryRunResult(await api.policyDryRun(request));
    } catch (err) {
      setDryRunError(describePolicyError(err, "policy dry-run failed"));
    } finally {
      setDryRunBusy(false);
    }
  }

  return (
    <section aria-labelledby="policy-heading" className="grid gap-6">
      <PageHeader
        titleId="policy-heading"
        title="Policy"
        description="Issue, deploy, and revoke mutations pass through the OPA/Rego default-deny gate, RA separation, dual-control approval, and bound-profile checks before state changes are emitted."
      />

      <section aria-labelledby="policy-gate-heading" className="grid gap-4 border-y border-border py-4">
        <div>
          <h2 id="policy-gate-heading" className="text-title font-semibold">
            Enforcement path
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            The browser does not send a tenant id or bypass policy. It asks the lifecycle workflow to mutate state; the backend evaluates policy and either
            emits the event or returns a fail-closed problem.
          </p>
        </div>
        <p className="text-sm text-muted-foreground">
          Decisions are evidence events. Use Audit to inspect allow, deny, and evaluation-error records with the actor, resource, hash, and payload from the
          event stream. Action errors still appear where the operator started the workflow on{" "}
          <Link className="underline" to="/identities">
            Identities
          </Link>{" "}
          .
        </p>
        <div className="flex flex-wrap gap-2">
          <Link className="underline" to="/audit?type=policy.decision">
            Open policy decisions in Audit
          </Link>
          <Link className="underline" to="/audit?type=issuance.profile_evaluated">
            Open profile evaluations in Audit
          </Link>
        </div>
      </section>

      <section aria-labelledby="compliance-heading" className="grid gap-4 border-y border-border py-4">
        <div>
          <h2 id="compliance-heading" className="text-title font-semibold">
            Compliance posture and reports
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            Evidence packs are signed exports built from the audit log and cryptographic inventory. They show what trstctl can prove and what your organization
            must still attest; they are evidence, not certification.
          </p>
        </div>
        <div className="flex flex-wrap gap-2" aria-label="Compliance framework">
          {complianceFrameworks.map((framework) => (
            <Button
              key={framework.id}
              type="button"
              variant={framework.id === selectedFramework ? "default" : "outline"}
              aria-pressed={framework.id === selectedFramework}
              onClick={() => setSelectedFramework(framework.id)}
            >
              {frameworkLabel(framework.id, t)}
            </Button>
          ))}
        </div>

        {evidencePackLoading && <LoadingState>Loading evidence pack.</LoadingState>}
        {evidencePackError && <ErrorState title="Evidence pack unavailable">{evidencePackError}</ErrorState>}
        {evidencePack && <ComplianceEvidencePackPanel pack={evidencePack} label={frameworkLabel(evidencePack.framework, t)} />}

        {reportLoading && <LoadingState>{t("policy.reporting.loading")}</LoadingState>}
        {reportError && <ErrorState title={t("policy.reporting.unavailableTitle")}>{reportError}</ErrorState>}
        {inventoryReport && <ComplianceInventoryReportPanel report={inventoryReport} schedules={reportSchedules} />}
        {nhiComplianceReport && <NHIComplianceReportPanel report={nhiComplianceReport} />}

        <form className="grid gap-3 rounded-md border border-border p-4 text-sm lg:grid-cols-6" onSubmit={(event) => void createReportSchedule(event)}>
          <label className="grid gap-1 lg:col-span-2">
            <span className="font-medium">{t("policy.reporting.schedule")}</span>
            <input
              className="min-h-10 rounded-md border border-input bg-background px-3 py-2"
              value={scheduleForm.name}
              onChange={(event) => setScheduleForm((current) => ({ ...current, name: event.target.value }))}
            />
          </label>
          <label className="grid gap-1">
            <span className="font-medium">{t("policy.reporting.framework")}</span>
            <select
              className="min-h-10 rounded-md border border-input bg-background px-3 py-2"
              value={scheduleForm.framework}
              onChange={(event) => setScheduleForm((current) => ({ ...current, framework: event.target.value as ComplianceFramework }))}
            >
              {complianceFrameworks.map((framework) => (
                <option key={framework.id} value={framework.id}>
                  {frameworkLabel(framework.id, t)}
                </option>
              ))}
            </select>
          </label>
          <label className="grid gap-1">
            <span className="font-medium">{t("policy.reporting.reportType")}</span>
            <select
              className="min-h-10 rounded-md border border-input bg-background px-3 py-2"
              value={scheduleForm.reportType}
              onChange={(event) => setScheduleForm((current) => ({ ...current, reportType: event.target.value as ComplianceReportType }))}
            >
              {complianceReportTypes.map((reportType) => (
                <option key={reportType.id} value={reportType.id}>
                  {t(reportType.labelKey)}
                </option>
              ))}
            </select>
          </label>
          <label className="grid gap-1">
            <span className="font-medium">{t("policy.reporting.cadenceDays")}</span>
            <input
              className="min-h-10 rounded-md border border-input bg-background px-3 py-2"
              inputMode="numeric"
              pattern="[0-9]*"
              value={scheduleForm.intervalDays}
              onChange={(event) => setScheduleForm((current) => ({ ...current, intervalDays: event.target.value }))}
            />
          </label>
          <label className="grid gap-1">
            <span className="font-medium">{t("policy.reporting.recipientRef")}</span>
            <input
              className="min-h-10 rounded-md border border-input bg-background px-3 py-2"
              value={scheduleForm.recipientRef}
              onChange={(event) => setScheduleForm((current) => ({ ...current, recipientRef: event.target.value }))}
            />
          </label>
          <div className="flex items-end lg:col-span-6">
            <Button type="submit" disabled={scheduleAction}>
              {scheduleAction ? t("policy.reporting.scheduling") : t("policy.reporting.createSchedule")}
            </Button>
          </div>
        </form>
        {reportNotice && (
          <p className="rounded-md border border-border bg-muted p-3 text-sm" role="status">
            {reportNotice}
          </p>
        )}

        <div className="flex flex-wrap items-center gap-3 border-t border-border pt-4">
          <Button type="button" onClick={() => void exportComplianceEvidence()} disabled={exporting}>
            {exporting ? "Exporting..." : "Export audit evidence"}
          </Button>
          <Link className="text-sm underline" to="/audit">
            Open audit explorer
          </Link>
        </div>
        {evidenceBundle && (
          <p className="rounded-md border border-border bg-muted p-3 font-mono text-xs" role="status">
            {evidenceBundle}
          </p>
        )}
        {evidenceError && (
          <p className="rounded-md border border-destructive/40 p-3 text-sm text-destructive" role="alert">
            {evidenceError}
          </p>
        )}
      </section>

      <section aria-labelledby="nhi-access-review-heading" className="grid gap-4 border-y border-border py-4">
        <div>
          <h2 id="nhi-access-review-heading" className="text-title font-semibold">
            NHI access certification
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            Campaigns certify non-human identity access from identifiers and evidence references. The console never accepts credential values here.
          </p>
        </div>

        <form className="grid gap-3 rounded-md border border-border p-4 text-sm lg:grid-cols-6" onSubmit={(event) => void startNHIReviewCampaign(event)}>
          <label className="grid gap-1 lg:col-span-2">
            <span className="font-medium">Campaign</span>
            <input
              className="min-h-10 rounded-md border border-input bg-background px-3 py-2"
              value={reviewForm.name}
              onChange={(event) => setReviewForm((current) => ({ ...current, name: event.target.value }))}
            />
          </label>
          <label className="grid gap-1 lg:col-span-2">
            <span className="font-medium">Reviewer</span>
            <input
              className="min-h-10 rounded-md border border-input bg-background px-3 py-2"
              placeholder="current session subject"
              value={reviewForm.reviewer}
              onChange={(event) => setReviewForm((current) => ({ ...current, reviewer: event.target.value }))}
            />
          </label>
          <label className="grid gap-1">
            <span className="font-medium">Risk</span>
            <select
              className="min-h-10 rounded-md border border-input bg-background px-3 py-2"
              value={reviewForm.risk}
              onChange={(event) => setReviewForm((current) => ({ ...current, risk: event.target.value }))}
            >
              <option value="low">Low</option>
              <option value="medium">Medium</option>
              <option value="high">High</option>
              <option value="critical">Critical</option>
            </select>
          </label>
          <div className="flex items-end">
            <Button className="w-full" type="submit" disabled={reviewAction === "start" || !reviewForm.name.trim() || !reviewForm.nhiId.trim()}>
              {reviewAction === "start" ? "Starting..." : "Start campaign"}
            </Button>
          </div>
          <label className="grid gap-1 lg:col-span-2">
            <span className="font-medium">NHI id</span>
            <input
              className="min-h-10 rounded-md border border-input bg-background px-3 py-2"
              value={reviewForm.nhiId}
              onChange={(event) => setReviewForm((current) => ({ ...current, nhiId: event.target.value }))}
            />
          </label>
          <label className="grid gap-1 lg:col-span-2">
            <span className="font-medium">Display name</span>
            <input
              className="min-h-10 rounded-md border border-input bg-background px-3 py-2"
              value={reviewForm.displayName}
              onChange={(event) => setReviewForm((current) => ({ ...current, displayName: event.target.value }))}
            />
          </label>
          <label className="grid gap-1 lg:col-span-2">
            <span className="font-medium">Evidence refs</span>
            <input
              className="min-h-10 rounded-md border border-input bg-background px-3 py-2"
              value={reviewForm.evidenceRefs}
              onChange={(event) => setReviewForm((current) => ({ ...current, evidenceRefs: event.target.value }))}
            />
          </label>
          <label className="grid gap-1 lg:col-span-3">
            <span className="font-medium">Resource</span>
            <input
              className="min-h-10 rounded-md border border-input bg-background px-3 py-2"
              value={reviewForm.resource}
              onChange={(event) => setReviewForm((current) => ({ ...current, resource: event.target.value }))}
            />
          </label>
          <label className="grid gap-1 lg:col-span-3">
            <span className="font-medium">Entitlement</span>
            <input
              className="min-h-10 rounded-md border border-input bg-background px-3 py-2"
              value={reviewForm.entitlement}
              onChange={(event) => setReviewForm((current) => ({ ...current, entitlement: event.target.value }))}
            />
          </label>
        </form>

        {reviewLoading && <LoadingState>Loading NHI access reviews.</LoadingState>}
        {reviewError && <ErrorState title="NHI access review unavailable">{reviewError}</ErrorState>}
        {reviewNotice && (
          <p className="rounded-md border border-border bg-muted p-3 text-sm" role="status">
            {reviewNotice}
          </p>
        )}

        <div className="grid gap-4 xl:grid-cols-[18rem_minmax(0,1fr)]">
          <section aria-label="NHI access review campaigns" className="rounded-md border border-border">
            {reviewCampaigns.length > 0 ? (
              <div className="divide-y divide-border">
                {reviewCampaigns.map((campaign) => (
                  <button
                    key={campaign.id}
                    className={`grid w-full gap-1 px-3 py-3 text-left hover:bg-muted ${activeReview?.id === campaign.id ? "bg-muted" : ""}`}
                    type="button"
                    onClick={() => void selectNHIReviewCampaign(campaign.id)}
                  >
                    <span className="font-medium">{campaign.name}</span>
                    <span className="text-xs text-muted-foreground">
                      {campaign.status} · {campaign.pending_count} pending · {campaign.certified_count} certified · {campaign.revoked_count} revoked
                    </span>
                  </button>
                ))}
              </div>
            ) : (
              <p className="p-3 text-sm text-muted-foreground">No access review campaigns.</p>
            )}
          </section>

          {activeReview && (
            <NHIReviewCampaignPanel
              campaign={activeReview}
              decisionReasons={decisionReasons}
              reviewAction={reviewAction}
              onDecision={decideNHIReviewItem}
              onReasonChange={setDecisionReasons}
            />
          )}
        </div>
      </section>

      <section aria-labelledby="policy-dry-run-heading" className="grid gap-4 border-y border-border py-4">
        <div>
          <h2 id="policy-dry-run-heading" className="text-title font-semibold">
            {t("policy.dryRun.heading")}
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            {t("policy.dryRun.description")}
          </p>
        </div>
        <form aria-label={t("policy.dryRun.formLabel")} className="grid gap-4 rounded-md border border-border p-4" onSubmit={(event) => void runPolicyDryRun(event)}>
          <div className="flex flex-wrap gap-2" role="group" aria-label={t("policy.dryRun.kindLabel")}>
            <Button type="button" variant={dryRunKind === "lifecycle" ? "default" : "outline"} aria-pressed={dryRunKind === "lifecycle"} onClick={() => selectDryRunKind("lifecycle")}>
              {t("policy.dryRun.lifecycle")}
            </Button>
            <Button type="button" variant={dryRunKind === "abac" ? "default" : "outline"} aria-pressed={dryRunKind === "abac"} onClick={() => selectDryRunKind("abac")}>
              {t("policy.dryRun.abac")}
            </Button>
          </div>
          <div className="grid gap-4 xl:grid-cols-2">
            <label className="grid gap-1 text-sm">
              <span className="font-medium">{t("policy.dryRun.moduleLabel")}</span>
              <textarea
                className="min-h-80 resize-y rounded-md border border-input bg-background px-3 py-2 font-mono text-xs"
                spellCheck={false}
                value={dryRunModule}
                onChange={(event) => setDryRunModule(event.target.value)}
              />
            </label>
            <label className="grid gap-1 text-sm">
              <span className="font-medium">{t("policy.dryRun.inputLabel")}</span>
              <textarea
                className="min-h-80 resize-y rounded-md border border-input bg-background px-3 py-2 font-mono text-xs"
                spellCheck={false}
                value={dryRunInput}
                onChange={(event) => setDryRunInput(event.target.value)}
              />
            </label>
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <Button type="submit" disabled={dryRunBusy || !dryRunModule.trim() || !dryRunInput.trim()}>
              {dryRunBusy ? t("policy.dryRun.running") : t("policy.dryRun.run")}
            </Button>
            <Link className="text-sm underline" to="/audit?type=policy.dry_run.evaluated">
              {t("policy.dryRun.auditLink")}
            </Link>
          </div>
        </form>
        {dryRunError && <ErrorState title={t("policy.dryRun.errorTitle")}>{dryRunError}</ErrorState>}
        {dryRunResult && <PolicyDryRunResultPanel result={dryRunResult} />}
      </section>
    </section>
  );
}

function PolicyDryRunResultPanel({ result }: { result: PolicyDryRun }) {
  const { t } = useTranslation();
  const trace = result.trace ?? [];
  const summary = result.input_summary;
  const decision = result.error
    ? t("policy.dryRun.decisionError")
    : result.allow
      ? t("policy.dryRun.decisionAllow")
      : result.deny
        ? t("policy.dryRun.decisionDeny")
        : t("policy.dryRun.decisionNone");
  return (
    <section aria-labelledby="policy-dry-run-result-heading" className="ui-panel p-comfortable text-sm" role="status">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h3 id="policy-dry-run-result-heading" className="text-title font-semibold">
            {t("policy.dryRun.resultHeading")}
          </h3>
          <p className="mt-1 text-muted-foreground">
            {decision}
            {result.reason ? `: ${result.reason}` : ""}
            {result.error ? `: ${result.error}` : ""}
          </p>
        </div>
        <span className="rounded-md border border-border px-3 py-2 font-mono text-xs">{result.audit_event}</span>
      </div>
      <dl className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <Metric label={t("policy.dryRun.metricKind")} value={result.kind} />
        <Metric label={t("policy.dryRun.metricValid")} value={result.valid ? t("policy.dryRun.validYes") : t("policy.dryRun.validNo")} />
        <Metric label={t("policy.dryRun.metricPackage")} value={result.package} mono />
        <Metric label={t("policy.dryRun.metricQuery")} value={result.query} mono />
        <Metric label={t("policy.dryRun.metricDigest")} value={result.module_sha256} mono />
        <Metric label={t("policy.dryRun.metricTenant")} value={summary?.tenant_id ?? ""} mono />
        <Metric label={t("policy.dryRun.metricActor")} value={summary?.actor ?? ""} mono />
        <Metric label={t("policy.dryRun.metricIdempotency")} value={result.idempotency_key} mono />
      </dl>
      {trace.length > 0 && (
        <div className="mt-4 overflow-x-auto rounded-md border border-border">
          <table className="ui-table min-w-[64rem]">
            <caption className="sr-only">{t("policy.dryRun.traceCaption")}</caption>
            <thead>
              <tr>
                <th scope="col">{t("policy.dryRun.traceOp")}</th>
                <th scope="col">{t("policy.dryRun.traceLocation")}</th>
                <th scope="col">{t("policy.dryRun.traceNode")}</th>
                <th scope="col">{t("policy.dryRun.traceMessage")}</th>
              </tr>
            </thead>
            <tbody>
              {trace.map((row, index) => (
                <tr key={`${row.query_id}:${index}`} className="align-top">
                  <td>{row.op}</td>
                  <td className="font-mono text-xs">{row.location ?? ""}</td>
                  <td className="font-mono text-xs">{row.node ?? ""}</td>
                  <td>{row.message ?? ""}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

function ComplianceEvidencePackPanel({ label, pack }: { label: string; pack: ComplianceEvidencePack }) {
  const manifest = manifestFromPack(pack);
  const controls = manifest.controls ?? [];
  const evidenced = controls.filter((control) => control.status === "evidenced").length;
  const gaps = controls.filter((control) => control.status === "gap").length;
  const posture = manifest.posture ?? {};
  const productEvidence = manifest.product_evidences ?? [];
  const operatorAttests = manifest.operator_attests ?? [];
  const payload = JSON.stringify(pack, null, 2);

  return (
    <section aria-labelledby="compliance-pack-heading" className="ui-panel p-comfortable text-sm">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h3 id="compliance-pack-heading" className="text-title font-semibold">
            {label} evidence pack
          </h3>
          <p className="mt-1 text-muted-foreground">Signed export plus offline verification key for auditor handoff.</p>
        </div>
        <a
          className="inline-flex items-center rounded-md border border-border px-3 py-2 text-sm underline"
          download={`${pack.framework}-evidence-pack.json`}
          href={`data:application/json;charset=utf-8,${encodeURIComponent(payload)}`}
        >
          Download signed bundle
        </a>
      </div>

      <dl className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <Metric label="Format" value={pack.format} mono />
        <Metric label="Controls" value={`${controls.length} ${plural(controls.length, "control")}`} />
        <Metric label="Evidenced" value={`${evidenced} evidenced`} />
        <Metric label="Gaps" value={`${gaps} ${plural(gaps, "gap")}`} />
        <Metric label="Crypto assets" value={String(posture.total_crypto_assets ?? 0)} />
        <Metric label="Quantum vulnerable" value={`${posture.quantum_vulnerable ?? 0} quantum vulnerable`} />
        <Metric label="Post-quantum" value={String(posture.post_quantum ?? 0)} />
        <Metric label="Public key DER" value={`${pack.public_key_der.length} bytes`} />
      </dl>

      {controls.length > 0 && (
        <div className="mt-4 overflow-x-auto rounded-md border border-border">
          <table className="ui-table min-w-[48rem]">
            <caption className="sr-only">{label} controls</caption>
            <thead>
              <tr>
                <th scope="col">Control</th>
                <th scope="col">Status</th>
                <th scope="col">Evidence</th>
              </tr>
            </thead>
            <tbody>
              {controls.map((control) => (
                <tr key={control.id ?? control.title ?? "control"} className="align-top">
                  <td>
                    <p className="font-medium">{control.title ?? control.id ?? "Control"}</p>
                    {control.id && <p className="mt-1 font-mono text-xs text-muted-foreground">{control.id}</p>}
                  </td>
                  <td>{control.status ?? "unknown"}</td>
                  <td>{control.evidence?.join(", ") || "No evidence label"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div className="mt-4 grid gap-3 md:grid-cols-2">
        <EvidenceList title="Product evidence" items={productEvidence} />
        <EvidenceList title="Operator attestations" items={operatorAttests} />
      </div>
    </section>
  );
}

function ComplianceInventoryReportPanel({ report, schedules }: { report: ComplianceInventoryReport; schedules: ComplianceReportSchedule[] }) {
  const { formatDate, t } = useTranslation();
  const rows = schedules.length > 0 ? schedules : report.schedules;

  return (
    <section aria-labelledby="compliance-inventory-report-heading" className="ui-panel p-comfortable text-sm">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h3 id="compliance-inventory-report-heading" className="text-title font-semibold">
            {t("policy.reporting.heading")}
          </h3>
          <p className="mt-1 text-muted-foreground">
            {t("policy.reporting.generated", { capability: report.capability, date: formatDate(report.generated_at) })}
          </p>
        </div>
        <span className="rounded-md border border-border px-3 py-2 font-mono text-xs">{t("policy.reporting.auditExport")}</span>
      </div>

      <dl className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <Metric label={t("policy.reporting.inventoryRows")} value={String(report.summary.inventory_rows)} />
        <Metric label={t("policy.reporting.certificates")} value={String(report.summary.certificates)} />
        <Metric label={t("policy.reporting.cryptoAssets")} value={String(report.summary.crypto_assets)} />
        <Metric label={t("policy.reporting.discoverySchedules")} value={String(report.summary.discovery_schedules)} />
        <Metric label={t("policy.reporting.frameworks")} value={String(report.summary.frameworks_supported)} />
        <Metric label={t("policy.reporting.reportTypes")} value={String(report.summary.report_types_supported)} />
        <Metric label={t("policy.reporting.schedules")} value={String(report.summary.report_schedules)} />
        <Metric label={t("policy.reporting.enabledSchedules")} value={String(report.summary.enabled_report_schedules)} />
      </dl>

      <div className="mt-4 grid gap-3 lg:grid-cols-2">
        <EvidenceList title={t("policy.reporting.reportTypeList")} items={report.report_types.map((reportType) => reportTypeLabel(reportType, t))} />
        <EvidenceList title={t("policy.reporting.routeList")} items={report.routes} />
      </div>

      {rows.length > 0 ? (
        <div className="mt-4 overflow-x-auto rounded-md border border-border">
          <table className="ui-table min-w-[48rem]">
            <caption className="sr-only">{t("policy.reporting.tableCaption")}</caption>
            <thead>
              <tr>
                <th scope="col">{t("policy.reporting.schedule")}</th>
                <th scope="col">{t("policy.reporting.framework")}</th>
                <th scope="col">{t("policy.reporting.type")}</th>
                <th scope="col">{t("policy.reporting.cadence")}</th>
                <th scope="col">{t("policy.reporting.nextRun")}</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((schedule) => (
                <tr key={schedule.id}>
                  <td>
                    <p className="font-medium">{schedule.name}</p>
                    {schedule.recipient_ref && <p className="mt-1 font-mono text-xs text-muted-foreground">{schedule.recipient_ref}</p>}
                  </td>
                  <td>{schedule.framework}</td>
                  <td>{reportTypeLabel(schedule.report_type, t)}</td>
                  <td>{Math.round(schedule.interval_seconds / 86400)}d</td>
                  <td>{formatDate(schedule.next_run_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p className="mt-4 rounded-md border border-border p-3 text-muted-foreground">{t("policy.reporting.empty")}</p>
      )}
    </section>
  );
}

function NHIComplianceReportPanel({ report }: { report: NHIComplianceReport }) {
  const { formatDate, t } = useTranslation();
  const controlRows = report.controls.slice(0, 8);

  return (
    <section aria-labelledby="nhi-compliance-report-heading" className="ui-panel p-comfortable text-sm">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h3 id="nhi-compliance-report-heading" className="text-title font-semibold">
            {t("policy.nhiCompliance.heading")}
          </h3>
          <p className="mt-1 text-muted-foreground">
            {t("policy.nhiCompliance.generated", {
              capability: report.capability,
              date: formatDate(report.generated_at),
              state: report.audit_ready ? t("policy.nhiCompliance.auditReady") : t("policy.nhiCompliance.draft"),
            })}
          </p>
        </div>
        <span className="rounded-md border border-border px-3 py-2 font-mono text-xs">{report.format}</span>
      </div>

      <dl className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <Metric label={t("policy.nhiCompliance.nhiRows")} value={String(report.summary.total_nhis)} />
        <Metric label={t("policy.nhiCompliance.frameworks")} value={String(report.summary.frameworks_supported)} />
        <Metric label={t("policy.nhiCompliance.mappedControls")} value={String(report.summary.controls_mapped)} />
        <Metric label={t("policy.nhiCompliance.overprivileged")} value={String(report.summary.overprivileged_findings)} />
        <Metric label={t("policy.nhiCompliance.staleFindings")} value={String(report.summary.stale_findings)} />
        <Metric label={t("policy.nhiCompliance.staticCredentials")} value={String(report.summary.static_credential_findings)} />
        <Metric label={t("policy.nhiCompliance.evidenceRefs")} value={String(report.summary.audit_evidence_refs)} />
        <Metric label={t("policy.nhiCompliance.attestations")} value={String(report.summary.operator_attestation_needed)} />
      </dl>

      <div className="mt-4 grid gap-3 lg:grid-cols-2">
        <EvidenceList title={t("policy.nhiCompliance.frameworkList")} items={report.frameworks.map((framework) => `${framework.name} ${framework.version}`)} />
        <EvidenceList title={t("policy.nhiCompliance.evidenceRoutes")} items={report.routes} />
      </div>

      {controlRows.length > 0 && (
        <div className="mt-4 overflow-x-auto rounded-md border border-border">
          <table className="ui-table min-w-[58rem]">
            <caption className="sr-only">{t("policy.nhiCompliance.tableCaption")}</caption>
            <thead>
              <tr>
                <th scope="col">{t("policy.nhiCompliance.frameworkColumn")}</th>
                <th scope="col">{t("policy.nhiCompliance.controlColumn")}</th>
                <th scope="col">{t("policy.nhiCompliance.statusColumn")}</th>
                <th scope="col">{t("policy.nhiCompliance.evidenceColumn")}</th>
              </tr>
            </thead>
            <tbody>
              {controlRows.map((control) => (
                <tr key={`${control.framework}:${control.control_id}`} className="align-top">
                  <td>{control.framework}</td>
                  <td>
                    <p className="font-medium">{control.title}</p>
                    <p className="mt-1 font-mono text-xs text-muted-foreground">{control.control_id}</p>
                  </td>
                  <td>
                    <p>{control.status}</p>
                    <p className="mt-1 text-xs text-muted-foreground">
                      {t("policy.nhiCompliance.mappedSignals", { count: control.finding_count })}
                    </p>
                  </td>
                  <td>{control.evidence_refs.join(", ")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div className="mt-4 grid gap-3 lg:grid-cols-2">
        <EvidenceList title={t("policy.reporting.reportTypeList")} items={report.report_types.map((reportType) => reportTypeLabel(reportType, t))} />
        <EvidenceList title={t("policy.nhiCompliance.residualAttestations")} items={report.residuals} />
      </div>
    </section>
  );
}

function NHIReviewCampaignPanel({
  campaign,
  decisionReasons,
  onDecision,
  onReasonChange,
  reviewAction,
}: {
  campaign: NHIReviewCampaign;
  decisionReasons: Record<string, string>;
  onDecision: (item: NHIReviewItem, decision: NHIReviewDecisionRequest["decision"]) => Promise<void>;
  onReasonChange: (value: Record<string, string> | ((current: Record<string, string>) => Record<string, string>)) => void;
  reviewAction: string | null;
}) {
  const items = campaign.items ?? [];

  return (
    <section aria-labelledby="nhi-access-review-detail-heading" className="ui-panel p-comfortable text-sm">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h3 id="nhi-access-review-detail-heading" className="text-title font-semibold">
            {campaign.name}
          </h3>
          <p className="mt-1 text-muted-foreground">
            {campaign.status} · requested by {campaign.requested_by} · reviewer {campaign.reviewer_subject}
          </p>
        </div>
        <span className="rounded-md border border-border px-3 py-2 font-mono text-xs">{campaign.id}</span>
      </div>

      <dl className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
        <Metric label="Items" value={String(campaign.item_count)} />
        <Metric label="Pending" value={String(campaign.pending_count)} />
        <Metric label="Certified" value={String(campaign.certified_count)} />
        <Metric label="Revoked" value={String(campaign.revoked_count)} />
        <Metric label="Exceptions" value={String(campaign.exception_count)} />
      </dl>

      {items.length > 0 ? (
        <div className="mt-4 overflow-x-auto rounded-md border border-border">
          <table className="ui-table min-w-[64rem]">
            <caption className="sr-only">NHI access review items</caption>
            <thead>
              <tr>
                <th scope="col">Identity</th>
                <th scope="col">Resource</th>
                <th scope="col">Evidence</th>
                <th scope="col">Status</th>
                <th scope="col">Decision</th>
              </tr>
            </thead>
            <tbody>
              {items.map((item) => {
                const reason = decisionReasons[item.item_id] ?? "";
                const busy = reviewAction?.startsWith(`${item.item_id}:`) ?? false;
                return (
                  <tr key={item.item_id} className="align-top">
                    <td>
                      <p className="font-medium">{item.display_name}</p>
                      <p className="mt-1 break-all font-mono text-xs text-muted-foreground">{item.nhi_id}</p>
                    </td>
                    <td>
                      <p>{item.resource}</p>
                      <p className="mt-1 text-xs text-muted-foreground">{item.entitlement}</p>
                    </td>
                    <td>{item.evidence_refs.join(", ") || "No evidence ref"}</td>
                    <td>{item.status}</td>
                    <td>
                      {item.status === "pending" ? (
                        <div className="grid min-w-60 gap-2">
                          <input
                            className="min-h-10 rounded-md border border-input bg-background px-3 py-2"
                            placeholder="Reason for revoke or exception"
                            value={reason}
                            onChange={(event) => onReasonChange((current) => ({ ...current, [item.item_id]: event.target.value }))}
                          />
                          <div className="flex flex-wrap gap-2">
                            <Button type="button" variant="outline" disabled={busy} onClick={() => void onDecision(item, "certified")}>
                              Certify
                            </Button>
                            <Button type="button" variant="outline" disabled={busy || !reason.trim()} onClick={() => void onDecision(item, "revoked")}>
                              Revoke
                            </Button>
                            <Button type="button" variant="outline" disabled={busy || !reason.trim()} onClick={() => void onDecision(item, "exception")}>
                              Exception
                            </Button>
                          </div>
                        </div>
                      ) : (
                        <div>
                          <p>{item.decision_reason || "Recorded"}</p>
                          {item.decision_by && <p className="mt-1 text-xs text-muted-foreground">{item.decision_by}</p>}
                        </div>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      ) : (
        <p className="mt-4 rounded-md border border-border p-3 text-muted-foreground">No item details loaded.</p>
      )}
    </section>
  );
}

function Metric({ label, mono = false, value }: { label: string; mono?: boolean; value: string }) {
  return (
    <div>
      <dt className="font-medium text-muted-foreground">{label}</dt>
      <dd className={mono ? "break-all font-mono text-xs" : "text-base font-semibold"}>{value}</dd>
    </div>
  );
}

function EvidenceList({ items, title }: { items: string[]; title: string }) {
  return (
    <section aria-label={title} className="rounded-md border border-border p-3">
      <p className="font-medium">{title}</p>
      {items.length > 0 ? (
        <ul className="mt-2 grid gap-1 text-muted-foreground">
          {items.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
      ) : (
        <p className="mt-2 text-muted-foreground">No labels in this pack.</p>
      )}
    </section>
  );
}

function manifestFromPack(pack: ComplianceEvidencePack): ComplianceManifest {
  const raw = pack.signed_export.manifest ?? pack.signed_export.Manifest;
  if (isRecord(raw)) return raw as ComplianceManifest;
  if (typeof raw === "string") {
    try {
      const parsed = JSON.parse(raw) as unknown;
      if (isRecord(parsed)) return parsed as ComplianceManifest;
    } catch {
      return {};
    }
  }
  return {};
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function frameworkLabel(framework: ComplianceFramework, t: (key: MessageKey) => string): string {
  const item = complianceFrameworks.find((candidate) => candidate.id === framework);
  if (!item) return framework;
  if (item.labelKey) return t(item.labelKey);
  return item.label ?? framework;
}

function plural(count: number, singular: string): string {
  if (count === 1) return singular;
  return `${singular}s`;
}

function optionalText(value: string): string | undefined {
  const trimmed = value.trim();
  return trimmed === "" ? undefined : trimmed;
}

function splitRefs(value: string): string[] {
  return value
    .split(/[\n,]/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function reportTypeLabel(value: string, t: (key: MessageKey) => string): string {
  const item = complianceReportTypes.find((candidate) => candidate.id === value);
  return item ? t(item.labelKey) : value;
}

function describePolicyError(err: unknown, fallback: string): string {
  if (err instanceof ApiError) {
    try {
      const problem = JSON.parse(err.body) as { detail?: string; title?: string };
      return problem.detail || problem.title || err.message;
    } catch {
      return err.body || err.message;
    }
  }
  if (err instanceof Error) return err.message;
  return fallback;
}
