import { type FormEvent, type ReactNode, useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { ComplianceEvidencePackPanel } from "@/components/ComplianceEvidencePackPanel";
import { Dialog } from "@/components/Dialog";
import { PageHeader } from "@/components/PageHeader";
import { ScrollableTableRegion } from "@/components/ScrollableTableRegion";
import { ErrorState, LoadingState } from "@/components/StatePrimitives";
import { Button } from "@/components/ui/button";
import { useTranslation, translateNow } from "@/i18n/I18nProvider";
import type { MessageKey } from "@/i18n/messages";
import { ComplianceInventoryReportPanel, NHIComplianceReportPanel } from "@/pages/policy/ComplianceReportingPanels";
import {
  api,
  ApiError,
  type AccessChangeDecisionRequest,
  type AccessChangeRequest,
  type ComplianceEvidencePack,
  type ComplianceInventoryReport,
  type ComplianceReportSchedule,
  type ComplianceReportSchedulePreview,
  type ComplianceReportScheduleRequest,
  type NHIComplianceReport,
  type NHIReviewCampaign,
  type NHIReviewDecisionRequest,
  type NHIReviewItem,
  type PolicyDryRun,
  type PolicyDryRunRequest,
  type PolicyVersion,
} from "@/lib/api";

type ComplianceFramework = ComplianceEvidencePack["framework"];
type ComplianceReportType = ComplianceReportScheduleRequest["report_type"];
type PolicyDryRunKind = "lifecycle" | "abac";
type SafeHref = { href: string; external: boolean };

const complianceFrameworks: Array<{ id: ComplianceFramework; labelKey: MessageKey }> = [
  { id: "pci-dss", labelKey: "policy.framework.pciDss" },
  { id: "hipaa", labelKey: "policy.framework.hipaa" },
  { id: "soc2", labelKey: "policy.framework.soc2" },
  { id: "nist-800-53", labelKey: "policy.framework.nist80053" },
  { id: "nist-csf-2.0", labelKey: "policy.framework.nistCsf20" },
  { id: "fedramp", labelKey: "policy.framework.fedramp" },
  { id: "cmmc-2.0", labelKey: "policy.framework.cmmc20" },
  { id: "cnsa-2.0", labelKey: "policy.framework.cnsa20" },
  { id: "fips-140", labelKey: "policy.framework.fips140" },
  { id: "common-criteria", labelKey: "policy.framework.commonCriteria" },
  { id: "cabf-br", labelKey: "policy.framework.cabfBR" },
  { id: "webtrust", labelKey: "policy.framework.webtrust" },
  { id: "etsi", labelKey: "policy.framework.etsi" },
  { id: "eidas", labelKey: "policy.framework.eidas" },
  { id: "nis2", labelKey: "policy.framework.nis2" },
];

const complianceReportTypes: Array<{ id: ComplianceReportType; labelKey: MessageKey }> = [
  { id: "inventory_snapshot", labelKey: "policy.reportType.inventorySnapshot" },
  { id: "framework_evidence_pack", labelKey: "policy.reportType.frameworkEvidencePack" },
  { id: "cbom_posture", labelKey: "policy.reportType.cbomPosture" },
  { id: "audit_summary", labelKey: "policy.reportType.auditSummary" },
  { id: "nhi_compliance_mapping", labelKey: "policy.reportType.nhiComplianceMapping" },
];

function hasUnsafeHrefChar(href: string): boolean {
  for (let i = 0; i < href.length; i += 1) {
    const code = href.charCodeAt(i);
    if (code <= 0x1f || code === 0x7f || href[i] === "\\") {
      return true;
    }
  }
  return false;
}

function safeHref(raw?: string | null): SafeHref | null {
  const href = raw?.trim();
  if (!href || hasUnsafeHrefChar(href)) {
    return null;
  }
  try {
    if (href.startsWith("/")) {
      if (href.startsWith("//")) {
        return null;
      }
      const parsed = new URL(href, window.location.origin);
      if (parsed.origin !== window.location.origin || !parsed.pathname.startsWith("/")) {
        return null;
      }
      return { href: `${parsed.pathname}${parsed.search}${parsed.hash}`, external: false };
    }
    const parsed = new URL(href);
    if (parsed.protocol !== "https:" || !parsed.hostname || parsed.username || parsed.password) {
      return null;
    }
    return { href: parsed.href, external: true };
  } catch {
    return null;
  }
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
  const [evidencePackLoading, setEvidencePackLoading] = useState(false);
  const [inventoryReport, setInventoryReport] = useState<ComplianceInventoryReport | null>(null);
  const [nhiComplianceReport, setNHIComplianceReport] = useState<NHIComplianceReport | null>(null);
  const [reportSchedules, setReportSchedules] = useState<ComplianceReportSchedule[]>([]);
  const [reportLoading, setReportLoading] = useState(false);
  const [reportError, setReportError] = useState<string | null>(null);
  const [reportNotice, setReportNotice] = useState<string | null>(null);
  const [scheduleAction, setScheduleAction] = useState<string | null>(null);
  const [schedulePreview, setSchedulePreview] = useState<ComplianceReportSchedulePreview | null>(null);
  const [evidenceBundle, setEvidenceBundle] = useState<string | null>(null);
  const [evidenceError, setEvidenceError] = useState<string | null>(null);
  const [exporting, setExporting] = useState(false);
  const [reviewCampaigns, setReviewCampaigns] = useState<NHIReviewCampaign[]>([]);
  const [activeReview, setActiveReview] = useState<NHIReviewCampaign | null>(null);
  const [reviewError, setReviewError] = useState<string | null>(null);
  const [reviewNotice, setReviewNotice] = useState<string | null>(null);
  const [reviewLoading, setReviewLoading] = useState(false);
  const [reviewAction, setReviewAction] = useState<string | null>(null);
  const [decisionReasons, setDecisionReasons] = useState<Record<string, string>>({});
  const [accessRequests, setAccessRequests] = useState<AccessChangeRequest[]>([]);
  const [activeAccessRequest, setActiveAccessRequest] = useState<AccessChangeRequest | null>(null);
  const [accessError, setAccessError] = useState<string | null>(null);
  const [accessNotice, setAccessNotice] = useState<string | null>(null);
  const [accessLoading, setAccessLoading] = useState(true);
  const [accessAction, setAccessAction] = useState<string | null>(null);
  const [accessDecisionReasons, setAccessDecisionReasons] = useState<Record<string, string>>({});
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
  const [accessForm, setAccessForm] = useState({
    requestedAction: "grant" as AccessChangeRequest["requested_action"],
    nhiId: "github-app:prod-deployer",
    nhiKind: "oauth_app",
    displayName: "Prod deployer GitHub App",
    resource: "github:org/prod-infra",
    entitlement: "repo:contents:write",
    changeRef: "github:org/prod-infra#4821",
    changeUrl: "https://github.com/org/prod-infra/pull/4821",
    reason: "Scoped deployment automation access",
    evidenceRefs: "pull:4821/checks, ticket:CAB-4821",
    requiredApprovals: "2",
    risk: "high",
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
  const [policyVersions, setPolicyVersions] = useState<PolicyVersion[]>([]);
  const [activePolicyVersion, setActivePolicyVersion] = useState<PolicyVersion | null>(null);
  const [policyVersionLoading, setPolicyVersionLoading] = useState(true);
  const [policyVersionError, setPolicyVersionError] = useState<string | null>(null);
  const [policyVersionNotice, setPolicyVersionNotice] = useState<string | null>(null);
  const [policyVersionAction, setPolicyVersionAction] = useState<string | null>(null);
  const [policyVersionForm, setPolicyVersionForm] = useState({
    description: translateNow("source.emergency.issuance.guard.5a3ad01167"),
    changeRef: "github:security/policy#42",
    evidenceRefs: "pr:policy-42, cab:2026-07-02",
    module: lifecycleDryRunModule,
  });
  const [ruleDialogOpen, setRuleDialogOpen] = useState(false);
  const [open, setOpen] = useState({ rules: false, test: false, compliance: false, approvals: false });
  const ruleDescriptionRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (!open.compliance) return undefined;
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
  }, [open.compliance, selectedFramework]);

  useEffect(() => {
    if (!open.compliance) return undefined;
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
  }, [open.compliance]);

  useEffect(() => {
    if (!open.approvals) return undefined;
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
  }, [open.approvals]);

  useEffect(() => {
    let active = true;
    setAccessLoading(true);
    setAccessError(null);
    api
      .accessChangeRequests({ limit: 5 })
      .then(async (page) => {
        if (!active) return;
        const requests = page.items ?? [];
        setAccessRequests(requests);
        if (!open.approvals || requests.length === 0) {
          setActiveAccessRequest(null);
          return;
        }
        const detailed = await api.getAccessChangeRequest(requests[0].id);
        if (active) setActiveAccessRequest(detailed);
      })
      .catch((err: unknown) => {
        if (active) setAccessError(describePolicyError(err, "access change requests unavailable"));
      })
      .finally(() => {
        if (active) setAccessLoading(false);
      });
    return () => {
      active = false;
    };
  }, [open.approvals]);

  useEffect(() => {
    let active = true;
    setPolicyVersionLoading(true);
    setPolicyVersionError(null);
    api
      .policyVersions()
      .then((page) => {
        if (!active) return;
        setPolicyVersions(page.items ?? []);
        setActivePolicyVersion(page.active ?? null);
      })
      .catch((err: unknown) => {
        if (active) setPolicyVersionError(describePolicyError(err, "policy versions unavailable"));
      })
      .finally(() => {
        if (active) setPolicyVersionLoading(false);
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
      const [report, nhiReport, schedules] = await Promise.all([
        api.complianceInventoryReport(),
        api.nhiComplianceReport(),
        api.complianceReportSchedules({ limit: 5 }),
      ]);
      setInventoryReport(report);
      setNHIComplianceReport(nhiReport);
      setReportSchedules(schedules.items ?? []);
    } catch (err) {
      setReportError(describePolicyError(err, "compliance reporting unavailable"));
    } finally {
      setReportLoading(false);
    }
  }

  function complianceScheduleRequest(): ComplianceReportScheduleRequest | null {
    const intervalDays = Number.parseInt(scheduleForm.intervalDays, 10);
    if (!Number.isFinite(intervalDays) || intervalDays < 1 || intervalDays > 366) {
      setReportError(t("policy.reporting.intervalError"));
      return null;
    }
    return {
      name: scheduleForm.name.trim(),
      framework: scheduleForm.framework,
      report_type: scheduleForm.reportType,
      interval_seconds: intervalDays * 24 * 60 * 60,
      enabled: true,
      delivery: "audit_export",
      recipient_ref: optionalText(scheduleForm.recipientRef),
    };
  }

  async function previewReportSchedule() {
    setScheduleAction("preview");
    setReportError(null);
    setReportNotice(null);
    setSchedulePreview(null);
    const request = complianceScheduleRequest();
    if (!request) {
      setScheduleAction(null);
      return;
    }
    try {
      setSchedulePreview(await api.previewComplianceReportSchedule(request));
    } catch (err) {
      setReportError(describePolicyError(err, "report schedule review failed"));
    } finally {
      setScheduleAction(null);
    }
  }

  async function createReportSchedule(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!schedulePreview?.ready) {
      setReportError(t("policy.reporting.reviewRequired"));
      return;
    }
    setScheduleAction("create");
    setReportError(null);
    setReportNotice(null);
    const request = complianceScheduleRequest();
    if (!request) {
      setScheduleAction(null);
      return;
    }
    try {
      const schedule = await api.createComplianceReportSchedule(request);
      setReportNotice(`${schedule.name} scheduled for ${formatDate(schedule.next_run_at)}.`);
      setSchedulePreview(null);
      await refreshComplianceReporting();
    } catch (err) {
      setReportError(describePolicyError(err, "report schedule create failed"));
    } finally {
      setScheduleAction(null);
    }
  }

  async function toggleReportSchedule(schedule: ComplianceReportSchedule) {
    const operation = schedule.enabled ? "pause" : "resume";
    setScheduleAction(`${operation}:${schedule.id}`);
    setReportError(null);
    setReportNotice(null);
    try {
      const changed = schedule.enabled ? await api.pauseComplianceReportSchedule(schedule.id) : await api.resumeComplianceReportSchedule(schedule.id);
      setReportNotice(changed.enabled ? t("policy.reporting.resumed") : t("policy.reporting.paused"));
      await refreshComplianceReporting();
    } catch (err) {
      setReportError(describePolicyError(err, `report schedule ${operation} failed`));
    } finally {
      setScheduleAction(null);
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

  async function refreshAccessChangeRequests(preferredID?: string) {
    setAccessLoading(true);
    setAccessError(null);
    try {
      const page = await api.accessChangeRequests({ limit: 5 });
      const requests = page.items ?? [];
      setAccessRequests(requests);
      const id = preferredID ?? activeAccessRequest?.id ?? requests[0]?.id;
      if (id) {
        setActiveAccessRequest(await api.getAccessChangeRequest(id));
      } else {
        setActiveAccessRequest(null);
      }
    } catch (err) {
      setAccessError(describePolicyError(err, "access change requests unavailable"));
    } finally {
      setAccessLoading(false);
    }
  }

  async function createAccessChangeRequest(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setAccessAction("create");
    setAccessError(null);
    setAccessNotice(null);
    const requiredApprovals = Number.parseInt(accessForm.requiredApprovals, 10);
    if (!Number.isFinite(requiredApprovals) || requiredApprovals < 1) {
      setAccessError("required approvals must be a positive integer");
      setAccessAction(null);
      return;
    }
    try {
      const request = await api.createAccessChangeRequest({
        requested_action: accessForm.requestedAction,
        nhi_id: accessForm.nhiId.trim(),
        nhi_kind: accessForm.nhiKind.trim(),
        display_name: optionalText(accessForm.displayName),
        resource: accessForm.resource.trim(),
        entitlement: accessForm.entitlement.trim(),
        change_ref: accessForm.changeRef.trim(),
        change_url: optionalText(accessForm.changeUrl),
        reason: accessForm.reason.trim(),
        risk: optionalText(accessForm.risk),
        evidence_refs: splitRefs(accessForm.evidenceRefs),
        required_approvals: requiredApprovals,
      });
      setActiveAccessRequest(request);
      setAccessDecisionReasons({});
      setAccessNotice(t("policy.accessChange.openedNotice", { action: request.requested_action, changeRef: request.change_ref, name: request.display_name }));
      await refreshAccessChangeRequests(request.id);
    } catch (err) {
      setAccessError(describePolicyError(err, "access change request failed"));
    } finally {
      setAccessAction(null);
    }
  }

  async function selectAccessChangeRequest(id: string) {
    setAccessLoading(true);
    setAccessError(null);
    try {
      setActiveAccessRequest(await api.getAccessChangeRequest(id));
    } catch (err) {
      setAccessError(describePolicyError(err, "access change request unavailable"));
    } finally {
      setAccessLoading(false);
    }
  }

  async function decideAccessChangeRequest(request: AccessChangeRequest, decision: AccessChangeDecisionRequest["decision"]) {
    const action = `${request.id}:${decision}`;
    setAccessAction(action);
    setAccessError(null);
    setAccessNotice(null);
    try {
      const updated = await api.decideAccessChangeRequest(request.id, {
        decision,
        reason: optionalText(accessDecisionReasons[request.id]),
        decision_evidence_refs: splitRefs(accessForm.evidenceRefs),
      });
      setActiveAccessRequest(updated);
      setAccessNotice(t("policy.accessChange.decisionNotice", { decision, name: request.display_name }));
      await refreshAccessChangeRequests(updated.id);
    } catch (err) {
      setAccessError(describePolicyError(err, "access change decision failed"));
    } finally {
      setAccessAction(null);
    }
  }

  async function refreshPolicyVersions(preferredID?: string) {
    setPolicyVersionLoading(true);
    setPolicyVersionError(null);
    try {
      const page = await api.policyVersions();
      const items = page.items ?? [];
      setPolicyVersions(items);
      setActivePolicyVersion(page.active ?? items.find((item) => item.id === preferredID) ?? null);
    } catch (err) {
      setPolicyVersionError(describePolicyError(err, "policy versions unavailable"));
    } finally {
      setPolicyVersionLoading(false);
    }
  }

  async function createPolicyVersion(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setPolicyVersionAction("create");
    setPolicyVersionError(null);
    setPolicyVersionNotice(null);
    try {
      const created = await api.createPolicyVersion({
        kind: "lifecycle",
        module: policyVersionForm.module,
        description: optionalText(policyVersionForm.description),
        change_ref: optionalText(policyVersionForm.changeRef),
        evidence_refs: splitRefs(policyVersionForm.evidenceRefs),
      });
      setPolicyVersionNotice(`Policy version ${created.module_sha256.slice(0, 12)} authored.`);
      await refreshPolicyVersions(created.id);
      setRuleDialogOpen(false);
      setOpen((current) => ({ ...current, rules: true }));
    } catch (err) {
      setPolicyVersionError(describePolicyError(err, "policy version create failed"));
    } finally {
      setPolicyVersionAction(null);
    }
  }

  async function activatePolicyVersion(version: PolicyVersion) {
    setPolicyVersionAction(`activate:${version.id}`);
    setPolicyVersionError(null);
    setPolicyVersionNotice(null);
    try {
      const activated = await api.activatePolicyVersion(version.id, {
        reason: "Operator activated from Policy console",
        evidence_refs: splitRefs(policyVersionForm.evidenceRefs),
      });
      setPolicyVersionNotice(`Policy version ${activated.module_sha256.slice(0, 12)} activated.`);
      await refreshPolicyVersions(activated.id);
    } catch (err) {
      setPolicyVersionError(describePolicyError(err, "policy activation failed"));
    } finally {
      setPolicyVersionAction(null);
    }
  }

  async function rollbackPolicyVersion(version: PolicyVersion) {
    setPolicyVersionAction(`rollback:${version.id}`);
    setPolicyVersionError(null);
    setPolicyVersionNotice(null);
    try {
      const rolledBack = await api.rollbackPolicyVersion(version.id, {
        reason: "Operator rollback from Policy console",
        evidence_refs: splitRefs(policyVersionForm.evidenceRefs),
      });
      setPolicyVersionNotice(`Policy version ${rolledBack.module_sha256.slice(0, 12)} rolled back.`);
      await refreshPolicyVersions(rolledBack.rollback_to_id);
    } catch (err) {
      setPolicyVersionError(describePolicyError(err, "policy rollback failed"));
    } finally {
      setPolicyVersionAction(null);
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
    <section aria-labelledby="policy-heading" className="grid min-w-0 grid-cols-[minmax(0,1fr)] gap-6">
      <PageHeader
        titleId="policy-heading"
        title={t("policy.design.title")}
        description={t("policy.design.answer")}
        technicalDetails={t("policy.design.technicalDetails")}
        actions={
          <Button type="button" onClick={() => setRuleDialogOpen(true)}>
            {t("policy.design.create")}
          </Button>
        }
      />

      {policyVersionLoading || accessLoading ? (
        <LoadingState>{t("policy.design.checking")}</LoadingState>
      ) : policyVersionError || accessError ? (
        <ErrorState title={t("policy.design.summaryUnavailable")}>
          <p>{t("policy.design.summaryUnavailableHelp")}</p>
          <ul className="mt-2 list-disc ps-5">
            {policyVersionError && <li>{policyVersionError}</li>}
            {accessError && <li>{accessError}</li>}
          </ul>
        </ErrorState>
      ) : (
        <div className="ui-panel grid gap-3 p-comfortable" role="status" aria-live="polite">
          <div>
            <h2 className="text-title font-semibold">{activePolicyVersion ? t("policy.design.protected") : t("policy.design.protectedNoCustom")}</h2>
            <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
              {activePolicyVersion
                ? t("policy.design.activeRule", { rule: activePolicyVersion.description || activePolicyVersion.id })
                : t("policy.design.defaultDeny")}
            </p>
          </div>
          <dl className="grid gap-3 text-sm sm:grid-cols-2">
            <Metric
              label={t("policy.design.approvalsLabel")}
              value={
                accessRequests.filter((request) => request.status === "pending").length === 1
                  ? t("policy.design.oneApproval")
                  : t("policy.design.manyApprovals", {
                      count: String(accessRequests.filter((request) => request.status === "pending").length),
                    })
              }
            />
            <Metric
              label={t("policy.design.changesLabel")}
              value={policyVersions.length === 1 ? t("policy.design.oneVersion") : t("policy.design.manyVersions", { count: String(policyVersions.length) })}
            />
          </dl>
        </div>
      )}

      <PolicyDetails title={t("policy.design.disclosure.rules")} open={open.rules} onToggle={(value) => setOpen((current) => ({ ...current, rules: value }))}>
        <div className="grid min-w-0 gap-6">
          <p className="max-w-3xl text-sm text-muted-foreground">{t("policy.design.rulesHelp")}</p>

          <section aria-labelledby="policy-gate-heading" className="grid min-w-0 gap-4 border-y border-border py-4">
            <div>
              <h2 id="policy-gate-heading" className="text-title font-semibold">
                {t("policy.enforcement.heading")}
              </h2>
              <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{t("policy.enforcement.description")}</p>
            </div>
            <p className="text-sm text-muted-foreground">
              {t("policy.enforcement.auditPrefix")}{" "}
              <Link className="underline" to="/identities">
                {t("policy.enforcement.identitiesLink")}
              </Link>{" "}
              {t("policy.enforcement.auditSuffix")}
            </p>
            <div className="flex flex-wrap gap-2">
              <Link className="underline" to="/audit?type=policy.decision">
                {t("policy.enforcement.policyDecisionsLink")}
              </Link>
              <Link className="underline" to="/audit?type=issuance.profile_evaluated">
                {t("policy.enforcement.profileEvaluationsLink")}
              </Link>
            </div>
          </section>

          <section aria-labelledby="policy-version-heading" className="grid min-w-0 gap-4 border-y border-border py-4">
            <div>
              <h2 id="policy-version-heading" className="text-title font-semibold">
                {t("policy.versions.heading")}
              </h2>
              <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{t("policy.versions.description")}</p>
            </div>

            <div className="grid min-w-0 gap-4">
              <section aria-labelledby="policy-active-version-heading" className="min-w-0 rounded-md border border-border p-4 text-sm">
                <h3 id="policy-active-version-heading" className="text-sm font-semibold">
                  {t("policy.versions.activePolicy")}
                </h3>
                {activePolicyVersion ? (
                  <dl className="mt-3 grid gap-2">
                    <div>
                      <dt className="text-xs font-medium text-muted-foreground">{t("policy.versions.status")}</dt>
                      <dd>{activePolicyVersion.status}</dd>
                    </div>
                    <div>
                      <dt className="text-xs font-medium text-muted-foreground">{t("policy.versions.moduleHash")}</dt>
                      <dd className="break-all font-mono text-xs">{activePolicyVersion.module_sha256}</dd>
                    </div>
                    <div>
                      <dt className="text-xs font-medium text-muted-foreground">{t("policy.versions.activated")}</dt>
                      <dd>{activePolicyVersion.activated_at ? formatDate(activePolicyVersion.activated_at) : t("policy.versions.notActivated")}</dd>
                    </div>
                  </dl>
                ) : (
                  <p className="mt-3 text-muted-foreground">{t("policy.versions.noActive")}</p>
                )}
              </section>
            </div>

            {policyVersionLoading && <LoadingState>{t("policy.versions.loading")}</LoadingState>}
            {policyVersionError && <ErrorState title={t("policy.versions.unavailableTitle")}>{policyVersionError}</ErrorState>}
            {policyVersionNotice && (
              <p className="rounded-md border border-border bg-muted p-3 text-sm" role="status">
                {policyVersionNotice}
              </p>
            )}

            <ScrollableTableRegion label={t("policy.versions.tableLabel")}>
              <table className="min-w-full text-left text-sm" aria-label={t("policy.versions.tableLabel")}>
                <thead className="border-b border-border text-xs text-muted-foreground">
                  <tr>
                    <th className="px-3 py-2">{t("policy.versions.descriptionLabel")}</th>
                    <th className="px-3 py-2">{t("policy.versions.status")}</th>
                    <th className="px-3 py-2">{t("policy.versions.hash")}</th>
                    <th className="px-3 py-2">{t("policy.versions.change")}</th>
                    <th className="px-3 py-2">{t("policy.versions.actions")}</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {policyVersions.map((version) => (
                    <tr key={version.id}>
                      <td className="max-w-sm px-3 py-2">{version.description || version.id}</td>
                      <td className="px-3 py-2">{version.status}</td>
                      <td className="px-3 py-2 font-mono text-xs">{version.module_sha256.slice(0, 12)}</td>
                      <td className="px-3 py-2">{version.change_ref || "-"}</td>
                      <td className="px-3 py-2">
                        <div className="flex flex-wrap gap-2">
                          <Button
                            type="button"
                            variant="outline"
                            onClick={() => void activatePolicyVersion(version)}
                            disabled={version.active || policyVersionAction === `activate:${version.id}`}
                          >
                            {policyVersionAction === `activate:${version.id}` ? t("policy.versions.activating") : t("policy.versions.activate")}
                          </Button>
                          <Button
                            type="button"
                            variant="outline"
                            onClick={() => void rollbackPolicyVersion(version)}
                            disabled={!version.active || policyVersionAction === `rollback:${version.id}`}
                          >
                            {policyVersionAction === `rollback:${version.id}` ? t("policy.versions.rollingBack") : t("policy.versions.rollback")}
                          </Button>
                        </div>
                      </td>
                    </tr>
                  ))}
                  {policyVersions.length === 0 && (
                    <tr>
                      <td className="px-3 py-4 text-muted-foreground" colSpan={5}>
                        {t("policy.versions.empty")}
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </ScrollableTableRegion>
          </section>
        </div>
      </PolicyDetails>

      <PolicyDetails
        title={t("policy.design.disclosure.compliance")}
        open={open.compliance}
        onToggle={(value) => setOpen((current) => ({ ...current, compliance: value }))}
      >
        <div className="grid min-w-0 gap-6">
          <p className="max-w-3xl text-sm text-muted-foreground">{t("policy.design.complianceHelp")}</p>
          <section aria-labelledby="compliance-heading" className="grid min-w-0 grid-cols-[minmax(0,1fr)] gap-4 border-y border-border py-4">
            <div>
              <h2 id="compliance-heading" className="text-title font-semibold">
                {t("policy.compliance.heading")}
              </h2>
              <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{t("policy.compliance.description")}</p>
            </div>
            <div className="flex flex-wrap gap-2" aria-label={t("policy.compliance.frameworkGroup")}>
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

            {evidencePackLoading && <LoadingState>{t("policy.compliance.loadingEvidencePack")}</LoadingState>}
            {evidencePackError && <ErrorState title={t("policy.compliance.evidencePackUnavailable")}>{evidencePackError}</ErrorState>}
            {evidencePack && <ComplianceEvidencePackPanel pack={evidencePack} label={frameworkLabel(evidencePack.framework, t)} />}

            {reportLoading && <LoadingState>{t("policy.reporting.loading")}</LoadingState>}
            {reportError && <ErrorState title={t("policy.reporting.unavailableTitle")}>{reportError}</ErrorState>}
            {inventoryReport && (
              <ComplianceInventoryReportPanel
                report={inventoryReport}
                schedules={reportSchedules}
                scheduleAction={scheduleAction}
                onToggleSchedule={(schedule) => void toggleReportSchedule(schedule)}
              />
            )}
            {nhiComplianceReport && <NHIComplianceReportPanel report={nhiComplianceReport} />}

            <form
              className="grid min-w-0 grid-cols-[minmax(0,1fr)] gap-3 rounded-md border border-border p-4 text-sm lg:grid-cols-6"
              onSubmit={(event) => void createReportSchedule(event)}
            >
              <label className="grid gap-1 lg:col-span-2">
                <span className="font-medium">{t("policy.reporting.schedule")}</span>
                <input
                  className="min-h-10 rounded-md border border-border bg-background px-3 py-2"
                  value={scheduleForm.name}
                  onChange={(event) => {
                    setSchedulePreview(null);
                    setScheduleForm((current) => ({ ...current, name: event.target.value }));
                  }}
                />
              </label>
              <label className="grid gap-1">
                <span className="font-medium">{t("policy.reporting.framework")}</span>
                <select
                  className="min-h-10 rounded-md border border-border bg-background px-3 py-2"
                  value={scheduleForm.framework}
                  onChange={(event) => {
                    setSchedulePreview(null);
                    setScheduleForm((current) => ({ ...current, framework: event.target.value as ComplianceFramework }));
                  }}
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
                  className="min-h-10 rounded-md border border-border bg-background px-3 py-2"
                  value={scheduleForm.reportType}
                  onChange={(event) => {
                    setSchedulePreview(null);
                    setScheduleForm((current) => ({ ...current, reportType: event.target.value as ComplianceReportType }));
                  }}
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
                  className="min-h-10 rounded-md border border-border bg-background px-3 py-2"
                  inputMode="numeric"
                  pattern="[0-9]*"
                  value={scheduleForm.intervalDays}
                  onChange={(event) => {
                    setSchedulePreview(null);
                    setScheduleForm((current) => ({ ...current, intervalDays: event.target.value }));
                  }}
                />
              </label>
              <label className="grid gap-1">
                <span className="font-medium">{t("policy.reporting.recipientRef")}</span>
                <input
                  className="min-h-10 rounded-md border border-border bg-background px-3 py-2"
                  value={scheduleForm.recipientRef}
                  onChange={(event) => {
                    setSchedulePreview(null);
                    setScheduleForm((current) => ({ ...current, recipientRef: event.target.value }));
                  }}
                />
              </label>
              <div className="flex flex-wrap items-end gap-2 lg:col-span-6">
                <Button type="button" variant="outline" onClick={() => void previewReportSchedule()} disabled={scheduleAction !== null}>
                  {scheduleAction === "preview" ? t("policy.reporting.reviewing") : t("policy.reporting.review")}
                </Button>
                <Button type="submit" disabled={scheduleAction !== null || !schedulePreview?.ready}>
                  {scheduleAction === "create" ? t("policy.reporting.scheduling") : t("policy.reporting.createSchedule")}
                </Button>
              </div>
            </form>
            {schedulePreview && (
              <section className="rounded-md border border-border bg-muted/40 p-4 text-sm" aria-labelledby="compliance-schedule-review-heading">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <h3 id="compliance-schedule-review-heading" className="font-semibold">
                      {t("policy.reporting.reviewHeading")}
                    </h3>
                    <p className="mt-1 text-muted-foreground">{t("policy.reporting.noStateChanged")}</p>
                  </div>
                  <span className="rounded-md border border-border bg-background px-2 py-1 text-xs font-medium">
                    {schedulePreview.ready ? t("policy.reporting.ready") : t("policy.reporting.setupNeeded")}
                  </span>
                </div>
                <dl className="mt-3 grid gap-3 sm:grid-cols-2">
                  <div>
                    <dt className="text-xs font-medium text-muted-foreground">{t("policy.reporting.fingerprint")}</dt>
                    <dd className="mt-1 break-all font-mono text-xs">{schedulePreview.request_fingerprint}</dd>
                  </div>
                  <div>
                    <dt className="text-xs font-medium text-muted-foreground">{t("policy.reporting.permission")}</dt>
                    <dd className="mt-1 font-mono text-xs">{schedulePreview.required_permission}</dd>
                  </div>
                </dl>
                <div className="mt-3 grid gap-3 lg:grid-cols-3">
                  <EvidenceList title={t("policy.reporting.executeWrites")} items={schedulePreview.execute_writes} />
                  <EvidenceList title={t("policy.reporting.recovery")} items={schedulePreview.recovery_steps} />
                  <EvidenceList title={t("policy.reporting.verify")} items={schedulePreview.verification_steps} />
                </div>
                <p className="mt-3 text-xs text-muted-foreground">{schedulePreview.secret_data_handling}</p>
              </section>
            )}
            {reportNotice && (
              <p className="rounded-md border border-border bg-muted p-3 text-sm" role="status">
                {reportNotice}
              </p>
            )}

            <div className="flex flex-wrap items-center gap-3 border-t border-border pt-4">
              <Button type="button" onClick={() => void exportComplianceEvidence()} disabled={exporting}>
                {exporting ? translateNow("source.exporting.639e45361b") : translateNow("source.export.audit.evidence.c3f3b4ad52")}
              </Button>
              <Link className="text-sm underline" to="/audit">
                {translateNow("source.open.audit.explorer.e155d6131a")}
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
        </div>
      </PolicyDetails>

      <PolicyDetails
        title={t("policy.design.disclosure.approvals")}
        open={open.approvals}
        onToggle={(value) => setOpen((current) => ({ ...current, approvals: value }))}
      >
        <div className="grid min-w-0 gap-6">
          <p className="max-w-3xl text-sm text-muted-foreground">{t("policy.design.approvalsHelp")}</p>
          <section aria-labelledby="nhi-access-review-heading" className="grid min-w-0 grid-cols-[minmax(0,1fr)] gap-4 border-y border-border py-4">
            <div>
              <h2 id="nhi-access-review-heading" className="text-title font-semibold">
                {translateNow("source.nhi.access.certification.3fd94ffdff")}
              </h2>
              <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{translateNow("source.campaigns.certify.non.human.identity.acces.5d99189fbe")}</p>
            </div>

            <form className="grid gap-3 rounded-md border border-border p-4 text-sm lg:grid-cols-6" onSubmit={(event) => void startNHIReviewCampaign(event)}>
              <label className="grid gap-1 lg:col-span-2">
                <span className="font-medium">{translateNow("source.campaign.268286d2ef")}</span>
                <input
                  className="min-h-10 rounded-md border border-border bg-background px-3 py-2"
                  value={reviewForm.name}
                  onChange={(event) => setReviewForm((current) => ({ ...current, name: event.target.value }))}
                />
              </label>
              <label className="grid gap-1 lg:col-span-2">
                <span className="font-medium">{translateNow("source.reviewer.d29f46772c")}</span>
                <input
                  className="min-h-10 rounded-md border border-border bg-background px-3 py-2"
                  placeholder={translateNow("source.current.session.subject.1f6510ea4d")}
                  value={reviewForm.reviewer}
                  onChange={(event) => setReviewForm((current) => ({ ...current, reviewer: event.target.value }))}
                />
              </label>
              <label className="grid gap-1">
                <span className="font-medium">{translateNow("source.risk.0711a8d636")}</span>
                <select
                  className="min-h-10 rounded-md border border-border bg-background px-3 py-2"
                  value={reviewForm.risk}
                  onChange={(event) => setReviewForm((current) => ({ ...current, risk: event.target.value }))}
                >
                  <option value="low">{translateNow("source.low.f793de205e")}</option>
                  <option value="medium">{translateNow("source.medium.8e588cd187")}</option>
                  <option value="high">{translateNow("source.high.c4ebc6d4a5")}</option>
                  <option value="critical">{translateNow("source.critical.427dd2969b")}</option>
                </select>
              </label>
              <div className="flex items-end">
                <Button className="w-full" type="submit" disabled={reviewAction === "start" || !reviewForm.name.trim() || !reviewForm.nhiId.trim()}>
                  {reviewAction === "start" ? translateNow("source.starting.82b93630a9") : translateNow("source.start.campaign.bfdb5d43fb")}
                </Button>
              </div>
              <label className="grid gap-1 lg:col-span-2">
                <span className="font-medium">{translateNow("source.nhi.id.52919bf0d5")}</span>
                <input
                  className="min-h-10 rounded-md border border-border bg-background px-3 py-2"
                  value={reviewForm.nhiId}
                  onChange={(event) => setReviewForm((current) => ({ ...current, nhiId: event.target.value }))}
                />
              </label>
              <label className="grid gap-1 lg:col-span-2">
                <span className="font-medium">{translateNow("source.display.name.2b7f6a84de")}</span>
                <input
                  className="min-h-10 rounded-md border border-border bg-background px-3 py-2"
                  value={reviewForm.displayName}
                  onChange={(event) => setReviewForm((current) => ({ ...current, displayName: event.target.value }))}
                />
              </label>
              <label className="grid gap-1 lg:col-span-2">
                <span className="font-medium">{translateNow("source.evidence.refs.edfa905c2f")}</span>
                <input
                  className="min-h-10 rounded-md border border-border bg-background px-3 py-2"
                  value={reviewForm.evidenceRefs}
                  onChange={(event) => setReviewForm((current) => ({ ...current, evidenceRefs: event.target.value }))}
                />
              </label>
              <label className="grid gap-1 lg:col-span-3">
                <span className="font-medium">{translateNow("source.resource.eb7a842ff9")}</span>
                <input
                  className="min-h-10 rounded-md border border-border bg-background px-3 py-2"
                  value={reviewForm.resource}
                  onChange={(event) => setReviewForm((current) => ({ ...current, resource: event.target.value }))}
                />
              </label>
              <label className="grid gap-1 lg:col-span-3">
                <span className="font-medium">{translateNow("source.entitlement.0d8f0b2d3a")}</span>
                <input
                  className="min-h-10 rounded-md border border-border bg-background px-3 py-2"
                  value={reviewForm.entitlement}
                  onChange={(event) => setReviewForm((current) => ({ ...current, entitlement: event.target.value }))}
                />
              </label>
            </form>

            {reviewLoading && <LoadingState>{translateNow("source.loading.nhi.access.reviews.cd87c4f77e")}</LoadingState>}
            {reviewError && <ErrorState title={translateNow("source.nhi.access.review.unavailable.7f4d6bdefd")}>{reviewError}</ErrorState>}
            {reviewNotice && (
              <p className="rounded-md border border-border bg-muted p-3 text-sm" role="status">
                {reviewNotice}
              </p>
            )}

            <div className="grid gap-4 xl:grid-cols-[18rem_minmax(0,1fr)]">
              <section aria-label={translateNow("source.nhi.access.review.campaigns.873389dac9")} className="rounded-md border border-border">
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
                          {campaign.status} · {campaign.pending_count} {translateNow("source.pending.64e6bbf0cf")} {campaign.certified_count}{" "}
                          {translateNow("source.certified.3d4b25dc0b")} {campaign.revoked_count} {translateNow("source.revoked.4bb47f186d")}
                        </span>
                      </button>
                    ))}
                  </div>
                ) : (
                  <p className="p-3 text-sm text-muted-foreground">{translateNow("source.no.access.review.campaigns.5e5e0fbd56")}</p>
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

          <section aria-labelledby="access-change-heading" className="grid min-w-0 grid-cols-[minmax(0,1fr)] gap-4 border-y border-border py-4">
            <div>
              <h2 id="access-change-heading" className="text-title font-semibold">
                {t("policy.accessChange.heading")}
              </h2>
              <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{t("policy.accessChange.description")}</p>
            </div>

            <form className="grid gap-3 rounded-md border border-border p-4 text-sm lg:grid-cols-6" onSubmit={(event) => void createAccessChangeRequest(event)}>
              <label className="grid gap-1">
                <span className="font-medium">{t("policy.accessChange.action")}</span>
                <select
                  className="min-h-10 rounded-md border border-border bg-background px-3 py-2"
                  value={accessForm.requestedAction}
                  onChange={(event) =>
                    setAccessForm((current) => ({ ...current, requestedAction: event.target.value as AccessChangeRequest["requested_action"] }))
                  }
                >
                  {["grant", "modify", "revoke", "rotate", "deploy", "break_glass"].map((action) => (
                    <option key={action} value={action}>
                      {action}
                    </option>
                  ))}
                </select>
              </label>
              <label className="grid gap-1">
                <span className="font-medium">{t("policy.accessChange.risk")}</span>
                <select
                  className="min-h-10 rounded-md border border-border bg-background px-3 py-2"
                  value={accessForm.risk}
                  onChange={(event) => setAccessForm((current) => ({ ...current, risk: event.target.value }))}
                >
                  <option value="low">{translateNow("source.low.f793de205e")}</option>
                  <option value="medium">{translateNow("source.medium.8e588cd187")}</option>
                  <option value="high">{translateNow("source.high.c4ebc6d4a5")}</option>
                  <option value="critical">{translateNow("source.critical.427dd2969b")}</option>
                </select>
              </label>
              <label className="grid gap-1">
                <span className="font-medium">{t("policy.accessChange.approvals")}</span>
                <input
                  className="min-h-10 rounded-md border border-border bg-background px-3 py-2"
                  inputMode="numeric"
                  pattern="[0-9]*"
                  value={accessForm.requiredApprovals}
                  onChange={(event) => setAccessForm((current) => ({ ...current, requiredApprovals: event.target.value }))}
                />
              </label>
              <label className="grid gap-1 lg:col-span-3">
                <span className="font-medium">{t("policy.accessChange.changeRef")}</span>
                <input
                  className="min-h-10 rounded-md border border-border bg-background px-3 py-2"
                  value={accessForm.changeRef}
                  onChange={(event) => setAccessForm((current) => ({ ...current, changeRef: event.target.value }))}
                />
              </label>
              <label className="grid gap-1 lg:col-span-2">
                <span className="font-medium">{t("policy.accessChange.nhiId")}</span>
                <input
                  className="min-h-10 rounded-md border border-border bg-background px-3 py-2"
                  value={accessForm.nhiId}
                  onChange={(event) => setAccessForm((current) => ({ ...current, nhiId: event.target.value }))}
                />
              </label>
              <label className="grid gap-1 lg:col-span-2">
                <span className="font-medium">{t("policy.accessChange.nhiKind")}</span>
                <input
                  className="min-h-10 rounded-md border border-border bg-background px-3 py-2"
                  value={accessForm.nhiKind}
                  onChange={(event) => setAccessForm((current) => ({ ...current, nhiKind: event.target.value }))}
                />
              </label>
              <label className="grid gap-1 lg:col-span-2">
                <span className="font-medium">{t("policy.accessChange.displayName")}</span>
                <input
                  className="min-h-10 rounded-md border border-border bg-background px-3 py-2"
                  value={accessForm.displayName}
                  onChange={(event) => setAccessForm((current) => ({ ...current, displayName: event.target.value }))}
                />
              </label>
              <label className="grid gap-1 lg:col-span-3">
                <span className="font-medium">{t("policy.accessChange.resource")}</span>
                <input
                  className="min-h-10 rounded-md border border-border bg-background px-3 py-2"
                  value={accessForm.resource}
                  onChange={(event) => setAccessForm((current) => ({ ...current, resource: event.target.value }))}
                />
              </label>
              <label className="grid gap-1 lg:col-span-3">
                <span className="font-medium">{t("policy.accessChange.entitlement")}</span>
                <input
                  className="min-h-10 rounded-md border border-border bg-background px-3 py-2"
                  value={accessForm.entitlement}
                  onChange={(event) => setAccessForm((current) => ({ ...current, entitlement: event.target.value }))}
                />
              </label>
              <label className="grid gap-1 lg:col-span-3">
                <span className="font-medium">{t("policy.accessChange.changeUrl")}</span>
                <input
                  className="min-h-10 rounded-md border border-border bg-background px-3 py-2"
                  value={accessForm.changeUrl}
                  onChange={(event) => setAccessForm((current) => ({ ...current, changeUrl: event.target.value }))}
                />
              </label>
              <label className="grid gap-1 lg:col-span-3">
                <span className="font-medium">{t("policy.accessChange.evidenceRefs")}</span>
                <input
                  className="min-h-10 rounded-md border border-border bg-background px-3 py-2"
                  value={accessForm.evidenceRefs}
                  onChange={(event) => setAccessForm((current) => ({ ...current, evidenceRefs: event.target.value }))}
                />
              </label>
              <label className="grid gap-1 lg:col-span-5">
                <span className="font-medium">{t("policy.accessChange.reason")}</span>
                <input
                  className="min-h-10 rounded-md border border-border bg-background px-3 py-2"
                  value={accessForm.reason}
                  onChange={(event) => setAccessForm((current) => ({ ...current, reason: event.target.value }))}
                />
              </label>
              <div className="flex items-end">
                <Button
                  className="w-full"
                  type="submit"
                  disabled={accessAction === "create" || !accessForm.nhiId.trim() || !accessForm.changeRef.trim() || !accessForm.reason.trim()}
                >
                  {accessAction === "create" ? t("policy.accessChange.opening") : t("policy.accessChange.openRequest")}
                </Button>
              </div>
            </form>

            {accessLoading && <LoadingState>{t("policy.accessChange.loading")}</LoadingState>}
            {accessError && <ErrorState title={t("policy.accessChange.unavailableTitle")}>{accessError}</ErrorState>}
            {accessNotice && (
              <p className="rounded-md border border-border bg-muted p-3 text-sm" role="status">
                {accessNotice}
              </p>
            )}

            <div className="grid gap-4 xl:grid-cols-[18rem_minmax(0,1fr)]">
              <section aria-label={t("policy.accessChange.listLabel")} className="rounded-md border border-border">
                {accessRequests.length > 0 ? (
                  <div className="divide-y divide-border">
                    {accessRequests.map((request) => (
                      <button
                        key={request.id}
                        className={`grid w-full gap-1 px-3 py-3 text-left hover:bg-muted ${activeAccessRequest?.id === request.id ? "bg-muted" : ""}`}
                        type="button"
                        onClick={() => void selectAccessChangeRequest(request.id)}
                      >
                        <span className="font-medium">{request.display_name}</span>
                        <span className="text-xs text-muted-foreground">
                          {request.status} · {request.approval_count}/{request.required_approvals} · {request.change_system}
                        </span>
                      </button>
                    ))}
                  </div>
                ) : (
                  <p className="p-3 text-sm text-muted-foreground">{t("policy.accessChange.empty")}</p>
                )}
              </section>

              {activeAccessRequest && (
                <AccessChangeRequestPanel
                  request={activeAccessRequest}
                  accessAction={accessAction}
                  decisionReasons={accessDecisionReasons}
                  onDecision={decideAccessChangeRequest}
                  onReasonChange={setAccessDecisionReasons}
                />
              )}
            </div>
          </section>
        </div>
      </PolicyDetails>

      <PolicyDetails title={t("policy.design.disclosure.test")} open={open.test} onToggle={(value) => setOpen((current) => ({ ...current, test: value }))}>
        <div className="grid min-w-0 gap-6">
          <p className="max-w-3xl text-sm text-muted-foreground">{t("policy.design.testHelp")}</p>
          <section aria-labelledby="policy-dry-run-heading" className="grid min-w-0 grid-cols-[minmax(0,1fr)] gap-4 border-y border-border py-4">
            <div>
              <h2 id="policy-dry-run-heading" className="text-title font-semibold">
                {t("policy.dryRun.heading")}
              </h2>
              <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{t("policy.dryRun.description")}</p>
            </div>
            <form
              aria-label={t("policy.dryRun.formLabel")}
              className="grid gap-4 rounded-md border border-border p-4"
              onSubmit={(event) => void runPolicyDryRun(event)}
            >
              <div className="flex flex-wrap gap-2" role="group" aria-label={t("policy.dryRun.kindLabel")}>
                <Button
                  type="button"
                  variant={dryRunKind === "lifecycle" ? "default" : "outline"}
                  aria-pressed={dryRunKind === "lifecycle"}
                  onClick={() => selectDryRunKind("lifecycle")}
                >
                  {t("policy.dryRun.lifecycle")}
                </Button>
                <Button
                  type="button"
                  variant={dryRunKind === "abac" ? "default" : "outline"}
                  aria-pressed={dryRunKind === "abac"}
                  onClick={() => selectDryRunKind("abac")}
                >
                  {t("policy.dryRun.abac")}
                </Button>
              </div>
              <div className="grid gap-4 xl:grid-cols-2">
                <label className="grid gap-1 text-sm">
                  <span className="font-medium">{t("policy.dryRun.moduleLabel")}</span>
                  <textarea
                    className="min-h-80 resize-y rounded-md border border-border bg-background px-3 py-2 font-mono text-xs"
                    spellCheck={false}
                    value={dryRunModule}
                    onChange={(event) => setDryRunModule(event.target.value)}
                  />
                </label>
                <label className="grid gap-1 text-sm">
                  <span className="font-medium">{t("policy.dryRun.inputLabel")}</span>
                  <textarea
                    className="min-h-80 resize-y rounded-md border border-border bg-background px-3 py-2 font-mono text-xs"
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
        </div>
      </PolicyDetails>

      <Dialog
        open={ruleDialogOpen}
        onClose={() => setRuleDialogOpen(false)}
        titleId="create-rule-heading"
        descriptionId="create-rule-description"
        initialFocusRef={ruleDescriptionRef}
        panelAnimation="none"
        panelClassName="fixed left-1/2 top-1/2 grid max-h-[calc(100dvh-2rem)] w-[min(94vw,48rem)] -translate-x-1/2 -translate-y-1/2 gap-4 overflow-y-auto overscroll-contain rounded-panel border border-border bg-card p-5 shadow-elevation3"
      >
        <form className="grid min-w-0 gap-4 text-sm" onSubmit={(event) => void createPolicyVersion(event)}>
          <div>
            <h2 id="create-rule-heading" className="text-title font-semibold">
              {t("policy.design.create")}
            </h2>
            <p id="create-rule-description" className="mt-1 max-w-3xl text-sm text-muted-foreground">
              {t("policy.design.createHelp")}
            </p>
          </div>
          <div className="grid min-w-0 gap-3 md:grid-cols-2">
            <label className="grid min-w-0 gap-1 font-medium">
              {t("policy.versions.descriptionLabel")}
              <input
                ref={ruleDescriptionRef}
                className="ui-input font-normal"
                value={policyVersionForm.description}
                onChange={(event) => setPolicyVersionForm((current) => ({ ...current, description: event.target.value }))}
                required
              />
            </label>
            <label className="grid min-w-0 gap-1 font-medium">
              {t("policy.versions.changeRef")}
              <input
                className="ui-input font-mono text-xs font-normal"
                value={policyVersionForm.changeRef}
                onChange={(event) => setPolicyVersionForm((current) => ({ ...current, changeRef: event.target.value }))}
              />
            </label>
          </div>
          <label className="grid min-w-0 gap-1 font-medium">
            {t("policy.versions.evidenceRefs")}
            <input
              className="ui-input font-mono text-xs font-normal"
              value={policyVersionForm.evidenceRefs}
              onChange={(event) => setPolicyVersionForm((current) => ({ ...current, evidenceRefs: event.target.value }))}
            />
          </label>
          <label className="grid min-w-0 gap-1 font-medium">
            {t("policy.versions.lifecycleModule")}
            <textarea
              className="ui-input min-h-64 font-mono text-xs font-normal"
              spellCheck={false}
              value={policyVersionForm.module}
              onChange={(event) => setPolicyVersionForm((current) => ({ ...current, module: event.target.value }))}
            />
          </label>
          <p className="text-sm text-muted-foreground">{t("policy.design.moduleHelp")}</p>
          <div className="flex flex-wrap justify-end gap-2">
            <Button type="button" variant="ghost" onClick={() => setRuleDialogOpen(false)}>
              {translateNow("source.cancel.19766ed6cc")}
            </Button>
            <Button type="submit" disabled={policyVersionAction === "create" || !policyVersionForm.module.trim()}>
              {policyVersionAction === "create" ? t("policy.versions.authoring") : t("policy.design.create")}
            </Button>
          </div>
        </form>
      </Dialog>
    </section>
  );
}

function PolicyDetails({ title, open, onToggle, children }: { title: string; open: boolean; onToggle: (open: boolean) => void; children: ReactNode }) {
  return (
    <details className="rounded-panel border border-border bg-card shadow-elevation1" open={open} onToggle={(event) => onToggle(event.currentTarget.open)}>
      <summary className="cursor-pointer px-4 py-3 font-semibold text-foreground">{title}</summary>
      <div className="border-t border-border p-4">{open ? children : null}</div>
    </details>
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
    <section aria-labelledby="policy-dry-run-result-heading" className="ui-panel min-w-0 p-comfortable text-sm" role="status">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h3 id="policy-dry-run-result-heading" className="text-title font-semibold">
            {t("policy.dryRun.resultHeading")}
          </h3>
          <p className="mt-1 text-muted-foreground">
            {decision}
            {result.reason ? translateNow("source.value1.92dd63d2f3", { value1: result.reason }) : ""}
            {result.error ? translateNow("source.value1.92dd63d2f3", { value1: result.error }) : ""}
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
        <ScrollableTableRegion className="mt-4" label={t("policy.dryRun.traceCaption")}>
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
        </ScrollableTableRegion>
      )}
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
    <section aria-labelledby="nhi-access-review-detail-heading" className="ui-panel min-w-0 p-comfortable text-sm">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h3 id="nhi-access-review-detail-heading" className="text-title font-semibold">
            {campaign.name}
          </h3>
          <p className="mt-1 text-muted-foreground">
            {campaign.status} {translateNow("source.requested.by.42aea0b1dd")} {campaign.requested_by} {translateNow("source.reviewer.63c2827d64")}{" "}
            {campaign.reviewer_subject}
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
        <ScrollableTableRegion className="mt-4" label={translateNow("source.nhi.access.review.items.d360cac314")}>
          <table className="ui-table min-w-[64rem]">
            <caption className="sr-only">{translateNow("source.nhi.access.review.items.d360cac314")}</caption>
            <thead>
              <tr>
                <th scope="col">{translateNow("source.identity.999f23fcd7")}</th>
                <th scope="col">{translateNow("source.resource.eb7a842ff9")}</th>
                <th scope="col">{translateNow("source.evidence.03867aea70")}</th>
                <th scope="col">{translateNow("source.status.920e413c7d")}</th>
                <th scope="col">{translateNow("source.decision.640ae4baf9")}</th>
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
                    <td>{item.evidence_refs.join(", ") || translateNow("source.no.evidence.ref.0697e8fb68")}</td>
                    <td>{item.status}</td>
                    <td>
                      {item.status === "pending" ? (
                        <div className="grid min-w-60 gap-2">
                          <input
                            className="min-h-10 rounded-md border border-border bg-background px-3 py-2"
                            placeholder={translateNow("source.reason.for.revoke.or.exception.5df8423828")}
                            value={reason}
                            onChange={(event) => onReasonChange((current) => ({ ...current, [item.item_id]: event.target.value }))}
                          />
                          <div className="flex flex-wrap gap-2">
                            <Button type="button" variant="outline" disabled={busy} onClick={() => void onDecision(item, "certified")}>
                              {translateNow("source.certify.c1567c2908")}
                            </Button>
                            <Button type="button" variant="outline" disabled={busy || !reason.trim()} onClick={() => void onDecision(item, "revoked")}>
                              {translateNow("source.revoke.87e6d00bbf")}
                            </Button>
                            <Button type="button" variant="outline" disabled={busy || !reason.trim()} onClick={() => void onDecision(item, "exception")}>
                              {translateNow("source.exception.b4fe3d529d")}
                            </Button>
                          </div>
                        </div>
                      ) : (
                        <div>
                          <p>{item.decision_reason || translateNow("source.recorded.c7175fa7a0")}</p>
                          {item.decision_by && <p className="mt-1 text-xs text-muted-foreground">{item.decision_by}</p>}
                        </div>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </ScrollableTableRegion>
      ) : (
        <p className="mt-4 rounded-md border border-border p-3 text-muted-foreground">{translateNow("source.no.item.details.loaded.e93e8c8e0d")}</p>
      )}
    </section>
  );
}

function AccessChangeRequestPanel({
  accessAction,
  decisionReasons,
  onDecision,
  onReasonChange,
  request,
}: {
  request: AccessChangeRequest;
  accessAction: string | null;
  decisionReasons: Record<string, string>;
  onDecision: (request: AccessChangeRequest, decision: AccessChangeDecisionRequest["decision"]) => Promise<void>;
  onReasonChange: (value: Record<string, string> | ((current: Record<string, string>) => Record<string, string>)) => void;
}) {
  const { t } = useTranslation();
  const decisions = request.decisions ?? [];
  const reason = decisionReasons[request.id] ?? "";
  const busy = accessAction === "create" || (accessAction?.startsWith(`${request.id}:`) ?? false);
  const changeHref = safeHref(request.change_url);
  const approve = () => {
    void onDecision(request, "approved");
  };
  const deny = () => {
    void onDecision(request, "denied");
  };

  return (
    <section aria-labelledby="access-change-detail-heading" className="ui-panel min-w-0 p-comfortable text-sm">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h3 id="access-change-detail-heading" className="text-title font-semibold">
            {request.display_name}
          </h3>
          <p className="mt-1 text-muted-foreground">
            {request.requested_action} · {request.status} {translateNow("source.requested.by.42aea0b1dd")} {request.requester_subject}
          </p>
        </div>
        <span className="rounded-md border border-border px-3 py-2 font-mono text-xs">{request.id}</span>
      </div>

      <dl className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <Metric label={t("policy.accessChange.approvals")} value={`${request.approval_count} / ${request.required_approvals}`} />
        <Metric label={t("policy.accessChange.risk")} value={request.risk} />
        <Metric label={t("policy.accessChange.changeSystem")} value={request.change_system} />
        <Metric label={t("policy.accessChange.status")} value={request.status} />
        <Metric label={t("policy.accessChange.nhi")} value={`${request.nhi_kind}: ${request.nhi_id}`} mono />
        <Metric label={t("policy.accessChange.resource")} value={request.resource} mono />
        <Metric label={t("policy.accessChange.entitlement")} value={request.entitlement} mono />
        <Metric label={t("policy.accessChange.changeRef")} value={request.change_ref} mono />
      </dl>

      <div className="mt-4 grid gap-3 lg:grid-cols-2">
        <EvidenceList title={t("policy.accessChange.requestEvidence")} items={request.evidence_refs} />
        <section aria-label={t("policy.accessChange.changeReason")} className="rounded-md border border-border p-3">
          <p className="font-medium">{t("policy.accessChange.reason")}</p>
          <p className="mt-2 text-muted-foreground">{request.reason}</p>
          {changeHref && (
            <a
              className="mt-2 block break-all text-sm underline"
              href={changeHref.href}
              rel={changeHref.external ? "noopener noreferrer" : undefined}
              target={changeHref.external ? "_blank" : undefined}
            >
              {changeHref.href}
            </a>
          )}
        </section>
      </div>

      {request.status === "pending" ? (
        <div className="mt-4 grid gap-2 rounded-md border border-border p-3">
          <label className="grid gap-1">
            <span className="font-medium">{t("policy.accessChange.decisionReason")}</span>
            <input
              className="min-h-10 rounded-md border border-border bg-background px-3 py-2"
              placeholder={t("policy.accessChange.requiredForDenial")}
              value={reason}
              onChange={(event) => onReasonChange((current) => ({ ...current, [request.id]: event.target.value }))}
            />
          </label>
          <div className="flex flex-wrap gap-2">
            <Button type="button" variant="outline" disabled={busy} onClick={approve}>
              {t("policy.accessChange.approve")}
            </Button>
            <Button type="button" variant="outline" disabled={busy || !reason.trim()} onClick={deny}>
              {t("policy.accessChange.deny")}
            </Button>
          </div>
        </div>
      ) : (
        <p className="mt-4 rounded-md border border-border p-3 text-muted-foreground">{t("policy.accessChange.terminal")}</p>
      )}

      {decisions.length > 0 && (
        <ScrollableTableRegion className="mt-4" label={t("policy.accessChange.decisionsCaption")}>
          <table className="ui-table min-w-[48rem]">
            <caption className="sr-only">{t("policy.accessChange.decisionsCaption")}</caption>
            <thead>
              <tr>
                <th scope="col">{t("policy.accessChange.approver")}</th>
                <th scope="col">{t("policy.accessChange.decision")}</th>
                <th scope="col">{t("policy.accessChange.reason")}</th>
                <th scope="col">{t("policy.accessChange.evidence")}</th>
              </tr>
            </thead>
            <tbody>
              {decisions.map((decision) => (
                <tr key={`${decision.request_id}:${decision.approver_subject}`} className="align-top">
                  <td className="break-all">{decision.approver_subject}</td>
                  <td>{decision.decision}</td>
                  <td>{decision.reason || t("policy.accessChange.recorded")}</td>
                  <td>{decision.decision_evidence_refs.join(", ") || t("policy.accessChange.noEvidenceRef")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </ScrollableTableRegion>
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
    <div role="group" aria-label={title} className="rounded-md border border-border p-3">
      <p className="font-medium">{title}</p>
      {items.length > 0 ? (
        <ul className="mt-2 grid gap-1 text-muted-foreground">
          {items.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
      ) : (
        <p className="mt-2 text-muted-foreground">{translateNow("source.no.labels.in.this.pack.afb9ef5039")}</p>
      )}
    </div>
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function frameworkLabel(framework: ComplianceFramework, t: (key: MessageKey) => string): string {
  const item = complianceFrameworks.find((candidate) => candidate.id === framework);
  if (!item) return framework;
  return t(item.labelKey);
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
