import { useState } from "react";
import { Link } from "react-router-dom";
import { UnavailableState } from "@/components/StatePrimitives";
import { Button } from "@/components/ui/button";
import { api, ApiError } from "@/lib/api";

const policyOutcomes = [
  {
    state: "Allowed",
    meaning: "The bound profile and deployed Rego policy explicitly allow the requested issue, deploy, or revoke action.",
    evidence: "policy.decision allow plus the normal lifecycle event",
  },
  {
    state: "Denied",
    meaning: "Default-deny wins when no rule allows the action, RA scope is wrong, approval is missing, or the profile rejects the request.",
    evidence: "policy.decision deny or issuance.profile_evaluated deny",
  },
  {
    state: "Policy error",
    meaning: "A compile or evaluation error fails closed. The browser should show the backend problem detail, not retry as an allow.",
    evidence: "problem+json denial and policy.decision error",
  },
  {
    state: "Overload 503",
    meaning: "The policy bulkhead sheds work when saturated. Operators see a 503 and retry later; issuance is not allowed through.",
    evidence: "503 problem+json, Retry-After when served",
  },
];

const notificationChannels = [
  {
    channel: "Slack",
    reference: "secret://notify/slack/prod:****",
    events: "certificate.expiring, approval.requested",
    delivery: "duplicate-safe delivery needs outbox status",
    status: "config and test delivery blocked on BACKEND-NOTIFY",
  },
  {
    channel: "Microsoft Teams",
    reference: "secret://notify/teams/prod:****",
    events: "incident.declared, connector.failed",
    delivery: "webhook response body is redacted",
    status: "library-only channel fixture",
  },
  {
    channel: "Email",
    reference: "secret://notify/smtp/prod:****",
    events: "audit.export.ready, policy.denied",
    delivery: "retry and bounce state need BACKEND-OUTBOX-STATUS",
    status: "recipient list is not served",
  },
  {
    channel: "PagerDuty",
    reference: "secret://notify/pagerduty/prod:****",
    events: "incident.declared, ca.compromise",
    delivery: "dedupe key would be event id plus tenant id",
    status: "test delivery not routed",
  },
  {
    channel: "OpsGenie",
    reference: "secret://notify/opsgenie/prod:****",
    events: "jit.expiring, rotation.failed",
    delivery: "retry receipt not served",
    status: "API key never leaves secret reference form",
  },
  {
    channel: "Webhook",
    reference: "secret://notify/webhook/prod:****",
    events: "credential.rotated, compliance.evidence.ready",
    delivery: "signed body and idempotency key are not served",
    status: "raw endpoint token is masked",
  },
];

const notificationFailures = [
  {
    channel: "Webhook",
    error: "401 unauthorized from https://hooks.example.test/ingest; credential ref secret://notify/webhook/prod:****",
  },
  {
    channel: "PagerDuty",
    error: "429 rate limited; integration key fingerprint sha256:91ab...7c20; response body redacted",
  },
];

const complianceRows = [
  {
    framework: "PCI DSS",
    controls: "certificate inventory, key custody, audit evidence",
    state: "evidence-only",
    caveat: "framework-mapped posture needs BACKEND-COMPLIANCE",
  },
  {
    framework: "HIPAA",
    controls: "access-control audit, encryption boundary, incident evidence",
    state: "control mapping not served",
    caveat: "evidence, not certification",
  },
  {
    framework: "SOC 2",
    controls: "change approval, revocation, logging, availability",
    state: "signed audit export is served",
    caveat: "framework report generation is library-only",
  },
  {
    framework: "FedRAMP",
    controls: "tenant isolation, crypto module posture, vulnerability evidence",
    state: "posture dashboard blocked",
    caveat: "requires compliance control state API",
  },
  {
    framework: "CNSA 2.0",
    controls: "algorithm posture, key sizes, PQC migration waves",
    state: "CBOM/PQC data shown elsewhere as disclosure",
    caveat: "certification mapping is not served",
  },
];

export function Policy() {
  const [evidenceBundle, setEvidenceBundle] = useState<string | null>(null);
  const [evidenceError, setEvidenceError] = useState<string | null>(null);
  const [exporting, setExporting] = useState(false);

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

  return (
    <section aria-labelledby="policy-heading" className="grid gap-6">
      <div>
        <h1 id="policy-heading" className="text-2xl font-semibold">
          Policy
        </h1>
        <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
          Served issue, deploy, and revoke mutations pass through the OPA/Rego default-deny gate, RA separation, dual-control approval, and bound-profile checks before state changes are emitted.
        </p>
      </div>

      <section aria-labelledby="policy-gate-heading" className="grid gap-4 border-y border-border py-4">
        <div>
          <h2 id="policy-gate-heading" className="text-lg font-semibold">
            Served enforcement path
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            The browser does not send a tenant id or bypass policy. It asks the served lifecycle endpoint to mutate state; the backend evaluates policy and either emits the event or returns a fail-closed problem.
          </p>
        </div>
        <div className="overflow-x-auto rounded-md border border-border">
          <table className="w-full min-w-[54rem] text-left text-sm">
            <caption className="sr-only">Policy decision outcomes</caption>
            <thead>
              <tr className="border-b border-border text-muted-foreground">
                <th scope="col" className="py-2 pl-3 pr-4 font-medium">Outcome</th>
                <th scope="col" className="py-2 pr-4 font-medium">ELI5 technical meaning</th>
                <th scope="col" className="py-2 pr-3 font-medium">Audit evidence</th>
              </tr>
            </thead>
            <tbody>
              {policyOutcomes.map((outcome) => (
                <tr key={outcome.state} className="border-b border-border align-top">
                  <td className="py-2 pl-3 pr-4 font-medium">{outcome.state}</td>
                  <td className="py-2 pr-4">{outcome.meaning}</td>
                  <td className="py-2 pr-3 font-mono text-xs">{outcome.evidence}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="text-sm text-muted-foreground">
          Denials are visible in the action error path on <Link className="underline" to="/identities">Identities</Link> and in <Link className="underline" to="/audit?type=policy.decision">Audit policy decisions</Link>. Profile-bound issuance denials are also visible through <Link className="underline" to="/audit?type=issuance.profile_evaluated">profile evaluation evidence</Link>.
        </p>
      </section>

      <section aria-labelledby="notifications-heading" className="grid gap-4 border-y border-border py-4">
        <div>
          <h2 id="notifications-heading" className="text-lg font-semibold">
            Notification integrations
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            Slack, Teams, email, PagerDuty, OpsGenie, and webhook notification channels need tenant-scoped channel config, masked secret references, test delivery, duplicate-safe outbox delivery, and redacted failure evidence. The served API does not configure or test channels yet.
          </p>
        </div>
        <UnavailableState title="Notification channels are library-only">
          `BACKEND-NOTIFY` and `BACKEND-OUTBOX-STATUS` must serve channel config reads, test delivery, retry state, and delivery receipts before this page can operate notification integrations.
        </UnavailableState>
        <div className="overflow-x-auto rounded-md border border-border">
          <table className="w-full min-w-[70rem] text-left text-sm">
            <caption className="sr-only">Notification channel fixtures</caption>
            <thead>
              <tr className="border-b border-border text-muted-foreground">
                <th scope="col" className="py-2 pl-3 pr-4 font-medium">Channel</th>
                <th scope="col" className="py-2 pr-4 font-medium">Secret reference</th>
                <th scope="col" className="py-2 pr-4 font-medium">Events</th>
                <th scope="col" className="py-2 pr-4 font-medium">Delivery posture</th>
                <th scope="col" className="py-2 pr-3 font-medium">Status</th>
              </tr>
            </thead>
            <tbody>
              {notificationChannels.map((row) => (
                <tr key={row.channel} className="border-b border-border align-top">
                  <td className="py-2 pl-3 pr-4 font-medium">{row.channel}</td>
                  <td className="py-2 pr-4 font-mono text-xs">{row.reference}</td>
                  <td className="py-2 pr-4">{row.events}</td>
                  <td className="py-2 pr-4">{row.delivery}</td>
                  <td className="py-2 pr-3">{row.status}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="rounded-md border border-border p-3 text-sm">
          <p className="font-medium">Redacted failure fixtures</p>
          <ul className="mt-2 grid gap-1 text-muted-foreground">
            {notificationFailures.map((failure) => (
              <li key={failure.channel}>
                <span className="font-medium text-foreground">{failure.channel}:</span> {failure.error}
              </li>
            ))}
          </ul>
        </div>
      </section>

      <section aria-labelledby="compliance-heading" className="grid gap-4 border-y border-border py-4">
        <div>
          <h2 id="compliance-heading" className="text-lg font-semibold">
            Compliance posture and reports
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            Framework dashboards need mapped controls, control state, caveats, and report packaging. Today the served path is the signed audit evidence export; it is evidence, not certification.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-3">
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
        <UnavailableState title="Framework-mapped compliance posture is not served yet">
          `BACKEND-COMPLIANCE` must serve PCI, HIPAA, SOC 2, FedRAMP, and CNSA 2.0 control mappings, caveats, and report state. The signed audit export above is real evidence, not a compliance certificate.
        </UnavailableState>
        <div className="overflow-x-auto rounded-md border border-border">
          <table className="w-full min-w-[62rem] text-left text-sm">
            <caption className="sr-only">Compliance control mapping fixtures</caption>
            <thead>
              <tr className="border-b border-border text-muted-foreground">
                <th scope="col" className="py-2 pl-3 pr-4 font-medium">Framework</th>
                <th scope="col" className="py-2 pr-4 font-medium">Control evidence</th>
                <th scope="col" className="py-2 pr-4 font-medium">Control state</th>
                <th scope="col" className="py-2 pr-3 font-medium">Caveat</th>
              </tr>
            </thead>
            <tbody>
              {complianceRows.map((row) => (
                <tr key={row.framework} className="border-b border-border align-top">
                  <td className="py-2 pl-3 pr-4 font-medium">{row.framework}</td>
                  <td className="py-2 pr-4">{row.controls}</td>
                  <td className="py-2 pr-4">{row.state}</td>
                  <td className="py-2 pr-3">{row.caveat}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section aria-labelledby="policy-dry-run-heading" className="grid gap-4 border-y border-border py-4">
        <div>
          <h2 id="policy-dry-run-heading" className="text-lg font-semibold">
            Policy authoring and dry run
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            A real editor needs a tenant-scoped API that reads active Rego, validates candidate modules, runs dry-run input, and returns a decision trace. That endpoint is not served yet.
          </p>
        </div>
        <UnavailableState title="Policy authoring and dry-run API not served yet">
          `BACKEND-POLICY-AUTHOR` must serve active policy read, candidate validation, dry-run input, allow/deny output, and trace rows before this page can expose an editor or evaluator. Until then, lifecycle mutations remain the real enforcement path.
        </UnavailableState>
      </section>
    </section>
  );
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
