import type { ReactNode } from "react";
import { Bell, FileWarning, Radar, ShieldAlert } from "lucide-react";
import { EmptyState } from "@/components/EmptyState";
import { UnavailableState } from "@/components/StatePrimitives";
import { Button } from "@/components/ui/button";

const ctRows = [
  {
    domain: "example.com",
    checkpoint: "RFC 6962 log index + STH",
    signal: "Unexpected SAN outside approved issuer profile",
    status: "Would create an outbox-backed alert when BACKEND-CT is served",
  },
  {
    domain: "api.example.com",
    checkpoint: "issuer/name/serial tuple",
    signal: "Shadow certificate from untracked CA",
    status: "Preview only - no CT polling endpoint exists",
  },
];

const driftRows = [
  {
    id: "deleted",
    type: "Deleted credential",
    severity: "high",
    evidence: "Agent expected a deployed certificate file but cannot read it",
    remediation: "Restore from intended state or revoke the identity",
  },
  {
    id: "replaced",
    type: "Replaced credential",
    severity: "critical",
    evidence: "Fingerprint on host does not match the issued credential",
    remediation: "Quarantine the host, re-issue, then verify deployment",
  },
  {
    id: "permission",
    type: "Permission changed",
    severity: "medium",
    evidence: "File mode or owner no longer matches the deployment plan",
    remediation: "Reset permissions through a served connector workflow",
  },
];

const cbomRows = [
  {
    asset: "public TLS endpoint",
    algorithms: "RSA-2048, ECDSA P-256, TLS 1.2+",
    posture: "Meets the current policy floor",
    next: "Track for PQC migration planning",
  },
  {
    asset: "legacy service mesh edge",
    algorithms: "TLS 1.0, RC4, MD5 signature",
    posture: "Weak crypto preview",
    next: "Link weak-crypto risk to the risk dashboard",
  },
  {
    asset: "future workload profile",
    algorithms: "ML-DSA, ML-KEM, SLH-DSA",
    posture: "PQC-recognized by scanner model",
    next: "Needs served CBOM scan trigger and findings",
  },
];

const cryptoAgilityRows = [
  {
    asset: "Weak legacy edge",
    inventory: "RSA-1024, SHA-1 signature, TLS 1.0",
    readiness: "disallowed by policy floor",
    blocker: "needs served CBOM evidence before migration planning",
  },
  {
    asset: "Classical compliant API",
    inventory: "ECDSA P-256, RSA-2048, TLS 1.3",
    readiness: "classical-ready, not PQC-ready",
    blocker: "hybrid X25519+ML-KEM policy not validated on clients",
  },
  {
    asset: "PQC-ready workload",
    inventory: "ML-DSA / ML-KEM / SLH-DSA",
    readiness: "PQC-recognized fixture",
    blocker: "needs served algorithm inventory and compatibility result",
  },
];

const pqcMigrationRows = [
  {
    wave: "Wave 0: inventory",
    action: "collect CBOM, graph blast radius, owner, and client compatibility",
    rollback: "no production change",
    signoff: "policy sign-off required",
  },
  {
    wave: "Wave 1: hybrid canary",
    action: "issue hybrid certificates to a small workload set",
    rollback: "rollback to classical profile",
    signoff: "owner plus policy approval",
  },
  {
    wave: "Wave 2: workload rotation",
    action: "rotate compatible services by dependency group",
    rollback: "resume from last successful wave",
    signoff: "security sign-off required",
  },
];

export function Posture() {
  return (
    <section aria-labelledby="posture-heading" className="grid gap-6">
      <div>
        <h1 id="posture-heading" className="text-2xl font-semibold">
          Posture
        </h1>
        <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
          CT monitoring, drift detection, and CBOM scanning are library-complete today. This page is a technical preview of the evidence model, not a live scanner.
        </p>
      </div>

      <UnavailableState title="Posture collector APIs not served yet">
        `BACKEND-CT`, `BACKEND-DRIFT`, and `BACKEND-CBOM` must expose watchlists, scan triggers, findings, and cited evidence before the GUI can operate these collectors.
      </UnavailableState>

      <section aria-labelledby="ct-heading" className="grid gap-3 border-y border-border py-4">
        <div className="flex items-start gap-3">
          <Radar className="mt-1 h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
          <div>
            <h2 id="ct-heading" className="text-lg font-semibold">
              Certificate Transparency monitoring
            </h2>
            <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
              CT monitoring watches public logs for certificates your tenant did not request. Watchlists, checkpoints, and unexpected-issuance alerts need the missing CT findings API.
            </p>
          </div>
        </div>
        <UnavailableState title="CT findings API not served yet">
          `BACKEND-CT` must serve domain watchlists, log checkpoints, poll state, and unexpected-certificate findings. There is no live Add watchlist or Poll CT control here.
        </UnavailableState>
        <PreviewTable title="Non-interactive CT triage preview" headers={["Domain", "Checkpoint", "Suspicious certificate", "Triage status"]}>
          {ctRows.map((row) => (
            <tr key={row.domain} className="border-b border-border align-top">
              <td className="py-2 pl-3 pr-4 font-medium">{row.domain}</td>
              <td className="py-2 pr-4">{row.checkpoint}</td>
              <td className="py-2 pr-4">{row.signal}</td>
              <td className="py-2 pr-3">{row.status}</td>
            </tr>
          ))}
        </PreviewTable>
      </section>

      <section aria-labelledby="drift-heading" className="grid gap-3 border-y border-border py-4">
        <div className="flex items-start gap-3">
          <FileWarning className="mt-1 h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
          <div>
            <h2 id="drift-heading" className="text-lg font-semibold">
              Drift detection
            </h2>
            <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
              Drift detection compares what trstctl intended to deploy with what an enrolled agent actually sees. Deleted, replaced, relocated, and permission-changed credentials remain agent-only until findings are served.
            </p>
          </div>
        </div>
        <UnavailableState title="Drift findings API not served yet">
          `BACKEND-DRIFT` must serve per-agent findings, timestamps, severity, and remediation eligibility. Preview remediation buttons are disabled because no served remediation workflow exists.
        </UnavailableState>
        <PreviewTable title="Non-interactive drift remediation preview" headers={["Finding", "Severity", "Evidence", "Remediation"]}>
          {driftRows.map((row) => (
            <tr key={row.id} className="border-b border-border align-top">
              <td className="py-2 pl-3 pr-4 font-medium">{row.type}</td>
              <td className="py-2 pr-4">{row.severity}</td>
              <td className="py-2 pr-4">{row.evidence}</td>
              <td className="py-2 pr-3">
                <Button type="button" size="sm" variant="outline" disabled aria-describedby={`${row.id}-blocked`} aria-label={`Remediation blocked for ${row.type.toLowerCase()}`}>
                  Remediation blocked
                </Button>
                <p id={`${row.id}-blocked`} className="mt-1 text-xs text-muted-foreground">
                  {row.remediation}; waits for `BACKEND-DRIFT`.
                </p>
              </td>
            </tr>
          ))}
        </PreviewTable>
      </section>

      <section aria-labelledby="cbom-heading" className="grid gap-3 border-y border-border py-4">
        <div className="flex items-start gap-3">
          <ShieldAlert className="mt-1 h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
          <div>
            <h2 id="cbom-heading" className="text-lg font-semibold">
              CBOM and cryptographic observability
            </h2>
            <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
              The CBOM scanner inventories algorithms, key sizes, TLS versions, weak crypto, and PQC posture. The policy floor is RSA-2048, EC-256, and TLS 1.2, while 3DES/DES/RC4/NULL/EXPORT/MD5 are banned.
            </p>
          </div>
        </div>
        <UnavailableState title="CBOM findings API not served yet">
          `BACKEND-CBOM` must serve scan triggers, asset-level findings, graph links, and posture timestamps. No Run CBOM scan control is rendered until then.
        </UnavailableState>
        <PreviewTable title="Non-interactive CBOM preview" headers={["Asset", "Algorithms", "Posture", "Next evidence"]}>
          {cbomRows.map((row) => (
            <tr key={row.asset} className="border-b border-border align-top">
              <td className="py-2 pl-3 pr-4 font-medium">{row.asset}</td>
              <td className="py-2 pr-4">{row.algorithms}</td>
              <td className="py-2 pr-4">{row.posture}</td>
              <td className="py-2 pr-3">
                {row.posture === "Weak crypto preview" ? (
                  <a className="text-primary underline" href="/risk">
                    {row.next}
                  </a>
                ) : (
                  row.next
                )}
              </td>
            </tr>
          ))}
        </PreviewTable>
        <EmptyState title="No served posture findings yet">
          This page intentionally shows preview rows only. Live CT, drift, and CBOM evidence becomes observable when the backend mounts the collector APIs.
        </EmptyState>
      </section>

      <section aria-labelledby="crypto-agility-heading" className="grid gap-3 border-y border-border py-4">
        <div className="flex items-start gap-3">
          <ShieldAlert className="mt-1 h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
          <div>
            <h2 id="crypto-agility-heading" className="text-lg font-semibold">
              Crypto-agility and PQC readiness
            </h2>
            <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
              Crypto-agility means the system can see weak algorithms, reject disallowed choices, and plan a move to PQC or hybrid algorithms without guessing from browser-only state.
            </p>
          </div>
        </div>
        <UnavailableState title="Algorithm inventory not served yet">
          `BACKEND-CBOM` must serve asset-level algorithm inventory, allowed/disallowed state, PQC readiness, hybrid policy, and migration blockers before this page can operate crypto-agility changes.
        </UnavailableState>
        <PreviewTable title="Crypto-agility readiness fixtures" headers={["Asset", "Inventory fixture", "Readiness", "Blocker"]}>
          {cryptoAgilityRows.map((row) => (
            <tr key={row.asset} className="border-b border-border align-top">
              <td className="py-2 pl-3 pr-4 font-medium">{row.asset}</td>
              <td className="py-2 pr-4">{row.inventory}</td>
              <td className="py-2 pr-4">{row.readiness}</td>
              <td className="py-2 pr-3">{row.blocker}</td>
            </tr>
          ))}
        </PreviewTable>
      </section>

      <section aria-labelledby="pqc-migration-heading" className="grid gap-3 border-y border-border py-4">
        <div className="flex items-start gap-3">
          <ShieldAlert className="mt-1 h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
          <div>
            <h2 id="pqc-migration-heading" className="text-lg font-semibold">
              PQC migration orchestration
            </h2>
            <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
              PQC migration is a staged rollout: inventory first, hybrid canary second, workload rotation third, with rollback and resume points at every wave.
            </p>
          </div>
        </div>
        <UnavailableState title="PQC migration orchestration is library-only">
          `BACKEND-PQC-MIGRATION` must serve candidate assets, dry-run results, migration waves, rollback, resume, and policy sign-off before this console can trigger migration work.
        </UnavailableState>
        <PreviewTable title="PQC migration plan fixture" headers={["Wave", "Action", "Rollback", "Sign-off"]}>
          {pqcMigrationRows.map((row) => (
            <tr key={row.wave} className="border-b border-border align-top">
              <td className="py-2 pl-3 pr-4 font-medium">{row.wave}</td>
              <td className="py-2 pr-4">{row.action}</td>
              <td className="py-2 pr-4">{row.rollback}</td>
              <td className="py-2 pr-3">{row.signoff}</td>
            </tr>
          ))}
        </PreviewTable>
      </section>

      <section aria-labelledby="alert-heading" className="flex items-start gap-3 rounded-md border border-border p-3 text-sm">
        <Bell className="mt-1 h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
        <div>
          <h2 id="alert-heading" className="font-semibold">
            Alert routing is not configured here
          </h2>
          <p className="mt-1 text-muted-foreground">
            CT anomalies, drift findings, and weak-crypto findings will need served notification-channel configuration before operators can route alerts. That remains a backend gap, not a browser-only setting.
          </p>
        </div>
      </section>
    </section>
  );
}

function PreviewTable({
  title,
  headers,
  children,
}: {
  title: string;
  headers: string[];
  children: ReactNode;
}) {
  return (
    <div className="overflow-x-auto rounded-md border border-border">
      <table className="w-full min-w-[52rem] text-left text-sm">
        <caption className="sr-only">{title}</caption>
        <thead>
          <tr className="border-b border-border text-muted-foreground">
            {headers.map((header, index) => (
              <th key={header} scope="col" className={index === 0 ? "py-2 pl-3 pr-4 font-medium" : index === headers.length - 1 ? "py-2 pr-3 font-medium" : "py-2 pr-4 font-medium"}>
                {header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>{children}</tbody>
      </table>
    </div>
  );
}
