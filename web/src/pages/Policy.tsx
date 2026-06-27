import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { PageHeader } from "@/components/PageHeader";
import { ErrorState, LoadingState, UnavailableState } from "@/components/StatePrimitives";
import { Button } from "@/components/ui/button";
import { api, ApiError, type ComplianceEvidencePack } from "@/lib/api";

type ComplianceFramework = ComplianceEvidencePack["framework"];

const complianceFrameworks: Array<{ id: ComplianceFramework; label: string }> = [
  { id: "pci-dss", label: "PCI DSS" },
  { id: "hipaa", label: "HIPAA" },
  { id: "soc2", label: "SOC 2" },
  { id: "fedramp", label: "FedRAMP" },
  { id: "cnsa-2.0", label: "CNSA 2.0" },
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

export function Policy() {
  const [selectedFramework, setSelectedFramework] = useState<ComplianceFramework>("soc2");
  const [evidencePack, setEvidencePack] = useState<ComplianceEvidencePack | null>(null);
  const [evidencePackError, setEvidencePackError] = useState<string | null>(null);
  const [evidencePackLoading, setEvidencePackLoading] = useState(true);
  const [evidenceBundle, setEvidenceBundle] = useState<string | null>(null);
  const [evidenceError, setEvidenceError] = useState<string | null>(null);
  const [exporting, setExporting] = useState(false);

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
              {framework.label}
            </Button>
          ))}
        </div>

        {evidencePackLoading && <LoadingState>Loading evidence pack.</LoadingState>}
        {evidencePackError && <ErrorState title="Evidence pack unavailable">{evidencePackError}</ErrorState>}
        {evidencePack && <ComplianceEvidencePackPanel pack={evidencePack} label={frameworkLabel(evidencePack.framework)} />}

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

      <section aria-labelledby="policy-dry-run-heading" className="grid gap-4 border-y border-border py-4">
        <div>
          <h2 id="policy-dry-run-heading" className="text-title font-semibold">
            Policy authoring and dry run
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            A real editor needs a tenant-scoped workflow that reads active Rego, validates candidate modules, runs dry-run input, and returns a decision trace.
            That workflow isn't in the console yet.
          </p>
        </div>
        <UnavailableState title="Policy authoring and dry-run aren't in the console yet">
          Active policy read, candidate validation, dry-run input, allow/deny output, and trace rows are not available in this console yet. Until then,
          lifecycle mutations remain the real enforcement path.
        </UnavailableState>
      </section>
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

function frameworkLabel(framework: ComplianceFramework): string {
  return complianceFrameworks.find((item) => item.id === framework)?.label ?? framework;
}

function plural(count: number, singular: string): string {
  if (count === 1) return singular;
  return `${singular}s`;
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
