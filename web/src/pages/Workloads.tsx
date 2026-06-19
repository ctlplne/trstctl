import { UnavailableState } from "@/components/StatePrimitives";

interface LeaseRow {
  credential: string;
  ttl: string;
  evidence: string;
  expiry: string;
  revoke: string;
}

interface AttestationRow {
  evidence: string;
  fixture: string;
  result: string;
  reason: string;
}

interface BrokerRow {
  field: string;
  value: string;
}

const leaseRows: LeaseRow[] = [
  {
    credential: "X.509-SVID",
    ttl: "15 minute default TTL, 5 minute renew window",
    evidence: "SPIFFE selector match plus attestation digest",
    expiry: "lease expires unless workload re-attests",
    revoke: "revoke-now is explained, not executable",
  },
  {
    credential: "JWT-SVID",
    ttl: "5 minute audience-bound token TTL",
    evidence: "audience, SPIFFE ID, and selector digest",
    expiry: "audience-specific token dies without renewal",
    revoke: "deny new minting by policy; no live revocation button",
  },
  {
    credential: "PKI secret bundle",
    ttl: "30 minute certificate plus key bundle",
    evidence: "secret name, profile, and attestation digest",
    expiry: "bundle must be reissued through served PKI secret path",
    revoke: "manual identity revoke is separate from this lease preview",
  },
];

const attestationRows: AttestationRow[] = [
  {
    evidence: "TPM quote",
    fixture: "accepted",
    result: "PCR digest matches the tenant policy",
    reason: "hardware-rooted proof, raw quote redacted",
  },
  {
    evidence: "AWS IID",
    fixture: "rejected",
    result: "account or region does not match policy",
    reason: "wrong cloud boundary",
  },
  {
    evidence: "GCP instance identity",
    fixture: "accepted",
    result: "service account and project match policy",
    reason: "metadata signature verified by library code",
  },
  {
    evidence: "Azure IMDS",
    fixture: "expired",
    result: "evidence timestamp is outside the freshness window",
    reason: "stale attestation",
  },
  {
    evidence: "Kubernetes SAT",
    fixture: "wrong-tenant",
    result: "namespace or service account maps to a different tenant",
    reason: "tenant isolation guardrail",
  },
  {
    evidence: "GitHub OIDC",
    fixture: "rejected",
    result: "repository claim is not in the allowed list",
    reason: "workflow provenance mismatch",
  },
];

const brokerRows: BrokerRow[] = [
  { field: "Agent identity", value: "spiffe://tenant/ai/build-agent" },
  { field: "Allowed tools and scopes", value: "mcp:read-only, secrets:read:ci, certs:issue:short" },
  { field: "Issued credentials", value: "short lease only; no standing secret" },
  { field: "Attestation", value: "OIDC subject, workload digest, and policy version" },
  { field: "Expiry", value: "15 minute max lease with no silent extension" },
  { field: "Audit", value: "credential lease audit event" },
];

export function Workloads() {
  return (
    <section aria-labelledby="workload-heading" className="grid gap-6">
      <div>
        <h1 id="workload-heading" className="text-2xl font-semibold">
          Workload identity
        </h1>
        <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
          Library-only workload workflows are rendered as safe disclosure fixtures. Served SPIFFE and PKI-secret paths can issue credentials, but there is no served lease ledger, attestation API, or broker issuance API yet.
        </p>
      </div>

      <UnavailableState title="Workload lease APIs are not served yet">
        `BACKEND-EPHEMERAL`, `BACKEND-ATTEST`, and `BACKEND-BROKER` must serve lease state, attestation decisions, and broker issuance before this page can operate. No live issue, revoke, approve, or mint controls are rendered.
      </UnavailableState>

      <section aria-labelledby="lease-heading" className="grid gap-3 border-y border-border py-4">
        <div>
          <h2 id="lease-heading" className="text-lg font-semibold">
            Ephemeral credential leases
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            A lease is a short promise: a workload proves who it is, receives one credential class, and loses it at expiry unless it re-attests.
          </p>
        </div>
        <ol className="grid gap-2 rounded-md border border-border p-3 text-sm md:grid-cols-3">
          <li>
            <p className="font-medium">00:00 issued</p>
            <p className="text-muted-foreground">policy and attestation digest bind the lease</p>
          </li>
          <li>
            <p className="font-medium">00:45 renew window</p>
            <p className="text-muted-foreground">workload must re-attest before renewal</p>
          </li>
          <li>
            <p className="font-medium">01:00 expires</p>
            <p className="text-muted-foreground">credential is no longer trusted by policy</p>
          </li>
        </ol>
        <div className="overflow-x-auto rounded-md border border-border">
          <table className="w-full min-w-[56rem] text-left text-sm">
            <caption className="sr-only">Ephemeral credential lease fixture</caption>
            <thead>
              <tr className="border-b border-border text-muted-foreground">
                <th scope="col" className="py-2 pl-3 pr-4 font-medium">Credential class</th>
                <th scope="col" className="py-2 pr-4 font-medium">TTL policy</th>
                <th scope="col" className="py-2 pr-4 font-medium">Attestation evidence</th>
                <th scope="col" className="py-2 pr-4 font-medium">Lease expiry</th>
                <th scope="col" className="py-2 pr-3 font-medium">Revoke-now posture</th>
              </tr>
            </thead>
            <tbody>
              {leaseRows.map((row) => (
                <tr key={row.credential} className="border-b border-border align-top">
                  <td className="py-2 pl-3 pr-4 font-medium">{row.credential}</td>
                  <td className="py-2 pr-4">{row.ttl}</td>
                  <td className="py-2 pr-4">{row.evidence}</td>
                  <td className="py-2 pr-4">{row.expiry}</td>
                  <td className="py-2 pr-3">{row.revoke}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section aria-labelledby="attestation-heading" className="grid gap-3 border-y border-border py-4">
        <div>
          <h2 id="attestation-heading" className="text-lg font-semibold">
            Workload attestation chain
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            Attestation proves the workload and its platform. This preview keeps raw tokens and signed evidence out of the browser and shows only decision fixtures.
          </p>
        </div>
        <div className="overflow-x-auto rounded-md border border-border">
          <table className="w-full min-w-[54rem] text-left text-sm">
            <caption className="sr-only">Workload attestation fixtures</caption>
            <thead>
              <tr className="border-b border-border text-muted-foreground">
                <th scope="col" className="py-2 pl-3 pr-4 font-medium">Evidence</th>
                <th scope="col" className="py-2 pr-4 font-medium">Fixture</th>
                <th scope="col" className="py-2 pr-4 font-medium">Decision</th>
                <th scope="col" className="py-2 pr-3 font-medium">Reason</th>
              </tr>
            </thead>
            <tbody>
              {attestationRows.map((row) => (
                <tr key={`${row.evidence}:${row.fixture}`} className="border-b border-border align-top">
                  <td className="py-2 pl-3 pr-4 font-medium">{row.evidence}</td>
                  <td className="py-2 pr-4">{row.fixture}</td>
                  <td className="py-2 pr-4">{row.result}</td>
                  <td className="py-2 pr-3">{row.reason}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <UnavailableState title="Attestation API is library-only">
          `BACKEND-ATTEST` must serve accepted/rejected/expired/wrong-tenant decisions before this page can show live workload evidence.
        </UnavailableState>
      </section>

      <section aria-labelledby="broker-heading" className="grid gap-3 border-y border-border py-4">
        <div>
          <h2 id="broker-heading" className="text-lg font-semibold">
            AI-agent / NHI broker
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            A broker turns an agent identity plus policy into a short credential lease. Broker issuance is library-only, so this fixture shows scope and audit shape only.
          </p>
        </div>
        <div className="overflow-x-auto rounded-md border border-border">
          <table className="w-full min-w-[42rem] text-left text-sm">
            <caption className="sr-only">AI agent broker lifecycle fixture</caption>
            <tbody>
              {brokerRows.map((row) => (
                <tr key={row.field} className="border-b border-border align-top">
                  <th scope="row" className="py-2 pl-3 pr-4 text-left font-medium">
                    {row.field}
                  </th>
                  <td className="py-2 pr-3">{row.value}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <UnavailableState title="Broker issuance is library-only">
          `BACKEND-BROKER` must serve agent-scoped broker issuance, expiry, and audit reads before live broker credentials can be minted in the console.
        </UnavailableState>
      </section>
    </section>
  );
}
