import { useState, type FormEvent } from "react";
import { Ban, Plus, RefreshCw } from "lucide-react";
import { ErrorState, UnavailableState } from "@/components/StatePrimitives";
import { PageHeader } from "@/components/PageHeader";
import { StatusBadge } from "@/components/StatusBadge";
import { Button } from "@/components/ui/button";
import { api, ApiError, type Attestation, type AttestedSVID, type BrokerAgentIdentity, type DynamicLease } from "@/lib/api";
import { formatDateTime as formatDateTimePolicy } from "@/i18n/format";

type SafeAttestation = Pick<Attestation, "id" | "method" | "selectors" | "subject" | "verified_at">;
type BrokerIdentityRow = Pick<BrokerAgentIdentity, "agent_id" | "certificate_id" | "credential_id" | "node_id" | "not_after" | "scopes" | "subject"> & {
  attestation: SafeAttestation;
};
type AttestedSVIDRow = Pick<AttestedSVID, "credential_id" | "not_after" | "subject"> & { attestation: SafeAttestation };

export function Workloads() {
  const [provider, setProvider] = useState("postgresql");
  const [role, setRole] = useState("readonly-reporting");
  const [ttlSeconds, setTtlSeconds] = useState(1200);
  const [leases, setLeases] = useState<DynamicLease[]>([]);
  const [brokerIdentities, setBrokerIdentities] = useState<BrokerIdentityRow[]>([]);
  const [attestedSVIDs, setAttestedSVIDs] = useState<AttestedSVIDRow[]>([]);
  const [busy, setBusy] = useState<string | null>(null);
  const [leaseError, setLeaseError] = useState<string | null>(null);
  const [brokerError, setBrokerError] = useState<string | null>(null);
  const [attestationError, setAttestationError] = useState<string | null>(null);

  function upsertLease(lease: DynamicLease) {
    const metadata = leaseMetadataOnly(lease);
    setLeases((current) => [metadata, ...current.filter((item) => item.id !== metadata.id)]);
  }

  function upsertBrokerIdentity(identity: BrokerAgentIdentity) {
    const metadata = brokerIdentityMetadataOnly(identity);
    setBrokerIdentities((current) => [metadata, ...current.filter((item) => item.credential_id !== metadata.credential_id)]);
  }

  function upsertAttestedSVID(svid: AttestedSVID) {
    const metadata = attestedSVIDMetadataOnly(svid);
    setAttestedSVIDs((current) => [metadata, ...current.filter((item) => item.credential_id !== metadata.credential_id)]);
  }

  async function issueLease(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy("issue");
    setLeaseError(null);
    try {
      upsertLease(await api.issueDynamicLease({ provider: provider.trim(), role: role.trim(), ttl_seconds: ttlSeconds }));
    } catch (err) {
      setLeaseError(apiProblemMessage(err, "Could not issue lease"));
    } finally {
      setBusy(null);
    }
  }

  async function renewLease(leaseId: string) {
    setBusy(`renew:${leaseId}`);
    setLeaseError(null);
    try {
      upsertLease(await api.renewDynamicLease(leaseId, { extend_seconds: 300 }));
    } catch (err) {
      setLeaseError(apiProblemMessage(err, "Could not renew lease"));
    } finally {
      setBusy(null);
    }
  }

  async function revokeLease(leaseId: string) {
    setBusy(`revoke:${leaseId}`);
    setLeaseError(null);
    try {
      upsertLease(await api.revokeDynamicLease(leaseId));
    } catch (err) {
      setLeaseError(apiProblemMessage(err, "Could not revoke lease"));
    } finally {
      setBusy(null);
    }
  }

  async function issueBrokerIdentity(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    setBusy("broker");
    setBrokerError(null);
    try {
      upsertBrokerIdentity(
        await api.issueBrokerAgentIdentity({
          agent_id: formString(data, "agent_id"),
          method: formString(data, "method"),
          payload_base64: formString(data, "payload_base64"),
          public_key_pem: formString(data, "public_key_pem"),
          scopes: parseScopes(formString(data, "scopes")),
          ttl_seconds: formNumber(data, "ttl_seconds"),
        }),
      );
      form.reset();
    } catch (err) {
      setBrokerError(apiProblemMessage(err, "Could not issue broker identity"));
    } finally {
      setBusy(null);
    }
  }

  async function issueAttestedSVID(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    setBusy("attested-svid");
    setAttestationError(null);
    try {
      upsertAttestedSVID(
        await api.issueAttestedSVID({
          method: formString(data, "method") as "aws_iid" | "azure_imds" | "gcp_iit" | "github_oidc" | "k8s_sat" | "tpm",
          payload_base64: formString(data, "payload_base64"),
          public_key_pem: formString(data, "public_key_pem"),
          ttl_seconds: formNumber(data, "ttl_seconds"),
        }),
      );
      form.reset();
    } catch (err) {
      setAttestationError(apiProblemMessage(err, "Could not issue attested SVID"));
    } finally {
      setBusy(null);
    }
  }

  return (
    <section aria-labelledby="workload-heading" className="grid gap-6">
      <PageHeader
        titleId="workload-heading"
        title="Workload identity"
        description="Short-lived identities for software workloads (services, pods, jobs): SPIFFE/SVID workload certificates, just-in-time (JIT) leases, and broker identities. Raw key material stays out of the browser — you see lease metadata here."
      />

      <section aria-labelledby="lease-heading" className="grid gap-3 border-y border-border py-4">
        <div>
          <h2 id="lease-heading" className="text-title font-semibold">
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

        <form aria-labelledby="lease-issue-heading" className="ui-panel grid gap-3 p-comfortable" onSubmit={issueLease}>
          <div>
            <h3 id="lease-issue-heading" className="text-title font-semibold">
              Issue dynamic lease
            </h3>
            <p className="mt-1 text-sm text-muted-foreground">
              The API returns lease metadata only. If a provider returns credential material, this panel keeps it out of the browser table.
            </p>
          </div>
          <div className="grid gap-3 md:grid-cols-[1fr_1fr_10rem_auto]">
            <label className="grid gap-1 text-sm font-medium">
              Provider
              <input className="ui-input" value={provider} onChange={(event) => setProvider(event.target.value)} required />
            </label>
            <label className="grid gap-1 text-sm font-medium">
              Role
              <input className="ui-input" value={role} onChange={(event) => setRole(event.target.value)} required />
            </label>
            <label className="grid gap-1 text-sm font-medium">
              TTL seconds
              <input
                className="ui-input"
                type="number"
                min={60}
                max={86400}
                value={ttlSeconds}
                onChange={(event) => setTtlSeconds(Number(event.target.value))}
                required
              />
            </label>
            <Button type="submit" className="self-end" disabled={busy === "issue"}>
              {busy === "issue" ? <RefreshCw className="h-4 w-4 animate-spin" aria-hidden="true" /> : <Plus className="h-4 w-4" aria-hidden="true" />}
              Issue lease
            </Button>
          </div>
        </form>

        {leaseError && <ErrorState title="Lease operation failed">{leaseError}</ErrorState>}

        <div className="ui-panel overflow-x-auto">
          <table className="ui-table min-w-[58rem]">
            <caption className="sr-only">Ephemeral credential leases</caption>
            <thead>
              <tr>
                <th scope="col">Lease</th>
                <th scope="col">Provider</th>
                <th scope="col">Role</th>
                <th scope="col">State</th>
                <th scope="col">Issued</th>
                <th scope="col">Expires</th>
                <th scope="col">Actions</th>
              </tr>
            </thead>
            <tbody>
              {leases.length === 0 ? (
                <tr>
                  <td colSpan={7} className="text-muted-foreground">
                    No lease has been issued in this browser session.
                  </td>
                </tr>
              ) : (
                leases.map((lease) => (
                  <tr key={lease.id} className="align-top">
                    <td className="font-mono text-xs">{lease.id}</td>
                    <td>{lease.provider}</td>
                    <td>{lease.role}</td>
                    <td>
                      <StatusBadge vocabulary="certificate" value={lease.state} />
                    </td>
                    <td>{formatDate(lease.issued_at)}</td>
                    <td>{formatDate(lease.expires_at)}</td>
                    <td>
                      <div className="flex flex-wrap gap-2">
                        <Button
                          type="button"
                          size="sm"
                          variant="outline"
                          disabled={busy === `renew:${lease.id}` || lease.state === "revoked"}
                          onClick={() => void renewLease(lease.id)}
                        >
                          <RefreshCw className={busy === `renew:${lease.id}` ? "h-4 w-4 animate-spin" : "h-4 w-4"} aria-hidden="true" />
                          Renew 5m
                        </Button>
                        <Button
                          type="button"
                          size="sm"
                          variant="outline"
                          disabled={busy === `revoke:${lease.id}` || lease.state === "revoked"}
                          aria-label={`Revoke lease ${lease.id}`}
                          onClick={() => void revokeLease(lease.id)}
                        >
                          <Ban className="h-4 w-4" aria-hidden="true" />
                          Revoke
                        </Button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
        <UnavailableState title="Lease history isn't in the console yet">
          The lease API can issue, read by ID, renew, and revoke. A tenant-wide lease list is not available in the browser contract yet, so this table shows
          leases returned during this session.
        </UnavailableState>
        <UnavailableState title="Ephemeral JIT issuance uses external approval flows">
          Approval-gated ephemeral issuance is available outside this console. This console does not collect live proof payloads or approval actions.
        </UnavailableState>
      </section>

      <section aria-labelledby="attestation-heading" className="grid gap-3 border-y border-border py-4">
        <div>
          <h2 id="attestation-heading" className="text-title font-semibold">
            Workload attestation chain
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            Attestation proves the workload and its platform. Submit a proof payload to issue an X.509-SVID, then keep only attestation metadata in the table.
          </p>
        </div>
        <form aria-labelledby="attested-issue-heading" className="ui-panel grid gap-3 p-comfortable" onSubmit={issueAttestedSVID}>
          <div>
            <h3 id="attested-issue-heading" className="text-title font-semibold">
              Issue attested SVID
            </h3>
            <p className="mt-1 text-sm text-muted-foreground">Proof payloads and returned certificates are cleared instead of being stored in UI state.</p>
          </div>
          <div className="grid gap-3 md:grid-cols-[12rem_1fr_1fr_10rem_auto]">
            <label className="grid gap-1 text-sm font-medium">
              Attestation method
              <select className="ui-input" name="method" defaultValue="k8s_sat">
                <option value="k8s_sat">Kubernetes service account</option>
                <option value="github_oidc">GitHub OIDC</option>
                <option value="aws_iid">AWS instance identity</option>
                <option value="azure_imds">Azure IMDS</option>
                <option value="gcp_iit">GCP instance identity</option>
                <option value="tpm">TPM quote</option>
              </select>
            </label>
            <label className="grid gap-1 text-sm font-medium">
              Attestation proof payload (base64)
              <textarea className="ui-input min-h-20 font-mono text-xs" name="payload_base64" required />
            </label>
            <label className="grid gap-1 text-sm font-medium">
              Workload public key
              <textarea className="ui-input min-h-20 font-mono text-xs" name="public_key_pem" required />
            </label>
            <label className="grid gap-1 text-sm font-medium">
              SVID TTL seconds
              <input className="ui-input" type="number" min={60} max={86400} name="ttl_seconds" defaultValue={600} />
            </label>
            <Button type="submit" className="self-end" disabled={busy === "attested-svid"}>
              {busy === "attested-svid" ? <RefreshCw className="h-4 w-4 animate-spin" aria-hidden="true" /> : <Plus className="h-4 w-4" aria-hidden="true" />}
              Issue attested SVID
            </Button>
          </div>
        </form>
        {attestationError && <ErrorState title="Attested SVID failed">{attestationError}</ErrorState>}
        <div className="ui-panel overflow-x-auto">
          <table className="ui-table min-w-[58rem]">
            <caption className="sr-only">Attested SVID outcomes</caption>
            <thead>
              <tr>
                <th scope="col">Credential</th>
                <th scope="col">Subject</th>
                <th scope="col">Method</th>
                <th scope="col">Selectors</th>
                <th scope="col">Verified</th>
                <th scope="col">Expires</th>
              </tr>
            </thead>
            <tbody>
              {attestedSVIDs.length === 0 ? (
                <tr>
                  <td colSpan={6} className="text-muted-foreground">
                    No attested SVID has been issued in this browser session.
                  </td>
                </tr>
              ) : (
                attestedSVIDs.map((row) => (
                  <tr key={row.credential_id} className="align-top">
                    <td className="font-mono text-xs">{row.credential_id}</td>
                    <td>{row.subject}</td>
                    <td>{row.attestation.method}</td>
                    <td>{row.attestation.selectors.join(", ") || "-"}</td>
                    <td>{formatDate(row.attestation.verified_at)}</td>
                    <td>{formatDate(row.not_after)}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
        <UnavailableState title="Raw attestation evidence stays out of the browser">
          Submitted proof fields are cleared after issue. Returned certificate PEM and claim maps are discarded before the row is stored.
        </UnavailableState>
      </section>

      <section aria-labelledby="broker-heading" className="grid gap-3 border-y border-border py-4">
        <div>
          <h2 id="broker-heading" className="text-title font-semibold">
            AI-agent / NHI broker
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            A broker turns an agent identity plus policy into a short credential lease. Submit proof once, then render only returned identity metadata.
          </p>
        </div>
        <form aria-labelledby="broker-issue-heading" className="ui-panel grid gap-3 p-comfortable" onSubmit={issueBrokerIdentity}>
          <div>
            <h3 id="broker-issue-heading" className="text-title font-semibold">
              Issue broker identity
            </h3>
            <p className="mt-1 text-sm text-muted-foreground">Proof payloads are submitted directly and cleared after the broker returns identity metadata.</p>
          </div>
          <div className="grid gap-3 md:grid-cols-[1fr_12rem_1fr_8rem]">
            <label className="grid gap-1 text-sm font-medium">
              Agent ID
              <input className="ui-input" name="agent_id" defaultValue="agent-build-1" required />
            </label>
            <label className="grid gap-1 text-sm font-medium">
              Broker method
              <input className="ui-input" name="method" defaultValue="github_oidc" required />
            </label>
            <label className="grid gap-1 text-sm font-medium">
              Broker scopes
              <input className="ui-input" name="scopes" defaultValue="mcp:read-only, secrets:read:ci" required />
            </label>
            <label className="grid gap-1 text-sm font-medium">
              Broker TTL seconds
              <input className="ui-input" type="number" min={60} max={86400} name="ttl_seconds" defaultValue={900} />
            </label>
          </div>
          <div className="grid gap-3 md:grid-cols-[1fr_1fr_auto]">
            <label className="grid gap-1 text-sm font-medium">
              Broker proof payload (base64)
              <textarea className="ui-input min-h-20 font-mono text-xs" name="payload_base64" required />
            </label>
            <label className="grid gap-1 text-sm font-medium">
              Broker public key
              <textarea className="ui-input min-h-20 font-mono text-xs" name="public_key_pem" required />
            </label>
            <Button type="submit" className="self-end" disabled={busy === "broker"}>
              {busy === "broker" ? <RefreshCw className="h-4 w-4 animate-spin" aria-hidden="true" /> : <Plus className="h-4 w-4" aria-hidden="true" />}
              Issue broker identity
            </Button>
          </div>
        </form>
        {brokerError && <ErrorState title="Broker identity failed">{brokerError}</ErrorState>}
        <div className="ui-panel overflow-x-auto">
          <table className="ui-table min-w-[58rem]">
            <caption className="sr-only">AI agent broker identities</caption>
            <thead>
              <tr>
                <th scope="col">Agent</th>
                <th scope="col">Subject</th>
                <th scope="col">Scopes</th>
                <th scope="col">Method</th>
                <th scope="col">Verified</th>
                <th scope="col">Expires</th>
                <th scope="col">Audit IDs</th>
              </tr>
            </thead>
            <tbody>
              {brokerIdentities.length === 0 ? (
                <tr>
                  <td colSpan={7} className="text-muted-foreground">
                    No broker identity has been issued in this browser session.
                  </td>
                </tr>
              ) : (
                brokerIdentities.map((identity) => (
                  <tr key={identity.credential_id} className="align-top">
                    <td className="font-medium">{identity.agent_id}</td>
                    <td>{identity.subject}</td>
                    <td>{identity.scopes.join(", ")}</td>
                    <td>{identity.attestation.method}</td>
                    <td>{formatDate(identity.attestation.verified_at)}</td>
                    <td>{formatDate(identity.not_after)}</td>
                    <td className="font-mono text-xs">
                      {identity.certificate_id} / {identity.credential_id} / {identity.node_id}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
        <UnavailableState title="Broker history isn't in the console yet">
          The broker API issues a single identity per request. A tenant-wide broker history list is not available in the browser contract yet, so this table
          shows identities returned during this session.
        </UnavailableState>
      </section>
    </section>
  );
}

function formatDate(value?: string): string {
  return formatDateTimePolicy(value);
}

function leaseMetadataOnly(lease: DynamicLease): DynamicLease {
  return {
    id: lease.id,
    provider: lease.provider,
    role: lease.role,
    state: lease.state,
    issued_at: lease.issued_at,
    expires_at: lease.expires_at,
  };
}

function brokerIdentityMetadataOnly(identity: BrokerAgentIdentity): BrokerIdentityRow {
  return {
    agent_id: identity.agent_id,
    subject: identity.subject,
    scopes: [...identity.scopes],
    not_after: identity.not_after,
    certificate_id: identity.certificate_id,
    credential_id: identity.credential_id,
    node_id: identity.node_id,
    attestation: attestationMetadataOnly(identity.attestation),
  };
}

function attestedSVIDMetadataOnly(svid: AttestedSVID): AttestedSVIDRow {
  return {
    credential_id: svid.credential_id,
    subject: svid.subject,
    not_after: svid.not_after,
    attestation: attestationMetadataOnly(svid.attestation),
  };
}

function attestationMetadataOnly(attestation: Attestation): SafeAttestation {
  return {
    id: attestation.id,
    method: attestation.method,
    subject: attestation.subject,
    selectors: [...attestation.selectors],
    verified_at: attestation.verified_at,
  };
}

function formString(data: FormData, name: string): string {
  const value = data.get(name);
  return typeof value === "string" ? value.trim() : "";
}

function formNumber(data: FormData, name: string): number | undefined {
  const value = Number(formString(data, name));
  return Number.isFinite(value) && value > 0 ? value : undefined;
}

function parseScopes(value: string): string[] {
  return value
    .split(",")
    .map((scope) => scope.trim())
    .filter(Boolean);
}

function apiProblemMessage(err: unknown, fallback: string): string {
  if (err instanceof ApiError) {
    if (err.retryAfterSeconds != null) return `${fallback}: retry in ${err.retryAfterSeconds}s`;
    try {
      const problem = JSON.parse(err.body) as { detail?: string; title?: string };
      return problem.detail || problem.title || err.message;
    } catch {
      return err.body || err.message;
    }
  }
  return err instanceof Error ? err.message : fallback;
}
