import { type FormEvent, useEffect, useMemo, useState } from "react";
import { PageHeader } from "@/components/PageHeader";
import { ErrorState, LoadingState } from "@/components/StatePrimitives";
import {
  api,
  type SSHAttestedUserCert,
  type SSHAttestedUserCertRequest,
  type SSHHostRetirement,
  type SSHStatus,
  type SSHTrustRollout,
  type SSHTrustRolloutRequest,
} from "@/lib/api";

const fallbackAttestors = ["k8s_sat", "github_oidc", "aws_iid", "azure_imds", "gcp_iit", "tpm"];
const rolloutStatuses: SSHTrustRolloutRequest["status"][] = ["planned", "validating", "health_passed", "rolled_back", "failed"];

function splitHosts(input: string): string[] {
  return input
    .split(/[\n,]/)
    .map((value) => value.trim())
    .filter(Boolean);
}

function numericOrUndefined(input: string): number | undefined {
  const n = Number(input);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : undefined;
}

export function SSHTrust() {
  const [status, setStatus] = useState<SSHStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [actionResult, setActionResult] = useState<string | null>(null);
  const [rollout, setRollout] = useState<SSHTrustRollout | null>(null);
  const [issuedCert, setIssuedCert] = useState<SSHAttestedUserCert | null>(null);
  const [retirement, setRetirement] = useState<SSHHostRetirement | null>(null);
  const [sourceId, setSourceId] = useState("");
  const [hosts, setHosts] = useState("edge-1.internal");
  const [fingerprint, setFingerprint] = useState("");
  const [reloadCommand, setReloadCommand] = useState("systemctl reload sshd");
  const [healthCommand, setHealthCommand] = useState("ssh -o BatchMode=yes localhost true");
  const [rollbackPlan, setRollbackPlan] = useState("restore trusted_user_ca_keys backup and reload sshd");
  const [rolloutStatus, setRolloutStatus] = useState<SSHTrustRolloutRequest["status"]>("health_passed");
  const [confirmed, setConfirmed] = useState(false);
  const [method, setMethod] = useState<SSHAttestedUserCertRequest["method"]>("k8s_sat");
  const [payloadBase64, setPayloadBase64] = useState("");
  const [publicKey, setPublicKey] = useState("");
  const [keyId, setKeyId] = useState("jit-deployer");
  const [ttlSeconds, setTTLSeconds] = useState("900");
  const [revokeSerial, setRevokeSerial] = useState("");
  const [revokeKeyId, setRevokeKeyId] = useState("");
  const [revokeReason, setRevokeReason] = useState("operator requested revocation");
  const [retireHost, setRetireHost] = useState("edge-1.internal");
  const [retireSourceId, setRetireSourceId] = useState("");
  const [retireRunId, setRetireRunId] = useState("");
  const [retireIdentityId, setRetireIdentityId] = useState("");
  const [retireReason, setRetireReason] = useState("standing SSH access replaced by certificate trust");

  const loadStatus = () =>
    api
      .sshStatus()
      .then((next) => {
        setStatus(next);
        setError(null);
      })
      .catch((err) => setError(err instanceof Error ? err.message : String(err)));

  useEffect(() => {
    let cancelled = false;
    api
      .sshStatus()
      .then((next) => {
        if (!cancelled) {
          setStatus(next);
          setError(null);
        }
      })
      .catch((err) => {
        if (!cancelled) setError(err instanceof Error ? err.message : String(err));
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const attestors = useMemo(() => (status?.attestors?.length ? status.attestors : fallbackAttestors), [status?.attestors]);

  const recordRollout = async (event: FormEvent) => {
    event.preventDefault();
    try {
      const result = await api.recordSSHTrustRollout({
        source_id: sourceId || undefined,
        target_hosts: splitHosts(hosts),
        candidate_ca_fingerprint: fingerprint || undefined,
        reload_command: reloadCommand || undefined,
        health_command: healthCommand || undefined,
        rollback_plan: rollbackPlan || undefined,
        status: rolloutStatus,
        confirmed,
      });
      setRollout(result);
      setActionResult(`trust-rollout:${result.status}`);
      await loadStatus();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  const issueAttested = async (event: FormEvent) => {
    event.preventDefault();
    try {
      const result = await api.issueAttestedSSHUserCert({
        method,
        payload_base64: payloadBase64,
        public_key: publicKey,
        key_id: keyId || undefined,
        ttl_seconds: numericOrUndefined(ttlSeconds),
      });
      setIssuedCert(result);
      setRevokeSerial(String(result.serial));
      setRevokeKeyId(result.key_id || "");
      setActionResult(`ssh-cert:${result.serial}`);
      await loadStatus();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  const revokeCertificate = async (event: FormEvent) => {
    event.preventDefault();
    try {
      const next = await api.revokeSSHCertificate({
        serial: numericOrUndefined(revokeSerial),
        key_id: revokeKeyId || undefined,
        reason: revokeReason || undefined,
      });
      setStatus(next);
      setActionResult(`krl:${next.krl_version}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  const retireHostSubmit = async (event: FormEvent) => {
    event.preventDefault();
    try {
      const result = await api.retireSSHHost({
        host: retireHost,
        source_id: retireSourceId || undefined,
        run_id: retireRunId || undefined,
        identity_id: retireIdentityId || undefined,
        reason: retireReason || undefined,
      });
      setRetirement(result);
      setActionResult(`host:${result.status}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  return (
    <section aria-labelledby="ssh-heading" className="grid gap-6">
      <PageHeader
        titleId="ssh-heading"
        title="SSH trust"
        description="SSH CA status, trust rollout evidence, attestation-gated user certificates, KRL revocation, and host retirement from the served SSH workflow API."
      />

      {error && <ErrorState title="SSH workflow failed">{error}</ErrorState>}
      {!status && !error && <LoadingState>Loading SSH workflow...</LoadingState>}
      {actionResult && <output className="font-mono text-xs text-muted-foreground">{actionResult}</output>}

      {status && (
        <section aria-labelledby="ssh-status-heading" className="grid gap-3 border-y border-border py-4">
          <div>
            <h2 id="ssh-status-heading" className="text-title font-semibold">
              SSH CA and KRL status
            </h2>
          </div>
          <div className="ui-panel grid gap-3 md:grid-cols-4">
            <div>
              <p className="text-xs text-muted-foreground">Workflow available</p>
              <p className="font-mono text-sm">{status.served ? "true" : "false"}</p>
            </div>
            <div>
              <p className="text-xs text-muted-foreground">KRL version</p>
              <p className="font-mono text-sm">{status.krl_version}</p>
            </div>
            <div>
              <p className="text-xs text-muted-foreground">Revoked certs</p>
              <p className="font-mono text-sm">{status.revoked_count}</p>
            </div>
            <div>
              <p className="text-xs text-muted-foreground">Attestors</p>
              <p className="break-all font-mono text-sm">{attestors.join(", ")}</p>
            </div>
            <div className="md:col-span-4">
              <p className="text-xs text-muted-foreground">Authority key</p>
              <p className="break-all font-mono text-xs">{status.authority_key || "not published"}</p>
            </div>
          </div>
        </section>
      )}

      <section aria-labelledby="rollout-heading" className="grid gap-3 border-y border-border py-4">
        <div>
          <h2 id="rollout-heading" className="text-title font-semibold">
            SSH deployment and trust rollout
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            A safe rollout names the candidate CA, target hosts, validation command, reload health command, rollback plan, and explicit confirmation copy before
            any host changes trust.
          </p>
        </div>
        <form aria-label="Record SSH trust rollout" className="ui-panel grid gap-3 md:grid-cols-3" onSubmit={(event) => void recordRollout(event)}>
          <label className="grid gap-1 text-sm">
            Discovery source
            <input className="ui-input" value={sourceId} onChange={(event) => setSourceId(event.target.value)} placeholder="source uuid" />
          </label>
          <label className="grid gap-1 text-sm">
            Target hosts
            <textarea className="ui-input min-h-20 font-mono text-xs" value={hosts} onChange={(event) => setHosts(event.target.value)} required />
          </label>
          <label className="grid gap-1 text-sm">
            Candidate CA fingerprint
            <input className="ui-input" value={fingerprint} onChange={(event) => setFingerprint(event.target.value)} />
          </label>
          <label className="grid gap-1 text-sm">
            Reload command
            <input className="ui-input" value={reloadCommand} onChange={(event) => setReloadCommand(event.target.value)} />
          </label>
          <label className="grid gap-1 text-sm">
            Health command
            <input className="ui-input" value={healthCommand} onChange={(event) => setHealthCommand(event.target.value)} />
          </label>
          <label className="grid gap-1 text-sm">
            Status
            <select className="ui-input" value={rolloutStatus} onChange={(event) => setRolloutStatus(event.target.value as SSHTrustRolloutRequest["status"])}>
              {rolloutStatuses.map((value) => (
                <option key={value} value={value}>
                  {value}
                </option>
              ))}
            </select>
          </label>
          <label className="grid gap-1 text-sm md:col-span-3">
            Rollback plan
            <textarea className="ui-input min-h-20" value={rollbackPlan} onChange={(event) => setRollbackPlan(event.target.value)} />
          </label>
          <label className="flex items-center gap-2 text-sm md:col-span-3">
            <input type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} />
            Confirm high-blast-radius SSH trust rollout evidence
          </label>
          <button className="ui-button md:col-span-3" type="submit" disabled={!confirmed || splitHosts(hosts).length === 0}>
            Record trust rollout
          </button>
          {rollout && <output className="font-mono text-xs text-muted-foreground md:col-span-3">{rollout.id}</output>}
        </form>
      </section>

      <section aria-labelledby="jit-heading" className="grid gap-3 border-y border-border py-4">
        <div>
          <h2 id="jit-heading" className="text-title font-semibold">
            Attestation-gated SSH user certs
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            Short-lived SSH user certs require attestation evidence, an approver, principal constraints, TTL, source-address, and force-command policy.
            Self-approval blocked is a hard rule, not a UI hint.
          </p>
        </div>
        <form aria-label="Issue attested SSH user certificate" className="ui-panel grid gap-3 md:grid-cols-3" onSubmit={(event) => void issueAttested(event)}>
          <label className="grid gap-1 text-sm">
            Attestation method
            <select className="ui-input" value={method} onChange={(event) => setMethod(event.target.value as SSHAttestedUserCertRequest["method"])}>
              {attestors.map((value) => (
                <option key={value} value={value}>
                  {value}
                </option>
              ))}
            </select>
          </label>
          <label className="grid gap-1 text-sm">
            Key ID
            <input className="ui-input" value={keyId} onChange={(event) => setKeyId(event.target.value)} />
          </label>
          <label className="grid gap-1 text-sm">
            TTL seconds
            <input className="ui-input" inputMode="numeric" value={ttlSeconds} onChange={(event) => setTTLSeconds(event.target.value)} />
          </label>
          <label className="grid gap-1 text-sm md:col-span-3">
            Attestation payload base64
            <textarea className="ui-input min-h-24 font-mono text-xs" value={payloadBase64} onChange={(event) => setPayloadBase64(event.target.value)} required />
          </label>
          <label className="grid gap-1 text-sm md:col-span-3">
            SSH public key
            <textarea className="ui-input min-h-24 font-mono text-xs" value={publicKey} onChange={(event) => setPublicKey(event.target.value)} required />
          </label>
          <button className="ui-button md:col-span-3" type="submit">
            Issue attested SSH cert
          </button>
          {issuedCert && (
            <div className="grid gap-2 md:col-span-3">
              <p className="font-mono text-xs text-muted-foreground">
                serial {issuedCert.serial} | subject {issuedCert.subject} | valid before {issuedCert.valid_before}
              </p>
              <textarea className="ui-input min-h-24 font-mono text-xs" readOnly value={issuedCert.certificate} aria-label="Issued SSH certificate" />
            </div>
          )}
        </form>
      </section>

      <section aria-labelledby="krl-heading" className="grid gap-3 border-y border-border py-4">
        <div>
          <h2 id="krl-heading" className="text-title font-semibold">
            KRL revocation
          </h2>
        </div>
        <form aria-label="Revoke SSH certificate" className="ui-panel grid gap-3 md:grid-cols-3" onSubmit={(event) => void revokeCertificate(event)}>
          <label className="grid gap-1 text-sm">
            Serial
            <input className="ui-input" inputMode="numeric" value={revokeSerial} onChange={(event) => setRevokeSerial(event.target.value)} />
          </label>
          <label className="grid gap-1 text-sm">
            Key ID
            <input className="ui-input" value={revokeKeyId} onChange={(event) => setRevokeKeyId(event.target.value)} />
          </label>
          <label className="grid gap-1 text-sm">
            Reason
            <input className="ui-input" value={revokeReason} onChange={(event) => setRevokeReason(event.target.value)} />
          </label>
          <button className="ui-button md:col-span-3" type="submit" disabled={!revokeSerial && !revokeKeyId}>
            Revoke and publish KRL
          </button>
        </form>
      </section>

      <section aria-labelledby="retire-heading" className="grid gap-3 border-y border-border py-4">
        <div>
          <h2 id="retire-heading" className="text-title font-semibold">
            Host retirement
          </h2>
        </div>
        <form aria-label="Retire SSH host" className="ui-panel grid gap-3 md:grid-cols-3" onSubmit={(event) => void retireHostSubmit(event)}>
          <label className="grid gap-1 text-sm">
            Host
            <input className="ui-input" value={retireHost} onChange={(event) => setRetireHost(event.target.value)} required />
          </label>
          <label className="grid gap-1 text-sm">
            Discovery source
            <input className="ui-input" value={retireSourceId} onChange={(event) => setRetireSourceId(event.target.value)} placeholder="source uuid" />
          </label>
          <label className="grid gap-1 text-sm">
            Discovery run
            <input className="ui-input" value={retireRunId} onChange={(event) => setRetireRunId(event.target.value)} placeholder="run uuid" />
          </label>
          <label className="grid gap-1 text-sm">
            Identity
            <input className="ui-input" value={retireIdentityId} onChange={(event) => setRetireIdentityId(event.target.value)} placeholder="identity uuid" />
          </label>
          <label className="grid gap-1 text-sm md:col-span-2">
            Reason
            <input className="ui-input" value={retireReason} onChange={(event) => setRetireReason(event.target.value)} />
          </label>
          <button className="ui-button md:col-span-3" type="submit">
            Record host retired
          </button>
          {retirement && <output className="font-mono text-xs text-muted-foreground md:col-span-3">{retirement.host}:{retirement.status}</output>}
        </form>
      </section>
    </section>
  );
}
