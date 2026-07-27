import { type FormEvent, useEffect, useMemo, useState } from "react";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/PageHeader";
import { ErrorState, LoadingState } from "@/components/StatePrimitives";
import { StatusBadge } from "@/components/StatusBadge";
import { useTranslation, translateNow } from "@/i18n/I18nProvider";
import {
  api,
  type SSHAttestedUserCert,
  type SSHAttestedUserCertRequest,
  type SSHFleetInventory,
  type SSHHostRetirement,
  type SSHStatus,
  type SSHTrustRollout,
  type SSHTrustRolloutRequest,
} from "@/lib/api";

const fallbackAttestors = ["k8s_sat", "github_oidc", "aws_iid", "azure_imds", "gcp_iit", "tpm"];
const rolloutStatuses: SSHTrustRolloutRequest["status"][] = ["planned", "validating", "health_passed", "rolled_back", "failed"];

// S-C16: the rollout's status was a bare enum in a dropdown and an id in the
// output line, so "where is this rollout, and is that good" needed knowledge
// of the state machine. The stepper draws the machine: plan → validate →
// health-passed is the intended path, and rolled-back / failed are terminal
// branches that replace the remaining steps rather than sitting beside them.
const rolloutHappyPath = ["planned", "validating", "health_passed"] as const;

export type RolloutStep = { status: string; state: "done" | "current" | "upcoming" | "terminal" };

export function rolloutSteps(status: string): RolloutStep[] {
  const terminalIndex = rolloutHappyPath.indexOf(status as (typeof rolloutHappyPath)[number]);
  if (terminalIndex >= 0) {
    return rolloutHappyPath.map((step, index) => ({
      status: step,
      state: index < terminalIndex ? "done" : index === terminalIndex ? "current" : "upcoming",
    }));
  }
  // rolled_back / failed: the run left the happy path after validation began.
  return [
    { status: "planned", state: "done" },
    { status: "validating", state: "done" },
    { status, state: "terminal" },
  ];
}

function RolloutStepper({ status }: { status: string }) {
  const steps = rolloutSteps(status);
  return (
    <ol className="flex flex-wrap items-center gap-2" aria-label={translateNow("ssh.rollout.stepperLabel")}>
      {steps.map((step, index) => (
        <li key={step.status} className="flex items-center gap-2">
          {index > 0 ? (
            <span aria-hidden="true" className="text-muted-foreground">
              →
            </span>
          ) : null}
          <StatusBadge
            vocabulary="lifecycle"
            value={step.status}
            label={step.status.replace(/_/g, " ")}
            tone={step.state === "terminal" ? "critical" : step.state === "current" ? "warning" : step.state === "done" ? "success" : "neutral"}
          />
        </li>
      ))}
    </ol>
  );
}

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
  const { t } = useTranslation();
  const [status, setStatus] = useState<SSHStatus | null>(null);
  const [fleet, setFleet] = useState<SSHFleetInventory | null>(null);
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
  const [approver, setApprover] = useState("ssh-approver");
  const [principals, setPrincipals] = useState("web");
  const [sourceAddresses, setSourceAddresses] = useState("10.0.0.0/24");
  const [forceCommand, setForceCommand] = useState("/usr/local/bin/deploy");
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
    Promise.all([api.sshStatus(), api.sshFleet()])
      .then(([next, nextFleet]) => {
        if (!cancelled) {
          setStatus(next);
          setFleet(nextFleet);
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
  // Route-level and rolling-upgrade callers can briefly see the pre-inventory
  // SSH payload, which has no `hosts` member. Keep that honest empty state
  // renderable instead of crashing the entire console shell.
  const fleetHosts = fleet?.hosts ?? [];

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
        approver: approver.trim(),
        principals: splitHosts(principals),
        source_addresses: splitHosts(sourceAddresses),
        force_command: forceCommand.trim() || undefined,
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
        title={translateNow("source.ssh.trust.8a25c0e13c")}
        description="SSH CA status, trust rollout evidence, attestation-gated user certificates, KRL revocation, and host retirement from the served SSH workflow API."
      />

      {error && <ErrorState title={translateNow("source.ssh.workflow.failed.e76cbdb07c")}>{error}</ErrorState>}
      {!status && !error && <LoadingState>{translateNow("source.loading.ssh.workflow.eee4586266")}</LoadingState>}
      {actionResult && <output className="font-mono text-xs text-muted-foreground">{actionResult}</output>}

      {status && (
        <section aria-labelledby="ssh-status-heading" className="grid gap-3 border-y border-border py-4">
          <div>
            <h2 id="ssh-status-heading" className="text-title font-semibold">
              {translateNow("source.ssh.ca.and.krl.status.f38597dc96")}
            </h2>
          </div>
          <div className="ui-panel grid gap-3 md:grid-cols-4">
            <div>
              <p className="text-xs text-muted-foreground">{translateNow("source.workflow.available.3946309163")}</p>
              <p className="font-mono text-sm">{status.served ? "true" : "false"}</p>
            </div>
            <div>
              <p className="text-xs text-muted-foreground">{translateNow("source.krl.version.2381c27676")}</p>
              <p className="font-mono text-sm">{status.krl_version}</p>
            </div>
            <div>
              <p className="text-xs text-muted-foreground">{translateNow("source.revoked.certs.267c0b721b")}</p>
              <p className="font-mono text-sm">{status.revoked_count}</p>
            </div>
            <div>
              <p className="text-xs text-muted-foreground">{translateNow("source.attestors.2e3ad3c00b")}</p>
              <p className="break-all font-mono text-sm">{attestors.join(", ")}</p>
            </div>
            <div className="md:col-span-4">
              <p className="text-xs text-muted-foreground">{translateNow("source.authority.key.60329d7d7b")}</p>
              <p className="break-all font-mono text-xs">{status.authority_key || translateNow("source.not.published.30839efda7")}</p>
            </div>
          </div>
        </section>
      )}

      {fleet && (
        <section aria-labelledby="ssh-fleet-heading" className="grid gap-3 border-y border-border py-4">
          <div>
            <h2 id="ssh-fleet-heading" className="text-title font-semibold">
              {t("sshTrust.fleet.heading")}
            </h2>
            <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{t("sshTrust.fleet.description")}</p>
          </div>
          <div className="grid gap-3 sm:grid-cols-3">
            <div className="ui-panel p-3">
              <p className="text-xs text-muted-foreground">{t("sshTrust.fleet.hostsOutsideCA")}</p>
              <p className="font-mono text-lg">{fleet.hosts_not_under_ca}</p>
            </div>
            <div className="ui-panel p-3">
              <p className="text-xs text-muted-foreground">{t("sshTrust.fleet.standingGrants")}</p>
              <p className="font-mono text-lg">{fleet.standing_key_count}</p>
            </div>
            <div className="ui-panel p-3">
              <p className="text-xs text-muted-foreground">{t("sshTrust.fleet.orphanedGrants")}</p>
              <p className="font-mono text-lg">{fleet.orphaned_key_count}</p>
            </div>
          </div>
          {fleetHosts.length === 0 ? (
            <p className="text-sm text-muted-foreground">{t("sshTrust.fleet.empty")}</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="ui-table" aria-label={t("sshTrust.fleet.tableLabel")}>
                <thead>
                  <tr>
                    <th scope="col">{t("sshTrust.fleet.location")}</th>
                    <th scope="col">{t("sshTrust.fleet.keyTypes")}</th>
                    <th scope="col">{t("sshTrust.fleet.sources")}</th>
                    <th scope="col">{t("sshTrust.fleet.access")}</th>
                  </tr>
                </thead>
                <tbody>
                  {fleetHosts.map((host) => (
                    <tr key={host.location}>
                      <td className="font-mono text-xs">{host.location}</td>
                      <td>{host.key_types.join(", ") || t("sshTrust.fleet.unknown")}</td>
                      <td>{host.sources.join(", ") || t("sshTrust.fleet.unknown")}</td>
                      <td>{t("sshTrust.fleet.accessSummary", { standing: host.standing_keys, orphaned: host.orphaned_keys })}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      )}

      <section aria-labelledby="rollout-heading" className="grid gap-3 border-y border-border py-4">
        <div>
          <h2 id="rollout-heading" className="text-title font-semibold">
            {translateNow("source.ssh.deployment.and.trust.rollout.098d316f31")}
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{translateNow("source.a.safe.rollout.names.the.candidate.ca.targ.fdf82b1ab9")}</p>
        </div>
        <form aria-label="Record SSH trust rollout" className="ui-panel grid gap-3 md:grid-cols-3" onSubmit={(event) => void recordRollout(event)}>
          <label className="grid gap-1 text-sm">
            {translateNow("source.discovery.source.f533df1c0c")}
            <input
              className="ui-input"
              value={sourceId}
              onChange={(event) => setSourceId(event.target.value)}
              placeholder={translateNow("source.source.uuid.266dd280b0")}
            />
          </label>
          <label className="grid gap-1 text-sm">
            {translateNow("source.target.hosts.b345027096")}
            <textarea className="ui-input min-h-20 font-mono text-xs" value={hosts} onChange={(event) => setHosts(event.target.value)} required />
          </label>
          <label className="grid gap-1 text-sm">
            {translateNow("source.candidate.ca.fingerprint.78e53d126d")}
            <input className="ui-input" value={fingerprint} onChange={(event) => setFingerprint(event.target.value)} />
          </label>
          <label className="grid gap-1 text-sm">
            {translateNow("source.reload.command.cf1acb1111")}
            <input className="ui-input" value={reloadCommand} onChange={(event) => setReloadCommand(event.target.value)} />
          </label>
          <label className="grid gap-1 text-sm">
            {translateNow("source.health.command.5ad9864488")}
            <input className="ui-input" value={healthCommand} onChange={(event) => setHealthCommand(event.target.value)} />
          </label>
          <label className="grid gap-1 text-sm">
            {translateNow("source.status.920e413c7d")}
            <select className="ui-input" value={rolloutStatus} onChange={(event) => setRolloutStatus(event.target.value as SSHTrustRolloutRequest["status"])}>
              {rolloutStatuses.map((value) => (
                <option key={value} value={value}>
                  {value}
                </option>
              ))}
            </select>
          </label>
          <label className="grid gap-1 text-sm md:col-span-3">
            {translateNow("source.rollback.plan.952efc8286")}
            <textarea className="ui-input min-h-20" value={rollbackPlan} onChange={(event) => setRollbackPlan(event.target.value)} />
          </label>
          <label className="flex items-center gap-2 text-sm md:col-span-3">
            <input type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} />
            {translateNow("source.confirm.high.blast.radius.ssh.trust.rollou.31dcb6c476")}
          </label>
          <Button className="md:col-span-3" type="submit" disabled={!confirmed || splitHosts(hosts).length === 0}>
            Record trust rollout
          </Button>
          {rollout && (
            <div className="grid gap-2 md:col-span-3">
              <RolloutStepper status={rollout.status} />
              <output className="font-mono text-xs text-muted-foreground">{rollout.id}</output>
            </div>
          )}
        </form>
      </section>

      <section aria-labelledby="jit-heading" className="grid gap-3 border-y border-border py-4">
        <div>
          <h2 id="jit-heading" className="text-title font-semibold">
            {translateNow("source.attestation.gated.ssh.user.certs.d49d24e892")}
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{t("sshTrust.attested.description")}</p>
        </div>
        <form
          aria-label={translateNow("source.issue.attested.ssh.user.certificate.f7e0f6ef66")}
          className="ui-panel grid gap-3 md:grid-cols-3"
          onSubmit={(event) => void issueAttested(event)}
        >
          <label className="grid gap-1 text-sm">
            {translateNow("source.attestation.method.1f0610be7c")}
            <select className="ui-input" value={method} onChange={(event) => setMethod(event.target.value as SSHAttestedUserCertRequest["method"])}>
              {attestors.map((value) => (
                <option key={value} value={value}>
                  {value}
                </option>
              ))}
            </select>
          </label>
          <label className="grid gap-1 text-sm">
            {translateNow("source.key.id.d54d56ee0a")}
            <input className="ui-input" value={keyId} onChange={(event) => setKeyId(event.target.value)} />
          </label>
          <label className="grid gap-1 text-sm">
            {translateNow("source.ttl.seconds.862d08de5a")}
            <input className="ui-input" inputMode="numeric" value={ttlSeconds} onChange={(event) => setTTLSeconds(event.target.value)} />
          </label>
          <label className="grid gap-1 text-sm">
            {t("sshTrust.attested.approver")}
            <input className="ui-input" value={approver} onChange={(event) => setApprover(event.target.value)} required />
          </label>
          <label className="grid gap-1 text-sm">
            {t("sshTrust.attested.boundPrincipals")}
            <textarea className="ui-input min-h-20 font-mono text-xs" value={principals} onChange={(event) => setPrincipals(event.target.value)} />
          </label>
          <label className="grid gap-1 text-sm">
            {t("sshTrust.attested.sourceAddresses")}
            <textarea className="ui-input min-h-20 font-mono text-xs" value={sourceAddresses} onChange={(event) => setSourceAddresses(event.target.value)} />
          </label>
          <label className="grid gap-1 text-sm md:col-span-3">
            {t("sshTrust.attested.forceCommand")}
            <input className="ui-input font-mono text-xs" value={forceCommand} onChange={(event) => setForceCommand(event.target.value)} />
          </label>
          <label className="grid gap-1 text-sm md:col-span-3">
            {translateNow("source.attestation.payload.base64.11bfdba122")}
            <textarea
              className="ui-input min-h-24 font-mono text-xs"
              value={payloadBase64}
              onChange={(event) => setPayloadBase64(event.target.value)}
              required
            />
          </label>
          <label className="grid gap-1 text-sm md:col-span-3">
            {translateNow("source.ssh.public.key.c9be6a369e")}
            <textarea className="ui-input min-h-24 font-mono text-xs" value={publicKey} onChange={(event) => setPublicKey(event.target.value)} required />
          </label>
          <Button className="md:col-span-3" type="submit">
            {translateNow("source.issue.attested.ssh.cert.fba31f1beb")}
          </Button>
          {issuedCert && (
            <div className="grid gap-2 md:col-span-3">
              <p className="font-mono text-xs text-muted-foreground">
                {translateNow("source.serial.0144b1defc")} {issuedCert.serial} {translateNow("source.subject.5dcd66f2ed")} {issuedCert.subject}{" "}
                {translateNow("source.valid.before.8b8acd434a")} {issuedCert.valid_before}
              </p>
              <p className="font-mono text-xs text-muted-foreground">
                {t("sshTrust.attested.resultConstraints", {
                  approver: issuedCert.approver,
                  principals: issuedCert.principals.join(", "),
                  source: issuedCert.source_addresses?.join(", ") || "none",
                  force: issuedCert.force_command || "none",
                })}
              </p>
              <textarea
                className="ui-input min-h-24 font-mono text-xs"
                readOnly
                value={issuedCert.certificate}
                aria-label={translateNow("source.issued.ssh.certificate.3775bb2dee")}
              />
            </div>
          )}
        </form>
      </section>

      <section aria-labelledby="krl-heading" className="grid gap-3 border-y border-border py-4">
        <div>
          <h2 id="krl-heading" className="text-title font-semibold">
            {translateNow("source.krl.revocation.7e579fb6c5")}
          </h2>
        </div>
        <form
          aria-label={translateNow("source.revoke.ssh.certificate.63b6e335c3")}
          className="ui-panel grid gap-3 md:grid-cols-3"
          onSubmit={(event) => void revokeCertificate(event)}
        >
          <label className="grid gap-1 text-sm">
            {translateNow("source.serial.8ea0949377")}
            <input className="ui-input" inputMode="numeric" value={revokeSerial} onChange={(event) => setRevokeSerial(event.target.value)} />
          </label>
          <label className="grid gap-1 text-sm">
            {translateNow("source.key.id.d54d56ee0a")}
            <input className="ui-input" value={revokeKeyId} onChange={(event) => setRevokeKeyId(event.target.value)} />
          </label>
          <label className="grid gap-1 text-sm">
            {translateNow("source.reason.f81ab834de")}
            <input className="ui-input" value={revokeReason} onChange={(event) => setRevokeReason(event.target.value)} />
          </label>
          <Button className="md:col-span-3" type="submit" disabled={!revokeSerial && !revokeKeyId}>
            {translateNow("source.revoke.and.publish.krl.d5e98fd13c")}
          </Button>
        </form>
      </section>

      <section aria-labelledby="retire-heading" className="grid gap-3 border-y border-border py-4">
        <div>
          <h2 id="retire-heading" className="text-title font-semibold">
            {translateNow("source.host.retirement.4f92fcc0ea")}
          </h2>
        </div>
        <form
          aria-label={translateNow("source.retire.ssh.host.6d1acfd432")}
          className="ui-panel grid gap-3 md:grid-cols-3"
          onSubmit={(event) => void retireHostSubmit(event)}
        >
          <label className="grid gap-1 text-sm">
            {translateNow("source.host.4a823118b9")}
            <input className="ui-input" value={retireHost} onChange={(event) => setRetireHost(event.target.value)} required />
          </label>
          <label className="grid gap-1 text-sm">
            {translateNow("source.discovery.source.f533df1c0c")}
            <input
              className="ui-input"
              value={retireSourceId}
              onChange={(event) => setRetireSourceId(event.target.value)}
              placeholder={translateNow("source.source.uuid.266dd280b0")}
            />
          </label>
          <label className="grid gap-1 text-sm">
            {translateNow("source.discovery.run.f6dd5be06b")}
            <input
              className="ui-input"
              value={retireRunId}
              onChange={(event) => setRetireRunId(event.target.value)}
              placeholder={translateNow("source.run.uuid.0b1b6844cb")}
            />
          </label>
          <label className="grid gap-1 text-sm">
            {translateNow("source.identity.999f23fcd7")}
            <input
              className="ui-input"
              value={retireIdentityId}
              onChange={(event) => setRetireIdentityId(event.target.value)}
              placeholder={translateNow("source.identity.uuid.ae37807bc4")}
            />
          </label>
          <label className="grid gap-1 text-sm md:col-span-2">
            {translateNow("source.reason.f81ab834de")}
            <input className="ui-input" value={retireReason} onChange={(event) => setRetireReason(event.target.value)} />
          </label>
          <Button className="md:col-span-3" type="submit">
            Record host retired
          </Button>
          {retirement && (
            <output className="font-mono text-xs text-muted-foreground md:col-span-3">
              {retirement.host}:{retirement.status}
            </output>
          )}
        </form>
      </section>
    </section>
  );
}
