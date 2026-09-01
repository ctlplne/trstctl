import { type FormEvent, useEffect, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { Button, buttonVariants } from "@/components/ui/button";
import { PageHeader } from "@/components/PageHeader";
import { ProgressiveTaskList } from "@/components/ProgressiveTaskList";
import { ErrorState, LoadingState, UnavailableState } from "@/components/StatePrimitives";
import { StatusBadge } from "@/components/StatusBadge";
import { useTranslation, translateNow } from "@/i18n/I18nProvider";
import {
  api,
  ApiError,
  type SSHAttestedUserCert,
  type SSHAttestedUserCertPreview,
  type SSHAttestedUserCertRequest,
  type SSHFleetInventory,
  type SSHHostRetirement,
  type SSHStatus,
  type SSHTrustRollout,
  type SSHTrustRolloutRequest,
} from "@/lib/api";
import { apiProblemMessage } from "@/lib/apiProblem";
import { SSHCertificateWorkflow } from "@/pages/ssh/SSHCertificateWorkflow";

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
  const [activeTask, setActiveTask] = useState<"certificate" | "rollout" | "access" | "remove" | null>(null);
  const [status, setStatus] = useState<SSHStatus | null>(null);
  const [fleet, setFleet] = useState<SSHFleetInventory | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [actionResult, setActionResult] = useState<string | null>(null);
  const [rollout, setRollout] = useState<SSHTrustRollout | null>(null);
  const [issuedCert, setIssuedCert] = useState<SSHAttestedUserCert | null>(null);
  const [attestedReview, setAttestedReview] = useState<{ requestKey: string; plan: SSHAttestedUserCertPreview } | null>(null);
  const [attestedPreviewing, setAttestedPreviewing] = useState(false);
  const [attestedIssuing, setAttestedIssuing] = useState(false);
  const [attestedPreviewError, setAttestedPreviewError] = useState<string | null>(null);
  const [attestedIssueError, setAttestedIssueError] = useState<string | null>(null);
  const attestedRetryKey = useRef<string | null>(null);
  const [retirement, setRetirement] = useState<SSHHostRetirement | null>(null);
  const [sourceId, setSourceId] = useState("");
  const [hosts, setHosts] = useState("edge-1.internal");
  const [fingerprint, setFingerprint] = useState("");
  const [reloadCommand, setReloadCommand] = useState("systemctl reload sshd");
  const [healthCommand, setHealthCommand] = useState("ssh -o BatchMode=yes localhost true");
  const [rollbackPlan, setRollbackPlan] = useState("restore trusted_user_ca_keys backup and reload sshd");
  const [rolloutStatus, setRolloutStatus] = useState<SSHTrustRolloutRequest["status"]>("planned");
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
      .catch((err) => setError(apiProblemMessage(err, "Could not load the SSH workflow")));

  useEffect(() => {
    let cancelled = false;
    Promise.allSettled([api.sshStatus(), api.sshFleet()]).then(([statusResult, fleetResult]) => {
      if (cancelled) return;

      if (statusResult.status === "fulfilled") setStatus(statusResult.value);
      if (fleetResult.status === "fulfilled") setFleet(fleetResult.value);

      // The status response says whether SSH exists at all; the fleet response
      // is secondary inventory. During overload both can fail, and Promise.all
      // used to surface whichever network rejection won the race. That let a
      // fleet 429 hide the more important "SSH workflow is not enabled" 503.
      const failure = statusResult.status === "rejected" ? statusResult.reason : fleetResult.status === "rejected" ? fleetResult.reason : null;
      setError(failure ? apiProblemMessage(failure, "Could not load the SSH workflow") : null);
    });
    return () => {
      cancelled = true;
    };
  }, []);

  const attestors = useMemo(() => status?.attestors ?? [], [status?.attestors]);
  const workflowUnavailable = !status && Boolean(error?.toLowerCase().includes("ssh workflow is not enabled"));
  // Route-level and rolling-upgrade callers can briefly see the pre-inventory
  // SSH payload, which has no `hosts` member. Keep that honest empty state
  // renderable instead of crashing the entire console shell.
  const fleetHosts = fleet?.hosts ?? [];

  useEffect(() => {
    if (attestors.length > 0 && !attestors.includes(method)) {
      setMethod(attestors[0] as SSHAttestedUserCertRequest["method"]);
    }
  }, [attestors, method]);

  const attestedRequest = useMemo<SSHAttestedUserCertRequest>(
    () => ({
      method,
      payload_base64: payloadBase64.trim(),
      public_key: publicKey.trim(),
      key_id: keyId.trim() || undefined,
      ttl_seconds: numericOrUndefined(ttlSeconds),
      approver: approver.trim(),
      principals: splitHosts(principals),
      source_addresses: splitHosts(sourceAddresses),
      force_command: forceCommand.trim() || undefined,
    }),
    [approver, forceCommand, keyId, method, payloadBase64, principals, publicKey, sourceAddresses, ttlSeconds],
  );
  const attestedRequestKey = JSON.stringify(attestedRequest);
  const exactAttestedPlan = attestedReview?.requestKey === attestedRequestKey ? attestedReview.plan : null;
  const attestedInputValid = Boolean(attestedRequest.payload_base64 && attestedRequest.public_key && attestedRequest.approver && attestors.length > 0);

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

  const previewAttested = async (event: FormEvent) => {
    event.preventDefault();
    if (!attestedInputValid || attestedPreviewing || attestedIssuing) return;
    setAttestedPreviewing(true);
    setAttestedPreviewError(null);
    setAttestedIssueError(null);
    setIssuedCert(null);
    attestedRetryKey.current = null;
    try {
      const response = await api.previewAttestedSSHUserCert(attestedRequest);
      // Older candidates serialized an empty Go slice as JSON null. Keep the
      // console usable while those nodes roll forward instead of crashing the
      // entire page when an operator reviews a ready plan.
      const plan = {
        ...response,
        blockers: response.blockers ?? [],
        recovery_steps: response.recovery_steps ?? [],
      };
      setAttestedReview({ requestKey: attestedRequestKey, plan });
    } catch (err) {
      setAttestedReview(null);
      setAttestedPreviewError(apiProblemMessage(err, t("sshTrust.attested.previewFailedFallback")));
    } finally {
      setAttestedPreviewing(false);
    }
  };

  const issueAttested = async () => {
    if (!exactAttestedPlan?.ready || !exactAttestedPlan.effect_free || attestedIssuing) return;
    setAttestedIssuing(true);
    setAttestedIssueError(null);
    try {
      attestedRetryKey.current ??= globalThis.crypto.randomUUID();
      const result = await api.issueAttestedSSHUserCert(attestedRequest, attestedRetryKey.current);
      setIssuedCert(result);
      setRevokeSerial(String(result.serial));
      setRevokeKeyId(result.key_id || "");
      // Proofs and public keys are inputs, not browser evidence. Clear both as
      // soon as issuance succeeds so a later screenshot or shared session
      // cannot recover the attestation payload.
      setPayloadBase64("");
      setPublicKey("");
      setAttestedReview(null);
      attestedRetryKey.current = null;
      setActionResult(`ssh-cert:${result.serial}`);
      await loadStatus();
    } catch (err) {
      setAttestedIssueError(
        err instanceof ApiError && err.status >= 500
          ? t("sshTrust.attested.uncertainResponse")
          : apiProblemMessage(err, t("sshTrust.attested.issueFailedFallback")),
      );
    } finally {
      setAttestedIssuing(false);
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
        title={t("nav.item.sshTrust")}
        description={t(status ? "sshTrust.page.answerReady" : "sshTrust.page.answerUnavailable")}
        technicalDetails={t("sshTrust.page.details")}
        actions={
          status ? (
            <Button type="button" onClick={() => setActiveTask("certificate")}>
              {t("sshTrust.certificate.taskAction")}
            </Button>
          ) : (
            <Link className={buttonVariants()} to="/protocols">
              {t("sshTrust.page.setupAction")}
            </Link>
          )
        }
      />

      {error && <ErrorState title={translateNow("source.ssh.workflow.failed.e76cbdb07c")}>{error}</ErrorState>}
      {workflowUnavailable ? (
        <UnavailableState title={t("sshTrust.readiness.unavailableHeading")}>
          <section aria-labelledby="ssh-unavailable-heading">
            <h2 id="ssh-unavailable-heading" className="sr-only">
              {t("sshTrust.readiness.unavailableHeading")}
            </h2>
            {t("sshTrust.readiness.unavailableBody")}
          </section>
        </UnavailableState>
      ) : null}
      {!status && !error && <LoadingState>{translateNow("source.loading.ssh.workflow.eee4586266")}</LoadingState>}
      {actionResult && (
        <details className="text-sm text-muted-foreground">
          <summary className="cursor-pointer font-medium text-foreground">{t("pageHeader.openDetails")}</summary>
          <output className="mt-2 block break-all font-mono text-xs">{actionResult}</output>
        </details>
      )}

      {status && (
        <section aria-labelledby="ssh-status-heading" className="grid gap-3 border-y border-border py-4">
          <div>
            <h2 id="ssh-status-heading" className="text-title font-semibold">
              {t("sshTrust.readiness.readyHeading")}
            </h2>
            <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{t("sshTrust.readiness.readyBody")}</p>
          </div>
          <p className="text-sm text-muted-foreground">
            {t("sshTrust.readiness.technicalSummary", { revoked: status.revoked_count, attestors: attestors.length })}
          </p>
          <details className="group text-sm">
            <summary className="cursor-pointer font-medium text-foreground">{t("sshTrust.readiness.technicalDetails")}</summary>
            <dl className="mt-3 grid gap-3 border-s border-border ps-4 sm:grid-cols-2 lg:grid-cols-4">
              <div>
                <dt className="text-xs text-muted-foreground">{translateNow("source.workflow.available.3946309163")}</dt>
                <dd className="font-mono text-sm">{status.served ? "true" : "false"}</dd>
              </div>
              <div>
                <dt className="text-xs text-muted-foreground">{translateNow("source.krl.version.2381c27676")}</dt>
                <dd className="font-mono text-sm">{status.krl_version}</dd>
              </div>
              <div>
                <dt className="text-xs text-muted-foreground">{translateNow("source.revoked.certs.267c0b721b")}</dt>
                <dd className="font-mono text-sm">{status.revoked_count}</dd>
              </div>
              <div>
                <dt className="text-xs text-muted-foreground">{translateNow("source.attestors.2e3ad3c00b")}</dt>
                <dd className="break-all font-mono text-sm">{attestors.join(", ")}</dd>
              </div>
              <div className="sm:col-span-2 lg:col-span-4">
                <dt className="text-xs text-muted-foreground">{t("sshTrust.advanced.authorityKeySummary")}</dt>
                <dd className="break-all font-mono text-xs">{status.authority_key || translateNow("source.not.published.30839efda7")}</dd>
              </div>
            </dl>
          </details>
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
          <p className="text-sm font-medium text-foreground">
            {t("sshTrust.fleet.summary", {
              hosts: fleet.host_count,
              standing: fleet.standing_key_count,
              orphaned: fleet.orphaned_key_count,
            })}
          </p>
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

      {status && (
        <>
          <ProgressiveTaskList
            heading={t("progressiveTasks.heading")}
            description={t("progressiveTasks.description")}
            activeTask={activeTask}
            closeLabel={t("progressiveTasks.close")}
            onTaskChange={(task) => setActiveTask(task as typeof activeTask)}
            tasks={[
              {
                id: "certificate",
                title: t("sshTrust.certificate.taskTitle"),
                description: t("sshTrust.certificate.taskDescription"),
                actionLabel: t("sshTrust.certificate.taskAction"),
              },
              {
                id: "rollout",
                title: t("sshTrust.tasks.rollout.title"),
                description: t("sshTrust.tasks.rollout.description"),
                actionLabel: t("sshTrust.page.rolloutAction"),
              },
              {
                id: "access",
                title: t("sshTrust.tasks.access.title"),
                description: t("sshTrust.tasks.access.description"),
                actionLabel: t("sshTrust.tasks.access.action"),
              },
              {
                id: "remove",
                title: t("sshTrust.tasks.remove.title"),
                description: t("sshTrust.tasks.remove.description"),
                actionLabel: t("sshTrust.tasks.remove.action"),
              },
            ]}
          />

          {activeTask === "certificate" && (
            <div id="task-panel-certificate" className="border-y border-border py-4">
              <SSHCertificateWorkflow />
            </div>
          )}

          {activeTask === "rollout" && (
            <section id="task-panel-rollout" aria-labelledby="rollout-heading" className="grid gap-3 border-y border-border py-4">
              <div>
                <h2 id="rollout-heading" className="text-title font-semibold">
                  {translateNow("source.ssh.deployment.and.trust.rollout.098d316f31")}
                </h2>
                <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{translateNow("source.a.safe.rollout.names.the.candidate.ca.targ.fdf82b1ab9")}</p>
                <p className="mt-1 max-w-3xl text-sm font-medium text-foreground">{t("sshTrust.rollout.recordOnly")}</p>
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
                  <input className="ui-input" value={fingerprint} onChange={(event) => setFingerprint(event.target.value)} required />
                </label>
                <label className="grid gap-1 text-sm">
                  {translateNow("source.reload.command.cf1acb1111")}
                  <input className="ui-input" value={reloadCommand} onChange={(event) => setReloadCommand(event.target.value)} required />
                </label>
                <label className="grid gap-1 text-sm">
                  {translateNow("source.health.command.5ad9864488")}
                  <input className="ui-input" value={healthCommand} onChange={(event) => setHealthCommand(event.target.value)} required />
                </label>
                <label className="grid gap-1 text-sm">
                  {translateNow("source.status.920e413c7d")}
                  <select
                    className="ui-input"
                    value={rolloutStatus}
                    onChange={(event) => setRolloutStatus(event.target.value as SSHTrustRolloutRequest["status"])}
                  >
                    {rolloutStatuses.map((value) => (
                      <option key={value} value={value}>
                        {value}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="grid gap-1 text-sm md:col-span-3">
                  {translateNow("source.rollback.plan.952efc8286")}
                  <textarea className="ui-input min-h-20" value={rollbackPlan} onChange={(event) => setRollbackPlan(event.target.value)} required />
                </label>
                <label className="flex items-center gap-2 text-sm md:col-span-3">
                  <input type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} />
                  {translateNow("source.confirm.high.blast.radius.ssh.trust.rollou.31dcb6c476")}
                </label>
                <Button
                  className="md:col-span-3"
                  type="submit"
                  disabled={
                    !confirmed ||
                    splitHosts(hosts).length === 0 ||
                    !fingerprint.trim() ||
                    !reloadCommand.trim() ||
                    !healthCommand.trim() ||
                    !rollbackPlan.trim()
                  }
                >
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
          )}

          {activeTask === "access" && (
            <section id="task-panel-access" aria-labelledby="jit-heading" className="grid gap-3 border-y border-border py-4">
              <div>
                <h2 id="jit-heading" className="text-title font-semibold">
                  {translateNow("source.attestation.gated.ssh.user.certs.d49d24e892")}
                </h2>
                <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{t("sshTrust.attested.description")}</p>
              </div>
              <form
                aria-label={translateNow("source.issue.attested.ssh.user.certificate.f7e0f6ef66")}
                className="ui-panel grid gap-3 md:grid-cols-3"
                onSubmit={(event) => void previewAttested(event)}
              >
                <div className="grid gap-1 text-sm">
                  <label htmlFor="ssh-attested-method">{translateNow("source.attestation.method.1f0610be7c")}</label>
                  <select id="ssh-attested-method" className="ui-input" value={method} onChange={(event) => setMethod(event.target.value as SSHAttestedUserCertRequest["method"])}>
                    {attestors.map((value) => (
                      <option key={value} value={value}>
                        {value}
                      </option>
                    ))}
                  </select>
                </div>
                <div className="grid gap-1 text-sm">
                  <label htmlFor="ssh-attested-key-id">{translateNow("source.key.id.d54d56ee0a")}</label>
                  <input id="ssh-attested-key-id" className="ui-input" value={keyId} onChange={(event) => setKeyId(event.target.value)} />
                </div>
                <div className="grid gap-1 text-sm">
                  <label htmlFor="ssh-attested-ttl">{translateNow("source.ttl.seconds.862d08de5a")}</label>
                  <input id="ssh-attested-ttl" className="ui-input" inputMode="numeric" value={ttlSeconds} onChange={(event) => setTTLSeconds(event.target.value)} />
                </div>
                <div className="grid gap-1 text-sm">
                  <label htmlFor="ssh-attested-approver">{t("sshTrust.attested.approver")}</label>
                  <input id="ssh-attested-approver" className="ui-input" value={approver} onChange={(event) => setApprover(event.target.value)} required />
                </div>
                <div className="grid gap-1 text-sm">
                  <label htmlFor="ssh-attested-principals">{t("sshTrust.attested.boundPrincipals")}</label>
                  <textarea id="ssh-attested-principals" className="ui-input min-h-20 font-mono text-xs" value={principals} onChange={(event) => setPrincipals(event.target.value)} />
                </div>
                <div className="grid gap-1 text-sm">
                  <label htmlFor="ssh-attested-source-addresses">{t("sshTrust.attested.sourceAddresses")}</label>
                  <textarea
                    id="ssh-attested-source-addresses"
                    className="ui-input min-h-20 font-mono text-xs"
                    value={sourceAddresses}
                    onChange={(event) => setSourceAddresses(event.target.value)}
                  />
                </div>
                <div className="grid gap-1 text-sm md:col-span-3">
                  <label htmlFor="ssh-attested-force-command">{t("sshTrust.attested.forceCommand")}</label>
                  <input id="ssh-attested-force-command" className="ui-input font-mono text-xs" value={forceCommand} onChange={(event) => setForceCommand(event.target.value)} />
                </div>
                <div className="grid gap-1 text-sm md:col-span-3">
                  <label htmlFor="ssh-attested-payload">{translateNow("source.attestation.payload.base64.11bfdba122")}</label>
                  <textarea
                    id="ssh-attested-payload"
                    className="ui-input min-h-24 font-mono text-xs"
                    value={payloadBase64}
                    onChange={(event) => setPayloadBase64(event.target.value)}
                    required
                  />
                </div>
                <div className="grid gap-1 text-sm md:col-span-3">
                  <label htmlFor="ssh-attested-public-key">{translateNow("source.ssh.public.key.c9be6a369e")}</label>
                  <textarea id="ssh-attested-public-key" className="ui-input min-h-24 font-mono text-xs" value={publicKey} onChange={(event) => setPublicKey(event.target.value)} required />
                </div>
                <Button className="md:col-span-3" type="submit" disabled={!attestedInputValid || attestedPreviewing || attestedIssuing}>
                  {attestedPreviewing ? t("sshTrust.attested.previewing") : t("sshTrust.attested.previewAction")}
                </Button>
                {attestedPreviewError ? (
                  <ErrorState title={t("sshTrust.attested.previewFailedTitle")}>
                    <p>{attestedPreviewError}</p>
                  </ErrorState>
                ) : null}
                {exactAttestedPlan ? (
                  <section
                    className="grid gap-4 rounded-panel border border-border bg-muted/25 p-comfortable md:col-span-3"
                    aria-label={t("sshTrust.attested.planLabel")}
                  >
                    <div>
                      <h3 className="font-semibold">
                        {exactAttestedPlan.ready && exactAttestedPlan.effect_free ? t("sshTrust.attested.readyTitle") : t("sshTrust.attested.blockedTitle")}
                      </h3>
                      <p className="mt-1 text-sm text-muted-foreground">{t("sshTrust.attested.effectFree")}</p>
                    </div>
                    <dl className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
                      <div>
                        <dt className="text-caption text-muted-foreground">{t("workloads.ephemeral.effectiveTTL")}</dt>
                        <dd className="mt-1 font-mono text-sm">{t("workloads.ephemeral.seconds", { count: exactAttestedPlan.effective_ttl_seconds })}</dd>
                      </div>
                      <div>
                        <dt className="text-caption text-muted-foreground">{t("workloads.attested.permission")}</dt>
                        <dd className="mt-1 font-mono text-sm">{exactAttestedPlan.required_permission}</dd>
                      </div>
                      <div>
                        <dt className="text-caption text-muted-foreground">{t("sshTrust.attested.publicKeyFingerprint")}</dt>
                        <dd className="mt-1 break-all font-mono text-xs">{exactAttestedPlan.public_key_fingerprint}</dd>
                      </div>
                      <div>
                        <dt className="text-caption text-muted-foreground">{t("sshTrust.attested.approver")}</dt>
                        <dd className="mt-1 break-words font-mono text-sm">{exactAttestedPlan.approver}</dd>
                      </div>
                    </dl>
                    <p className="text-sm text-muted-foreground">{t("workloads.attested.proofDeferred")}</p>
                    {exactAttestedPlan.blockers.length ? (
                      <section>
                        <h4 className="text-sm font-semibold">{t("workloads.ephemeral.blockers")}</h4>
                        <ul className="mt-2 list-disc space-y-1 ps-5 text-sm text-muted-foreground">
                          {exactAttestedPlan.blockers.map((item) => (
                            <li key={item}>{item}</li>
                          ))}
                        </ul>
                      </section>
                    ) : null}
                    <section>
                      <h4 className="text-sm font-semibold">{t("workloads.ephemeral.recovery")}</h4>
                      <ul className="mt-2 list-disc space-y-1 ps-5 text-sm text-muted-foreground">
                        {exactAttestedPlan.recovery_steps.map((item) => (
                          <li key={item}>{item}</li>
                        ))}
                      </ul>
                    </section>
                    <details className="rounded-panel border border-border p-3">
                      <summary className="cursor-pointer text-sm font-medium">{t("workloads.attested.exactEvidence")}</summary>
                      <dl className="mt-3 grid gap-3 sm:grid-cols-2">
                        <div>
                          <dt className="text-caption text-muted-foreground">{t("workloads.ephemeral.proofDigest")}</dt>
                          <dd className="mt-1 break-all font-mono text-xs">{exactAttestedPlan.payload_sha256}</dd>
                        </div>
                        <div>
                          <dt className="text-caption text-muted-foreground">{t("sshTrust.attested.authorityFingerprint")}</dt>
                          <dd className="mt-1 break-all font-mono text-xs">{exactAttestedPlan.authority_fingerprint}</dd>
                        </div>
                      </dl>
                    </details>
                    {attestedIssueError ? <ErrorState title={t("sshTrust.attested.issueFailedTitle")}>{attestedIssueError}</ErrorState> : null}
                    <div className="flex justify-end">
                      <Button
                        type="button"
                        onClick={() => void issueAttested()}
                        disabled={!exactAttestedPlan.ready || !exactAttestedPlan.effect_free || attestedIssuing}
                      >
                        {attestedIssuing
                          ? t("sshTrust.attested.issuing")
                          : attestedIssueError
                            ? t("sshTrust.attested.retryAction")
                            : t("sshTrust.attested.issueAction")}
                      </Button>
                    </div>
                  </section>
                ) : null}
                {issuedCert && (
                  <div className="grid gap-2 md:col-span-3">
                    <h3 className="font-semibold">{t("sshTrust.attested.issuedTitle")}</h3>
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
          )}

          {activeTask === "remove" && (
            <div id="task-panel-remove" className="grid gap-4">
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
            </div>
          )}
        </>
      )}
    </section>
  );
}
