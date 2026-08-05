import { useEffect, useMemo, useRef, useState } from "react";
import { Copy, Loader2, RefreshCw, ShieldOff, UserX, X } from "lucide-react";
import { CredentialChip } from "@/components/CredentialChip";
import { Dialog } from "@/components/Dialog";
import { useToast } from "@/components/ToastProvider";
import { EmptyState } from "@/components/EmptyState";
import { ErrorState, LoadingState } from "@/components/StatePrimitives";
import { StatusBadge } from "@/components/StatusBadge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { PageHeader } from "@/components/PageHeader";
import { DataGrid, type DataGridColumn } from "@/components/DataGrid";
import { api, type Agent, type EnrollmentToken } from "@/lib/api";
import { formatDate as formatDatePolicy, formatDateTime as formatDateTimePolicy } from "@/i18n/format";
import { useTranslation, translateNow } from "@/i18n/I18nProvider";
import type { MessageKey } from "@/i18n/messages";

const staleAfterMs = 24 * 60 * 60 * 1000;
const certRevocationReasons = [
  "unspecified",
  "keyCompromise",
  "caCompromise",
  "affiliationChanged",
  "superseded",
  "cessationOfOperation",
  "certificateHold",
  "removeFromCRL",
  "privilegeWithdrawn",
  "aaCompromise",
] as const;

// A2: the two capability grants an operator can attach at enrollment. They are
// vantages, not ranks: a host agent acts on the machine it runs on, a network
// agent acts on things in its segment that cannot run an agent at all. An agent
// can hold both — that is the F5-beside-a-server case.
type AgentRole = "host" | "network";

const AGENT_ROLE_CHOICES = [
  { value: "host", labelKey: "source.agent.role.host.a2r0le0003", helpKey: "source.agent.role.host.help.a2r0le0004" },
  { value: "network", labelKey: "source.agent.role.network.a2r0le0005", helpKey: "source.agent.role.network.help.a2r0le0006" },
] as const satisfies readonly { value: AgentRole; labelKey: MessageKey; helpKey: MessageKey }[];

// AgentRoleBadges renders what an agent's CERTIFICATE says it may do. An agent
// that has not heartbeated since roles shipped reports nothing, which is shown as
// unreported rather than as host — the console should not fill a gap in evidence
// with a guess.
function AgentRoleBadges({ agent }: { agent: Agent }) {
  const roles = agent.roles ?? [];
  if (agent.role_source !== "certificate" || roles.length === 0) {
    return <span className="text-xs text-muted-foreground">{translateNow("source.agent.role.unreported.a2r0le0009")}</span>;
  }
  return (
    <span className="flex flex-wrap gap-1">
      {roles.map((role) => (
        <span
          key={role}
          className={
            role === "network"
              ? "rounded-full border border-status-warning px-2 py-0.5 text-xs text-status-warning"
              : "rounded-full border border-border px-2 py-0.5 text-xs text-muted-foreground"
          }
        >
          {role === "network" ? translateNow("source.agent.role.network.a2r0le0005") : translateNow("source.agent.role.host.a2r0le0003")}
        </span>
      ))}
    </span>
  );
}

export function Agents() {
  const { t } = useTranslation();
  const [agents, setAgents] = useState<Agent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedID, setSelectedID] = useState<string | null>(null);
  const [token, setToken] = useState<EnrollmentToken | null>(null);
  const [tokenAllowedIdentity, setTokenAllowedIdentity] = useState("");
  // The capability grant this token will carry into the enrolled certificate
  // (epic A2). Host is the default because it is what an agent with no grant
  // already is — offering "none" would offer something that does not exist.
  const [tokenRoles, setTokenRoles] = useState<AgentRole[]>(["host"]);
  const [tokenIdentity, setTokenIdentity] = useState("");
  const [tokenBusy, setTokenBusy] = useState(false);
  const [tokenError, setTokenError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [offboardTarget, setOffboardTarget] = useState<Agent | null>(null);
  const [offboardReason, setOffboardReason] = useState("");
  const [offboardBusy, setOffboardBusy] = useState(false);
  const [offboardError, setOffboardError] = useState<string | null>(null);
  const [offboardEvidence, setOffboardEvidence] = useState<string | null>(null);
  const offboardConfirmRef = useRef<HTMLButtonElement>(null);
  const [revokeTarget, setRevokeTarget] = useState<Agent | null>(null);
  const [revokeReason, setRevokeReason] = useState("keyCompromise");
  const [revokeSerial, setRevokeSerial] = useState("");
  const [revokeFingerprint, setRevokeFingerprint] = useState("");
  const [revokeConfirmed, setRevokeConfirmed] = useState(false);
  const [revokeBusy, setRevokeBusy] = useState(false);
  const [revokeError, setRevokeError] = useState<string | null>(null);
  const { toast } = useToast();

  async function load() {
    setError(null);
    setLoading(true);
    try {
      const list = await api.agents();
      setAgents(list);
      setSelectedID((current) => current ?? list[0]?.id ?? null);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void load();
  }, []);

  async function mintToken() {
    setTokenError(null);
    setCopied(false);
    setTokenBusy(true);
    try {
      const allowedIdentity = tokenAllowedIdentity.trim();
      setToken(
        await api.createEnrollmentToken({
          ...(allowedIdentity ? { allowed_identity: allowedIdentity } : {}),
          roles: tokenRoles,
        }),
      );
      setTokenIdentity(allowedIdentity);
    } catch (err) {
      setTokenError(err instanceof Error ? err.message : String(err));
    } finally {
      setTokenBusy(false);
    }
  }

  const selected = useMemo(() => agents.find((agent) => agent.id === selectedID) ?? agents[0] ?? null, [agents, selectedID]);
  const command = token ? enrollmentCommand(token, tokenIdentity) : "";

  async function copyCommand() {
    if (!command) return;
    try {
      await navigator.clipboard?.writeText(command);
      setCopied(true);
    } catch {
      setCopied(true);
    }
  }

  function openOffboard(agent: Agent) {
    setSelectedID(agent.id);
    setOffboardTarget(agent);
    setOffboardReason(agent.offboard_reason || "");
    setOffboardError(null);
  }

  async function offboardAgent() {
    if (!offboardTarget) return;
    setOffboardBusy(true);
    setOffboardError(null);
    try {
      const result = await api.offboardAgent(offboardTarget.id, { reason: offboardReason.trim() });
      setAgents((current) => current.map((agent) => (agent.id === result.agent.id ? result.agent : agent)));
      setSelectedID(result.agent.id);
      setOffboardEvidence(result.revocation_evidence);
      setOffboardTarget(null);
      setOffboardReason("");
    } catch (err) {
      setOffboardError(err instanceof Error ? err.message : String(err));
    } finally {
      setOffboardBusy(false);
    }
  }

  function openRevokeCert(agent: Agent) {
    setRevokeTarget(agent);
    setRevokeReason("keyCompromise");
    setRevokeSerial("");
    setRevokeFingerprint("");
    setRevokeConfirmed(false);
    setRevokeError(null);
  }

  async function revokeCert() {
    if (!revokeTarget || !revokeConfirmed) return;
    setRevokeBusy(true);
    setRevokeError(null);
    try {
      const revocation = await api.revokeAgentCert(revokeTarget.id, {
        reason: revokeReason,
        serial: revokeSerial.trim() || undefined,
        fingerprint: revokeFingerprint.trim() || undefined,
      });
      toast({
        kind: "success",
        title: `Certificate revoked for ${revokeTarget.name}`,
        description: `Revoked at ${formatDate(revocation.revoked_at)}.`,
      });
      setRevokeTarget(null);
    } catch (err) {
      setRevokeError(err instanceof Error ? err.message : String(err));
    } finally {
      setRevokeBusy(false);
    }
  }

  const agentColumns: DataGridColumn<Agent>[] = [
    { id: "name", header: "Name", className: "font-medium", cell: (agent) => agent.name },
    { id: "status", header: "Status", cell: (agent) => <StatusBadge vocabulary="agent" value={agent.status} /> },
    {
      id: "roles",
      header: translateNow("source.agent.role.a2r0le0001"),
      cell: (agent: Agent) => <AgentRoleBadges agent={agent} />,
    },
    { id: "version", header: "Version", className: "font-mono text-xs", cell: (agent) => agent.version || "-" },
    {
      id: "lastSeen",
      header: "Last seen",
      cell: (agent) => {
        if (isOffboarded(agent)) {
          return (
            <>
              <p>{formatOffboarded(agent.offboarded_at)}</p>
              <p className="text-xs text-muted-foreground">{agent.offboard_reason || translateNow("source.terminal.tombstone.f332513267")}</p>
            </>
          );
        }
        const freshness = heartbeatFreshness(agent.last_seen_at);
        return (
          <>
            <p>{formatDate(agent.last_seen_at)}</p>
            <p className={freshness.stale ? "text-xs font-medium text-status-warning" : "text-xs text-muted-foreground"}>{freshness.label}</p>
          </>
        );
      },
    },
    {
      id: "action",
      header: "Action",
      cell: (agent) => (
        <div className="flex flex-wrap gap-2">
          <Button type="button" size="sm" variant="outline" onClick={() => setSelectedID(agent.id)}>
            {translateNow("source.view.details.d1bf045bb5")}
          </Button>
          {!isOffboarded(agent) && (
            <>
              <Button
                type="button"
                size="sm"
                variant="outline"
                className="border-risk-critical/40 text-risk-critical hover:bg-risk-critical/10"
                onClick={() => openRevokeCert(agent)}
              >
                <ShieldOff className="h-4 w-4" aria-hidden="true" />
                {t("parity.revokeCertificate_338ad7")}
              </Button>
              <Button
                type="button"
                size="sm"
                variant="outline"
                className="border-risk-critical/40 text-risk-critical hover:bg-risk-critical/10"
                onClick={() => openOffboard(agent)}
              >
                <UserX className="h-4 w-4" aria-hidden="true" />
                {translateNow("source.offboard.9053e68ef6")}
              </Button>
            </>
          )}
        </div>
      ),
    },
  ];

  return (
    <section aria-labelledby="agents-heading" className="grid gap-6">
      <PageHeader
        titleId="agents-heading"
        title={translateNow("source.agents.279b44d2ab")}
        description="The in-network agents that deploy and rotate credentials on your hosts. Register a new agent with a one-time enrollment token."
        actions={
          <Button type="button" variant="outline" onClick={() => void load()} disabled={loading}>
            {loading ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <RefreshCw className="h-4 w-4" aria-hidden="true" />}
            {translateNow("source.refresh.0e91610117")}
          </Button>
        }
      />

      <section aria-labelledby="enrollment-heading" className="border-y border-border py-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h2 id="enrollment-heading" className="text-title font-semibold">
              {translateNow("source.enrollment.token.6c86be7863")}
            </h2>
            <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
              Mint a one-time bootstrap token. The token stays in component memory only; it is never written to browser storage.
            </p>
          </div>
          <div className="grid gap-2 sm:grid-cols-[minmax(12rem,18rem)_auto] sm:items-end">
            <label className="grid gap-1 text-sm font-medium">
              {translateNow("source.agent.identity.698c87920a")}
              <input
                className="rounded-control border border-border bg-background px-3 py-2 text-sm font-normal"
                placeholder={translateNow("source.node.a.66570ff05a")}
                value={tokenAllowedIdentity}
                onChange={(event) => setTokenAllowedIdentity(event.target.value)}
                disabled={tokenBusy}
                autoComplete="off"
                spellCheck={false}
              />
            </label>
            <Button type="button" onClick={() => void mintToken()} disabled={tokenBusy}>
              {tokenBusy && <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />}
              {translateNow("source.mint.enrollment.token.b50d28fa1d")}
            </Button>
          </div>
        </div>

        <fieldset className="mt-4 grid gap-2 rounded-md border border-border p-3">
          <legend className="px-1 text-sm font-medium">{translateNow("source.agent.role.a2r0le0001")}</legend>
          <p className="text-sm text-muted-foreground">{translateNow("source.agent.role.help.a2r0le0002")}</p>
          <div className="grid gap-2 sm:grid-cols-2">
            {AGENT_ROLE_CHOICES.map((choice) => (
              // Explicitly paired rather than relying on the wrapping label:
              // the control is a component, so neither a reader of this code nor
              // the a11y linter can see that a form control is inside it.
              <label
                key={choice.value}
                htmlFor={`agent-role-${choice.value}`}
                className="flex items-start gap-2 text-sm"
              >
                <Checkbox
                  id={`agent-role-${choice.value}`}
                  className="mt-1"
                  checked={tokenRoles.includes(choice.value)}
                  onChange={(event) =>
                    setTokenRoles((current) =>
                      event.target.checked
                        ? [...current.filter((role) => role !== choice.value), choice.value]
                        : current.filter((role) => role !== choice.value),
                    )
                  }
                  disabled={tokenBusy}
                />
                <span>
                  <span className="font-medium">{translateNow(choice.labelKey)}</span>
                  <span className="block text-muted-foreground">{translateNow(choice.helpKey)}</span>
                </span>
              </label>
            ))}
          </div>
          {tokenRoles.includes("network") && <p className="text-sm text-status-warning">{translateNow("source.agent.role.relay.warning.a2r0le0007")}</p>}
          {tokenRoles.length === 0 && <p className="text-sm text-muted-foreground">{translateNow("source.agent.role.empty.a2r0le0008")}</p>}
        </fieldset>

        {tokenError && <ErrorState title={translateNow("source.could.not.mint.enrollment.token.7b0b6374e9")}>{tokenError}</ErrorState>}

        {token && (
          <div className="mt-4 grid gap-3 rounded-md border border-border p-3 text-sm">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div>
                <p className="font-medium">{translateNow("source.shown.once.22548d041f")}</p>
                <p className="mt-1 text-muted-foreground">
                  Save the token to ./trstctl-bootstrap-token with 0600 permissions, then copy this command. Dismiss clears the token from the page state; the
                  console does not persist it.
                </p>
              </div>
              <Button type="button" variant="ghost" size="sm" onClick={() => setToken(null)}>
                <X className="h-4 w-4" aria-hidden="true" />
                {translateNow("source.dismiss.48845bff33")}
              </Button>
            </div>
            <dl className="grid gap-2">
              <div>
                <dt className="font-medium text-muted-foreground">{translateNow("source.bootstrap.token.2996dc8b78")}</dt>
                <dd className="mt-0.5">
                  <CredentialChip value={token.token} label="bootstrap token" head={14} tail={8} />
                </dd>
              </div>
              <div>
                <dt className="font-medium text-muted-foreground">{translateNow("source.install.command.1ae9754205")}</dt>
                <dd className="mt-1">
                  <code className="block overflow-x-auto rounded bg-muted px-3 py-2 text-xs">{command}</code>
                </dd>
              </div>
            </dl>
            <div className="flex flex-wrap items-center gap-2">
              <Button type="button" size="sm" variant="outline" onClick={() => void copyCommand()}>
                <Copy className="h-4 w-4" aria-hidden="true" />
                {translateNow("source.copy.command.9a01feecae")}
              </Button>
              {copied && <p className="text-xs text-muted-foreground">{translateNow("source.copied.once.from.memory.ffb61f0314")}</p>}
            </div>
          </div>
        )}
      </section>

      {error && <ErrorState title={translateNow("source.could.not.load.agents.1d510cf246")}>{error}</ErrorState>}
      {loading && <LoadingState>{translateNow("source.loading.agents.a4e0608f99")}</LoadingState>}

      {!loading && !error && agents.length === 0 && (
        <EmptyState title={translateNow("source.no.agents.enrolled.yet.345799ad5d")}>
          {translateNow("source.mint.a.one.time.enrollment.token.install.a.d9cbac0c9e")}
        </EmptyState>
      )}

      {!loading && !error && agents.length > 0 && (
        <section aria-labelledby="fleet-heading" className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_22rem]">
          <div>
            <h2 id="fleet-heading" className="mb-3 text-title font-semibold">
              {translateNow("source.agent.fleet.ac46d1b700")}
            </h2>
            {offboardEvidence && <p className="mb-3 text-sm text-muted-foreground">{offboardEvidence}</p>}
            <DataGrid ariaLabel="Registered in-network agents" rows={agents} columns={agentColumns} getRowId={(agent) => agent.id} state="ready" />
          </div>
          {selected && <AgentDetail agent={selected} />}
        </section>
      )}

      <Dialog
        open={offboardTarget !== null}
        onClose={() => {
          if (!offboardBusy) setOffboardTarget(null);
        }}
        titleId="agent-offboard-title"
        descriptionId="agent-offboard-description"
        role="alertdialog"
        initialFocusRef={offboardConfirmRef}
        closeOnBackdropClick={false}
        panelClassName="fixed left-1/2 top-1/2 grid w-[min(92vw,30rem)] -translate-x-1/2 -translate-y-1/2 gap-4 rounded-panel border border-border bg-card p-5 shadow-elevation3"
      >
        {offboardTarget && (
          <form
            className="grid gap-4"
            onSubmit={(event) => {
              event.preventDefault();
              void offboardAgent();
            }}
          >
            <div>
              <h2 id="agent-offboard-title" className="text-title font-semibold">
                {translateNow("source.offboard.9053e68ef6")} {offboardTarget.name}
              </h2>
              <p id="agent-offboard-description" className="mt-1 text-sm text-muted-foreground">
                {translateNow("source.the.agent.row.remains.as.an.offboarded.tom.42a25faa10")}
              </p>
            </div>
            <label className="grid gap-1 text-sm font-medium">
              {translateNow("source.reason.f81ab834de")}
              <textarea
                className="min-h-24 rounded-control border border-border bg-background px-3 py-2 text-sm font-normal"
                value={offboardReason}
                onChange={(event) => setOffboardReason(event.target.value)}
              />
            </label>
            {offboardError && <p className="text-sm font-medium text-risk-critical">{offboardError}</p>}
            <div className="flex flex-wrap justify-end gap-2">
              <Button type="button" variant="ghost" onClick={() => setOffboardTarget(null)} disabled={offboardBusy}>
                {translateNow("source.cancel.19766ed6cc")}
              </Button>
              <Button ref={offboardConfirmRef} type="submit" disabled={offboardBusy}>
                {offboardBusy && <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />}
                {translateNow("source.offboard.agent.f673bf87e3")}
              </Button>
            </div>
          </form>
        )}
      </Dialog>

      <Dialog
        open={revokeTarget !== null}
        onClose={() => {
          if (!revokeBusy) setRevokeTarget(null);
        }}
        titleId="agent-revoke-cert-title"
        descriptionId="agent-revoke-cert-description"
        role="alertdialog"
        closeOnBackdropClick={false}
        panelClassName="fixed left-1/2 top-1/2 grid w-[min(92vw,30rem)] -translate-x-1/2 -translate-y-1/2 gap-4 rounded-panel border border-border bg-card p-5 shadow-elevation3"
      >
        {revokeTarget && (
          <form
            className="grid gap-4"
            onSubmit={(event) => {
              event.preventDefault();
              void revokeCert();
            }}
          >
            <div>
              <h2 id="agent-revoke-cert-title" className="text-title font-semibold">
                {translateNow("source.revoke.certificate.for.a0ed3562dc")} {revokeTarget.name}
              </h2>
              <p id="agent-revoke-cert-description" className="mt-1 text-sm text-muted-foreground">
                Records a revocation for this agent's client certificate; mTLS RPCs presenting it are rejected once CRL and OCSP propagate. Leave serial and
                fingerprint empty to revoke the current certificate.
              </p>
            </div>
            <label className="grid gap-1 text-body font-medium" htmlFor="agent-revoke-reason">
              {translateNow("source.reason.f81ab834de")}
              <select
                id="agent-revoke-reason"
                className="min-h-9 rounded-control border border-border bg-background px-3 py-2 text-body font-normal"
                value={revokeReason}
                onChange={(event) => setRevokeReason(event.target.value)}
              >
                {certRevocationReasons.map((reason) => (
                  <option key={reason} value={reason}>
                    {reason}
                  </option>
                ))}
              </select>
            </label>
            <label className="grid gap-1 text-body font-medium" htmlFor="agent-revoke-serial">
              {t("parity.serialOptional_e59169")}
              <input
                id="agent-revoke-serial"
                className="min-h-9 rounded-control border border-border bg-background px-3 py-2 font-mono text-xs font-normal"
                value={revokeSerial}
                onChange={(event) => setRevokeSerial(event.target.value)}
                autoComplete="off"
                spellCheck={false}
              />
            </label>
            <label className="grid gap-1 text-body font-medium" htmlFor="agent-revoke-fingerprint">
              {t("parity.fingerprintOptional_b6cd87")}
              <input
                id="agent-revoke-fingerprint"
                className="min-h-9 rounded-control border border-border bg-background px-3 py-2 font-mono text-xs font-normal"
                value={revokeFingerprint}
                onChange={(event) => setRevokeFingerprint(event.target.value)}
                autoComplete="off"
                spellCheck={false}
              />
            </label>
            <label className="flex items-start gap-2 text-body font-medium" htmlFor="agent-revoke-confirm">
              <input
                id="agent-revoke-confirm"
                type="checkbox"
                className="mt-1 h-4 w-4 rounded border-border"
                checked={revokeConfirmed}
                onChange={(event) => setRevokeConfirmed(event.target.checked)}
              />
              {t("parity.iUnderstandThisRevocationCannotBe_92d164")}
            </label>
            {revokeError && <p className="text-sm font-medium text-risk-critical">{revokeError}</p>}
            <div className="flex flex-wrap justify-end gap-2">
              <Button type="button" variant="ghost" onClick={() => setRevokeTarget(null)} disabled={revokeBusy}>
                {translateNow("source.cancel.19766ed6cc")}
              </Button>
              <Button type="submit" disabled={revokeBusy || !revokeConfirmed}>
                {revokeBusy && <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />}
                {t("parity.revokeCertificate_338ad7")}
              </Button>
            </div>
          </form>
        )}
      </Dialog>
    </section>
  );
}

function AgentDetail({ agent }: { agent: Agent }) {
  const { t } = useTranslation();
  // Capability comes from the served response only. The console used to fall back
  // to its own hardcoded list — which named PKCS#11, the Windows certificate
  // store, and Kubernetes Secrets, none of which the agent binary can collect —
  // so an agent that reported nothing still rendered as covering a Windows
  // estate. If the server advertises nothing, the panel says nothing
  // (truth-integrity 1).
  const capabilities = agent.discovery_capabilities ?? [];
  const reportPath = agent.inventory_report_path || "agent.mtls.ReportInventory";

  return (
    <aside aria-labelledby="agent-detail-heading" className="grid content-start gap-3 border-y border-border py-4">
      <div>
        <h2 id="agent-detail-heading" className="text-title font-semibold">
          {agent.name}
        </h2>
        <p className="mt-1 text-sm text-muted-foreground">{translateNow("source.agent.profile.heartbeat.and.version.detail.fbb4a88e48")}</p>
      </div>
      <dl className="grid gap-2 text-sm">
        <div>
          <dt className="font-medium text-muted-foreground">{translateNow("source.agent.id.510bce732d")}</dt>
          <dd className="mt-0.5">
            <CredentialChip value={agent.id} label="agent ID" />
          </dd>
        </div>
        <div>
          <dt className="font-medium text-muted-foreground">{translateNow("source.status.920e413c7d")}</dt>
          <dd>{agent.status}</dd>
          <dt className="font-medium text-muted-foreground">{translateNow("source.agent.role.a2r0le0001")}</dt>
          <dd>
            <AgentRoleBadges agent={agent} />
            <span className="mt-1 block text-xs text-muted-foreground">{translateNow("source.agent.role.source.a2r0le0010")}</span>
          </dd>
          {agent.roles?.includes("network") ? (
            <>
              <dt className="font-medium text-muted-foreground">{translateNow("source.relay.executes.a3rel0001")}</dt>
              <dd>
                {(agent.relay_capabilities ?? []).length === 0 ? (
                  <span className="text-xs text-muted-foreground">{translateNow("source.relay.none.a3rel0002")}</span>
                ) : (
                  <ul className="grid gap-1">
                    {(agent.relay_capabilities ?? []).map((capability) => (
                      <li key={capability.kind}>
                        <span className="font-mono text-xs">{capability.kind}</span>
                        <span className="block text-xs text-muted-foreground">{(capability.connectors ?? []).join(", ")}</span>
                        {(capability.enable_flags ?? []).length > 0 ? (
                          <span className="block text-xs text-status-warning">
                            {translateNow("source.relay.flags.a3rel0003")} <span className="font-mono">{(capability.enable_flags ?? []).join(" ")}</span>
                          </span>
                        ) : null}
                      </li>
                    ))}
                  </ul>
                )}
                <span className="mt-1 block text-xs text-muted-foreground">{translateNow("source.relay.help.a3rel0004")}</span>
              </dd>
            </>
          ) : null}
        </div>
        <div>
          <dt className="font-medium text-muted-foreground">{translateNow("source.version.dd167905de")}</dt>
          <dd className="font-mono text-xs">{agent.version || "-"}</dd>
        </div>
        <div>
          <dt className="font-medium text-muted-foreground">{translateNow("source.last.seen.21fd79c7de")}</dt>
          <dd>{formatDate(agent.last_seen_at)}</dd>
        </div>
        {isOffboarded(agent) && (
          <>
            <div>
              <dt className="font-medium text-muted-foreground">{translateNow("source.offboarded.bc5f0c93d1")}</dt>
              <dd>{formatDate(agent.offboarded_at)}</dd>
            </div>
            {agent.offboarded_by && (
              <div>
                <dt className="font-medium text-muted-foreground">{translateNow("source.offboarded.by.4c49b0d40c")}</dt>
                <dd className="break-all font-mono text-xs">{agent.offboarded_by}</dd>
              </div>
            )}
            {agent.offboard_reason && (
              <div>
                <dt className="font-medium text-muted-foreground">{translateNow("source.offboard.reason.6c2b7a820c")}</dt>
                <dd>{agent.offboard_reason}</dd>
              </div>
            )}
          </>
        )}
      </dl>
      <section aria-labelledby="endpoint-discovery-heading" className="grid gap-2 border-t border-border pt-3 text-sm">
        <div>
          <h3 id="endpoint-discovery-heading" className="font-semibold">
            {t("agents.endpointDiscovery.heading")}
          </h3>
          <p className="mt-1 text-muted-foreground">{t("agents.endpointDiscovery.description", { path: reportPath })}</p>
        </div>
        <dl className="grid gap-1">
          <div>
            <dt className="font-medium text-muted-foreground">{t("agents.endpointDiscovery.reportPath")}</dt>
            <dd className="break-all font-mono text-xs">{reportPath}</dd>
          </div>
        </dl>
        {capabilities.length === 0 ? <p className="text-sm text-muted-foreground">{t("agents.endpointDiscovery.none")}</p> : null}
        <ul className="grid gap-2">
          {capabilities.map((capability) => (
            <li key={capability.source_kind} className="grid gap-1 border-l-2 border-brand-accent/60 pl-2">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-mono text-xs">{capability.source_kind}</span>
                <span className="text-xs text-muted-foreground">
                  {capability.metadata_only ? t("agents.endpointDiscovery.metadataOnly") : t("agents.endpointDiscovery.payload")}
                </span>
                {!capability.private_key_bytes && <span className="text-xs text-muted-foreground">{t("agents.endpointDiscovery.noKeyBytes")}</span>}
              </div>
              <span className="text-muted-foreground">{capability.label}</span>
              {capability.enable_flags?.length ? <span className="font-mono text-2xs text-muted-foreground">{capability.enable_flags.join(" ")}</span> : null}
            </li>
          ))}
        </ul>
      </section>
    </aside>
  );
}

function heartbeatFreshness(lastSeen?: string): { label: string; stale: boolean } {
  if (!lastSeen) return { label: translateNow("source.no.heartbeat.timestamp.7c01a4e0ea"), stale: true };
  const ts = Date.parse(lastSeen);
  if (Number.isNaN(ts)) return { label: translateNow("source.unparseable.heartbeat.timestamp.bb97c8934b"), stale: true };
  const ageMs = Date.now() - ts;
  if (ageMs > staleAfterMs) return { label: translateNow("source.stale.heartbeat.d8742526e2"), stale: true };
  return { label: translateNow("source.fresh.heartbeat.39d75ce503"), stale: false };
}

function formatDate(value?: string): string {
  return formatDateTimePolicy(value);
}

function formatDateOnly(value?: string): string {
  return formatDatePolicy(value);
}

function formatOffboarded(value?: string): string {
  return `Offboarded ${formatDateOnly(value)}`;
}

function isOffboarded(agent: Agent): boolean {
  return agent.status.toLowerCase() === "offboarded";
}

function enrollmentCommand(token: EnrollmentToken, agentName?: string): string {
  const origin = typeof window !== "undefined" ? window.location.origin : "https://trstctl.example.test";
  const enrollPath = token.enroll_path || "/enroll/bootstrap";
  const nameArg = agentName?.trim() ? shellArg(agentName.trim()) : "<agent-name>";
  return [
    "trstctl-agent",
    `--enroll-url ${origin}${enrollPath}`,
    "--bootstrap-token-file ./trstctl-bootstrap-token",
    "--server <control-plane-grpc:9443>",
    `--name ${nameArg}`,
    "--ca-bundle ./trstctl-ca.pem",
  ].join(" ");
}

function shellArg(value: string): string {
  if (/^[A-Za-z0-9._:/@-]+$/.test(value)) return value;
  return `'${value.replace(/'/g, "'\\''")}'`;
}
