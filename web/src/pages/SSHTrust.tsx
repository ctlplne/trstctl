import { UnavailableState } from "@/components/StatePrimitives";

const rolloutRows = [
  {
    step: "candidate CA",
    check: "fingerprint, tenant, intended principals, and target host group",
    failure: "reject if candidate CA is not pinned to the rollout plan",
  },
  {
    step: "sshd -t validation",
    check: "agent validates sshd_config before reload",
    failure: "rollback trusted_ca_keys from backup when validation fails",
  },
  {
    step: "reload health failed",
    check: "agent reloads sshd and verifies a health command",
    failure: "restore prior trusted CA file, reload, then mark drift",
  },
];

const jitRows = [
  {
    fixture: "attestation approved",
    evidence: "TPM quote digest plus approver",
    constraint: "principal: deployer",
    ttl: "TTL: 10 minutes",
  },
  {
    fixture: "attestation denied",
    evidence: "wrong device posture or stale evidence",
    constraint: "source-address: 10.0.0.0/24",
    ttl: "no certificate minted",
  },
  {
    fixture: "attestation expired",
    evidence: "freshness window exceeded",
    constraint: "force-command: /usr/local/bin/deploy",
    ttl: "request must re-attest",
  },
];

export function SSHTrust() {
  return (
    <section aria-labelledby="ssh-heading" className="grid gap-6">
      <div>
        <h1 id="ssh-heading" className="text-2xl font-semibold">
          SSH trust
        </h1>
        <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
          SSH trust changes can lock out operators. This surface explains the agent-side model and attestation-gated cert posture without changing `sshd_config`, `authorized_keys`, or trusted CA files from the browser.
        </p>
      </div>

      <UnavailableState title="High-blast-radius change">
        SSH trust rollout is agent-side opt-in only. Operators must start the agent with `--ssh-trust-add-ca` and `--ssh-trust-confirm`; the console renders no live trust mutation control.
      </UnavailableState>

      <section aria-labelledby="rollout-heading" className="grid gap-3 border-y border-border py-4">
        <div>
          <h2 id="rollout-heading" className="text-lg font-semibold">
            SSH deployment and trust rollout
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            A safe rollout names the candidate CA, target hosts, validation command, reload health command, rollback plan, and explicit confirmation copy before any host changes trust.
          </p>
        </div>
        <UnavailableState title="SSH trust mutation is not served">
          `BACKEND-CONNECTORS` and `BACKEND-DRIFT` must serve target-host state, rollout status, health failures, and rollback evidence. This page must never weaken `authorized_keys` or rewrite trust without agent confirmation.
        </UnavailableState>
        <div className="overflow-x-auto rounded-md border border-border">
          <table className="w-full min-w-[52rem] text-left text-sm">
            <caption className="sr-only">SSH trust rollout fixtures</caption>
            <thead>
              <tr className="border-b border-border text-muted-foreground">
                <th scope="col" className="py-2 pl-3 pr-4 font-medium">Rollout step</th>
                <th scope="col" className="py-2 pr-4 font-medium">Validation</th>
                <th scope="col" className="py-2 pr-3 font-medium">Rollback fixture</th>
              </tr>
            </thead>
            <tbody>
              {rolloutRows.map((row) => (
                <tr key={row.step} className="border-b border-border align-top">
                  <td className="py-2 pl-3 pr-4 font-medium">{row.step}</td>
                  <td className="py-2 pr-4">{row.check}</td>
                  <td className="py-2 pr-3">{row.failure}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section aria-labelledby="jit-heading" className="grid gap-3 border-y border-border py-4">
        <div>
          <h2 id="jit-heading" className="text-lg font-semibold">
            Attestation-gated SSH user certs
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            Short-lived SSH user certs require attestation evidence, an approver, principal constraints, TTL, source-address, and force-command policy. Self-approval blocked is a hard rule, not a UI hint.
          </p>
        </div>
        <UnavailableState title="Attested SSH issue flow is library-only">
          `BACKEND-ATTEST` must serve attestation decisions before this console can request short-lived SSH user certs. The SSH CA private key stays in the signer and is never shown here.
        </UnavailableState>
        <div className="overflow-x-auto rounded-md border border-border">
          <table className="w-full min-w-[52rem] text-left text-sm">
            <caption className="sr-only">Attestation gated SSH cert fixtures</caption>
            <thead>
              <tr className="border-b border-border text-muted-foreground">
                <th scope="col" className="py-2 pl-3 pr-4 font-medium">Fixture</th>
                <th scope="col" className="py-2 pr-4 font-medium">Evidence</th>
                <th scope="col" className="py-2 pr-4 font-medium">Constraint</th>
                <th scope="col" className="py-2 pr-3 font-medium">TTL posture</th>
              </tr>
            </thead>
            <tbody>
              {jitRows.map((row) => (
                <tr key={row.fixture} className="border-b border-border align-top">
                  <td className="py-2 pl-3 pr-4 font-medium">{row.fixture}</td>
                  <td className="py-2 pr-4">{row.evidence}</td>
                  <td className="py-2 pr-4">{row.constraint}</td>
                  <td className="py-2 pr-3">{row.ttl}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </section>
  );
}
