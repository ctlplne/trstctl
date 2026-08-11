// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/custody"
	"trstctl.com/trstctl/internal/editionseam"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/profile"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/tenantseal"
	"trstctl.com/trstctl/internal/usage"
)

// leafTTL is the validity of a certificate issued by the assembled CA. It is
// comfortably within the issuing CA's own validity so the leaf never outlives it.
const leafTTL = orchestrator.DefaultIdentityIssuanceTTL

// caNamespace is the fixed UUIDv5 namespace under which the served binary's
// stable CA handles are turned into the ca_id used by the revocation tables. It
// never changes, so a CA's ca_id is the same across restarts and the
// issued/revoked records for it line up over time.
var caNamespace = uuid.MustParse("8f6a0c1e-4d2b-5a3c-9e7f-1b2c3d4e5f60")
var evidenceNamespace = uuid.MustParse("d3f1677d-2e53-5d77-9c7f-8895a74f5c31")

const (
	connectorDeploySealedFormat  = "trstctl.connector.deploy.sealed"
	connectorDeploySealedVersion = 1
)

// IssuingCAID is the deterministic ca_id of the served binary's single issuing
// CA (keyed off the stable issuing-CA signer handle). It is the CA identifier
// recorded in ca_issued_certs / ca_crls for every leaf the served path mints,
// so the OCSP responder and CRL generator (and the served revocation handler)
// resolve the same CA. It is stable across restarts and shared by all tenants
// (the issuing CA is shared infrastructure; rows stay tenant-isolated by
// tenant_id under RLS).
func IssuingCAID() string {
	return uuid.NewSHA1(caNamespace, []byte(issuingCAHandle)).String()
}

// issueFunc mints a leaf certificate from a CSR under the caller-supplied served
// leaf profile (Server.IssueLeafWithProfile satisfies it).
type issueFunc func(ctx context.Context, csrDER []byte, ttl time.Duration, leafProfile crypto.LeafProfile) ([]byte, error)

// connectorPluginDeployer is the narrow signed-plugin surface needed by the
// outbox dispatcher. Keeping the seam small also lets replay-safety tests prove
// that an untrusted plugin is never assumed idempotent merely because it loaded.
type connectorPluginDeployer interface {
	Has(name string) bool
	Deploy(ctx context.Context, tenantID string, payload connector.DeployPayload) (handled bool, err error)
}

// connectorPluginDeployerFromManager avoids Go's typed-nil interface trap. ELI5:
// putting a nil *PluginManager into an interface gives the interface a type label,
// so `plugins != nil` even though calling a method dereferences nil. Production
// assembly uses this conversion so an unconfigured plugin surface stays a truly
// nil interface and connector delivery fails closed instead of panicking.
func connectorPluginDeployerFromManager(pm *PluginManager) connectorPluginDeployer {
	if pm == nil {
		return nil
	}
	return pm
}

// issuanceDispatcher is the real outbox handler (AN-6). For a requested→issued
// lifecycle transition it mints a leaf certificate from the assembled CA (whose
// key lives in the out-of-process signer, AN-4) and records it in the inventory
// as an event (AN-2); for an *→revoked transition it revokes that leaf so the
// certificate stops validating. The same projected events also rebuild the
// ca_issued_certs responder table, so inventory and OCSP/CRL state share one
// source of truth. It is idempotent on
// the outbox message's key (AN-5), so a redelivery never mints a second
// certificate nor double-revokes.
// Scope decision (A0.3d): the direct identity API deliberately performs
// server-side CLASSICAL keygen (ephemeral NHI identities; no CSR input), so
// this dispatcher carries no licensed signer twin — CSR-based enrollment,
// including licensed subject algorithms, is the protocols' job through
// protocolIssuer. A future identity key-algorithm parameter is roadmap work,
// not a dormant seam here.
type issuanceDispatcher struct {
	// relayPresence overrides the store for the E1 control-plane refusal; nil in
	// production, where the store answers.
	relayPresence relayPresence
	issue         issueFunc
	orch          *orchestrator.Orchestrator
	idem          *orchestrator.Idempotency
	outbox        *orchestrator.Outbox
	store         *store.Store
	admission     editionseam.AdmissionHook

	// log is the event log used to emit the profile-gated issuance decision
	// (issuance.profile_evaluated) on the served mint (PKIGOV-002); nil disables the
	// audit emit but the deny still rejects.
	log *events.Log
	// chainPEM is the issuing CA chain returned alongside a certificate issued
	// against an agent-generated CSR (epic B2). Empty is legitimate — the agent
	// then serves the leaf alone, exactly as the sealed-deploy path did.
	chainPEM []byte
	// defaultProfile is the certificate-profile name enforced on the served mint
	// when it resolves for the tenant (PKIGOV-002). Empty means no served-side
	// profile binding, preserving the prior behavior.
	defaultProfile string
	// leafProfile is the operator-configured served issuer profile (revocation
	// pointers, policy OIDs, and any static constraints). Tenant certificate-profile
	// constraints are merged into a per-issuance copy before signing.
	leafProfile crypto.LeafProfile
	// ensureCRL makes sure the tenant has a public CRL after trusted issue/renew
	// paths record issued serial state; publishCRL forces a fresh CRL after trusted
	// revocation state changes. Neither is used by public GET /crl/{tenant}; reads
	// must never create tenant state.
	ensureCRL  func(context.Context, string) error
	publishCRL func(context.Context, string) error
	// plugins is the served WASM-plugin surface (ARCH-007). When non-nil, a
	// connector.deploy whose connector names a loaded, provenance-verified plugin
	// (SUPPLY-004) is pushed through the capability sandbox. Missing or declining
	// plugins fail the row closed so configured work cannot be acknowledged without
	// touching its receiver. Tenant-scoped (AN-1) and event-sourced (AN-2); the
	// plugin holds no store/signer handle.
	plugins connectorPluginDeployer
	// connectorRegistry is the trusted native deployment connector registry
	// (CLM-05/F7/F27). When a connector.deploy payload names a registered native
	// connector and carries the credential bytes, the served outbox worker performs
	// the real deploy through the connector SDK sandbox and records a durable receipt.
	connectorRegistry *connector.Registry
	// connectorRightSize applies connector.right_size entitlement mutations and
	// verifies the effective scopes before the outbox row is acknowledged.
	connectorRightSize RightSizeMutator
	// The right-size seams are test-only crash boundaries. Production leaves them
	// nil; adversarial tests fail after receiver I/O or after the terminal append
	// to prove retry/reconciliation converges without inventing a second identity.
	afterRightSizeSideEffects    func(context.Context) error
	afterRightSizeTerminalAppend func(context.Context) error
	// connectorPayloadKey seals connector.deploy payloads before they are persisted
	// in outbox.payload and opens them only inside this dispatcher.
	connectorPayloadKey sealKeyWrapper
	// tenantCrypto holds one shared tenant-domain fence across a complete worker
	// delivery. The tenantseal.seal command itself bypasses this shared gate because
	// it must acquire the matching exclusive fence.
	tenantCrypto tenantseal.Access
	// externalCAs owns external-ca.issue rows. Provider-backed issuance is routed
	// through this registry so upstream CA side effects happen from the outbox
	// worker, not the request handler.
	externalCAs *externalCARegistry
	// notifications fans notification.* outbox rows to operator-configured channels
	// (NOTIF-01/F29). Nil preserves the prior no-channel behavior.
	notifications *notify.Dispatcher
	// transparency handles transparency.* outbox rows such as Rekor publication for
	// served code signing (CLM-06/F50). Nil fails those rows closed.
	transparency orchestrator.Handler
	// codeSign owns codesign.command and codesign.cleanup. Both are internal,
	// first-party worker commands and must never fall through as acknowledged
	// unknown destinations.
	codeSign *servedCodeSigningService
	// secretRepoScanner runs repository secret scans from the discovery.run outbox
	// worker. It is the same pinned/redacting scanner used by POST /secrets/scans.
	secretRepoScanner secretScanner
	// dns01 publishes and cleans ACME DNS-01 challenge records through tenant
	// provider configs. Nil makes acme.dns01.* destinations fail closed.
	dns01 *servedACMEDNS01Automation
	// licensed handles first-party destinations owned by EE packages. It returns
	// handled=false for destinations it does not own, so core still fails closed for
	// unknown first-party work.
	licensed LicensedOutboxHandler
	// secretIntegrations owns dynsecret.* and secret.sync.* first-party rows. It
	// returns errors for unconfigured targets so those rows are never silently
	// acknowledged by the generic fallback.
	secretIntegrations *secretIntegrationOutboxDispatcher
	// tenantKeyDomains owns the internal tenantseal.seal command. It proves the
	// accepted HTTP result is durable before the lifecycle makes tenant crypto
	// unavailable, and runs only on the bounded outbox worker.
	tenantKeyDomains *tenantKeyDomainSealOutboxDispatcher

	// nil in production; tests use it to inject a crash-equivalent error after
	// signer/event side effects but before the idempotency result is completed.
	afterIssueSideEffects func(context.Context) error
	// nil in production; tests use it to inject the connector crash window after
	// the receiver and durable delivery receipt commit but before the idempotency
	// result is completed.
	afterDeploySideEffects func(context.Context) error
}

// Deliver implements orchestrator.Handler. It mints on a ca.issue trigger,
// renews on a ca.renew trigger, revokes on a revocation.publish trigger, and
// pushes a connector.deploy through a served WASM connector plugin when one owns
// the named connector (ARCH-007). Unknown CA/revocation first-party destinations
// fail closed so the outbox never marks a lifecycle side effect delivered without
// doing real work.
func (d *issuanceDispatcher) Deliver(ctx context.Context, m orchestrator.Message) error {
	if d.tenantCrypto == nil || m.Destination == store.TenantKeyDomainSealDestination {
		return d.deliver(ctx, m)
	}
	err := withTenantCipher(ctx, d.tenantCrypto, d.connectorPayloadKey, m.TenantID, func(scoped context.Context, _ tenantseal.Cipher) error {
		return d.deliver(scoped, m)
	})
	if _, unavailable := tenantseal.StatusOf(err); unavailable {
		// Access failed before any receiver handler ran, so a seal or custody outage
		// pauses the row without spending its finite external-delivery retry budget.
		return orchestrator.DeferDelivery(err)
	}
	return err
}

func (d *issuanceDispatcher) deliver(ctx context.Context, m orchestrator.Message) error {
	switch m.Destination {
	case "ca.issue":
		return d.handleIssue(ctx, m)
	case "ca.renew":
		return d.handleRenew(ctx, m)
	case "revocation.publish":
		return d.handleRevoke(ctx, m)
	case "connector.deploy":
		return d.handleDeploy(ctx, m)
	case orchestrator.DestinationFleetReissuanceBatch:
		return d.handleFleetReissuanceBatch(ctx, m)
	case orchestrator.DestinationConnectorRollback, "connector.test":
		// Relay-executed kinds. This dispatcher sweeps every "connector." row
		// (see outboxDispatchFamilies) and does not filter on
		// required_agent_role, so without this case the default branch below
		// returns a hard error, the row burns its attempt budget, and it lands
		// in status='failed' — where ClaimAgentJobs, which requires 'pending',
		// can never see it. The work is dead-lettered before any relay has a
		// chance to claim it, while the API has already told the operator it is
		// queued.
		//
		// DeferDelivery is attempt-budget-neutral: it proves no receiver I/O
		// began, so the row re-pends indefinitely and stays claimable by the
		// agent that is actually supposed to run it.
		return orchestrator.DeferDelivery(fmt.Errorf(
			"server: %s executes on a relay, not the control plane", m.Destination))
	case orchestrator.DestinationConnectorRightSize:
		return d.handleConnectorRightSize(ctx, m)
	case "discovery.run":
		relayOwned, err := d.discoveryRunRelayOwned(ctx, m)
		if err != nil {
			return err
		}
		if relayOwned {
			return orchestrator.DeferDelivery(errors.New(
				"server: network and SSH discovery execute on a network relay, not the control plane"))
		}
		return d.handleDiscoveryRun(ctx, m)
	case destinationACMEDNS01Present, destinationACMEDNS01Cleanup:
		if d.dns01 == nil {
			return fmt.Errorf("server: acme dns-01 outbox destination is not configured")
		}
		return d.dns01.Deliver(ctx, m)
	case ca.DestinationExternalCAIssue:
		if d.externalCAs == nil {
			return fmt.Errorf("server: external CA outbox destination is not configured")
		}
		return d.externalCAs.DeliverExternalCAIssue(ctx, m)
	case orchestrator.DestinationITSMServiceNow:
		return d.handleServiceNowTicket(ctx, m)
	case orchestrator.DestinationResponseSplunk:
		return d.handleSplunkResponseIntegration(ctx, m)
	case orchestrator.DestinationResponseJira:
		return d.handleJiraResponseIntegration(ctx, m)
	case ctSubmissionDestination:
		return d.handleCTSubmission(ctx, m)
	default:
		if d.tenantKeyDomains != nil {
			handled, err := d.tenantKeyDomains.Deliver(ctx, m)
			if handled || err != nil {
				return err
			}
		}
		if d.codeSign != nil {
			handled, err := d.codeSign.Deliver(ctx, m)
			if handled || err != nil {
				return err
			}
		}
		if d.secretIntegrations != nil {
			handled, err := d.secretIntegrations.Deliver(ctx, m)
			if handled || err != nil {
				return err
			}
		}
		if d.licensed != nil {
			handled, err := d.licensed.DeliverLicensed(ctx, m)
			if handled || err != nil {
				return err
			}
		}
		if strings.HasPrefix(m.Destination, "notification.") {
			if d.notifications == nil {
				return fmt.Errorf("server: notification outbox destination is not configured")
			}
			return d.notifications.DispatchMessage(ctx, notify.DeliveryMessage{
				TenantID: m.TenantID, Destination: m.Destination,
				IdempotencyKey: m.IdempotencyKey, Payload: m.Payload,
				OutboxID: m.ID, Attempts: m.Attempts,
			})
		}
		if strings.HasPrefix(m.Destination, "transparency.") {
			if d.transparency == nil {
				return fmt.Errorf("server: transparency outbox destination is not configured")
			}
			return d.transparency.Deliver(ctx, m)
		}
		if strings.HasPrefix(m.Destination, "managedkey.") {
			return fmt.Errorf("server: managed-key outbox destination is not configured")
		}
		// An AGENT-CLAIMABLE kind with no control-plane handler is not unknown —
		// it is work waiting for an agent, and it must wait rather than die.
		//
		// This is the general form of a bug that had already been fixed twice by
		// hand and was still live four times over. connector.rollback and
		// connector.test got explicit deferral cases above, with a comment
		// explaining that without them the default branch burns the row's
		// attempt budget and lands it in status='failed' — where ClaimAgentJobs,
		// which requires 'pending', can never see it. Nobody added the same case
		// for endpoint.verify, endpoint.renew, revocation.probe, adcs.inventory
		// or trust.distribute, so each of those enqueued a row that dead-lettered
		// before any agent could claim it, while the API had already told the
		// operator the work was queued.
		//
		// Deriving the answer from agentJobKindAllowlist instead of adding a
		// fifth case means a kind added to that allowlist can never again be
		// missing from here. The allowlist is the one place that decides what an
		// agent may execute; this reads it rather than restating it.
		if agentJobKindAllowlist[m.Destination] {
			return orchestrator.DeferDelivery(fmt.Errorf(
				"server: %s is agent-claimable work with no control-plane executor; it waits for "+
					"an agent to claim it", m.Destination))
		}
		// This dispatcher is the sole handler passed to every scoped and unscoped
		// outbox sweep. There is no second worker to own an unknown destination, so
		// accepting it here would be a global silent ACK.
		return fmt.Errorf("server: unsupported first-party outbox destination %q", m.Destination)
	}
}

// DeliverTerminalFailure records domain terminal states before the generic
// outbox dead-letters a row. Subsystems that do not own a projected pending state
// need no callback; secret integrations and licensed managed keys do.
func (d *issuanceDispatcher) DeliverTerminalFailure(ctx context.Context, m orchestrator.Message, cause error) error {
	if m.Destination == orchestrator.DestinationConnectorRightSize {
		return d.failConnectorRightSizeTerminal(ctx, m)
	}
	if d.tenantKeyDomains != nil {
		handled, err := d.tenantKeyDomains.DeliverTerminalFailure(ctx, m, cause)
		if handled || err != nil {
			return err
		}
	}
	if d.codeSign != nil {
		handled, err := d.codeSign.DeliverTerminalFailure(ctx, m, cause)
		if handled || err != nil {
			return err
		}
	}
	if d.secretIntegrations != nil {
		handled, err := d.secretIntegrations.DeliverTerminalFailure(ctx, m, cause)
		if handled || err != nil {
			return err
		}
	}
	if terminal, ok := d.licensed.(LicensedOutboxTerminalFailureHandler); ok {
		handled, err := terminal.DeliverLicensedTerminalFailure(ctx, m, cause)
		if handled || err != nil {
			return err
		}
	}
	return nil
}

// transitionTrigger is the part of a lifecycle transition payload the issuance
// and revocation handlers need (the same JSON the orchestrator enqueues on the
// outbox entry).
type transitionTrigger struct {
	IdentityID             string `json:"identity_id"`
	To                     string `json:"to"`
	Reason                 string `json:"reason"`
	Origin                 string `json:"origin,omitempty"`
	PredecessorFingerprint string `json:"predecessor_fingerprint,omitempty"`
	// SubjectCSRPEM is the caller's own PKCS#10 request (epic B1). When it is
	// present the dispatcher signs it and generates no subject key, so the
	// private key stays wherever the caller made it. The JSON tag matches
	// orchestrator's transitionPayload, which is where the field is written.
	SubjectCSRPEM string                                  `json:"subject_csr_pem,omitempty"`
	Approval      *store.OperationApprovalUse             `json:"approval,omitempty"`
	Issuance      *store.OperationApprovalIssuanceBinding `json:"issuance,omitempty"`
}

type sealedConnectorDeployPayload struct {
	Format      string `json:"format"`
	Version     int    `json:"version"`
	IdentityID  string `json:"identity_id,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Sealed      []byte `json:"sealed"`
	// Routing fields carried OUTSIDE the seal (epic A3) so a relay can be told
	// what it is being asked to do without holding ciphertext it cannot open.
	// None of these is a secret: the connector kind and target name appear in
	// the tenant's own deployment-target configuration, and target_config holds
	// secret:// REFERENCES, never values — it is stored unsealed in
	// deployment_targets.config for exactly that reason.
	//
	// They are not bound into the AAD, because changing the AAD would make every
	// already-sealed in-flight row fail to open. Instead the resolver verifies
	// them against the sealed copy at redemption and refuses on mismatch, so
	// tampering with the public routing is caught before any credential moves.
	// Rows sealed before this field existed carry it empty and skip the check.
	Connector    string          `json:"connector,omitempty"`
	Target       string          `json:"target,omitempty"`
	TargetID     string          `json:"target_id,omitempty"`
	Revision     string          `json:"target_revision,omitempty"`
	TargetConfig json.RawMessage `json:"target_config,omitempty"`
}

type issuedLeafMaterial struct {
	Certificate store.Certificate
	CertPEM     []byte
	KeyPEM      []byte
}

func (d *issuanceDispatcher) handleIssue(ctx context.Context, m orchestrator.Message) error {
	var p transitionTrigger
	if err := json.Unmarshal(m.Payload, &p); err != nil {
		return fmt.Errorf("server: decode ca.issue payload: %w", err)
	}
	// Only a requested→issued transition triggers minting. Other ca.issue entries
	// (e.g. the IssuanceService's post-issuance observability record) are
	// acknowledged.
	if p.IdentityID == "" || p.To != string(orchestrator.StateIssued) {
		return nil
	}
	idemKey := "issue:" + m.IdempotencyKey
	// Idempotent on the outbox key: a redelivery returns the recorded result
	// without minting again (AN-5 ↔ AN-6).
	_, err := d.idem.Do(ctx, m.TenantID, idemKey, func(ctx context.Context) ([]byte, error) {
		recovered, err := recoverCertificatesByIssuanceKey(ctx, d.store, d.log, m.TenantID, idemKey)
		if err != nil {
			return nil, err
		}
		if len(recovered) > 0 {
			return []byte(recovered[len(recovered)-1].Fingerprint), nil
		}
		ident, err := d.store.GetIdentity(ctx, m.TenantID, p.IdentityID)
		if err != nil {
			return nil, fmt.Errorf("server: load identity %s: %w", p.IdentityID, err)
		}
		if err := d.admitIssuance(ctx, m, p, ident, "issue"); err != nil {
			return nil, err
		}
		// B2: first issuance to an agent-executed target, with no CSR to honour.
		//
		// Narrow on purpose. An identity that carries a CSR — on the transition
		// or recorded at creation — already has the custody B2 wants: the
		// requester generated the key and the control plane never held it, so
		// mintServedLeafForTrigger produces no key bytes and the parity gate
		// passes. Only the server-keygen FALLBACK is a problem, and it is a
		// sharp one: it generates a control-plane key, records the certificate,
		// and only then reaches enforceExecutorParity, which refuses. The key
		// was made for a target that explicitly opted out of receiving one, and
		// no later refusal unmakes it.
		//
		// So the fallback is diverted to the host instead of being refused after
		// the fact.
		target, hostExecuted, targetErr := d.hostRenewalTargetFor(ctx, m.TenantID, ident)
		if targetErr != nil {
			return nil, targetErr
		}
		if hostExecuted &&
			strings.TrimSpace(p.SubjectCSRPEM) == "" && subjectCSRFromIdentity(ident) == "" {
			binding, err := issuanceBindingForTrigger(p)
			if err != nil {
				return nil, err
			}
			if err := d.enqueueHostRenewal(ctx, m.TenantID, ident, target,
				ident.Name, []string{ident.Name}, "", binding, "host-issue:"+idemKey); err != nil {
				return nil, err
			}
			d.recordAgentRenewalDispatch(ctx, m.TenantID, ident, target, []string{ident.Name})
			return []byte("first issuance dispatched to host agent"), nil
		}

		material, err := d.mintServedLeafForTrigger(ctx, m.TenantID, ident, p)
		if err != nil {
			return nil, err
		}
		defer secret.Wipe(material.KeyPEM)
		cert := material.Certificate
		cert.IssuanceIdempotencyKey = idemKey
		recorded, err := d.orch.RecordCertificate(ctx, m.TenantID, cert)
		if err != nil {
			return nil, err
		}
		if err := d.transitionDeployedWithCredential(ctx, m.TenantID, ident, p.Reason, material.CertPEM, material.KeyPEM, recorded.Fingerprint); err != nil {
			return nil, err
		}
		usage.Record(m.TenantID, usage.MeterCertificatesIssued, 1)
		if d.afterIssueSideEffects != nil {
			if err := d.afterIssueSideEffects(ctx); err != nil {
				return nil, err
			}
		}
		return []byte(recorded.Fingerprint), nil
	})
	if err != nil {
		return err
	}
	return d.ensureTenantCRL(ctx, m.TenantID)
}

func (d *issuanceDispatcher) admitIssuance(ctx context.Context, m orchestrator.Message, p transitionTrigger, ident store.Identity, operation string) error {
	if d.admission == nil {
		return nil
	}
	req := editionseam.AdmissionRequest{
		TenantID:        m.TenantID,
		Operation:       operation,
		IdentityID:      p.IdentityID,
		IdempotencyKey:  m.IdempotencyKey,
		Reason:          p.Reason,
		ObservedInputs:  observedStateInputs(ident.Attributes),
		ObservedSummary: string(ident.Kind),
	}
	decision, err := d.admission.Admit(ctx, req)
	if err != nil {
		return fmt.Errorf("server: issuance admission: %w", err)
	}
	if decision.Allowed {
		return nil
	}
	reason := strings.TrimSpace(decision.Reason)
	if reason == "" {
		reason = "operation refused by admission policy"
	}
	return fmt.Errorf("server: issuance admission refused: %s", reason)
}

type observedStateAttributes struct {
	ObservedInputs []editionseam.ObservedStateInput `json:"observed_state_inputs"`
}

func observedStateInputs(raw json.RawMessage) []editionseam.ObservedStateInput {
	if len(raw) == 0 {
		return nil
	}
	var attrs observedStateAttributes
	if err := json.Unmarshal(raw, &attrs); err != nil {
		return []editionseam.ObservedStateInput{{Source: "identity.attributes"}}
	}
	out := make([]editionseam.ObservedStateInput, 0, len(attrs.ObservedInputs))
	for _, input := range attrs.ObservedInputs {
		input.AuthorityID = strings.TrimSpace(input.AuthorityID)
		input.RecordKey = strings.TrimSpace(input.RecordKey)
		input.Source = strings.TrimSpace(input.Source)
		out = append(out, input)
	}
	return out
}

func (d *issuanceDispatcher) completeRecoveredRenewal(ctx context.Context, tenantID, identityID, reason string) error {
	state, err := d.orch.State(ctx, tenantID, identityID)
	if err != nil {
		return err
	}
	if state == orchestrator.StateDeployed {
		return nil
	}
	if state != orchestrator.StateRenewing {
		return fmt.Errorf("server: recovered renewal for identity %s while state is %q", identityID, state)
	}
	if reason == "" {
		reason = "renewal completed"
	}
	return d.orch.Transition(ctx, tenantID, identityID, orchestrator.StateDeployed, reason)
}

// mintServedLeaf builds a fresh subject key through the crypto boundary, signs the
// CSR with the served signer-backed issuing CA, and returns the inventory metadata
// for the public certificate. The private key is destroyed before returning; the
// control plane never persists or logs it.
func (d *issuanceDispatcher) mintServedLeaf(ctx context.Context, tenantID, ownerID, commonName string, dnsNames []string) (store.Certificate, error) {
	material, err := d.mintServedLeafMaterial(ctx, tenantID, ownerID, commonName, dnsNames)
	if err != nil {
		return store.Certificate{}, err
	}
	secret.Wipe(material.KeyPEM)
	return material.Certificate, nil
}

// mintServedLeafMaterial returns the same inventory certificate as mintServedLeaf
// plus a transient PEM credential bundle for a connector outbox payload. Callers
// must wipe KeyPEM after encoding the deployment intent; the key is never written
// to the event log or read model.
func (d *issuanceDispatcher) mintServedLeafMaterial(ctx context.Context, tenantID, ownerID, commonName string, dnsNames []string, issuance ...*store.OperationApprovalIssuanceBinding) (issuedLeafMaterial, error) {
	if d.issue == nil {
		return issuedLeafMaterial{}, errors.New("server: issuing CA is unavailable")
	}
	if len(dnsNames) == 0 {
		dnsNames = []string{commonName}
	}
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		return issuedLeafMaterial{}, err
	}
	defer key.Destroy()
	keyPEM, err := key.PrivateKeyPEM()
	if err != nil {
		return issuedLeafMaterial{}, err
	}
	keepKeyPEM := false
	defer func() {
		if !keepKeyPEM {
			secret.Wipe(keyPEM)
		}
	}()
	csrDER, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: commonName, DNSNames: dnsNames}, key)
	if err != nil {
		return issuedLeafMaterial{}, err
	}
	// Enforce the certificate-profile model on the served mint (PKIGOV-002):
	// when a default profile is configured and resolves for the tenant, validate
	// this request against it BEFORE signing and emit the allow/deny decision as
	// an issuance.profile_evaluated event. A violation rejects (fail closed) so an
	// out-of-profile certificate is never minted on the served path.
	ttl, binding, err := approvedIssuanceTTL(issuance)
	if err != nil {
		return issuedLeafMaterial{}, err
	}
	leafProfile, err := d.enforceProfile(ctx, tenantID, csrDER, dnsNames, ttl, binding)
	if err != nil {
		return issuedLeafMaterial{}, err
	}
	leafPEM, err := d.issue(ctx, csrDER, ttl, leafProfile)
	if err != nil {
		return issuedLeafMaterial{}, err
	}
	blk, _ := pem.Decode(leafPEM)
	if blk == nil {
		return issuedLeafMaterial{}, errors.New("server: issued certificate is not PEM")
	}
	info, err := certinfo.Inspect(blk.Bytes)
	if err != nil {
		return issuedLeafMaterial{}, err
	}
	var ownerPtr *string
	if ownerID = strings.TrimSpace(ownerID); ownerID != "" {
		owner := ownerID
		ownerPtr = &owner
	}
	nb, na := info.NotBefore, info.NotAfter
	keepKeyPEM = true
	return issuedLeafMaterial{
		Certificate: store.Certificate{
			CAID: IssuingCAID(), OwnerID: ownerPtr, Subject: info.Subject, SANs: sansOf(info),
			Issuer: info.Issuer, Serial: info.SerialNumber, Fingerprint: info.SHA256Fingerprint,
			KeyAlgorithm: info.KeyAlgorithm, NotBefore: &nb, NotAfter: &na,
			Source: "issued", CertificateDER: append([]byte(nil), blk.Bytes...),
			// B5: the deprecated path. The key was held in locked memory and
			// wiped, but it existed outside the requester, and a credential on
			// this path is one an operator should plan to replace. They cannot
			// plan for what is not written down, so it is written down here
			// rather than only in a deprecation event nobody queries.
			KeyOrigin:  string(custody.OriginControlPlane),
			KeyStorage: string(custody.StorageLockedMemory),
		},
		CertPEM: append([]byte(nil), leafPEM...),
		KeyPEM:  keyPEM,
	}, nil
}

// handleRenew processes a ca.renew outbox entry (the side effect of a deployed→
// renewing lifecycle transition): it mints a signer-backed successor certificate,
// records the successor through the event-sourced certificate.recorded path with
// a replaces_id link, whose projection atomically inserts the successor,
// supersedes the predecessor, records the successor serial for OCSP/CRL, and
// moves the identity back to deployed via identity.renewed. It is idempotent on
// the outbox key (AN-5), so a redelivery cannot mint a second successor.
func (d *issuanceDispatcher) handleRenew(ctx context.Context, m orchestrator.Message) error {
	var p transitionTrigger
	if err := json.Unmarshal(m.Payload, &p); err != nil {
		return fmt.Errorf("server: decode ca.renew payload: %w", err)
	}
	if p.IdentityID == "" || p.To != string(orchestrator.StateRenewing) {
		return nil
	}
	idemKey := "renew:" + m.IdempotencyKey
	_, err := d.idem.Do(ctx, m.TenantID, idemKey, func(ctx context.Context) ([]byte, error) {
		run := rotationRunEvidence{
			ID:                     evidenceID("rotation", m.TenantID, m.IdempotencyKey, m.ID),
			IdentityID:             p.IdentityID,
			OutboxID:               outboxPtr(m.ID),
			Trigger:                rotationTrigger(p.Origin, m.IdempotencyKey, p.Reason),
			Reason:                 p.Reason,
			IdempotencyKey:         m.IdempotencyKey,
			PredecessorFingerprint: p.PredecessorFingerprint,
		}
		ident, err := d.store.GetIdentity(ctx, m.TenantID, p.IdentityID)
		if err != nil {
			_ = d.recordRotationRun(ctx, m.TenantID, run, "failed", err.Error())
			return nil, fmt.Errorf("server: load identity %s: %w", p.IdentityID, err)
		}
		recovered, err := recoverCertificatesByIssuanceKey(ctx, d.store, d.log, m.TenantID, idemKey)
		if err != nil {
			_ = d.recordRotationRun(ctx, m.TenantID, run, "failed", err.Error())
			return nil, err
		}
		if len(recovered) > 0 {
			return d.completeRecoveredRenewalRun(ctx, m.TenantID, p, run, recovered)
		}
		certs, err := d.store.ListActiveIssuedCertificatesForIdentity(ctx, m.TenantID, ident.OwnerID, ident.Name)
		if err != nil {
			_ = d.recordRotationRun(ctx, m.TenantID, run, "failed", err.Error())
			return nil, fmt.Errorf("server: find issued certs for identity %s: %w", p.IdentityID, err)
		}
		certs, err = renewalCertificatesForTrigger(certs, p)
		if err != nil {
			_ = d.recordRotationRun(ctx, m.TenantID, run, "failed", err.Error())
			return nil, err
		}
		if run.PredecessorFingerprint == "" && len(certs) > 0 {
			run.PredecessorFingerprint = certs[0].Fingerprint
		}
		if err := d.recordRotationRun(ctx, m.TenantID, run, "running", ""); err != nil {
			return nil, err
		}
		if len(certs) == 0 {
			err := fmt.Errorf("server: no active issued certificate to renew for identity %s", p.IdentityID)
			_ = d.recordRotationRun(ctx, m.TenantID, run, "failed", err.Error())
			return nil, err
		}
		if err := d.admitIssuance(ctx, m, p, ident, "renew"); err != nil {
			_ = d.recordRotationRun(ctx, m.TenantID, run, "failed", err.Error())
			return nil, err
		}
		// B2: hand the whole renewal to the host, before anything is minted.
		dispatched, hostErr := d.dispatchHostRenewal(ctx, m.TenantID, ident, certs[0], run, idemKey)
		if hostErr != nil {
			return nil, hostErr
		}
		if dispatched {
			return []byte("renewal dispatched to host agent"), nil
		}

		var deployCertPEM, deployKeyPEM []byte
		deployFingerprint := ""
		defer func() { secret.Wipe(deployKeyPEM) }()
		for _, old := range certs {
			dnsNames := old.SANs
			if len(dnsNames) == 0 {
				dnsNames = []string{ident.Name}
			}
			commonName := ident.Name
			if len(dnsNames) > 0 {
				commonName = dnsNames[0]
			}
			// B2: a renewal honours the identity's CSR exactly as first
			// issuance does.
			//
			// This closed a custody hole that ran on a timer. B1 made first
			// issuance CSR-first, but renewal called mintServedLeafMaterial
			// unconditionally — so an operator who enrolled with a CSR, key
			// never leaving their host, silently received a
			// control-plane-generated key on their FIRST RENEWAL, 30 to 90 days
			// later. Nothing announced it: the renewal path did not even emit
			// the server-side-keygen deprecation event the issue path emits.
			// Custody that degrades automatically is worse than custody that
			// was never claimed, because the claim outlives the property.
			material, err := d.mintServedLeafForRenewal(ctx, m.TenantID, ident, commonName, dnsNames)
			if err != nil {
				_ = d.recordRotationRun(ctx, m.TenantID, run, "failed", err.Error())
				return nil, err
			}
			successor := material.Certificate
			successor.IssuanceIdempotencyKey = idemKey
			recorded, err := d.orch.RecordSuccessorCertificate(ctx, m.TenantID, successor, old.ID)
			if err != nil {
				secret.Wipe(material.KeyPEM)
				_ = d.recordRotationRun(ctx, m.TenantID, run, "failed", err.Error())
				return nil, fmt.Errorf("server: record renewal successor: %w", err)
			}
			secret.Wipe(deployKeyPEM)
			deployCertPEM = material.CertPEM
			deployKeyPEM = material.KeyPEM
			deployFingerprint = recorded.Fingerprint
			run.SuccessorFingerprint = recorded.Fingerprint
		}
		reason := p.Reason
		if reason == "" {
			reason = "renewal completed"
		}
		if err := d.transitionDeployedWithCredential(ctx, m.TenantID, ident, reason, deployCertPEM, deployKeyPEM, deployFingerprint); err != nil {
			_ = d.recordRotationRun(ctx, m.TenantID, run, "failed", err.Error())
			return nil, fmt.Errorf("server: complete renewal transition: %w", err)
		}
		if d.afterIssueSideEffects != nil {
			if err := d.afterIssueSideEffects(ctx); err != nil {
				_ = d.recordRotationRun(ctx, m.TenantID, run, "failed", err.Error())
				return nil, err
			}
		}
		if run.RollbackRef == "" && run.PredecessorFingerprint != "" {
			run.RollbackRef = "restore certificate fingerprint " + run.PredecessorFingerprint
		}
		if err := d.recordRotationRun(ctx, m.TenantID, run, "succeeded", ""); err != nil {
			return nil, err
		}
		return []byte(fmt.Sprintf("renewed:%d", len(certs))), nil
	})
	if err != nil {
		return err
	}
	return d.ensureTenantCRL(ctx, m.TenantID)
}

// enforceProfile applies the served-side certificate-profile model to a mint
// (PKIGOV-002). When no default profile is configured it is a no-op (the prior
// served behavior). When a default profile is configured AND resolves for the
// tenant, it inspects the CSR through the crypto boundary (AN-3), validates the
// request against the active profile version, emits the allow/deny decision as an
// issuance.profile_evaluated event (AN-2), and returns a non-nil error on a
// violation so the mint is rejected before any signature. A configured-but-
// unresolved profile fails closed: the platform must not silently mint outside a
// declared governance model.
func (d *issuanceDispatcher) enforceProfile(ctx context.Context, tenantID string, csrDER []byte, dnsNames []string, ttl time.Duration, issuance ...*store.OperationApprovalIssuanceBinding) (crypto.LeafProfile, error) {
	if len(issuance) > 1 {
		return crypto.LeafProfile{}, errors.New("server: multiple issuance approval bindings")
	}
	var (
		rec         store.ProfileRecord
		profileName string
		err         error
	)
	if len(issuance) == 1 && issuance[0] != nil {
		binding := issuance[0]
		profileName = strings.TrimSpace(binding.ProfileName)
		if profileName == "" {
			if d.defaultProfile == "" {
				return d.leafProfile, nil
			}
			return crypto.LeafProfile{}, errors.New("server: approved issuance did not pin the configured profile revision")
		}
		if binding.ProfileID == "" || binding.ProfileVersion <= 0 || binding.ProfileSpecDigest == "" {
			return crypto.LeafProfile{}, fmt.Errorf("server: approved profile %q has no immutable revision binding", profileName)
		}
		rec, err = d.store.GetProfileVersion(ctx, tenantID, profileName, binding.ProfileVersion)
		if err != nil {
			return crypto.LeafProfile{}, fmt.Errorf("server: resolve approved profile %q version %d: %w", profileName, binding.ProfileVersion, err)
		}
		if rec.ID != binding.ProfileID || store.ProfileSpecDigest(rec.Spec) != binding.ProfileSpecDigest {
			return crypto.LeafProfile{}, fmt.Errorf("server: approved profile %q revision evidence drifted", profileName)
		}
	} else {
		profileName = d.defaultProfile
		if profileName == "" {
			return d.leafProfile, nil
		}
		rec, err = d.store.GetActiveProfile(ctx, tenantID, profileName)
		if err != nil {
			if store.IsNotFound(err) {
				// Configured profile does not resolve: deny (fail closed) and record it.
				msg := fmt.Sprintf("served default profile %q not found", profileName)
				if aerr := d.auditProfileDecision(ctx, tenantID, profileName, 0, "deny", msg); aerr != nil {
					return crypto.LeafProfile{}, aerr
				}
				return crypto.LeafProfile{}, fmt.Errorf("server: %s (fail closed)", msg)
			}
			return crypto.LeafProfile{}, err
		}
	}
	var prof profile.CertificateProfile
	if err := json.Unmarshal(rec.Spec, &prof); err != nil {
		return crypto.LeafProfile{}, fmt.Errorf("server: decode profile %q: %w", profileName, err)
	}
	info, err := crypto.InspectCSR(csrDER)
	if err != nil {
		if aerr := d.auditProfileDecision(ctx, tenantID, profileName, rec.Version, "deny", "unparseable CSR"); aerr != nil {
			return crypto.LeafProfile{}, aerr
		}
		return crypto.LeafProfile{}, fmt.Errorf("server: profile %q: unparseable CSR: %w", profileName, err)
	}
	requestedEKUs := intendedProfileEKUs(info.RequestedEKUs, prof.AllowedEKUs)
	preq := profile.Request{
		KeyAlgorithm:   info.KeyAlgorithm,
		KeyBits:        info.KeyBits,
		RequestedEKUs:  requestedEKUs,
		TTL:            ttl,
		DNSNames:       profileDNSNames(info, dnsNames),
		IPAddresses:    info.IPAddresses,
		EmailAddresses: info.EmailAddresses,
		URIs:           info.URIs,
		Protocol:       "api",
	}
	if verr := prof.Validate(preq); verr != nil {
		if aerr := d.auditProfileDecision(ctx, tenantID, profileName, rec.Version, "deny", verr.Error()); aerr != nil {
			return crypto.LeafProfile{}, aerr
		}
		return crypto.LeafProfile{}, verr
	}
	if err := d.auditProfileDecision(ctx, tenantID, profileName, rec.Version, "allow", ""); err != nil {
		return crypto.LeafProfile{}, err
	}
	return leafProfileForCertificateProfile(d.leafProfile, prof, requestedEKUs), nil
}

func approvedIssuanceTTL(bindings []*store.OperationApprovalIssuanceBinding) (time.Duration, *store.OperationApprovalIssuanceBinding, error) {
	if len(bindings) == 0 || bindings[0] == nil {
		return leafTTL, nil, nil
	}
	if len(bindings) > 1 {
		return 0, nil, errors.New("server: multiple issuance approval bindings")
	}
	binding := bindings[0]
	if binding.RequestedTTLSeconds <= 0 || binding.EffectiveTTLSeconds <= 0 ||
		binding.EffectiveTTLSeconds > binding.RequestedTTLSeconds ||
		binding.EffectiveTTLSeconds > math.MaxInt64/int64(time.Second) {
		return 0, nil, errors.New("server: approved issuance TTL binding is invalid")
	}
	return time.Duration(binding.EffectiveTTLSeconds) * time.Second, binding, nil
}

func issuanceBindingForTrigger(trigger transitionTrigger) (*store.OperationApprovalIssuanceBinding, error) {
	if trigger.Approval != nil && trigger.Issuance != nil {
		return nil, errors.New("server: lifecycle trigger has multiple issuance authority sources")
	}
	if trigger.Approval != nil {
		return trigger.Approval.Issuance, nil
	}
	return trigger.Issuance, nil
}

// auditProfileDecision emits the served profile-gated decision as an AN-2 event,
// mirroring the IssuanceService's issuance.profile_evaluated record so the served
// and library paths produce the same audit shape. A nil log is a no-op, but the
// deny (the returned error in enforceProfile) still rejects the mint.
func (d *issuanceDispatcher) auditProfileDecision(ctx context.Context, tenantID, profileName string, version int, decision, reason string) error {
	if d.log == nil {
		return nil
	}
	payload, err := json.Marshal(struct {
		Profile  string `json:"profile"`
		Version  int    `json:"version"`
		Decision string `json:"decision"`
		Reason   string `json:"reason,omitempty"`
		Protocol string `json:"protocol,omitempty"`
	}{profileName, version, decision, reason, "api"})
	if err != nil {
		return err
	}
	_, err = d.log.Append(ctx, events.Event{Type: "issuance.profile_evaluated", TenantID: tenantID, Data: payload})
	return err
}

// handleRevoke processes a revocation.publish outbox entry (the side effect of an
// *→revoked lifecycle transition): it actually invalidates the identity's issued
// certificate(s). For each active issued cert it emits a certificate.revoked
// event whose projection flips both the inventory status and the OCSP/CRL serial
// row. It is idempotent on the outbox key (AN-5): a redelivery returns the
// recorded result rather than revoking again, and the projection keeps the first
// revocation time. All access is tenant-scoped under RLS (AN-1).
//
// Note: the served binary's CA key lives in the signer (AN-4). This handler makes
// revocation real and recorded — the certificate stops validating and the serial
// is on record in ca_issued_certs — and the served OCSP responder and CRL endpoint
// (EXC-REVOKE-01, internal/server/revocation.go) then publish that revocation to
// relying parties, signing through the signer so the CA key never enters the
// control plane.
func (d *issuanceDispatcher) handleRevoke(ctx context.Context, m orchestrator.Message) error {
	var p transitionTrigger
	if err := json.Unmarshal(m.Payload, &p); err != nil {
		return fmt.Errorf("server: decode revocation.publish payload: %w", err)
	}
	if p.IdentityID == "" || p.To != string(orchestrator.StateRevoked) {
		return nil
	}
	_, err := d.idem.Do(ctx, m.TenantID, "revoke:"+m.IdempotencyKey, func(ctx context.Context) ([]byte, error) {
		ident, err := d.store.GetIdentity(ctx, m.TenantID, p.IdentityID)
		if err != nil {
			return nil, fmt.Errorf("server: load identity %s: %w", p.IdentityID, err)
		}
		certs, err := d.store.ListActiveIssuedCertificatesForIdentity(ctx, m.TenantID, ident.OwnerID, ident.Name)
		if err != nil {
			return nil, fmt.Errorf("server: find issued certs for identity %s: %w", p.IdentityID, err)
		}
		reason := p.Reason
		if reason == "" {
			reason = string(crypto.RevocationReasonUnspecified)
		}
		reasonCode := crypto.CRLReasonCode(crypto.RevocationReason(reason))
		now := time.Now()
		for _, c := range certs {
			if c.Serial == "" {
				continue
			}
			// Flip inventory and responder state through one projected event (AN-2),
			// so a Rebuild() reproduces both from the log.
			if err := d.orch.RevokeCertificateForCA(ctx, m.TenantID, c.Fingerprint, c.Serial, IssuingCAID(), reason, reasonCode, now); err != nil {
				return nil, err
			}
		}
		return []byte(fmt.Sprintf("revoked:%d", len(certs))), nil
	})
	if err != nil {
		return err
	}
	return d.publishTenantCRL(ctx, m.TenantID)
}

func (d *issuanceDispatcher) publishTenantCRL(ctx context.Context, tenantID string) error {
	if d.publishCRL == nil {
		return nil
	}
	return d.publishCRL(ctx, tenantID)
}

func (d *issuanceDispatcher) ensureTenantCRL(ctx context.Context, tenantID string) error {
	if d.ensureCRL == nil {
		return nil
	}
	return d.ensureCRL(ctx, tenantID)
}

func (d *issuanceDispatcher) transitionDeployedWithCredential(ctx context.Context, tenantID string, ident store.Identity, reason string, certPEM, keyPEM []byte, fingerprint string) error {
	connName, target := deploymentRoutingAttrs(ident.Attributes)
	targetID := deploymentTargetID(ident.Attributes)
	if target == "" {
		target = ident.Name
	}
	state, err := d.orch.State(ctx, tenantID, ident.ID)
	if err != nil {
		return err
	}
	if connName == "" || len(certPEM) == 0 || len(keyPEM) == 0 {
		if state == orchestrator.StateRenewing {
			return d.orch.Transition(ctx, tenantID, ident.ID, orchestrator.StateDeployed, reason)
		}
		return nil
	}
	deployment := connector.Deployment{Target: target, CertPEM: certPEM, KeyPEM: keyPEM, Fingerprint: fingerprint}
	var payload []byte
	if targetID != "" {
		configured, targetErr := d.store.GetDeploymentTarget(ctx, tenantID, targetID)
		if targetErr != nil {
			return fmt.Errorf("server: load deployment target %s for credential intent: %w", targetID, targetErr)
		}
		if !configured.Enabled {
			return fmt.Errorf("server: deployment target %s is disabled", targetID)
		}
		// B2: refuse rather than degrade. A target marked executor=agent must
		// never receive key bytes, and the check happens HERE because this is
		// the last moment before the payload is sealed into an outbox row and
		// an append-only event — after that the bytes are durable and the
		// event log is permanent.
		if err := enforceExecutorParity(configured.Config, keyPEM); err != nil {
			return err
		}
		connName = configured.Type
		payload, err = connector.EncodeTargetIdentityDeploy(connName, ident.ID, configured.ID, configured.RevisionID, configured.Config, deployment)
	} else {
		payload, err = connector.EncodeIdentityDeploy(connName, ident.ID, deployment)
	}
	if err != nil {
		return err
	}
	defer secret.Wipe(payload)
	switch state {
	case orchestrator.StateIssued, orchestrator.StateRenewing:
		return d.orch.TransitionWithSideEffectPayloadTransform(ctx, tenantID, ident.ID, orchestrator.StateDeployed, reason, payload, d.sealConnectorDeploySideEffect)
	case orchestrator.StateDeployed:
		return d.enqueueCredentialDeploy(ctx, tenantID, ident.ID, fingerprint, payload)
	default:
		return nil
	}
}

func (d *issuanceDispatcher) enqueueCredentialDeploy(ctx context.Context, tenantID, identityID, fingerprint string, payload []byte) error {
	if d.outbox == nil || d.store == nil || identityID == "" || fingerprint == "" {
		return nil
	}
	// Classify the claim demand from the raw payload BEFORE sealing makes the
	// connector name unreadable (epic A3) — the same classifier the transition
	// path uses, so the two enqueue routes cannot disagree about a target.
	requiredAgentRole := ""
	if d.connectorRegistry != nil {
		requiredAgentRole = connectorSideEffectRoleClassifier(d.connectorRegistry)("connector.deploy", payload)
	}
	idemKey := "credential-deploy:" + identityID + ":" + fingerprint
	sealedPayload, err := d.sealConnectorDeployBytes(ctx, tenantID, "connector.deploy", idemKey, payload)
	if err != nil {
		return err
	}
	return d.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := d.outbox.EnqueueIfAbsent(ctx, tx, orchestrator.Entry{
			TenantID:          tenantID,
			Destination:       "connector.deploy",
			IdempotencyKey:    idemKey,
			Payload:           sealedPayload,
			EffectLane:        "connector.deploy:identity:" + identityID,
			RequiredAgentRole: requiredAgentRole,
		})
		return err
	})
}

// handleDeploy processes a connector.deploy outbox entry (the side effect of an
// issued→deployed lifecycle transition, or a direct connector deployment payload).
// Every attempt records a tenant-scoped, event-sourced delivery receipt before the
// outbox row is acknowledged or retried. The receipt carries only routing evidence
// (connector, target, fingerprint, status, rollback reference), never PEM/key
// material (AN-8). When a served WASM connector plugin is configured and owns the
// named connector, the deployment is pushed through the capability sandbox. Missing
// routing, missing credentials, and declined plugins record a closed failure receipt
// and leave the row pending; configured work is never acknowledged as "unrouted".
func (d *issuanceDispatcher) handleDeploy(ctx context.Context, m orchestrator.Message) error {
	p, identityID, detail, err := d.resolveDeployPayload(ctx, m)
	if err != nil {
		return err
	}
	defer wipeConnectorDeployPayload(&p)
	p.TenantID = m.TenantID
	receipt := connectorDeliveryEvidence{
		ID:             evidenceID("connector-delivery", m.TenantID, m.IdempotencyKey, m.ID),
		OutboxID:       outboxPtr(m.ID),
		IdentityID:     identityID,
		Destination:    m.Destination,
		Connector:      nonempty(p.Connector, "unconfigured"),
		Target:         nonempty(p.Target, "unconfigured"),
		Fingerprint:    p.Fingerprint,
		Attempts:       m.Attempts,
		IdempotencyKey: m.IdempotencyKey,
		Detail:         detail,
	}
	if m.IdempotencyKey == "" {
		return d.failConnectorDelivery(ctx, m.TenantID, receipt,
			"missing_idempotency_key", "connector deployment requires a stable idempotency key",
			errors.New("server: connector.deploy requires an idempotency key"))
	}
	if p.Connector == "" {
		return d.failConnectorDelivery(ctx, m.TenantID, receipt,
			"missing_connector", "identity has no connector target configured",
			errors.New("server: connector.deploy has no configured connector"))
	}
	// E1: a family through its relay parity gate executes on a relay, and the
	// control plane must not race the relay for its work.
	//
	// The outbox claim query carries no required_agent_role predicate — that
	// column is read by ClaimAgentJobs when an agent asks for work, never by the
	// dispatcher — so without this the control plane sweeps the same pending row
	// on a one-second ticker and beats every relay to it. The A3 role stamp
	// would be correct in the column and decide nothing.
	//
	// Conditional on a relay actually being ENROLLED, and that condition is the
	// difference between a guarantee and an outage. Refusing unconditionally
	// would turn "this estate has not deployed a relay yet" into "this estate's
	// appliance deploys stopped working", and would retire the one path with
	// end-to-end proof through the served API. Refusing only when a relay exists
	// keeps the promise where it can be kept: if you run a relay, the control
	// plane will not do its work behind its back.
	//
	// DeferDelivery rather than a failure, matching connector.rollback and
	// connector.test: attempt-budget-neutral, so the row re-pends and stays
	// claimable by the relay that is supposed to run it. An aged row is already
	// reported by the ops doctor probe rather than lost silently.
	if connector.RelayMigrated(p.Connector) && d.relayPresenceSource() != nil {
		hasRelay, relayErr := d.relayPresenceSource().TenantHasNetworkRelay(ctx, m.TenantID)
		if relayErr != nil {
			// Failing the lookup must not silently hand the work back to the
			// control plane: that is the fallback direction that removes the
			// guarantee. Defer and let the next tick re-ask.
			return orchestrator.DeferDelivery(fmt.Errorf(
				"server: check network relay before %s deploy: %w", p.Connector, relayErr))
		}
		if hasRelay {
			return orchestrator.DeferDelivery(fmt.Errorf(
				"server: %s completed its relay parity gate and this tenant has a network relay "+
					"enrolled, so its deploys execute there, not in the control plane", p.Connector))
		}
	}
	if d.connectorRegistry != nil && d.connectorRegistry.Has(p.Connector) {
		if len(p.CertPEM) == 0 || len(p.KeyPEM) == 0 {
			return d.failConnectorDelivery(ctx, m.TenantID, receipt,
				"native_payload_missing_credential", "native connector payload is missing credential material",
				errors.New("server: native connector payload is missing credential material"))
		}
		if p.Fingerprint == "" {
			return d.failConnectorDelivery(ctx, m.TenantID, receipt,
				"native_payload_missing_fingerprint", "native connector payload is missing its public fingerprint",
				errors.New("server: native connector payload is missing its fingerprint"))
		}
		effect := func(ctx context.Context) ([]byte, error) {
			if derr := d.connectorRegistry.Deploy(ctx, p); derr != nil {
				return nil, d.failConnectorDelivery(ctx, m.TenantID, receipt,
					"native_delivery_failed", "served native connector reported a deployment failure", derr)
			}
			receipt.Detail = "delivered by served native connector registry"
			receipt.RollbackRef = "restore previous certificate for " + p.Target
			if err := d.recordConnectorDelivery(ctx, m.TenantID, receipt, "delivered", "native_delivered"); err != nil {
				return nil, err
			}
			if d.afterDeploySideEffects != nil {
				if err := d.afterDeploySideEffects(ctx); err != nil {
					return nil, err
				}
			}
			return []byte("deployed:" + p.Connector), nil
		}
		return d.runConnectorEffect(ctx, m, receipt, d.connectorRegistry.ReplaySafetyFor(p.Connector), effect)
	}
	if d.plugins == nil {
		return d.failConnectorDelivery(ctx, m.TenantID, receipt,
			"plugin_surface_unconfigured", "no signed connector plugin surface is configured",
			errors.New("server: signed connector plugin surface is not configured"))
	}
	if !d.plugins.Has(p.Connector) {
		return d.failConnectorDelivery(ctx, m.TenantID, receipt,
			"plugin_not_loaded", "connector is not owned by a loaded signed plugin",
			errors.New("server: connector is not owned by a loaded signed plugin"))
	}
	// A signed plugin has no enforceable receiver-side idempotency contract. Claim
	// it before I/O and never guess that replaying its mutation is harmless.
	effect := func(ctx context.Context) ([]byte, error) {
		handled, derr := d.plugins.Deploy(ctx, m.TenantID, p)
		if derr != nil {
			return nil, d.failConnectorDelivery(ctx, m.TenantID, receipt,
				"plugin_delivery_failed", "signed connector plugin reported a deployment failure", derr)
		}
		if !handled {
			return nil, d.failConnectorDelivery(ctx, m.TenantID, receipt,
				"plugin_declined", "loaded signed plugin declined the connector payload",
				errors.New("server: loaded signed plugin declined connector deployment"))
		}
		receipt.Detail = "delivered by served signed connector plugin"
		receipt.RollbackRef = "restore previous certificate for " + p.Target
		if err := d.recordConnectorDelivery(ctx, m.TenantID, receipt, "delivered", "plugin_delivered"); err != nil {
			return nil, err
		}
		if d.afterDeploySideEffects != nil {
			if err := d.afterDeploySideEffects(ctx); err != nil {
				return nil, err
			}
		}
		return []byte("deployed:" + p.Connector), nil
	}
	return d.runConnectorEffect(ctx, m, receipt, connector.ReplaySafetyAtMostOnce, effect)
}

// runConnectorEffect applies the connector's audited receiver contract. A
// replay-safe receiver may be called again after a crash; an unsafe receiver is
// claimed before I/O. For the unsafe path, an already committed delivery receipt
// is the local reconciliation point for the smaller crash-after-receipt window.
func (d *issuanceDispatcher) runConnectorEffect(ctx context.Context, m orchestrator.Message, receipt connectorDeliveryEvidence, safety connector.ReplaySafety, effect func(context.Context) ([]byte, error)) error {
	key := "deploy:" + m.IdempotencyKey
	if safety == connector.ReplaySafetyReconciled {
		_, err := d.idem.DoDurableEffect(ctx, m.TenantID, key, effect)
		return err
	}
	delivered, err := d.hasCommittedConnectorDelivery(ctx, m.TenantID, receipt)
	if err != nil {
		return err
	}
	if delivered {
		return nil
	}
	_, err = d.idem.DoAtMostOnceEffect(ctx, m.TenantID, key, effect)
	return err
}

func (d *issuanceDispatcher) failConnectorDelivery(ctx context.Context, tenantID string, receipt connectorDeliveryEvidence, reason, detail string, cause error) error {
	receipt.Detail = detail
	receipt.RollbackRef = ""
	recordErr := d.recordConnectorDelivery(ctx, tenantID, receipt, "failed", reason)
	if recordErr != nil {
		return errors.Join(cause, fmt.Errorf("server: record connector delivery failure: %w", recordErr))
	}
	return cause
}

// hasCommittedConnectorDelivery accepts only the deterministic receipt for this
// exact outbox effect. A collision or altered binding fails closed instead of
// treating some other delivery as proof that this credential reached its target.
func (d *issuanceDispatcher) hasCommittedConnectorDelivery(ctx context.Context, tenantID string, want connectorDeliveryEvidence) (bool, error) {
	if d.store == nil {
		return false, nil
	}
	got, err := d.store.GetConnectorDeliveryReceipt(ctx, tenantID, want.ID)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("server: reconcile connector delivery receipt: %w", err)
	}
	if got.Status != "delivered" {
		return false, nil
	}
	if !sameOutboxID(got.OutboxID, want.OutboxID) ||
		got.Destination != want.Destination ||
		got.IdempotencyKey != want.IdempotencyKey ||
		got.Connector != want.Connector ||
		got.Target != want.Target ||
		got.Fingerprint != want.Fingerprint {
		return false, fmt.Errorf("server: connector delivery receipt %s does not match its outbox binding", want.ID)
	}
	return true, nil
}

func sameOutboxID(a, b *int64) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

type connectorDeliveryEvidence struct {
	ID             string
	OutboxID       *int64
	IdentityID     *string
	Destination    string
	Connector      string
	Target         string
	Fingerprint    string
	Attempts       int
	Reason         string
	Detail         string
	RollbackRef    string
	IdempotencyKey string
}

type rotationRunEvidence struct {
	ID                     string
	IdentityID             string
	OutboxID               *int64
	Trigger                string
	Reason                 string
	PredecessorFingerprint string
	SuccessorFingerprint   string
	RollbackRef            string
	IdempotencyKey         string
}

func (d *issuanceDispatcher) resolveDeployPayload(ctx context.Context, m orchestrator.Message) (connector.DeployPayload, *string, string, error) {
	if p, identityID, detail, sealed, err := d.openSealedConnectorDeployPayload(ctx, m); sealed || err != nil {
		p.TenantID = m.TenantID
		return p, identityID, detail, err
	}
	var p connector.DeployPayload
	if err := json.Unmarshal(m.Payload, &p); err == nil && (p.Connector != "" || p.Target != "" || p.Fingerprint != "" || len(p.CertPEM) > 0 || len(p.KeyPEM) > 0) {
		p.TenantID = m.TenantID
		var identityID *string
		if id := strings.TrimSpace(p.IdentityID); id != "" {
			identityID = &id
		}
		return p, identityID, "direct connector deploy payload", nil
	}
	var trig transitionTrigger
	if err := json.Unmarshal(m.Payload, &trig); err != nil {
		return connector.DeployPayload{}, nil, "", fmt.Errorf("server: decode connector.deploy payload: %w", err)
	}
	if trig.IdentityID == "" {
		return connector.DeployPayload{}, nil, "connector.deploy payload did not name an identity", nil
	}
	ident, err := d.store.GetIdentity(ctx, m.TenantID, trig.IdentityID)
	if err != nil {
		return connector.DeployPayload{}, nil, "", fmt.Errorf("server: load identity %s for deploy receipt: %w", trig.IdentityID, err)
	}
	connName, target := deploymentRoutingAttrs(ident.Attributes)
	targetID := deploymentTargetID(ident.Attributes)
	p.Connector = connName
	p.Target = nonempty(target, ident.Name)
	p.TargetID = targetID
	p.TenantID = m.TenantID
	if targetID != "" {
		configured, targetErr := d.store.GetDeploymentTarget(ctx, m.TenantID, targetID)
		if targetErr != nil {
			return connector.DeployPayload{}, nil, "", fmt.Errorf("server: load deployment target %s for deploy receipt: %w", targetID, targetErr)
		}
		p.Connector = configured.Type
		p.TargetRevision = configured.RevisionID
		p.TargetConfig = append(json.RawMessage(nil), configured.Config...)
	}
	certs, err := d.store.ListActiveIssuedCertificatesForIdentity(ctx, m.TenantID, ident.OwnerID, ident.Name)
	if err != nil {
		return connector.DeployPayload{}, nil, "", fmt.Errorf("server: load active certificate for deploy receipt %s: %w", trig.IdentityID, err)
	}
	if len(certs) > 0 {
		p.Fingerprint = certs[len(certs)-1].Fingerprint
	}
	identityID := trig.IdentityID
	return p, &identityID, "lifecycle transition deploy payload", nil
}

func (d *issuanceDispatcher) sealConnectorDeploySideEffect(ctx context.Context, payloadCtx orchestrator.SideEffectPayloadContext) ([]byte, error) {
	if payloadCtx.Destination != "connector.deploy" {
		return payloadCtx.Payload, nil
	}
	return d.sealConnectorDeployBytes(ctx, payloadCtx.TenantID, payloadCtx.Destination, payloadCtx.IdempotencyKey, payloadCtx.Payload)
}

func (d *issuanceDispatcher) sealConnectorDeployBytes(ctx context.Context, tenantID, destination, idempotencyKey string, payload []byte) ([]byte, error) {
	var p connector.DeployPayload
	if err := json.Unmarshal(payload, &p); err != nil {
		return nil, fmt.Errorf("server: decode connector deploy payload for sealing: %w", err)
	}
	defer secret.Wipe(p.KeyPEM)
	if len(p.KeyPEM) == 0 {
		return payload, nil
	}
	if d.connectorPayloadKey == nil {
		return nil, errors.New("server: connector.deploy outbox requires a credential KEK")
	}
	identityID := strings.TrimSpace(p.IdentityID)
	fingerprint := strings.TrimSpace(p.Fingerprint)
	sealed, err := sealTenantValue(ctx, d.tenantCrypto, d.connectorPayloadKey, tenantID, payload, connectorDeployAAD(tenantID, destination, idempotencyKey, identityID, fingerprint))
	if err != nil {
		return nil, fmt.Errorf("server: seal connector deploy payload: %w", err)
	}
	out, err := json.Marshal(sealedConnectorDeployPayload{
		Format:       connectorDeploySealedFormat,
		Version:      connectorDeploySealedVersion,
		IdentityID:   identityID,
		Fingerprint:  fingerprint,
		Sealed:       sealed,
		Connector:    p.Connector,
		Target:       p.Target,
		TargetID:     p.TargetID,
		Revision:     p.TargetRevision,
		TargetConfig: append(json.RawMessage(nil), p.TargetConfig...),
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (d *issuanceDispatcher) openSealedConnectorDeployPayload(ctx context.Context, m orchestrator.Message) (connector.DeployPayload, *string, string, bool, error) {
	var wrapped sealedConnectorDeployPayload
	if err := json.Unmarshal(m.Payload, &wrapped); err != nil || wrapped.Format == "" {
		return connector.DeployPayload{}, nil, "", false, nil
	}
	if wrapped.Format != connectorDeploySealedFormat {
		return connector.DeployPayload{}, nil, "", false, nil
	}
	if wrapped.Version != connectorDeploySealedVersion || len(wrapped.Sealed) == 0 {
		return connector.DeployPayload{}, nil, "", true, fmt.Errorf("server: unsupported sealed connector deploy payload")
	}
	if d.connectorPayloadKey == nil {
		return connector.DeployPayload{}, nil, "", true, errors.New("server: sealed connector.deploy outbox requires a credential KEK")
	}
	identityIDValue := strings.TrimSpace(wrapped.IdentityID)
	fingerprintValue := strings.TrimSpace(wrapped.Fingerprint)
	plaintext, err := openTenantValue(ctx, d.tenantCrypto, d.connectorPayloadKey, m.TenantID, wrapped.Sealed, connectorDeployAAD(m.TenantID, m.Destination, m.IdempotencyKey, identityIDValue, fingerprintValue))
	if err != nil {
		return connector.DeployPayload{}, nil, "", true, fmt.Errorf("server: open sealed connector deploy payload: %w", err)
	}
	defer secret.Wipe(plaintext)
	var p connector.DeployPayload
	if err := json.Unmarshal(plaintext, &p); err != nil {
		return connector.DeployPayload{}, nil, "", true, fmt.Errorf("server: decode sealed connector deploy payload: %w", err)
	}
	if strings.TrimSpace(p.IdentityID) != identityIDValue || strings.TrimSpace(p.Fingerprint) != fingerprintValue {
		wipeConnectorDeployPayload(&p)
		return connector.DeployPayload{}, nil, "", true, errors.New("server: sealed connector deploy payload metadata mismatch")
	}
	var identityID *string
	if identityIDValue != "" {
		identityID = &identityIDValue
	}
	return p, identityID, "sealed connector deploy payload", true, nil
}

func connectorDeployAAD(tenantID, destination, idempotencyKey, identityID, fingerprint string) []byte {
	return []byte(strings.Join([]string{
		"connector-deploy-v1",
		strings.TrimSpace(tenantID),
		strings.TrimSpace(destination),
		strings.TrimSpace(idempotencyKey),
		strings.TrimSpace(identityID),
		strings.TrimSpace(fingerprint),
	}, "\x00"))
}

func wipeConnectorDeployPayload(p *connector.DeployPayload) {
	if p == nil {
		return
	}
	secret.Wipe(p.KeyPEM)
}

func deploymentRoutingAttrs(raw json.RawMessage) (string, string) {
	if len(raw) == 0 {
		return "", ""
	}
	var attrs map[string]any
	if err := json.Unmarshal(raw, &attrs); err != nil {
		return "", ""
	}
	connectorName := firstStringAttr(attrs, "connector", "deployment_connector", "connector_name")
	target := firstStringAttr(attrs, "deployment_route", "target", "deployment_target", "deployment_target_id", "deployment_location")
	return connectorName, target
}

func deploymentTargetID(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var attrs map[string]any
	if err := json.Unmarshal(raw, &attrs); err != nil {
		return ""
	}
	return firstStringAttr(attrs, "deployment_target_id")
}

func firstStringAttr(attrs map[string]any, keys ...string) string {
	for _, key := range keys {
		if v, ok := attrs[key]; ok {
			if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
				return strings.TrimSpace(s)
			}
		}
	}
	return ""
}

func (d *issuanceDispatcher) recordConnectorDelivery(ctx context.Context, tenantID string, r connectorDeliveryEvidence, status, reason string) error {
	if d.log == nil || d.store == nil {
		return nil
	}
	if r.Destination == "" {
		r.Destination = "connector.deploy"
	}
	if r.ID == "" {
		r.ID = evidenceID("connector-delivery", tenantID, r.IdempotencyKey, 0)
	}
	payload := projections.ConnectorDeliveryRecorded{
		ID: r.ID, OutboxID: r.OutboxID, IdentityID: r.IdentityID, Destination: r.Destination,
		Connector: r.Connector, Target: r.Target, Fingerprint: r.Fingerprint, Status: status,
		Attempts: r.Attempts, Reason: reason, Detail: r.Detail, RollbackRef: r.RollbackRef,
		IdempotencyKey: r.IdempotencyKey,
	}
	return d.appendProjected(ctx, tenantID, projections.EventConnectorDeliveryRecorded, payload)
}

func (d *issuanceDispatcher) recordRotationRun(ctx context.Context, tenantID string, r rotationRunEvidence, status, msg string) error {
	if d.log == nil || d.store == nil {
		return nil
	}
	if r.ID == "" {
		r.ID = evidenceID("rotation", tenantID, r.IdempotencyKey, 0)
	}
	var completedAt *time.Time
	if status == "succeeded" || status == "failed" {
		now := time.Now().UTC()
		completedAt = &now
	}
	payload := projections.LifecycleRotationRecorded{
		ID: r.ID, IdentityID: r.IdentityID, OutboxID: r.OutboxID, Status: status,
		Trigger: r.Trigger, Reason: r.Reason, PredecessorFingerprint: r.PredecessorFingerprint,
		SuccessorFingerprint: r.SuccessorFingerprint, RollbackRef: r.RollbackRef, Error: msg,
		IdempotencyKey: r.IdempotencyKey, CompletedAt: completedAt,
	}
	return d.appendProjected(ctx, tenantID, projections.EventLifecycleRotationRecorded, payload)
}

func (d *issuanceDispatcher) appendProjected(ctx context.Context, tenantID, eventType string, payload any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	ev, err := d.log.Append(ctx, events.Event{Type: eventType, TenantID: tenantID, Data: data})
	if err != nil {
		return err
	}
	return projections.New(d.store).Apply(ctx, ev)
}

func evidenceID(kind, tenantID, idempotencyKey string, outboxID int64) string {
	key := fmt.Sprintf("%s:%s:%s:%d", kind, tenantID, idempotencyKey, outboxID)
	return uuid.NewSHA1(evidenceNamespace, []byte(key)).String()
}

func outboxPtr(id int64) *int64 {
	if id == 0 {
		return nil
	}
	return &id
}

func renewalCertificatesForTrigger(certs []store.Certificate, trigger transitionTrigger) ([]store.Certificate, error) {
	if trigger.Origin != lifecycleTransitionOriginScheduler {
		return certs, nil
	}
	if trigger.PredecessorFingerprint == "" {
		return nil, fmt.Errorf("server: structured scheduler renewal is missing its selected predecessor for identity %s", trigger.IdentityID)
	}
	for _, cert := range certs {
		if cert.Fingerprint == trigger.PredecessorFingerprint {
			return []store.Certificate{cert}, nil
		}
	}
	return nil, fmt.Errorf(
		"server: scheduler-selected predecessor %s is no longer active for identity %s",
		trigger.PredecessorFingerprint,
		trigger.IdentityID,
	)
}

func rotationTrigger(origin, idempotencyKey, reason string) string {
	if origin == lifecycleTransitionOriginScheduler {
		return "scheduler"
	}
	if origin != "" || strings.HasPrefix(idempotencyKey, "transition:") || !isEventNUID(idempotencyKey) {
		return "manual"
	}
	if strings.HasPrefix(reason, lifecycleARIRenewalReasonPrefix) ||
		strings.HasPrefix(reason, lifecycleFixedRenewalReasonPrefix) {
		return "scheduler"
	}
	return "manual"
}

func isEventNUID(value string) bool {
	if len(value) != 22 {
		return false
	}
	for _, r := range value {
		if (r < '0' || r > '9') && (r < 'A' || r > 'Z') && (r < 'a' || r > 'z') {
			return false
		}
	}
	return true
}

func nonempty(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}

// sansOf collects the subject alternative names from a parsed certificate.
func sansOf(info certinfo.Info) []string {
	sans := make([]string, 0, len(info.DNSNames)+len(info.IPAddresses)+len(info.EmailAddresses)+len(info.URIs))
	sans = append(sans, info.DNSNames...)
	sans = append(sans, info.IPAddresses...)
	sans = append(sans, info.EmailAddresses...)
	sans = append(sans, info.URIs...)
	return sans
}

// CSR-first issuance (epic B1).
//
// The direct identity API had no CSR input at all: transitioning an identity to
// issued made the control plane generate the subject key, sign for it, and hand
// the key onward. That is a custody claim nobody wants to defend — "your private
// key was created in our process" — and it is the reason the served surface could
// not say private keys never reach the control plane.
//
// A caller who supplies their own PKCS#10 request gets the other shape: we sign
// what they made and never see a key. Both paths still enforce the same profile
// gate before signing, because whose key it is does not change what the
// certificate is allowed to say.

// mintServedLeafForTrigger signs the caller's CSR when the transition carries
// one, and otherwise falls back to generating the subject key. The fallback
// records a deprecation event each time it is used, so an operator can see which
// of their flows still hand key generation to the control plane before the path
// is removed.
func (d *issuanceDispatcher) mintServedLeafForTrigger(ctx context.Context, tenantID string, ident store.Identity, p transitionTrigger) (issuedLeafMaterial, error) {
	binding, err := issuanceBindingForTrigger(p)
	if err != nil {
		return issuedLeafMaterial{}, err
	}
	// A CSR on the transition wins: it is the most specific statement of intent
	// for this particular issuance.
	if csr := strings.TrimSpace(p.SubjectCSRPEM); csr != "" {
		return d.mintServedLeafFromCSR(ctx, tenantID, ident, []byte(csr), binding)
	}
	// Otherwise the request's own CSR, recorded when the identity was created.
	// The CSR belongs to the requester, not to whoever approves them: an approver
	// pressing "approve" should not have to re-supply key material they never had.
	if csr := subjectCSRFromIdentity(ident); csr != "" {
		return d.mintServedLeafFromCSR(ctx, tenantID, ident, []byte(csr), binding)
	}
	d.recordServerSideKeygenDeprecation(ctx, tenantID, ident)
	return d.mintServedLeafMaterial(ctx, tenantID, ident.OwnerID, ident.Name, []string{ident.Name}, binding)
}

// mintServedLeafForRenewal mints a renewal leaf, honouring a recorded CSR.
//
// Separate from mintServedLeafForTrigger because a renewal has no transition
// CSR to prefer — the scheduler queued it, not a requester — and because the
// subject and SAN set come from the certificate being REPLACED rather than from
// the identity name. Renewing a certificate for a different name set than the
// one it is replacing would be a reissue wearing a renewal's clothes.
//
// A CSR recorded on the identity means the requester holds the key, and they
// still hold it: nothing about a renewal transfers custody. Falling back to
// control-plane keygen for such an identity is what this exists to prevent.
func (d *issuanceDispatcher) mintServedLeafForRenewal(
	ctx context.Context, tenantID string, ident store.Identity, commonName string, dnsNames []string,
) (issuedLeafMaterial, error) {
	if csr := subjectCSRFromIdentity(ident); csr != "" {
		// The recorded CSR fixes the public key; its own subject and SANs are
		// re-validated against the profile inside mintServedLeafFromCSR, so a
		// stale CSR cannot widen what the renewal asserts.
		return d.mintServedLeafFromCSR(ctx, tenantID, ident, []byte(csr))
	}
	// No CSR on record: this identity's key has always been control-plane
	// generated, so a renewal that generates one changes nothing about its
	// custody. It is still worth announcing, for the same reason the issue path
	// announces it.
	d.recordServerSideKeygenDeprecation(ctx, tenantID, ident)
	return d.mintServedLeafMaterial(ctx, tenantID, ident.OwnerID, commonName, dnsNames)
}

// subjectCSRFromIdentity reads the CSR a requester attached when they created the
// request. Attributes are free-form, so read defensively: a malformed attribute
// block means no CSR, not a failed issuance.
func subjectCSRFromIdentity(ident store.Identity) string {
	if len(ident.Attributes) == 0 {
		return ""
	}
	var attrs map[string]any
	if err := json.Unmarshal(ident.Attributes, &attrs); err != nil {
		return ""
	}
	csr, _ := attrs["subject_csr_pem"].(string)
	return strings.TrimSpace(csr)
}

// mintServedLeafFromCSR signs a caller-supplied request. It returns no KeyPEM,
// because there is no key here to return — which is the point. The connector
// deploy path degrades to certificate-only for this identity, since the material
// it would need is on the caller's side; host-executed renewal (epic B2) is what
// closes that loop properly.
func (d *issuanceDispatcher) mintServedLeafFromCSR(ctx context.Context, tenantID string, ident store.Identity, csrPEM []byte, issuance ...*store.OperationApprovalIssuanceBinding) (issuedLeafMaterial, error) {
	if d.issue == nil {
		return issuedLeafMaterial{}, errors.New("server: issuing CA is unavailable")
	}
	csrDER, dnsNames, err := decodeSubjectCSR(csrPEM)
	if err != nil {
		return issuedLeafMaterial{}, err
	}
	if len(dnsNames) == 0 {
		dnsNames = []string{ident.Name}
	}
	// Same profile gate as the server-keygen path: the origin of the key does not
	// change what the certificate may assert, and skipping it here would make
	// "bring your own CSR" a way around policy.
	ttl, binding, err := approvedIssuanceTTL(issuance)
	if err != nil {
		return issuedLeafMaterial{}, err
	}
	leafProfile, err := d.enforceProfile(ctx, tenantID, csrDER, dnsNames, ttl, binding)
	if err != nil {
		return issuedLeafMaterial{}, err
	}
	leafPEM, err := d.issue(ctx, csrDER, ttl, leafProfile)
	if err != nil {
		return issuedLeafMaterial{}, err
	}
	blk, _ := pem.Decode(leafPEM)
	if blk == nil {
		return issuedLeafMaterial{}, errors.New("server: issued certificate is not PEM")
	}
	info, err := certinfo.Inspect(blk.Bytes)
	if err != nil {
		return issuedLeafMaterial{}, err
	}
	var ownerPtr *string
	if ownerID := strings.TrimSpace(ident.OwnerID); ownerID != "" {
		owner := ownerID
		ownerPtr = &owner
	}
	nb, na := info.NotBefore, info.NotAfter
	return issuedLeafMaterial{
		Certificate: store.Certificate{
			CAID: IssuingCAID(), OwnerID: ownerPtr, Subject: info.Subject, SANs: sansOf(info),
			Issuer: info.Issuer, Serial: info.SerialNumber, Fingerprint: info.SHA256Fingerprint,
			KeyAlgorithm: info.KeyAlgorithm, NotBefore: &nb, NotAfter: &na,
			Source: "issued", CertificateDER: append([]byte(nil), blk.Bytes...),
			// B5: the requester generated this key and the control plane never
			// held it. That is a fact about THIS certificate, recorded from what
			// the code did rather than from what the documentation says the
			// system does — which is the difference an auditor is asking about.
			KeyOrigin: string(custody.OriginRequester),
		},
		CertPEM: append([]byte(nil), leafPEM...),
		// The material field is left zero on purpose: the subject key was never
		// here, so there is nothing to return, wipe, or leak.
	}, nil
}

// recordServerSideKeygenDeprecation appends an audit event naming the identity
// that used the legacy path. It is deliberately best-effort: failing to record
// the deprecation must not fail the issuance an operator is relying on today.
func (d *issuanceDispatcher) recordServerSideKeygenDeprecation(ctx context.Context, tenantID string, ident store.Identity) {
	if d.log == nil {
		return
	}
	body, err := json.Marshal(struct {
		IdentityID string `json:"identity_id"`
		Name       string `json:"name"`
		Detail     string `json:"detail"`
		Successor  string `json:"successor"`
	}{
		IdentityID: ident.ID, Name: ident.Name,
		Detail:    "the control plane generated this identity's subject key because the issuance carried no CSR; this path is deprecated",
		Successor: "supply subject_csr_pem on the transition to issued so the key is generated where it will be used",
	})
	if err != nil {
		return
	}
	_, _ = d.log.Append(ctx, events.Event{Type: "issuance.server_side_keygen", TenantID: tenantID, Data: body})
}

// decodeSubjectCSR turns a caller-supplied PKCS#10 request into DER plus the
// names it asks for, verifying the request's self-signature through the crypto
// boundary (AN-3) before anything downstream trusts it.
//
// Rejecting here rather than at the signer is deliberate: a malformed or
// unsigned CSR is a caller mistake, and it should come back as one instead of
// surfacing as an opaque signing failure later in the outbox.
func decodeSubjectCSR(csrPEM []byte) (der []byte, dnsNames []string, err error) {
	blk, _ := pem.Decode(csrPEM)
	if blk == nil {
		return nil, nil, errors.New("server: subject CSR is not PEM")
	}
	if blk.Type != "CERTIFICATE REQUEST" && blk.Type != "NEW CERTIFICATE REQUEST" {
		return nil, nil, fmt.Errorf("server: subject CSR PEM block is %q, want CERTIFICATE REQUEST", blk.Type)
	}
	info, err := crypto.InspectCSR(blk.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("server: subject CSR is not a valid, self-signed PKCS#10 request: %w", err)
	}
	names := append([]string(nil), info.DNSNames...)
	if len(names) == 0 && strings.TrimSpace(info.CommonName) != "" {
		names = []string{info.CommonName}
	}
	return append([]byte(nil), blk.Bytes...), names, nil
}

// relayPresence answers whether a tenant runs a network relay (epic E1).
//
// An interface with a test seam rather than a direct store call, because the
// property worth testing is the DECISION — refuse when a relay exists, execute
// when none does, defer when the answer is unknown — and a test that had to
// stand up PostgreSQL to exercise three branches would end up exercising one.
type relayPresence interface {
	TenantHasNetworkRelay(ctx context.Context, tenantID string) (bool, error)
}

// relayPresenceSource prefers an injected seam and falls back to the store.
func (d *issuanceDispatcher) relayPresenceSource() relayPresence {
	if d.relayPresence != nil {
		return d.relayPresence
	}
	if d.store != nil {
		return d.store
	}
	return nil
}
