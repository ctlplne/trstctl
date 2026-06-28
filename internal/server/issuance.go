package server

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/profile"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/usage"
)

// leafTTL is the validity of a certificate issued by the assembled CA. It is
// comfortably within the issuing CA's own validity so the leaf never outlives it.
const leafTTL = 30 * 24 * time.Hour

// caNamespace is the fixed UUIDv5 namespace under which the served binary's
// stable CA handles are turned into the ca_id used by the revocation tables. It
// never changes, so a CA's ca_id is the same across restarts and the
// issued/revoked records for it line up over time.
var caNamespace = uuid.MustParse("8f6a0c1e-4d2b-5a3c-9e7f-1b2c3d4e5f60")
var evidenceNamespace = uuid.MustParse("d3f1677d-2e53-5d77-9c7f-8895a74f5c31")

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

// issuanceDispatcher is the real outbox handler (AN-6). For a requested→issued
// lifecycle transition it mints a leaf certificate from the assembled CA (whose
// key lives in the out-of-process signer, AN-4) and records it in the inventory
// as an event (AN-2); for an *→revoked transition it revokes that leaf so the
// certificate stops validating. The same projected events also rebuild the
// ca_issued_certs responder table, so inventory and OCSP/CRL state share one
// source of truth. It is idempotent on
// the outbox message's key (AN-5), so a redelivery never mints a second
// certificate nor double-revokes.
type issuanceDispatcher struct {
	issue       issueFunc
	issueHybrid issueFunc
	orch        *orchestrator.Orchestrator
	idem        *orchestrator.Idempotency
	outbox      *orchestrator.Outbox
	store       *store.Store

	// log is the event log used to emit the profile-gated issuance decision
	// (issuance.profile_evaluated) on the served mint (PKIGOV-002); nil disables the
	// audit emit but the deny still rejects.
	log *events.Log
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
	// (SUPPLY-004) is pushed through the capability sandbox; otherwise the entry is
	// acknowledged unrouted as before. Tenant-scoped (AN-1) and event-sourced
	// (AN-2); the plugin holds no store/signer handle.
	plugins *PluginManager
	// connectorRegistry is the trusted native deployment connector registry
	// (CLM-05/F7/F27). When a connector.deploy payload names a registered native
	// connector and carries the credential bytes, the served outbox worker performs
	// the real deploy through the connector SDK sandbox and records a durable receipt.
	connectorRegistry *connector.Registry
	// externalCAs owns external-ca.issue rows. Provider-backed issuance is routed
	// through this registry so upstream CA side effects happen from the outbox
	// worker, not the request handler.
	externalCAs *externalCARegistry
	// notifications fans notification.* outbox rows to operator-configured channels
	// (NOTIF-01/F29). Nil preserves the prior no-channel behavior.
	notifications *notify.Dispatcher
	// transparency handles transparency.* outbox rows such as Rekor publication for
	// served code signing (CLM-06/F50). Nil leaves rows acknowledged-unrouted, matching
	// the generic external-destination posture.
	transparency orchestrator.Handler

	// nil in production; tests use it to inject a crash-equivalent error after
	// signer/event side effects but before the idempotency result is completed.
	afterIssueSideEffects func(context.Context) error
}

// Deliver implements orchestrator.Handler. It mints on a ca.issue trigger,
// renews on a ca.renew trigger, revokes on a revocation.publish trigger, and
// pushes a connector.deploy through a served WASM connector plugin when one owns
// the named connector (ARCH-007). Unknown CA/revocation first-party destinations
// fail closed so the outbox never marks a lifecycle side effect delivered without
// doing real work.
func (d *issuanceDispatcher) Deliver(ctx context.Context, m orchestrator.Message) error {
	switch m.Destination {
	case "ca.issue":
		return d.handleIssue(ctx, m)
	case "ca.renew":
		return d.handleRenew(ctx, m)
	case "revocation.publish":
		return d.handleRevoke(ctx, m)
	case "connector.deploy":
		return d.handleDeploy(ctx, m)
	case "discovery.run":
		return d.handleDiscoveryRun(ctx, m)
	case ca.DestinationExternalCAIssue:
		if d.externalCAs == nil {
			return fmt.Errorf("server: external CA outbox destination is not configured")
		}
		return d.externalCAs.DeliverExternalCAIssue(ctx, m)
	case orchestrator.DestinationITSMServiceNow:
		return d.handleServiceNowTicket(ctx, m)
	case pqcMigrationReissueDestination:
		return d.handlePQCReissue(ctx, m)
	case pqcMigrationRollbackDestination:
		return d.handlePQCRollback(ctx, m)
	default:
		if strings.HasPrefix(m.Destination, "notification.") {
			if d.notifications == nil {
				return nil
			}
			return d.notifications.Dispatch(ctx, m.Payload)
		}
		if strings.HasPrefix(m.Destination, "transparency.") {
			if d.transparency == nil {
				return nil
			}
			return d.transparency.Deliver(ctx, m)
		}
		if strings.HasPrefix(m.Destination, "ca.") || strings.HasPrefix(m.Destination, "external-ca.") || strings.HasPrefix(m.Destination, "revocation.") || strings.HasPrefix(m.Destination, "discovery.") || strings.HasPrefix(m.Destination, "itsm.") {
			return fmt.Errorf("server: unsupported first-party outbox destination %q", m.Destination)
		}
		return nil
	}
}

// transitionTrigger is the part of a lifecycle transition payload the issuance
// and revocation handlers need (the same JSON the orchestrator enqueues on the
// outbox entry).
type transitionTrigger struct {
	IdentityID string `json:"identity_id"`
	To         string `json:"to"`
	Reason     string `json:"reason"`
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
		cert, err := d.mintServedLeaf(ctx, m.TenantID, ident.OwnerID, ident.Name, []string{ident.Name})
		if err != nil {
			return nil, err
		}
		cert.IssuanceIdempotencyKey = idemKey
		recorded, err := d.orch.RecordCertificate(ctx, m.TenantID, cert)
		if err != nil {
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
	if d.issue == nil {
		return store.Certificate{}, errors.New("server: issuing CA is unavailable")
	}
	if len(dnsNames) == 0 {
		dnsNames = []string{commonName}
	}
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		return store.Certificate{}, err
	}
	defer key.Destroy()
	csrDER, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: commonName, DNSNames: dnsNames}, key)
	if err != nil {
		return store.Certificate{}, err
	}
	// Enforce the certificate-profile model on the served mint (PKIGOV-002):
	// when a default profile is configured and resolves for the tenant, validate
	// this request against it BEFORE signing and emit the allow/deny decision as
	// an issuance.profile_evaluated event. A violation rejects (fail closed) so an
	// out-of-profile certificate is never minted on the served path.
	leafProfile, err := d.enforceProfile(ctx, tenantID, csrDER, dnsNames, leafTTL)
	if err != nil {
		return store.Certificate{}, err
	}
	leafPEM, err := d.issue(ctx, csrDER, leafTTL, leafProfile)
	if err != nil {
		return store.Certificate{}, err
	}
	blk, _ := pem.Decode(leafPEM)
	if blk == nil {
		return store.Certificate{}, errors.New("server: issued certificate is not PEM")
	}
	info, err := certinfo.Inspect(blk.Bytes)
	if err != nil {
		return store.Certificate{}, err
	}
	var ownerPtr *string
	if ownerID = strings.TrimSpace(ownerID); ownerID != "" {
		owner := ownerID
		ownerPtr = &owner
	}
	nb, na := info.NotBefore, info.NotAfter
	return store.Certificate{
		CAID: IssuingCAID(), OwnerID: ownerPtr, Subject: info.Subject, SANs: sansOf(info),
		Issuer: info.Issuer, Serial: info.SerialNumber, Fingerprint: info.SHA256Fingerprint,
		KeyAlgorithm: info.KeyAlgorithm, NotBefore: &nb, NotAfter: &na,
		Source: "issued", CertificateDER: append([]byte(nil), blk.Bytes...),
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
			ID:             evidenceID("rotation", m.TenantID, m.IdempotencyKey, m.ID),
			IdentityID:     p.IdentityID,
			OutboxID:       outboxPtr(m.ID),
			Trigger:        rotationTrigger(p.Reason),
			Reason:         p.Reason,
			IdempotencyKey: m.IdempotencyKey,
		}
		if err := d.recordRotationRun(ctx, m.TenantID, run, "running", ""); err != nil {
			return nil, err
		}
		recovered, err := recoverCertificatesByIssuanceKey(ctx, d.store, d.log, m.TenantID, idemKey)
		if err != nil {
			_ = d.recordRotationRun(ctx, m.TenantID, run, "failed", err.Error())
			return nil, err
		}
		if len(recovered) > 0 {
			if err := d.completeRecoveredRenewal(ctx, m.TenantID, p.IdentityID, p.Reason); err != nil {
				_ = d.recordRotationRun(ctx, m.TenantID, run, "failed", err.Error())
				return nil, fmt.Errorf("server: complete recovered renewal transition: %w", err)
			}
			run.SuccessorFingerprint = recovered[len(recovered)-1].Fingerprint
			if err := d.recordRotationRun(ctx, m.TenantID, run, "succeeded", ""); err != nil {
				return nil, err
			}
			return []byte(fmt.Sprintf("renewed:%d", len(recovered))), nil
		}
		ident, err := d.store.GetIdentity(ctx, m.TenantID, p.IdentityID)
		if err != nil {
			_ = d.recordRotationRun(ctx, m.TenantID, run, "failed", err.Error())
			return nil, fmt.Errorf("server: load identity %s: %w", p.IdentityID, err)
		}
		certs, err := d.store.ListActiveIssuedCertificatesForIdentity(ctx, m.TenantID, ident.OwnerID, ident.Name)
		if err != nil {
			_ = d.recordRotationRun(ctx, m.TenantID, run, "failed", err.Error())
			return nil, fmt.Errorf("server: find issued certs for identity %s: %w", p.IdentityID, err)
		}
		if len(certs) == 0 {
			err := fmt.Errorf("server: no active issued certificate to renew for identity %s", p.IdentityID)
			_ = d.recordRotationRun(ctx, m.TenantID, run, "failed", err.Error())
			return nil, err
		}
		for _, old := range certs {
			if run.PredecessorFingerprint == "" {
				run.PredecessorFingerprint = old.Fingerprint
			}
			dnsNames := old.SANs
			if len(dnsNames) == 0 {
				dnsNames = []string{ident.Name}
			}
			commonName := ident.Name
			if len(dnsNames) > 0 {
				commonName = dnsNames[0]
			}
			successor, err := d.mintServedLeaf(ctx, m.TenantID, ident.OwnerID, commonName, dnsNames)
			if err != nil {
				_ = d.recordRotationRun(ctx, m.TenantID, run, "failed", err.Error())
				return nil, err
			}
			successor.IssuanceIdempotencyKey = idemKey
			recorded, err := d.orch.RecordSuccessorCertificate(ctx, m.TenantID, successor, old.ID)
			if err != nil {
				_ = d.recordRotationRun(ctx, m.TenantID, run, "failed", err.Error())
				return nil, fmt.Errorf("server: record renewal successor: %w", err)
			}
			run.SuccessorFingerprint = recorded.Fingerprint
		}
		reason := p.Reason
		if reason == "" {
			reason = "renewal completed"
		}
		if err := d.orch.Transition(ctx, m.TenantID, p.IdentityID, orchestrator.StateDeployed, reason); err != nil {
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
func (d *issuanceDispatcher) enforceProfile(ctx context.Context, tenantID string, csrDER []byte, dnsNames []string, ttl time.Duration) (crypto.LeafProfile, error) {
	if d.defaultProfile == "" {
		return d.leafProfile, nil
	}
	rec, err := d.store.GetActiveProfile(ctx, tenantID, d.defaultProfile)
	if err != nil {
		if store.IsNotFound(err) {
			// Configured profile does not resolve: deny (fail closed) and record it.
			msg := fmt.Sprintf("served default profile %q not found", d.defaultProfile)
			if aerr := d.auditProfileDecision(ctx, tenantID, 0, "deny", msg); aerr != nil {
				return crypto.LeafProfile{}, aerr
			}
			return crypto.LeafProfile{}, fmt.Errorf("server: %s (fail closed)", msg)
		}
		return crypto.LeafProfile{}, err
	}
	var prof profile.CertificateProfile
	if err := json.Unmarshal(rec.Spec, &prof); err != nil {
		return crypto.LeafProfile{}, fmt.Errorf("server: decode profile %q: %w", d.defaultProfile, err)
	}
	info, err := crypto.InspectCSR(csrDER)
	if err != nil {
		if aerr := d.auditProfileDecision(ctx, tenantID, rec.Version, "deny", "unparseable CSR"); aerr != nil {
			return crypto.LeafProfile{}, aerr
		}
		return crypto.LeafProfile{}, fmt.Errorf("server: profile %q: unparseable CSR: %w", d.defaultProfile, err)
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
		if aerr := d.auditProfileDecision(ctx, tenantID, rec.Version, "deny", verr.Error()); aerr != nil {
			return crypto.LeafProfile{}, aerr
		}
		return crypto.LeafProfile{}, verr
	}
	if err := d.auditProfileDecision(ctx, tenantID, rec.Version, "allow", ""); err != nil {
		return crypto.LeafProfile{}, err
	}
	return leafProfileForCertificateProfile(d.leafProfile, prof, requestedEKUs), nil
}

// auditProfileDecision emits the served profile-gated decision as an AN-2 event,
// mirroring the IssuanceService's issuance.profile_evaluated record so the served
// and library paths produce the same audit shape. A nil log is a no-op, but the
// deny (the returned error in enforceProfile) still rejects the mint.
func (d *issuanceDispatcher) auditProfileDecision(ctx context.Context, tenantID string, version int, decision, reason string) error {
	if d.log == nil {
		return nil
	}
	payload, err := json.Marshal(struct {
		Profile  string `json:"profile"`
		Version  int    `json:"version"`
		Decision string `json:"decision"`
		Reason   string `json:"reason,omitempty"`
		Protocol string `json:"protocol,omitempty"`
	}{d.defaultProfile, version, decision, reason, "api"})
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

// handleDeploy processes a connector.deploy outbox entry (the side effect of an
// issued→deployed lifecycle transition, or a direct connector deployment payload).
// Every attempt records a tenant-scoped, event-sourced delivery receipt before the
// outbox row is acknowledged or retried. The receipt carries only routing evidence
// (connector, target, fingerprint, status, rollback reference), never PEM/key
// material (AN-8). When a served WASM connector plugin is configured and owns the
// named connector, the deployment is pushed through the capability sandbox; when no
// native connector nor plugin owns it the row is acknowledged as "unrouted" and
// the reason is visible.
func (d *issuanceDispatcher) handleDeploy(ctx context.Context, m orchestrator.Message) error {
	p, identityID, detail, err := d.resolveDeployPayload(ctx, m)
	if err != nil {
		return err
	}
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
	if p.Connector == "" {
		receipt.Detail = nonempty(receipt.Detail, "identity has no connector target configured")
		return d.recordConnectorDelivery(ctx, m.TenantID, receipt, "unrouted", "missing_connector")
	}
	if d.connectorRegistry != nil && d.connectorRegistry.Has(p.Connector) {
		if len(p.CertPEM) == 0 || len(p.KeyPEM) == 0 {
			receipt.Detail = "native connector payload did not carry cert_pem and key_pem"
			return d.recordConnectorDelivery(ctx, m.TenantID, receipt, "unrouted", "native_payload_missing_credential")
		}
		// Idempotent on the outbox key (AN-5 ↔ AN-6): a redelivery returns the
		// recorded result without pushing the same credential to the target again.
		_, err = d.idem.Do(ctx, m.TenantID, "deploy:"+m.IdempotencyKey, func(ctx context.Context) ([]byte, error) {
			if derr := d.connectorRegistry.Deploy(ctx, p); derr != nil {
				_ = d.recordConnectorDelivery(ctx, m.TenantID, receipt, "failed", derr.Error())
				return nil, derr
			}
			receipt.Detail = "delivered by served native connector registry"
			receipt.RollbackRef = "restore previous certificate for " + p.Target
			if err := d.recordConnectorDelivery(ctx, m.TenantID, receipt, "delivered", "native_delivered"); err != nil {
				return nil, err
			}
			return []byte("deployed:" + p.Connector), nil
		})
		return err
	}
	if d.plugins == nil {
		receipt.Detail = "no signed connector plugin surface is configured"
		return d.recordConnectorDelivery(ctx, m.TenantID, receipt, "unrouted", "plugin_surface_unconfigured")
	}
	if !d.plugins.Has(p.Connector) {
		receipt.Detail = "connector is not owned by a loaded signed plugin"
		return d.recordConnectorDelivery(ctx, m.TenantID, receipt, "unrouted", "plugin_not_loaded")
	}
	// Idempotent on the outbox key (AN-5 ↔ AN-6): a redelivery returns the recorded
	// result without invoking the plugin again.
	_, err = d.idem.Do(ctx, m.TenantID, "deploy:"+m.IdempotencyKey, func(ctx context.Context) ([]byte, error) {
		handled, derr := d.plugins.Deploy(ctx, m.TenantID, p)
		if derr != nil {
			_ = d.recordConnectorDelivery(ctx, m.TenantID, receipt, "failed", derr.Error())
			return nil, derr
		}
		if !handled {
			receipt.Detail = "loaded plugin declined this connector payload"
			if err := d.recordConnectorDelivery(ctx, m.TenantID, receipt, "unrouted", "plugin_declined"); err != nil {
				return nil, err
			}
			return []byte("unrouted"), nil
		}
		receipt.RollbackRef = "restore previous certificate for " + p.Target
		if err := d.recordConnectorDelivery(ctx, m.TenantID, receipt, "delivered", "plugin_delivered"); err != nil {
			return nil, err
		}
		return []byte("deployed:" + p.Connector), nil
	})
	return err
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
	var p connector.DeployPayload
	if err := json.Unmarshal(m.Payload, &p); err == nil && (p.Connector != "" || p.Target != "" || p.Fingerprint != "" || len(p.CertPEM) > 0 || len(p.KeyPEM) > 0) {
		return p, nil, "direct connector deploy payload", nil
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
	p.Connector = connName
	p.Target = nonempty(target, ident.Name)
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

func deploymentRoutingAttrs(raw json.RawMessage) (string, string) {
	if len(raw) == 0 {
		return "", ""
	}
	var attrs map[string]any
	if err := json.Unmarshal(raw, &attrs); err != nil {
		return "", ""
	}
	connectorName := firstStringAttr(attrs, "connector", "deployment_connector", "connector_name")
	target := firstStringAttr(attrs, "target", "deployment_target", "deployment_target_id", "deployment_location")
	return connectorName, target
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

func rotationTrigger(reason string) string {
	if strings.Contains(strings.ToLower(reason), "scheduled") {
		return "scheduler"
	}
	return "manual"
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
