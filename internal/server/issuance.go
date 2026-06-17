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

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/profile"
	"trstctl.com/trstctl/internal/store"
)

// leafTTL is the validity of a certificate issued by the assembled CA. It is
// comfortably within the issuing CA's own validity so the leaf never outlives it.
const leafTTL = 30 * 24 * time.Hour

// caNamespace is the fixed UUIDv5 namespace under which the served binary's
// stable CA handles are turned into the ca_id used by the revocation tables. It
// never changes, so a CA's ca_id is the same across restarts and the
// issued/revoked records for it line up over time.
var caNamespace = uuid.MustParse("8f6a0c1e-4d2b-5a3c-9e7f-1b2c3d4e5f60")

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

// issueFunc mints a leaf certificate from a CSR (Server.IssueLeaf satisfies it).
type issueFunc func(ctx context.Context, csrDER []byte, ttl time.Duration) ([]byte, error)

// issuanceDispatcher is the real outbox handler (AN-6). For a requested→issued
// lifecycle transition it mints a leaf certificate from the assembled CA (whose
// key lives in the out-of-process signer, AN-4) and records it in the inventory
// as an event (AN-2); for an *→revoked transition it revokes that leaf so the
// certificate stops validating — the inventory status flips to revoked (via a
// projected certificate.revoked event, AN-2) and the serial is written to the
// revocation table (ca_issued_certs) that backs OCSP/CRL. It is idempotent on
// the outbox message's key (AN-5), so a redelivery never mints a second
// certificate nor double-revokes.
type issuanceDispatcher struct {
	issue issueFunc
	orch  *orchestrator.Orchestrator
	idem  *orchestrator.Idempotency
	store *store.Store

	// log is the event log used to emit the profile-gated issuance decision
	// (issuance.profile_evaluated) on the served mint (PKIGOV-002); nil disables the
	// audit emit but the deny still rejects.
	log *events.Log
	// defaultProfile is the certificate-profile name enforced on the served mint
	// when it resolves for the tenant (PKIGOV-002). Empty means no served-side
	// profile binding, preserving the prior behavior.
	defaultProfile string
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
	default:
		if strings.HasPrefix(m.Destination, "ca.") || strings.HasPrefix(m.Destination, "revocation.") {
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
	// Idempotent on the outbox key: a redelivery returns the recorded result
	// without minting again (AN-5 ↔ AN-6).
	_, err := d.idem.Do(ctx, m.TenantID, "issue:"+m.IdempotencyKey, func(ctx context.Context) ([]byte, error) {
		ident, err := d.store.GetIdentity(ctx, m.TenantID, p.IdentityID)
		if err != nil {
			return nil, fmt.Errorf("server: load identity %s: %w", p.IdentityID, err)
		}
		cert, err := d.mintServedLeaf(ctx, m.TenantID, ident.OwnerID, ident.Name, []string{ident.Name})
		if err != nil {
			return nil, err
		}
		if _, err := d.orch.RecordCertificate(ctx, m.TenantID, cert); err != nil {
			return nil, err
		}
		// Bridge the minted serial into the revocation table (ca_issued_certs) so
		// the OCSP responder can answer good-vs-unknown and so a later revoke has a
		// row to flip (the link the inventory and the responder previously lacked).
		// Idempotent in the store (ON CONFLICT DO NOTHING).
		if err := d.store.RecordIssuedCert(ctx, m.TenantID, IssuingCAID(), cert.Serial, time.Now()); err != nil {
			return nil, err
		}
		return []byte(cert.Fingerprint), nil
	})
	if err != nil {
		return err
	}
	return d.ensureTenantCRL(ctx, m.TenantID)
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
	if err := d.enforceProfile(ctx, tenantID, csrDER, dnsNames, leafTTL); err != nil {
		return store.Certificate{}, err
	}
	leafPEM, err := d.issue(ctx, csrDER, leafTTL)
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
	owner := ownerID
	nb, na := info.NotBefore, info.NotAfter
	return store.Certificate{
		OwnerID: &owner, Subject: info.Subject, SANs: sansOf(info),
		Issuer: info.Issuer, Serial: info.SerialNumber, Fingerprint: info.SHA256Fingerprint,
		KeyAlgorithm: info.KeyAlgorithm, NotBefore: &nb, NotAfter: &na,
		Source: "issued",
	}, nil
}

// handleRenew processes a ca.renew outbox entry (the side effect of a deployed→
// renewing lifecycle transition): it mints a signer-backed successor certificate,
// records the successor through the event-sourced certificate.recorded path with
// a replaces_id link, supersedes the predecessor through certificate.superseded,
// records the successor serial for OCSP/CRL, and moves the identity back to
// deployed via identity.renewed. It is idempotent on the outbox key (AN-5), so a
// redelivery cannot mint a second successor.
func (d *issuanceDispatcher) handleRenew(ctx context.Context, m orchestrator.Message) error {
	var p transitionTrigger
	if err := json.Unmarshal(m.Payload, &p); err != nil {
		return fmt.Errorf("server: decode ca.renew payload: %w", err)
	}
	if p.IdentityID == "" || p.To != string(orchestrator.StateRenewing) {
		return nil
	}
	_, err := d.idem.Do(ctx, m.TenantID, "renew:"+m.IdempotencyKey, func(ctx context.Context) ([]byte, error) {
		ident, err := d.store.GetIdentity(ctx, m.TenantID, p.IdentityID)
		if err != nil {
			return nil, fmt.Errorf("server: load identity %s: %w", p.IdentityID, err)
		}
		certs, err := d.store.ListActiveIssuedCertificatesForIdentity(ctx, m.TenantID, ident.OwnerID, ident.Name)
		if err != nil {
			return nil, fmt.Errorf("server: find issued certs for identity %s: %w", p.IdentityID, err)
		}
		if len(certs) == 0 {
			return nil, fmt.Errorf("server: no active issued certificate to renew for identity %s", p.IdentityID)
		}
		now := time.Now()
		for _, old := range certs {
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
				return nil, err
			}
			if _, err := d.orch.RecordSuccessorCertificate(ctx, m.TenantID, successor, old.ID); err != nil {
				return nil, fmt.Errorf("server: record renewal successor: %w", err)
			}
			if err := d.orch.SupersedeCertificate(ctx, m.TenantID, old.Fingerprint, old.Serial, successor.Serial, now); err != nil {
				return nil, fmt.Errorf("server: supersede renewed predecessor: %w", err)
			}
			if err := d.store.RecordIssuedCert(ctx, m.TenantID, IssuingCAID(), successor.Serial, now); err != nil {
				return nil, fmt.Errorf("server: record renewal serial: %w", err)
			}
		}
		reason := p.Reason
		if reason == "" {
			reason = "renewal completed"
		}
		if err := d.orch.Transition(ctx, m.TenantID, p.IdentityID, orchestrator.StateDeployed, reason); err != nil {
			return nil, fmt.Errorf("server: complete renewal transition: %w", err)
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
func (d *issuanceDispatcher) enforceProfile(ctx context.Context, tenantID string, csrDER []byte, dnsNames []string, ttl time.Duration) error {
	if d.defaultProfile == "" {
		return nil
	}
	rec, err := d.store.GetActiveProfile(ctx, tenantID, d.defaultProfile)
	if err != nil {
		if store.IsNotFound(err) {
			// Configured profile does not resolve: deny (fail closed) and record it.
			msg := fmt.Sprintf("served default profile %q not found", d.defaultProfile)
			if aerr := d.auditProfileDecision(ctx, tenantID, 0, "deny", msg); aerr != nil {
				return aerr
			}
			return fmt.Errorf("server: %s (fail closed)", msg)
		}
		return err
	}
	var prof profile.CertificateProfile
	if err := json.Unmarshal(rec.Spec, &prof); err != nil {
		return fmt.Errorf("server: decode profile %q: %w", d.defaultProfile, err)
	}
	info, err := crypto.InspectCSR(csrDER)
	if err != nil {
		if aerr := d.auditProfileDecision(ctx, tenantID, rec.Version, "deny", "unparseable CSR"); aerr != nil {
			return aerr
		}
		return fmt.Errorf("server: profile %q: unparseable CSR: %w", d.defaultProfile, err)
	}
	preq := profile.Request{
		KeyAlgorithm: info.KeyAlgorithm, KeyBits: info.KeyBits,
		TTL: ttl, DNSNames: dnsNames, Protocol: "api",
	}
	if verr := prof.Validate(preq); verr != nil {
		if aerr := d.auditProfileDecision(ctx, tenantID, rec.Version, "deny", verr.Error()); aerr != nil {
			return aerr
		}
		return verr
	}
	return d.auditProfileDecision(ctx, tenantID, rec.Version, "allow", "")
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
// certificate(s). For each active issued cert it (1) emits a certificate.revoked
// event so the inventory status is projected to revoked (AN-2), and (2) records
// the serial revoked in the revocation table (ca_issued_certs) that backs OCSP
// and the CRL. It is idempotent on the outbox key (AN-5): a redelivery returns
// the recorded result rather than revoking again, and the store keeps the first
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
			reason = "unspecified"
		}
		// reasonCode 0 == unspecified (RFC 5280); the human-readable reason is kept
		// on the inventory row. A richer reason->code mapping is future work.
		const reasonCode = 0
		now := time.Now()
		for _, c := range certs {
			// Flip the inventory status through a projected event (AN-2), so it
			// survives a read-model Rebuild() rather than being a lost direct write.
			if err := d.orch.RevokeCertificate(ctx, m.TenantID, c.Fingerprint, c.Serial, reason, now); err != nil {
				return nil, err
			}
			// Record the serial revoked in the responder's table so OCSP/CRL reflect
			// it. Skip an empty serial (a malformed/legacy row) rather than erroring.
			if c.Serial != "" {
				if err := d.store.RevokeIssuedCert(ctx, m.TenantID, IssuingCAID(), c.Serial, reasonCode, now); err != nil {
					return nil, err
				}
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
// issued→deployed lifecycle transition). When a served WASM connector plugin is
// configured and owns the named connector (ARCH-007), the deployment is pushed
// through the capability sandbox; the plugin runs in its own wazero runtime with
// no store/signer handle, and an operation outside its grant fails the deploy. It
// is idempotent on the outbox key (AN-5) so a redelivery does not re-run the
// plugin, tenant-scoped (AN-1), and event-sourced (AN-2 — the plugin outcome is
// recorded by the manager). When no plugin owns the connector the entry is
// acknowledged unrouted, exactly as before, so first-party in-process connectors
// (still routed elsewhere) and not-yet-wired targets do not dead-letter.
func (d *issuanceDispatcher) handleDeploy(ctx context.Context, m orchestrator.Message) error {
	if d.plugins == nil {
		return nil // no served plugin surface: ack unrouted (prior behavior)
	}
	var p connector.DeployPayload
	if err := json.Unmarshal(m.Payload, &p); err != nil {
		return fmt.Errorf("server: decode connector.deploy payload: %w", err)
	}
	if p.Connector == "" || !d.plugins.Has(p.Connector) {
		return nil // not a plugin-owned connector: ack unrouted
	}
	// Idempotent on the outbox key (AN-5 ↔ AN-6): a redelivery returns the recorded
	// result without invoking the plugin again.
	_, err := d.idem.Do(ctx, m.TenantID, "deploy:"+m.IdempotencyKey, func(ctx context.Context) ([]byte, error) {
		handled, derr := d.plugins.Deploy(ctx, m.TenantID, p)
		if derr != nil {
			return nil, derr
		}
		if !handled {
			return []byte("unrouted"), nil
		}
		return []byte("deployed:" + p.Connector), nil
	})
	return err
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
