package server

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/auth"
	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/profile"
	"trstctl.com/trstctl/internal/store"
)

// protocolLeafTTL is the validity of a certificate minted through one of the
// served issuance protocols (ACME/EST/SCEP/CMP). It is comfortably within the
// issuing CA's own validity so a protocol-issued leaf never outlives its issuer.
// ACME clients ask for 90d, but the served path caps to this so a protocol caller
// cannot mint a leaf that outlives the CA; the per-request TTL is honored only up
// to this ceiling.
const protocolLeafTTL = 30 * 24 * time.Hour

// protocolIssuer is the single seam every served HTTP/gRPC issuance protocol
// (ACME, EST, SCEP, CMP, SPIFFE, SSH) mints through. It is the EXC-WIRE-02 wire-in
// guarantee: a protocol never signs anything itself and never reaches the signer
// directly — it calls here, and here every non-negotiable is enforced in one place:
//
//   - AN-4/AN-3: the leaf is signed by Server.IssueLeaf, i.e. the issuing CA key
//     in the out-of-process signer through the internal/crypto boundary. No
//     protocol holds a private key; SCEP/CMP transport keys are their own RSA pair
//     and never the CA key.
//   - AN-1: every mint is bound to a tenant_id; the issued-cert record and the
//     revocation-table bridge are written under that tenant's RLS.
//   - AN-5: issuance runs under the orchestrator idempotency cache keyed by the
//     protocol's natural request key (ACME order, EST CSR, SCEP/CMP transaction id),
//     so a retried enrollment returns the original certificate rather than minting a
//     second one.
//   - AN-2: the minted certificate is recorded as a certificate.recorded event and
//     a protocol.issued event, so issuance is event-sourced and audited; the read
//     model is a projection.
//   - PKIGOV-002: when a default certificate profile is configured and resolves for
//     the tenant, the CSR is validated against it BEFORE signing (fail closed).
//   - EXC-WIRE-03: the served policy / RA / dual-control gate governs the
//     identities:write transition path; protocol enrollment is the machine
//     credential-request path and is gated by transport auth + the bound profile,
//     and (like the API mint) records its decision as an event. It never bypasses
//     the signer.
//
// The minted serial is also bridged into ca_issued_certs so the served OCSP
// responder / CRL endpoint (EXC-REVOKE-01) can answer for a protocol-issued cert and
// a later revocation has a row to flip — the same bridge the API mint uses.
type protocolIssuer struct {
	issue          issueFunc                  // Server.IssueLeaf — signs through the signer (AN-3/AN-4)
	orch           *orchestrator.Orchestrator // records the cert as an event (AN-2)
	idem           *orchestrator.Idempotency  // dedupe a retried enrollment (AN-5)
	store          *store.Store               // tenant-scoped reads/writes under RLS (AN-1)
	log            *events.Log                // protocol.issued / profile decision events (AN-2)
	caID           string                     // the served issuing CA's deterministic ca_id
	defaultProfile string                     // PKIGOV-002 served profile binding; empty = none
}

// errProtocolIssuanceUnavailable is returned when the served path has no issuing CA
// (no signer): like the API mint, protocols then fail closed rather than mint with
// an in-process key.
var errProtocolIssuanceUnavailable = errors.New("server: protocol issuance unavailable — no out-of-process signer (fail closed)")

// IssueProtocolLeaf mints a leaf for a protocol enrollment: it validates the CSR
// against the served profile (PKIGOV-002), signs it through the signer (AN-3/AN-4)
// idempotently (AN-5), records it as an event (AN-2) under the tenant (AN-1), and
// bridges its serial into the revocation table. It returns the leaf DER (protocols
// re-encode it to their wire format). It is the shared body behind the ca.CA and
// Enroller adapters below.
func (p *protocolIssuer) IssueProtocolLeaf(ctx context.Context, tenantID, protocolName, idempotencyKey string, csrDER []byte, ttl time.Duration) ([]byte, error) {
	if p.issue == nil {
		return nil, errProtocolIssuanceUnavailable
	}
	if tenantID == "" {
		// AN-1: a protocol mount that did not resolve a tenant must not mint into a
		// shared/blank tenant. Fail closed.
		return nil, errors.New("server: protocol issuance requires a tenant (AN-1)")
	}
	if ttl <= 0 || ttl > protocolLeafTTL {
		ttl = protocolLeafTTL
	}
	if idempotencyKey == "" {
		// Derive a deterministic key from the CSR so a retried enrollment without an
		// explicit key still dedupes (AN-5). The fingerprint is over the request bytes.
		idempotencyKey = protocolName + ":" + fingerprintOf(csrDER)
	}
	// Idempotent on (tenant, key): the first enrollment mints + records; a replay
	// returns the recorded leaf without minting again (AN-5).
	raw, err := p.idem.Do(ctx, tenantID, "protocol-issue:"+idempotencyKey, func(ctx context.Context) ([]byte, error) {
		csrInfo, err := crypto.InspectCSR(csrDER)
		if err != nil {
			return nil, fmt.Errorf("server: protocol CSR does not parse: %w", err)
		}
		dnsNames := csrInfo.DNSNames
		if len(dnsNames) == 0 && csrInfo.CommonName != "" {
			dnsNames = []string{csrInfo.CommonName}
		}
		// PKIGOV-002 served profile gate: validate before signing, fail closed, and
		// record the decision (AN-2). A no-op when no default profile is configured.
		if err := p.enforceProfile(ctx, tenantID, protocolName, csrDER, csrInfo, dnsNames, ttl); err != nil {
			return nil, err
		}
		// Sign through the signer (AN-3/AN-4) — Server.IssueLeaf fails closed when the
		// signer is slow/unavailable and never signs in-process.
		leafPEM, err := p.issue(ctx, csrDER, ttl)
		if err != nil {
			return nil, err
		}
		blk, _ := pem.Decode(leafPEM)
		if blk == nil {
			return nil, errors.New("server: protocol-issued certificate is not PEM")
		}
		info, err := certinfo.Inspect(blk.Bytes)
		if err != nil {
			return nil, err
		}
		// Record the minted cert as an event (AN-2): the inventory read model is a
		// projection, so a protocol-issued cert is visible, auditable, and survives a
		// read-model rebuild. Bound to the tenant (AN-1).
		nb, na := info.NotBefore, info.NotAfter
		if _, err := p.orch.RecordCertificate(ctx, tenantID, store.Certificate{
			Subject: info.Subject, SANs: sansOf(info), Issuer: info.Issuer,
			Serial: info.SerialNumber, Fingerprint: info.SHA256Fingerprint,
			KeyAlgorithm: info.KeyAlgorithm, NotBefore: &nb, NotAfter: &na,
			Source: "issued",
		}); err != nil {
			return nil, err
		}
		// Bridge the serial into ca_issued_certs so the served OCSP/CRL responder can
		// answer for it and a later revoke has a row to flip (the same bridge the API
		// mint uses). Idempotent in the store (ON CONFLICT DO NOTHING).
		if info.SerialNumber != "" {
			if err := p.store.RecordIssuedCert(ctx, tenantID, p.caID, info.SerialNumber, time.Now()); err != nil {
				return nil, err
			}
		}
		// Emit a protocol-specific issuance event so the served protocol path is
		// auditable distinctly from the API mint (AN-2). A nil log is a no-op.
		p.auditIssued(ctx, tenantID, protocolName, info.SerialNumber)
		return blk.Bytes, nil
	})
	if err != nil {
		return nil, err
	}
	return raw, nil
}

// enforceProfile applies the served certificate-profile model to a protocol mint
// (PKIGOV-002), mirroring the API mint's gate (internal/server/issuance.go) and the
// IssuanceService gate so all three produce the same audit shape. A no-op when no
// default profile is configured; a configured-but-unresolved profile fails closed.
func (p *protocolIssuer) enforceProfile(ctx context.Context, tenantID, protocolName string, csrDER []byte, csrInfo crypto.CSRInfo, dnsNames []string, ttl time.Duration) error {
	if p.defaultProfile == "" {
		return nil
	}
	rec, err := p.store.GetActiveProfile(ctx, tenantID, p.defaultProfile)
	if err != nil {
		if store.IsNotFound(err) {
			msg := fmt.Sprintf("served default profile %q not found", p.defaultProfile)
			p.auditProfileDecision(ctx, tenantID, protocolName, 0, "deny", msg)
			return fmt.Errorf("server: %s (fail closed)", msg)
		}
		return err
	}
	var prof profile.CertificateProfile
	if err := json.Unmarshal(rec.Spec, &prof); err != nil {
		return fmt.Errorf("server: decode profile %q: %w", p.defaultProfile, err)
	}
	preq := profile.Request{
		KeyAlgorithm: csrInfo.KeyAlgorithm, KeyBits: csrInfo.KeyBits,
		TTL: ttl, DNSNames: dnsNames, Protocol: protocolName,
	}
	if verr := prof.Validate(preq); verr != nil {
		p.auditProfileDecision(ctx, tenantID, protocolName, rec.Version, "deny", verr.Error())
		return verr
	}
	p.auditProfileDecision(ctx, tenantID, protocolName, rec.Version, "allow", "")
	return nil
}

// caCA adapts the protocol issuer to the ca.CA interface so the built-in ACME
// server (which brokers issuance to a ca.CA) mints through the served signer path.
type protocolCAAdapter struct {
	tenantID string
	issuer   *protocolIssuer
}

// Name identifies the authority in events and the issued Certificate.
func (a protocolCAAdapter) Name() string { return "trstctl-served-ca" }

// Issue implements ca.CA: it mints the leaf through the served signer path and
// returns it in the ca.Certificate shape the ACME server expects (leaf PEM + serial
// + notAfter). The ACME order's DNS names are authorized by the ACME challenge flow
// before finalize; here we sign the order's CSR.
func (a protocolCAAdapter) Issue(ctx context.Context, req ca.IssueRequest) (ca.Certificate, error) {
	tenant := req.TenantID
	if tenant == "" {
		tenant = a.tenantID
	}
	// The ACME order carries no idempotency key of its own, so derive one from the
	// CSR (a re-finalize of the same order presents the same CSR → same key → AN-5).
	leafDER, err := a.issuer.IssueProtocolLeaf(ctx, tenant, "acme", "", req.CSR, req.TTL)
	if err != nil {
		return ca.Certificate{}, err
	}
	info, err := certinfo.Inspect(leafDER)
	if err != nil {
		return ca.Certificate{}, err
	}
	return ca.Certificate{
		CertificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		Serial:         info.SerialNumber,
		NotAfter:       info.NotAfter,
		Issuer:         info.Issuer,
	}, nil
}

// enrollerAdapter adapts the protocol issuer to the EST/SCEP/CMP Enroller interface
// (they share the same Enroll signature). It mints through the served signer path,
// tenant-scoped + idempotent + event-sourced + profile-gated.
type enrollerAdapter struct {
	tenantID string
	issuer   *protocolIssuer
}

// Enroll implements the EST/SCEP/CMP Enroller interface. profileName is passed
// through; the served issuer applies the configured default profile (PKIGOV-002).
// The idempotencyKey is the protocol's natural request key (CSR hash, transaction
// id), so a retried enrollment dedupes (AN-5).
func (e enrollerAdapter) Enroll(ctx context.Context, csrDER []byte, profileName, protocol, idempotencyKey string) ([]byte, error) {
	tenant := e.tenantID
	return e.issuer.IssueProtocolLeaf(ctx, tenant, protocol, idempotencyKey, csrDER, protocolLeafTTL)
}

// servedEnrollAuth is the EST §3.2.3 HTTP authenticator for the served EST endpoint:
// it requires a valid, unexpired trstctl API Bearer token bound to the EST tenant
// (the same token mechanism the REST API uses), so EST enrollment is auth-gated and
// not anonymous. The CSR is still profile-gated and signed through the signer; this
// is the transport-level credential check on top of TLS.
type servedEnrollAuth struct {
	store    *store.Store
	tenantID string
}

// Authenticate implements est.Authenticator. It returns true only for a Bearer
// trstctl API token (trst_…) that resolves in the store, is unexpired, and is bound to
// this endpoint's tenant (AN-1: a token for another tenant cannot enroll here).
func (a servedEnrollAuth) Authenticate(r *http.Request) bool {
	if a.store == nil {
		return false
	}
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, prefix) {
		return false
	}
	tok := strings.TrimSpace(h[len(prefix):])
	if !strings.HasPrefix(tok, auth.TokenPrefix) {
		return false
	}
	hash, err := auth.HashAPIToken(tok)
	if err != nil {
		return false
	}
	rec, err := a.store.LookupAPITokenByHash(r.Context(), hash)
	if err != nil {
		return false
	}
	if rec.ExpiresAt != nil && !rec.ExpiresAt.After(time.Now()) {
		return false
	}
	// AN-1: the token's tenant must match the endpoint's tenant.
	return a.tenantID == "" || rec.TenantID == a.tenantID
}

// auditIssued emits the served protocol issuance as an AN-2 event so a
// protocol-minted certificate is attributable to its protocol and tenant. A nil log
// is a no-op (but the cert is still recorded via RecordCertificate above).
func (p *protocolIssuer) auditIssued(ctx context.Context, tenantID, protocolName, serial string) {
	if p.log == nil {
		return
	}
	payload, err := json.Marshal(struct {
		Protocol string `json:"protocol"`
		Serial   string `json:"serial,omitempty"`
		Decision string `json:"decision"`
	}{protocolName, serial, "allow"})
	if err != nil {
		return
	}
	_, _ = p.log.Append(ctx, events.Event{Type: "protocol.issued", TenantID: tenantID, Data: payload})
}

// auditProfileDecision emits the served profile-gated decision for a protocol mint
// as an AN-2 event, mirroring the API mint's issuance.profile_evaluated record so
// the served paths produce the same audit shape. A nil log is a no-op, but the deny
// (the returned error in enforceProfile) still rejects the mint.
func (p *protocolIssuer) auditProfileDecision(ctx context.Context, tenantID, protocolName string, version int, decision, reason string) {
	if p.log == nil {
		return
	}
	payload, err := json.Marshal(struct {
		Profile  string `json:"profile"`
		Version  int    `json:"version"`
		Decision string `json:"decision"`
		Reason   string `json:"reason,omitempty"`
		Protocol string `json:"protocol,omitempty"`
	}{p.defaultProfile, version, decision, reason, protocolName})
	if err != nil {
		return
	}
	_, _ = p.log.Append(ctx, events.Event{Type: "issuance.profile_evaluated", TenantID: tenantID, Data: payload})
}

// fingerprintOf returns a stable hex fingerprint of arbitrary request bytes through
// the crypto boundary (AN-3 — this package must not import crypto/*). It is used to
// derive a deterministic idempotency key when a protocol supplies none.
func fingerprintOf(b []byte) string { return crypto.SHA256Hex(b) }
