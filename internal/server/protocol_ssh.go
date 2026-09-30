// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/protocols/bodylimit"
	"trstctl.com/trstctl/internal/protocols/spiffe"
	"trstctl.com/trstctl/internal/protocols/ssh"
)

// sshProtocol is the served SSH CA surface (EXC-WIRE-02 / F43). SSH has no single
// standardized issuance wire protocol, so trstctl exposes a small JSON API for cert
// issuance plus the two artifacts a host needs: the CA authority key (for
// TrustedUserCAKeys / @cert-authority) and the OpenSSH BINARY KRL (for sshd's
// RevokedKeys; INTEROP-009). The SSH CA key lives in the signer (AN-4) and issuance
// is tenant-scoped, audited (AN-2), and bulkheaded (AN-7) by the wrapped ssh.CA.
type sshProtocol struct {
	ca       *ssh.CA
	krl      *ssh.KRL
	tenantID string
	mux      *http.ServeMux

	// guard serves the three MUTATING routes. Issuance and revocation are not
	// public: an SSH user certificate names its own principals, so an anonymous
	// caller could otherwise mint `root` for any host that trusts this CA, and an
	// anonymous revoker could poison the KRL. The guard is the API's own mutation
	// guard (authentication, RBAC, the ABAC deny overlay, the per-tenant rate
	// limit, the event actor and Idempotency-Key replay), so the raw routes cannot
	// drift from /api/v1/ssh/certificates. The two GET routes stay public because
	// they serve trust material a host must fetch before it can authenticate
	// anything (the CA public key and the binary KRL), exactly like a CRL
	// distribution point.
	guard sshMutationGuard

	// workflow is the product SSH workflow the raw routes delegate to, so a raw
	// request gets the same normalization, principal allowlist, option checks and
	// durable revocation record as the product API.
	workflow sshRawWorkflow

	// userPrincipals is protocols.ssh_user_principals: the only login names a
	// direct (non-attested) user certificate may carry. Empty refuses direct user
	// certificates.
	userPrincipals []string

	// krlVersion is the monotonic OpenSSH KRL version a host uses to reject an older
	// KRL; it counts the tenant revocation events applied, so replicas at the same
	// log position serve the same version.
	krlVersion atomic.Uint64

	// The served KRL is a read model of the tenant's ssh.cert.revoked events
	// (AN-2). syncMu serializes catch-up; applied is the highest event sequence
	// read; syncedFrom is when the last successful catch-up started.
	log        *events.Log
	syncMu     sync.Mutex
	applied    uint64
	syncedFrom time.Time
}

// sshMutationGuard wraps a raw SSH mutation in the API mutation guard for perm.
type sshMutationGuard func(perm authz.Permission, fn api.ProtocolMutationFunc) http.HandlerFunc

// sshRawWorkflow is the slice of the product SSH workflow the raw routes use.
type sshRawWorkflow interface {
	IssueSSHCertificate(ctx context.Context, tenantID, idempotencyKey string, req api.SSHCertificateRequest) (api.SSHCertificate, error)
	RevokeSSHCertificate(ctx context.Context, tenantID, idempotencyKey string, req api.SSHRevokeCertificateRequest) (api.SSHStatus, error)
}

// sshKRLSyncTimeout bounds how long a KRL read waits to catch up with the event
// log before it reports 503 and the host keeps its last KRL.
const sshKRLSyncTimeout = 5 * time.Second

// sshKRLSyncInterval bounds how often an unauthenticated KRL read may trigger a
// catch-up. A replay currently re-reads history before it starts (RV-12.2), so
// public reads cost at most one catch-up per interval per process; a revocation
// recorded on another replica is listed within about this long.
const sshKRLSyncInterval = 2 * time.Second

// newSSHProtocol wires the served SSH CA surface over a built ssh.CA. A fresh KRL is
// attached so revocations published through it render as a binary KRL sshd consumes.
//
// guard and workflow must be non-nil: without them the mutating routes would be
// anonymous or unrecorded, so construction fails closed rather than serving an
// open CA.
func newSSHProtocol(ca *ssh.CA, tenantID string, guard sshMutationGuard, workflow sshRawWorkflow) (*sshProtocol, error) {
	if guard == nil {
		return nil, fmt.Errorf("server: served SSH CA requires the API mutation guard")
	}
	if workflow == nil {
		return nil, fmt.Errorf("server: served SSH CA requires the SSH workflow")
	}
	p := &sshProtocol{ca: ca, krl: ssh.NewKRL(), tenantID: tenantID, guard: guard, workflow: workflow}
	mux := http.NewServeMux()
	// Public trust material — a host must read these before it can trust anything.
	mux.HandleFunc("GET /ssh/ca", p.authorityKey)
	mux.HandleFunc("GET /ssh/krl", p.serveKRL)
	// Mutating routes: issuance needs certs:issue; revocation needs certs:write,
	// the authority the product revoke route requires.
	mux.HandleFunc("POST /ssh/issue/user", guard(authz.CertsIssue, p.issue("user")))
	mux.HandleFunc("POST /ssh/issue/host", guard(authz.CertsIssue, p.issue("host")))
	mux.HandleFunc("POST /ssh/revoke", guard(authz.CertsWrite, p.revoke))
	p.mux = mux
	return p, nil
}

// ServeHTTP implements http.Handler.
func (p *sshProtocol) ServeHTTP(w http.ResponseWriter, r *http.Request) { p.mux.ServeHTTP(w, r) }

// authorityKey serves the SSH CA public key (authorized_keys form) for
// TrustedUserCAKeys / @cert-authority known_hosts lines.
func (p *sshProtocol) authorityKey(w http.ResponseWriter, _ *http.Request) {
	key, err := p.ca.AuthorityKey()
	if err != nil {
		http.Error(w, "ssh: CA key unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write(key)
}

// sshIssueRequest is the JSON body for an SSH cert issuance.
type sshIssueRequest struct {
	PublicKey       string            `json:"public_key"`  // subject SSH public key (authorized_keys form)
	KeyID           string            `json:"key_id"`      // certificate key id (logged)
	Principals      []string          `json:"principals"`  // usernames (user cert) or hostnames (host cert)
	TTLSeconds      int64             `json:"ttl_seconds"` // requested validity
	CriticalOptions map[string]string `json:"critical_options,omitempty"`
	Extensions      map[string]string `json:"extensions,omitempty"`
}

// sshIssueResponse is the JSON response carrying the issued certificate.
type sshIssueResponse struct {
	Certificate string `json:"certificate"` // OpenSSH cert (authorized_keys form)
	Serial      uint64 `json:"serial"`
	KeyID       string `json:"key_id"`
	ValidBefore string `json:"valid_before"` // RFC3339
}

const maxSSHJSONBody = 1 << 16

// readSSHJSON reads a bounded raw SSH request body into v.
func readSSHJSON(r *http.Request, v any) error {
	body, err := bodylimit.ReadAll(r.Body, maxSSHJSONBody)
	if errors.Is(err, bodylimit.ErrTooLarge) {
		return api.ProtocolRequestError(http.StatusRequestEntityTooLarge, "ssh: request body too large")
	}
	if err != nil {
		return api.ProtocolRequestError(http.StatusBadRequest, "ssh: cannot read body")
	}
	if err := json.Unmarshal(body, v); err != nil {
		return api.ProtocolRequestError(http.StatusBadRequest, "ssh: malformed request")
	}
	return nil
}

// issue mints an SSH user or host certificate through the product SSH workflow:
// the same normalization (TTL clamp, deduplicated principals, host certificates
// without user permit-* defaults or critical options), the principal allowlist
// for user certificates, and the audited signer-backed issuance.
func (p *sshProtocol) issue(certificateType string) api.ProtocolMutationFunc {
	return func(ctx context.Context, tenantID string, r *http.Request) (int, any, error) {
		var req sshIssueRequest
		if err := readSSHJSON(r, &req); err != nil {
			return 0, nil, err
		}
		issued, err := p.workflow.IssueSSHCertificate(ctx, tenantID, r.Header.Get("Idempotency-Key"), api.SSHCertificateRequest{
			CertificateType: certificateType,
			PublicKey:       req.PublicKey,
			KeyID:           req.KeyID,
			Principals:      req.Principals,
			TTLSeconds:      req.TTLSeconds,
			CriticalOptions: req.CriticalOptions,
			Extensions:      req.Extensions,
		})
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, sshIssueResponse{
			Certificate: issued.Certificate,
			Serial:      issued.Serial,
			KeyID:       issued.KeyID,
			ValidBefore: issued.ValidBefore,
		}, nil
	}
}

// sshRevokeRequest revokes an SSH certificate by serial or key id.
type sshRevokeRequest struct {
	Serial uint64 `json:"serial,omitempty"`
	KeyID  string `json:"key_id,omitempty"`
}

// revoke records an SSH certificate revocation through the product workflow: the
// tenant's ssh.cert.revoked event is appended first, and the served KRL is a read
// model of those events, so the revocation survives restart and reaches every
// replica.
func (p *sshProtocol) revoke(ctx context.Context, tenantID string, r *http.Request) (int, any, error) {
	var req sshRevokeRequest
	if err := readSSHJSON(r, &req); err != nil {
		return 0, nil, err
	}
	if _, err := p.workflow.RevokeSSHCertificate(ctx, tenantID, r.Header.Get("Idempotency-Key"), api.SSHRevokeCertificateRequest{
		Serial: req.Serial,
		KeyID:  req.KeyID,
	}); err != nil {
		return 0, nil, err
	}
	return http.StatusNoContent, nil, nil
}

func (p *sshProtocol) Revoke(serial uint64, keyID string) {
	if serial != 0 {
		p.krl.RevokeSerial(serial)
	}
	if keyID != "" {
		p.krl.RevokeKeyID(keyID)
	}
	p.krlVersion.Add(1)
}

// restoreRevocations rebuilds the served in-memory KRL from its tenant's
// immutable events before the HTTP surface is exposed, and keeps the log so
// later reads can catch up. The event log remains the source of truth (AN-2);
// without this replay, every control-plane restart would briefly publish an
// empty KRL and could let a revoked certificate work again. Malformed matching
// history fails startup closed instead of serving a partial revocation view.
func (p *sshProtocol) restoreRevocations(ctx context.Context, log *events.Log) error {
	if p == nil || p.krl == nil {
		return errors.New("server: SSH protocol is unavailable during revocation replay")
	}
	if log == nil {
		return errors.New("server: SSH revocation replay requires the event log")
	}
	p.syncMu.Lock()
	p.log = log
	p.syncMu.Unlock()
	return p.syncRevocations(ctx, true)
}

// syncRevocations applies every tenant ssh.cert.revoked event appended since the
// last one this process read, whichever replica appended it. Catch-ups are
// serialized and coalesced: a caller that arrives while another catch-up is
// running waits for it, and skips its own when a catch-up that started after it
// arrived already succeeded, so at most one replay runs at a time. Unless force
// is set (startup, or right after this process recorded a revocation), a caller
// also skips when the last catch-up started less than sshKRLSyncInterval ago.
func (p *sshProtocol) syncRevocations(ctx context.Context, force bool) error {
	arrived := time.Now()
	p.syncMu.Lock()
	defer p.syncMu.Unlock()
	if p.log == nil {
		return errors.New("server: SSH revocation sync requires the event log")
	}
	if !p.syncedFrom.IsZero() {
		if p.syncedFrom.After(arrived) || (!force && arrived.Sub(p.syncedFrom) < sshKRLSyncInterval) {
			return nil
		}
	}
	started := time.Now()
	if err := p.log.Replay(ctx, p.applied+1, p.applyRevocationEvent); err != nil {
		return fmt.Errorf("server: replay SSH revocations: %w", err)
	}
	p.syncedFrom = started
	return nil
}

// applyRevocationEvent applies one event under syncMu. Every event advances the
// read position; only this tenant's ssh.cert.revoked events change the KRL.
func (p *sshProtocol) applyRevocationEvent(event events.Event) error {
	if event.Type == eventSSHCertRevoked && event.TenantID == p.tenantID {
		var req sshRevokeRequest
		if err := json.Unmarshal(event.Data, &req); err != nil {
			return fmt.Errorf("decode ssh.cert.revoked event %d: %w", event.Sequence, err)
		}
		req.KeyID = strings.TrimSpace(req.KeyID)
		if req.Serial == 0 && req.KeyID == "" {
			return fmt.Errorf("decode ssh.cert.revoked event %d: serial or key_id is required", event.Sequence)
		}
		p.Revoke(req.Serial, req.KeyID)
	}
	if event.Sequence > p.applied {
		p.applied = event.Sequence
	}
	return nil
}

func (p *sshProtocol) KRLVersion() uint64 { return p.krlVersion.Load() }

func (p *sshProtocol) RevokedCount() int {
	snap := p.krl.Distribute()
	return len(snap.Serials) + len(snap.KeyIDs)
}

// serveKRL emits the current KRL in the OpenSSH BINARY KRL format (PROTOCOL.krl) —
// the artifact sshd's RevokedKeys directive consumes and `ssh-keygen -Qf` reads
// (INTEROP-009). The JSON snapshot sshd cannot load is deliberately not served here.
// It first catches up with the event log (at most once per sshKRLSyncInterval), so
// a KRL from any replica lists every revocation recorded more than that long
// before the request; if it cannot, it answers 503 and the host keeps its last
// KRL rather than loading an incomplete one.
func (p *sshProtocol) serveKRL(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), sshKRLSyncTimeout)
	defer cancel()
	if err := p.syncRevocations(ctx, false); err != nil {
		http.Error(w, "ssh: the revocation list cannot be brought up to date; keep the last KRL and retry", http.StatusServiceUnavailable)
		return
	}
	der := p.krl.DistributeKRL(p.krlVersion.Load())
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="trstctl.krl"`)
	_, _ = w.Write(der)
}

// AuthorityKey exposes the SSH CA public key for the assembled-server acceptance test
// (so it can verify an issued cert against the CA without an HTTP round-trip).
func (p *sshProtocol) AuthorityKey() ([]byte, error) { return p.ca.AuthorityKey() }

// CA exposes the wrapped ssh.CA for the acceptance test.
func (p *sshProtocol) CA() *ssh.CA { return p.ca }

// KRLBytes returns the current binary KRL (for the acceptance test / ssh-keygen -Qf).
func (p *sshProtocol) KRLBytes() []byte { return p.krl.DistributeKRL(p.krlVersion.Load()) }

// spiffeProtocol holds the assembled SPIFFE Workload API gRPC server and its UDS
// path. It is served over the socket by Server.RunSPIFFE (a gRPC service, not on the
// HTTP mux).
type spiffeProtocol struct {
	server                 *spiffe.WorkloadAPIServer
	socket                 string
	tenantID               string
	registrationEntryCount int
	bulkheadReady          bool
	running                atomic.Bool
	// wl is the underlying issuance server, kept so the agent channel can reach
	// it for node-scoped fetches (epic B3). The Workload API server above wraps
	// the same value for the control plane's own socket; the agent path needs
	// the node-scoped entry point the wrapper does not expose.
	wl *spiffe.Server
	// trustDomain is carried for the console's per-host status view.
	trustDomain string
}

// RunSPIFFE serves the SPIFFE Workload API gRPC server on its UDS until ctx is
// canceled (EXC-WIRE-02 / INTEROP-004). It is a no-op when SPIFFE is not enabled or
// no issuing CA is provisioned, so it is always safe to start in its own goroutine.
func (s *Server) RunSPIFFE(ctx context.Context) {
	if s.protocols == nil || s.protocols.spiffe == nil {
		return
	}
	if !s.protocols.activation.Wait(ctx) {
		return
	}
	sp := s.protocols.spiffe
	sp.running.Store(true)
	defer sp.running.Store(false)
	if err := spiffe.ServeWorkloadAPI(ctx, sp.socket, sp.server); err != nil && ctx.Err() == nil {
		s.logger.Warn("spiffe workload API server stopped", "error", err.Error())
	}
}

// SPIFFESocket returns the UDS path the SPIFFE Workload API is served on, or "" when
// SPIFFE is not served. Exposed for the acceptance test (it dials this socket).
func (s *Server) SPIFFESocket() string {
	if s.protocols == nil || s.protocols.spiffe == nil {
		return ""
	}
	return s.protocols.spiffe.socket
}
