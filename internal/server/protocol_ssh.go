// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"

	"trstctl.com/trstctl/internal/protocols/bodylimit"
	"trstctl.com/trstctl/internal/protocols/est"
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

	// auth gates the three MUTATING routes. Issuance and revocation are not
	// public: an SSH user certificate names its own principals, so an anonymous
	// caller could otherwise mint `root` for any host that trusts this CA, and an
	// anonymous revoker could poison the KRL. The two GET routes stay public
	// because they serve trust material a host must fetch before it can
	// authenticate anything (the CA public key and the binary KRL), exactly like
	// a CRL distribution point.
	auth sshAuthenticator

	// krlVersion is the monotonic OpenSSH KRL version a host uses to reject an older
	// KRL; it increments each time the served KRL is regenerated.
	krlVersion atomic.Uint64
}

// sshAuthenticator decides whether a request may mint or revoke an SSH
// certificate. It is deliberately the same credential path the served EST
// endpoint uses, so there is one audited token implementation rather than a
// second, SSH-shaped one.
type sshAuthenticator interface {
	Authenticate(r *http.Request) est.AuthenticationResult
}

// newSSHProtocol wires the served SSH CA surface over a built ssh.CA. A fresh KRL is
// attached so revocations published through it render as a binary KRL sshd consumes.
//
// auth must be non-nil: a nil authenticator would restore the anonymous-issuance
// defect, so construction fails closed rather than serving an open CA.
func newSSHProtocol(ca *ssh.CA, tenantID string, auth sshAuthenticator) (*sshProtocol, error) {
	if auth == nil {
		return nil, fmt.Errorf("server: served SSH CA requires an authenticator")
	}
	p := &sshProtocol{ca: ca, krl: ssh.NewKRL(), tenantID: tenantID, auth: auth}
	mux := http.NewServeMux()
	// Public trust material — a host must read these before it can trust anything.
	mux.HandleFunc("GET /ssh/ca", p.authorityKey)
	mux.HandleFunc("GET /ssh/krl", p.serveKRL)
	// Mutating routes: authenticated and authorized for certs:issue.
	mux.HandleFunc("POST /ssh/issue/user", p.authenticated(p.issue(true)))
	mux.HandleFunc("POST /ssh/issue/host", p.authenticated(p.issue(false)))
	mux.HandleFunc("POST /ssh/revoke", p.authenticated(p.revoke))
	p.mux = mux
	return p, nil
}

// authenticated wraps a mutating handler with the credential check. Denials
// carry the authenticator's fixed RFC 6750 challenge and never reflect a token,
// a store error, or whether the credential merely lacked authority.
func (p *sshProtocol) authenticated(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		result := p.auth.Authenticate(r)
		if !result.Allowed {
			status := result.StatusCode
			if status == 0 {
				status = http.StatusUnauthorized
			}
			if result.Challenge != "" {
				w.Header().Set("WWW-Authenticate", result.Challenge)
			}
			http.Error(w, "ssh: unauthorized", status)
			return
		}
		next(w, r)
	}
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

// issue mints an SSH user or host certificate through the signer-backed SSH CA.
func (p *sshProtocol) issue(userCert bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := bodylimit.ReadAll(r.Body, maxSSHJSONBody)
		if err == bodylimit.ErrTooLarge {
			http.Error(w, "ssh: request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		if err != nil {
			http.Error(w, "ssh: cannot read body", http.StatusBadRequest)
			return
		}
		var req sshIssueRequest
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "ssh: malformed request", http.StatusBadRequest)
			return
		}
		ttl := time.Duration(req.TTLSeconds) * time.Second
		if ttl <= 0 {
			ttl = time.Hour
		}
		// A permissive served profile: principals/TTL come from the request and are
		// bounded by a max TTL; default extensions enable interactive use. Per-tenant
		// SSH profiles (force-command, source-address) are a profile-model follow-up.
		profile := ssh.Profile{
			Name:           "served-ssh",
			MaxTTL:         24 * time.Hour,
			AllowUserCerts: userCert,
			AllowHostCerts: !userCert,
			DefaultExtensions: map[string]string{
				"permit-pty":              "",
				"permit-user-rc":          "",
				"permit-port-forwarding":  "",
				"permit-agent-forwarding": "",
			},
		}
		issReq := ssh.IssueRequest{
			SubjectPublicKey: []byte(req.PublicKey),
			KeyID:            req.KeyID,
			Principals:       req.Principals,
			TTL:              ttl,
			CriticalOptions:  req.CriticalOptions,
			Extensions:       req.Extensions,
		}
		var issued ssh.Issued
		if userCert {
			issued, err = p.ca.IssueUserCert(r.Context(), profile, issReq)
		} else {
			issued, err = p.ca.IssueHostCert(r.Context(), profile, issReq)
		}
		if err != nil {
			http.Error(w, "ssh: issuance refused: "+err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(sshIssueResponse{
			Certificate: string(issued.Certificate),
			Serial:      issued.Serial,
			KeyID:       issued.KeyID,
			ValidBefore: issued.ValidBefore.UTC().Format(time.RFC3339),
		})
	}
}

// sshRevokeRequest revokes an SSH certificate by serial or key id.
type sshRevokeRequest struct {
	Serial uint64 `json:"serial,omitempty"`
	KeyID  string `json:"key_id,omitempty"`
}

// revoke records an SSH cert revocation in the KRL so the next /ssh/krl reflects it.
func (p *sshProtocol) revoke(w http.ResponseWriter, r *http.Request) {
	body, err := bodylimit.ReadAll(r.Body, maxSSHJSONBody)
	if err == bodylimit.ErrTooLarge {
		http.Error(w, "ssh: request body too large", http.StatusRequestEntityTooLarge)
		return
	}
	if err != nil {
		http.Error(w, "ssh: cannot read body", http.StatusBadRequest)
		return
	}
	var req sshRevokeRequest
	if err := json.Unmarshal(body, &req); err != nil || (req.Serial == 0 && req.KeyID == "") {
		http.Error(w, "ssh: malformed revoke request", http.StatusBadRequest)
		return
	}
	p.Revoke(req.Serial, req.KeyID)
	w.WriteHeader(http.StatusNoContent)
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

func (p *sshProtocol) KRLVersion() uint64 { return p.krlVersion.Load() }

func (p *sshProtocol) RevokedCount() int {
	snap := p.krl.Distribute()
	return len(snap.Serials) + len(snap.KeyIDs)
}

// serveKRL emits the current KRL in the OpenSSH BINARY KRL format (PROTOCOL.krl) —
// the artifact sshd's RevokedKeys directive consumes and `ssh-keygen -Qf` reads
// (INTEROP-009). The JSON snapshot sshd cannot load is deliberately not served here.
func (p *sshProtocol) serveKRL(w http.ResponseWriter, _ *http.Request) {
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
// cancelled (EXC-WIRE-02 / INTEROP-004). It is a no-op when SPIFFE is not enabled or
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
