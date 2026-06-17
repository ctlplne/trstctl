package server

import (
	"context"
	"encoding/json"
	"net/http"
	"sync/atomic"
	"time"

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

	// krlVersion is the monotonic OpenSSH KRL version a host uses to reject an older
	// KRL; it increments each time the served KRL is regenerated.
	krlVersion atomic.Uint64
}

// newSSHProtocol wires the served SSH CA surface over a built ssh.CA. A fresh KRL is
// attached so revocations published through it render as a binary KRL sshd consumes.
func newSSHProtocol(ca *ssh.CA, tenantID string) (*sshProtocol, error) {
	p := &sshProtocol{ca: ca, krl: ssh.NewKRL(), tenantID: tenantID}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /ssh/ca", p.authorityKey)
	mux.HandleFunc("POST /ssh/issue/user", p.issue(true))
	mux.HandleFunc("POST /ssh/issue/host", p.issue(false))
	mux.HandleFunc("GET /ssh/krl", p.serveKRL)
	mux.HandleFunc("POST /ssh/revoke", p.revoke)
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
	if req.Serial != 0 {
		p.krl.RevokeSerial(req.Serial)
	}
	if req.KeyID != "" {
		p.krl.RevokeKeyID(req.KeyID)
	}
	p.krlVersion.Add(1)
	w.WriteHeader(http.StatusNoContent)
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
	server *spiffe.WorkloadAPIServer
	socket string
}

// RunSPIFFE serves the SPIFFE Workload API gRPC server on its UDS until ctx is
// cancelled (EXC-WIRE-02 / INTEROP-004). It is a no-op when SPIFFE is not enabled or
// no issuing CA is provisioned, so it is always safe to start in its own goroutine.
func (s *Server) RunSPIFFE(ctx context.Context) {
	if s.protocols == nil || s.protocols.spiffe == nil {
		return
	}
	sp := s.protocols.spiffe
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
