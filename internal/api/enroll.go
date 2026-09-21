// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/protocol"
	"trstctl.com/trstctl/internal/tenancy"
)

// ErrInvalidBootstrapToken is what a BootstrapEnroller returns (recognizable via
// errors.Is) when a presented bootstrap token is unknown or already used. The API
// maps it to 401 so a bad token is an authentication failure, not a server error.
// It is declared here so the API never imports the enrollment authority's
// transport stack (the same decoupling as BootstrapTokenIssuer).
var ErrInvalidBootstrapToken = errors.New("api: invalid or already-used bootstrap token")

// ErrUnauthenticatedAgentRenewal is what a renewal-capable enroller returns when a
// request is not authenticated by a verified current agent client certificate.
var ErrUnauthenticatedAgentRenewal = errors.New("api: agent renewal requires a verified client certificate")

// BootstrapTokenIssuer mints one-time agent bootstrap tokens (S5.1) bound to the
// authorizing tenant (WIRE-003/AN-1). The web first-run wizard (S7.3) uses it to
// build the agent install command; the agent presents the token once to enroll,
// and the issued certificate is attributed to tenantID. The API depends only on
// this minimal interface so it never imports the enrollment authority's transport
// stack.
type BootstrapTokenIssuer interface {
	IssueBootstrapToken(
		ctx context.Context,
		tenantID, allowedIdentity string,
	) ([]byte, error)
	// IssueBootstrapTokenWithRoles mints a token carrying a capability grant
	// (epic A2). The roles are recorded with the token and stamped by the CA into
	// the certificate the agent receives, so what an agent may be asked to do is
	// fixed by the operator who enrolled it rather than by anything the agent
	// says about itself later. Empty roles mean host-only.
	IssueBootstrapTokenWithRoles(
		ctx context.Context,
		tenantID, allowedIdentity string,
		roles []string,
	) ([]byte, error)
}

// BootstrapEnroller consumes a one-time agent bootstrap token and signs the
// agent's CSR into a client-certificate chain (PEM), and exposes the CA bundle an
// agent trusts. Agents generate keys locally and submit only a CSR, so private
// keys never reach the control plane.
type BootstrapEnroller interface {
	EnrollBootstrap(ctx context.Context, token []byte, csrDER []byte) ([]byte, error)
	CABundlePEM() []byte
}

// RenewalEnroller signs an agent's rotation CSR after the caller has already
// authenticated with its current, verified agent client certificate. The peer
// chain is DER and leaf-first; the implementation binds the new certificate to
// the tenant in that verified leaf rather than trusting the CSR.
type RenewalEnroller interface {
	EnrollRenewal(ctx context.Context, peerCertsDER [][]byte, csrDER []byte) ([]byte, error)
}

// WithAgentEnroller wires the authority that backs POST /enroll/bootstrap — the
// path an agent presents its one-time token and CSR to. If the authority also
// implements RenewalEnroller, AgentRenewalHandler exposes POST /enroll/renewal for
// the dedicated agent-CA mTLS listener. When unset, the routes are not mounted (the
// capability is simply absent).
func WithAgentEnroller(e BootstrapEnroller) Option {
	return func(c *config) { c.agentEnroller = e }
}

// AgentRenewalHandler returns a narrow handler for the dedicated embedded-agent
// renewal listener. It exposes only POST /enroll/renewal; bootstrap stays on the
// control-plane HTTPS surface because it is token-authenticated, while renewal is
// additionally enforced by the listener's agent-CA mTLS handshake.
func (a *API) AgentRenewalHandler() http.Handler {
	mux := http.NewServeMux()
	if a.agentEnroller != nil {
		if _, ok := a.agentEnroller.(RenewalEnroller); ok {
			mux.HandleFunc("POST /enroll/renewal", a.enrollRenewal)
		}
	}
	return mux
}

// enrollBootstrapRequest is the body an agent POSTs to /enroll/bootstrap: the
// one-time token from the wizard and its CSR (PEM, or base64-encoded DER).
type enrollBootstrapRequest struct {
	Token secretJSONBytes `json:"token"`
	CSR   string          `json:"csr"`
}

// enrollBootstrapResponse returns the signed client-certificate chain and the CA
// bundle the agent installs to trust the control plane.
type enrollBootstrapResponse struct {
	Certificate string `json:"certificate"`
	CABundle    string `json:"ca_bundle"`
}

// enrollBootstrap signs an agent's CSR into a client certificate after consuming
// its one-time bootstrap token (S5.1/F15). The token authenticates the request
// (so the route carries no RBAC permission and lives outside /api); a bad or
// reused token is a 401. It performs no store mutation — the agent registers
// itself over its new mTLS identity afterward — so it is not idempotency-keyed.
func (a *API) enrollBootstrap(w http.ResponseWriter, r *http.Request) {
	result := "failed"
	defer func() { a.observeAgentEnrollment(result) }()
	if a.agentEnroller == nil {
		a.writeError(w, errStatus(http.StatusServiceUnavailable, "agent enrollment is not configured"))
		return
	}
	if !a.negotiateAgentProtocol(w, r) {
		return
	}
	var req enrollBootstrapRequest
	if err := decodeJSON(r, &req); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	defer req.Token.wipe()
	if len(req.Token) == 0 || req.CSR == "" {
		a.writeError(w, errStatus(http.StatusBadRequest, "both token and csr are required"))
		return
	}
	if !a.allowSpecialRouteRequest(w, r, specialRouteAbuseRequest{TokenKey: "enroll:" + crypto.SHA256Hex([]byte(req.Token))}) {
		return
	}
	csrDER, err := decodeCSR(req.CSR)
	if err != nil {
		a.writeError(w, errStatus(http.StatusBadRequest, err.Error()))
		return
	}
	chain, err := a.agentEnroller.EnrollBootstrap(r.Context(), []byte(req.Token), csrDER)
	if err != nil {
		if errors.Is(err, tenancy.ErrServiceUnavailable) {
			a.writeError(w, errStatus(http.StatusForbidden, err.Error()))
			return
		}
		if errors.Is(err, ErrInvalidBootstrapToken) {
			a.writeError(w, errStatus(http.StatusUnauthorized, "invalid or already-used bootstrap token"))
			return
		}
		a.writeError(w, err)
		return
	}
	result = "success"
	a.writeJSON(w, http.StatusOK, enrollBootstrapResponse{
		Certificate: string(chain),
		CABundle:    string(a.agentEnroller.CABundlePEM()),
	})
}

type enrollRenewalRequest struct {
	CSR string `json:"csr"`
}

// enrollRenewal signs a rotation CSR after the caller authenticates with the
// current agent client certificate. It intentionally lives outside /api/v1 and has
// no bearer/RBAC path: the credential boundary is the verified agent mTLS peer
// chain. A missing, raw-unverified, expired, or not-yet-valid client certificate is
// a 401, and the enrollment authority receives only DER from VerifiedChains.
func (a *API) enrollRenewal(w http.ResponseWriter, r *http.Request) {
	if a.agentEnroller == nil {
		a.writeError(w, errStatus(http.StatusServiceUnavailable, "agent enrollment is not configured"))
		return
	}
	renewal, ok := a.agentEnroller.(RenewalEnroller)
	if !ok {
		a.writeError(w, errStatus(http.StatusServiceUnavailable, "agent renewal is not configured"))
		return
	}
	if !a.negotiateAgentProtocol(w, r) {
		return
	}
	peerCertsDER, err := mtls.VerifiedPeerCertsDERFromTLS(r.TLS)
	if err != nil {
		a.writeError(w, errStatus(http.StatusUnauthorized, "agent renewal requires a valid verified client certificate"))
		return
	}
	tenantID, err := mtls.TenantFromClientCert(peerCertsDER[0])
	if err != nil {
		a.writeError(w, errStatus(http.StatusUnauthorized, "agent renewal certificate is not tenant-attributed"))
		return
	}
	fingerprint, err := mtls.CertFingerprintSHA256(peerCertsDER[0])
	if err != nil {
		a.writeError(w, errStatus(http.StatusUnauthorized, "agent renewal certificate is invalid"))
		return
	}
	if !a.allowSpecialRouteRequest(w, r, specialRouteAbuseRequest{
		TokenKey: "enroll-renewal:" + fingerprint,
		TenantID: tenantID,
	}) {
		return
	}
	var req enrollRenewalRequest
	if err := decodeJSON(r, &req); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	if req.CSR == "" {
		a.writeError(w, errStatus(http.StatusBadRequest, "csr is required"))
		return
	}
	csrDER, err := decodeCSR(req.CSR)
	if err != nil {
		a.writeError(w, errStatus(http.StatusBadRequest, err.Error()))
		return
	}
	signRenewal := func(ctx context.Context) ([]byte, error) {
		return renewal.EnrollRenewal(ctx, peerCertsDER, csrDER)
	}
	var chain []byte
	if a.idem != nil {
		chain, err = a.idem.Do(r.Context(), tenantID, "agent-enroll-renewal:"+fingerprint+":"+crypto.SHA256Hex(csrDER), signRenewal)
	} else {
		chain, err = signRenewal(r.Context())
	}
	if err != nil {
		if errors.Is(err, ErrUnauthenticatedAgentRenewal) {
			a.writeError(w, errStatus(http.StatusUnauthorized, "agent renewal requires a valid verified client certificate"))
			return
		}
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, enrollBootstrapResponse{
		Certificate: string(chain),
		CABundle:    string(a.agentEnroller.CABundlePEM()),
	})
}

func (a *API) negotiateAgentProtocol(w http.ResponseWriter, r *http.Request) bool {
	// Agent↔control-plane version negotiation (SCHEMA-003): the server always echoes
	// the protocol version it speaks, and rejects an agent whose protocol is outside
	// the supported window with a clear, actionable error instead of failing opaquely
	// later. A pre-handshake agent (no header) reads as the baseline and is accepted,
	// so the handshake is additive and does not break already-deployed agents.
	w.Header().Set(protocol.HeaderServerProtocol, strconv.Itoa(protocol.Version))
	if ver := protocol.ParseAgentProtocol(r.Header); !protocol.Supported(ver) {
		a.writeError(w, errStatus(http.StatusBadRequest, fmt.Sprintf(
			"unsupported agent protocol version %d (this control plane supports %d-%d); upgrade or downgrade the agent",
			ver, protocol.MinSupportedVersion, protocol.MaxSupportedVersion)))
		return false
	}
	return true
}

func (a *API) observeAgentEnrollment(result string) {
	if a.agentEnrollmentObserver != nil {
		a.agentEnrollmentObserver(result)
	}
}

// decodeCSR accepts a CSR as PEM or as base64-encoded DER and returns the DER.
func decodeCSR(s string) ([]byte, error) {
	if blk, _ := pem.Decode([]byte(s)); blk != nil {
		return blk.Bytes, nil
	}
	der, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, errors.New("csr must be PEM or base64-encoded DER")
	}
	return der, nil
}
