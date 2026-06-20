package api

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"trstctl.com/trstctl/internal/protocol"
)

// ErrInvalidBootstrapToken is what a BootstrapEnroller returns (recognizable via
// errors.Is) when a presented bootstrap token is unknown or already used. The API
// maps it to 401 so a bad token is an authentication failure, not a server error.
// It is declared here so the API never imports the enrollment authority's
// transport stack (the same decoupling as BootstrapTokenIssuer).
var ErrInvalidBootstrapToken = errors.New("api: invalid or already-used bootstrap token")

// BootstrapEnroller consumes a one-time agent bootstrap token and signs the
// agent's CSR into a client-certificate chain (PEM), and exposes the CA bundle an
// agent trusts. Agents generate keys locally and submit only a CSR, so private
// keys never reach the control plane.
type BootstrapEnroller interface {
	EnrollBootstrap(ctx context.Context, token string, csrDER []byte) ([]byte, error)
	CABundlePEM() []byte
}

// WithAgentEnroller wires the authority that backs POST /enroll/bootstrap — the
// path an agent presents its one-time token and CSR to. When unset, the route is
// not mounted (the capability is simply absent).
func WithAgentEnroller(e BootstrapEnroller) Option {
	return func(c *config) { c.agentEnroller = e }
}

// enrollBootstrapRequest is the body an agent POSTs to /enroll/bootstrap: the
// one-time token from the wizard and its CSR (PEM, or base64-encoded DER).
type enrollBootstrapRequest struct {
	Token string `json:"token"`
	CSR   string `json:"csr"`
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
// itself over its new mTLS identity afterwards — so it is not idempotency-keyed.
func (a *API) enrollBootstrap(w http.ResponseWriter, r *http.Request) {
	if a.agentEnroller == nil {
		a.writeError(w, errStatus(http.StatusServiceUnavailable, "agent enrollment is not configured"))
		return
	}
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
		return
	}
	var req enrollBootstrapRequest
	if err := decodeJSON(r, &req); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	if req.Token == "" || req.CSR == "" {
		a.writeError(w, errStatus(http.StatusBadRequest, "both token and csr are required"))
		return
	}
	csrDER, err := decodeCSR(req.CSR)
	if err != nil {
		a.writeError(w, errStatus(http.StatusBadRequest, err.Error()))
		return
	}
	chain, err := a.agentEnroller.EnrollBootstrap(r.Context(), req.Token, csrDER)
	if err != nil {
		if errors.Is(err, ErrInvalidBootstrapToken) {
			a.writeError(w, errStatus(http.StatusUnauthorized, "invalid or already-used bootstrap token"))
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
