package enroll

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/secretjson"
)

const maxBody = 1 << 20

// enrollRequest is the JSON body of an enrollment request: a base64 CSR (DER)
// and, for bootstrap, the one-time token.
type enrollRequest struct {
	Token secretjson.StringBytes `json:"token,omitempty"`
	CSR   string                 `json:"csr"`
}

func (r *enrollRequest) wipeSecrets() { secret.Wipe([]byte(r.Token)) }

type enrollResponse struct {
	Certificate string `json:"certificate,omitempty"` // PEM chain
	Error       string `json:"error,omitempty"`
}

// Handler serves the enrollment endpoints over HTTP: POST /enroll/bootstrap
// (token + CSR) and POST /enroll/renewal (CSR).
//
// Renewal authentication is enforced IN CODE, not by deployment topology: the
// handler passes the TLS stack's verified peer chain to EnrollRenewal, which
// refuses unless the caller presented a verified client certificate carrying a
// tenant SPIFFE SAN, and binds the renewed certificate to that same tenant
// (WIRE-006). If this handler is mounted over plain TLS with no client-cert
// verification, r.TLS.VerifiedChains is empty and every renewal is rejected — so a
// misconfiguration fails closed rather than exposing an unauthenticated
// cert-minting endpoint. (The served API does not mount renewal today; it 404s —
// DOCS-001. This handler is library-complete and safe to serve once the verified
// mTLS listener is wired, EXC-WIRE-02.)
func Handler(a *Authority) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /enroll/bootstrap", func(w http.ResponseWriter, r *http.Request) {
		req, csr, ok := decode(w, r)
		if !ok {
			return
		}
		defer req.wipeSecrets()
		chain, err := a.EnrollBootstrap(r.Context(), []byte(req.Token), csr)
		respond(w, chain, err)
	})
	mux.HandleFunc("POST /enroll/renewal", func(w http.ResponseWriter, r *http.Request) {
		req, csr, ok := decode(w, r)
		if !ok {
			return
		}
		defer req.wipeSecrets()
		chain, err := a.EnrollRenewal(r.Context(), verifiedPeerCertsDER(r), csr)
		respond(w, chain, err)
	})
	return mux
}

// verifiedPeerCertsDER extracts the DER of the verified client-certificate chain
// (leaf first) from the request's TLS state. It returns nil when there is no TLS
// or no verified chain — i.e. when the caller was not authenticated by a client
// certificate — so EnrollRenewal fails closed. Only VerifiedChains (not the raw
// PeerCertificates) is used, so an unverified/attacker-supplied cert is ignored.
func verifiedPeerCertsDER(r *http.Request) [][]byte {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
		return nil
	}
	leaf := r.TLS.VerifiedChains[0][0]
	return [][]byte{leaf.Raw}
}

func decode(w http.ResponseWriter, r *http.Request) (enrollRequest, []byte, bool) {
	var req enrollRequest
	data, err := io.ReadAll(io.LimitReader(r.Body, maxBody))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "cannot read request")
		return req, nil, false
	}
	if err := json.Unmarshal(data, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return req, nil, false
	}
	csr, err := base64.StdEncoding.DecodeString(req.CSR)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "csr is not valid base64")
		return req, nil, false
	}
	return req, csr, true
}

func respond(w http.ResponseWriter, chain []byte, err error) {
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, ErrBadToken) {
			status = http.StatusForbidden
		}
		writeErr(w, status, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, enrollResponse{Certificate: string(chain)})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, enrollResponse{Error: msg})
}
