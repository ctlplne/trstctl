// SPDX-License-Identifier: BUSL-1.1

package venafifake

import (
	"encoding/json"
	"encoding/pem"
	"net/http"
	"strings"

	"trstctl.com/trstctl/internal/crypto"
)

// Revocations returns each revoked certificate DN with the reason it was
// revoked with.
func (s *Server) Revocations() map[string]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]int, len(s.revoked))
	for dn, reason := range s.revoked {
		out[dn] = reason
	}
	return out
}

// handleRevoke mirrors POST /vedsdk/Certificates/Revoke addressed by SHA-1
// thumbprint. Revoking a revoked certificate answers revoked again.
func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Thumbprint string `json:"Thumbprint"`
		Reason     int    `json:"Reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Thumbprint == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"Success": false, "Error": "Thumbprint or CertificateDN is required"})
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for dn, chain := range s.certs {
		block, _ := pem.Decode(chain)
		if block == nil || crypto.CertificateSHA1Thumbprint(block.Bytes) != strings.ToUpper(body.Thumbprint) {
			continue
		}
		if _, done := s.revoked[dn]; !done {
			s.revoked[dn] = body.Reason
		}
		writeJSON(w, http.StatusOK, map[string]any{"Success": true, "Requested": true, "Revoked": true})
		return
	}
	writeJSON(w, http.StatusBadRequest, map[string]any{"Success": false, "Error": "Certificate does not exist"})
}
