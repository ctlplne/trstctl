// SPDX-License-Identifier: BUSL-1.1

package venafifake

import (
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"strings"
	"time"

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

// RevokeByDNOnly makes the double a Venafi policy that revokes only by
// CertificateDN, refusing a revocation addressed by thumbprint (OD-7).
func (s *Server) RevokeByDNOnly() {
	s.mu.Lock()
	s.revokeByDNOnly = true
	s.mu.Unlock()
}

// Renew replaces the current certificate of the object that holds
// certificatePEM with one issued from csrDER, keeping the old one in the
// object's history, and returns the object's DN, so a test can show that a
// revocation by DN never takes the object's newer certificate in place of
// the one it names (OD-7).
func (s *Server) Renew(certificatePEM, csrDER []byte) (string, error) {
	block, _ := pem.Decode(certificatePEM)
	if block == nil {
		return "", errors.New("venafifake: no certificate to renew")
	}
	thumbprint := crypto.CertificateSHA1Thumbprint(block.Bytes)
	issued, err := s.authority.IssueFromCSR(csrDER, 90*24*time.Hour)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for dn, chain := range s.certs {
		if current, _ := pem.Decode(chain); current != nil && crypto.CertificateSHA1Thumbprint(current.Bytes) == thumbprint {
			s.history[dn] = append(s.history[dn], chain)
			s.certs[dn] = issued.CertificatePEM
			return dn, nil
		}
	}
	return "", errors.New("venafifake: no object holds that certificate")
}

// handleSearch mirrors GET Certificates with the Thumbprint filter: every
// object whose current certificate, or a replaced one in its history, has
// that thumbprint, each summarized with its current certificate's X509.
func (s *Server) handleSearch(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/vedsdk/Certificates/" {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	want := strings.ToUpper(r.URL.Query().Get("Thumbprint"))
	type summary struct {
		DN   string `json:"DN"`
		Guid string `json:"Guid"`
		X509 struct {
			Thumbprint string `json:"Thumbprint"`
		} `json:"X509"`
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var found []summary
	for dn, chain := range s.certs {
		current, _ := pem.Decode(chain)
		if current == nil {
			continue
		}
		matches := crypto.CertificateSHA1Thumbprint(current.Bytes) == want
		for _, old := range s.history[dn] {
			if block, _ := pem.Decode(old); block != nil && crypto.CertificateSHA1Thumbprint(block.Bytes) == want {
				matches = true
			}
		}
		if !matches {
			continue
		}
		item := summary{DN: dn}
		for guid, guidDN := range s.guids {
			if guidDN == dn {
				item.Guid = guid
			}
		}
		item.X509.Thumbprint = crypto.CertificateSHA1Thumbprint(current.Bytes)
		found = append(found, item)
	}
	writeJSON(w, http.StatusOK, map[string]any{"Certificates": found, "TotalCount": len(found)})
}

// handleRevoke mirrors POST /vedsdk/Certificates/Revoke addressed by SHA-1
// thumbprint or by CertificateDN, which revokes the object's current
// certificate. Revoking a revoked certificate answers revoked again.
func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Thumbprint    string `json:"Thumbprint"`
		CertificateDN string `json:"CertificateDN"`
		Reason        int    `json:"Reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || (body.Thumbprint == "" && body.CertificateDN == "") {
		writeJSON(w, http.StatusBadRequest, map[string]any{"Success": false, "Error": "Need either CertificateDN or Thumbprint"})
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if body.CertificateDN != "" {
		if _, ok := s.certs[body.CertificateDN]; !ok {
			writeJSON(w, http.StatusBadRequest, map[string]any{"Success": false, "Error": "Certificate [ " + body.CertificateDN + " ] does not have a certificate to revoke."})
			return
		}
		if _, done := s.revoked[body.CertificateDN]; !done {
			s.revoked[body.CertificateDN] = body.Reason
		}
		writeJSON(w, http.StatusOK, map[string]any{"Success": true, "Requested": true, "Revoked": true})
		return
	}
	if s.revokeByDNOnly {
		writeJSON(w, http.StatusBadRequest, map[string]any{"Success": false, "Error": "This policy revokes only by CertificateDN"})
		return
	}
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
	writeJSON(w, http.StatusBadRequest, map[string]any{"Success": false, "Error": "Could not find a certificate with the [" + body.Thumbprint + "] thumbprint."})
}
