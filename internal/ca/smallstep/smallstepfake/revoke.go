// SPDX-License-Identifier: BUSL-1.1

package smallstepfake

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/crypto/jose"
)

// revocations is the fake's revocation table, keyed by decimal serial the way
// step-ca's database keys it.
type revocations struct {
	mu      sync.Mutex
	reasons map[string]int
}

// Revoked reports whether serial (decimal) is revoked, and with which reason
// code.
func (s *Server) Revoked(serial string) (int, bool) {
	s.revoked.mu.Lock()
	defer s.revoked.mu.Unlock()
	reason, ok := s.revoked.reasons[serial]
	return reason, ok
}

// handleRevoke mirrors step-ca's POST /1.0/revoke for a JWK-provisioner token:
// the token's subject must be the serial and its audience the revoke URL;
// revocation is passive, and a second revocation of a serial is refused as
// already revoked.
func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Serial     string `json:"serial"`
		OTT        string `json:"ott"`
		ReasonCode int    `json:"reasonCode"`
		Passive    bool   `json:"passive"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Serial == "" {
		writeErr(w, http.StatusBadRequest, "could not parse revoke request")
		return
	}
	payload, err := jose.VerifyHS256(s.key, body.OTT)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "the provisioner token signature is invalid")
		return
	}
	var claims struct {
		Iss string `json:"iss"`
		Aud string `json:"aud"`
		Sub string `json:"sub"`
		Exp int64  `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		writeErr(w, http.StatusUnauthorized, "invalid token claims")
		return
	}
	switch {
	case claims.Iss != provisionerName:
		writeErr(w, http.StatusUnauthorized, "token issued by an unknown provisioner")
		return
	case claims.Aud != s.ts.URL+"/1.0/revoke":
		writeErr(w, http.StatusUnauthorized, "token audience is not the revoke endpoint")
		return
	case claims.Sub != body.Serial:
		writeErr(w, http.StatusUnauthorized, "token subject does not match the serial")
		return
	case claims.Exp != 0 && time.Now().Unix() > claims.Exp:
		writeErr(w, http.StatusUnauthorized, "token has expired")
		return
	case !body.Passive:
		writeErr(w, http.StatusNotImplemented, "only passive revocation is supported")
		return
	}
	s.revoked.mu.Lock()
	defer s.revoked.mu.Unlock()
	if _, ok := s.revoked.reasons[body.Serial]; ok {
		writeErr(w, http.StatusBadRequest, "certificate with serial number "+body.Serial+" has already been revoked")
		return
	}
	s.revoked.reasons[body.Serial] = body.ReasonCode
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

// RevokedCount is how many serials the fake step-ca has revoked.
func (s *Server) RevokedCount() int {
	s.revoked.mu.Lock()
	defer s.revoked.mu.Unlock()
	return len(s.revoked.reasons)
}
