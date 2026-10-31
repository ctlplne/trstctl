// SPDX-License-Identifier: BUSL-1.1

package digicertfake

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"trstctl.com/trstctl/internal/crypto/certinfo"
)

// RequireRevocationApproval makes revocation requests wait for an approver, the
// way an account without skip-approval rights behaves.
func (s *Server) RequireRevocationApproval(on bool) {
	s.mu.Lock()
	s.revokeNeedsApproval = on
	s.mu.Unlock()
}

// Revocations returns each revoked certificate id with its CertCentral reason.
func (s *Server) Revocations() map[int]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[int]string, len(s.revoked))
	for id, reason := range s.revoked {
		out[id] = reason
	}
	return out
}

func serialKey(serial string) string {
	return strings.TrimLeft(strings.ToUpper(strings.NewReplacer(":", "", " ", "").Replace(serial)), "0")
}

// handleOrderList mirrors GET /services/v2/order/certificate filtered by
// filters[serial_number].
func (s *Server) handleOrderList(w http.ResponseWriter, r *http.Request) {
	want := serialKey(r.URL.Query().Get("filters[serial_number]"))
	s.mu.Lock()
	defer s.mu.Unlock()
	orders := []map[string]any{}
	for _, o := range s.orders {
		info, err := certinfo.Inspect(s.certs[o.certID])
		if err != nil || want == "" || serialKey(info.SerialNumber) != want {
			continue
		}
		orders = append(orders, map[string]any{
			"id": o.id, "status": o.status,
			"certificate": map[string]any{"id": o.certID, "serial_number": strings.ToUpper(info.SerialNumber)},
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"orders": orders})
}

// handleRevoke mirrors PUT /services/v2/certificate/{certID}/revoke.
func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	certID, err := strconv.Atoi(r.PathValue("certID"))
	var body struct {
		Reason       string `json:"reason"`
		SkipApproval bool   `json:"skip_approval"`
	}
	if err != nil || json.NewDecoder(r.Body).Decode(&body) != nil {
		writeErr(w, http.StatusBadRequest, "bad_request_format", "could not parse revoke request")
		return
	}
	switch body.Reason {
	case "unspecified", "key_compromise", "affiliation_changed", "superseded", "cessation_of_operation":
	default:
		writeErr(w, http.StatusBadRequest, "invalid_reason", "unsupported revocation reason")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var target *order
	for _, o := range s.orders {
		if o.certID == certID {
			target = o
		}
	}
	if target == nil {
		writeErr(w, http.StatusNotFound, "not_found|certificate", "certificate not found")
		return
	}
	if target.status == "revoked" {
		writeErr(w, http.StatusBadRequest, "invalid_status", "the certificate is already revoked")
		return
	}
	s.seq++
	if s.revokeNeedsApproval || !body.SkipApproval {
		writeJSON(w, http.StatusCreated, map[string]any{"id": s.seq, "status": "pending"})
		return
	}
	target.status = "revoked"
	s.revoked[certID] = body.Reason
	writeJSON(w, http.StatusCreated, map[string]any{"id": s.seq, "status": "approved"})
}
