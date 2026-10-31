// SPDX-License-Identifier: BUSL-1.1

package sectigofake

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"trstctl.com/trstctl/internal/crypto/certinfo"
)

// Revocations returns each revoked sslId with the reason code it was revoked
// with.
func (s *Server) Revocations() map[int]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[int]int, len(s.revoked))
	for id, reason := range s.revoked {
		out[id] = reason
	}
	return out
}

func normalizeSerial(serial string) string {
	return strings.TrimLeft(strings.ToUpper(strings.NewReplacer(":", "", " ", "").Replace(serial)), "0")
}

// sslIDBySerial finds the certificate with this serial; the caller holds mu.
func (s *Server) sslIDBySerial(serial string) (int, bool) {
	want := normalizeSerial(serial)
	for id, chain := range s.certs {
		info, err := certinfo.Inspect(chain)
		if err == nil && normalizeSerial(info.SerialNumber) == want {
			return id, true
		}
	}
	return 0, false
}

// handleRevokeBySerial mirrors POST /api/ssl/v1/revoke/serial/{serial}: 204 on
// revocation, and SCM's refusal for a certificate it already revoked.
func (s *Server) handleRevokeBySerial(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ReasonCode int    `json:"reasonCode"`
		Reason     string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Reason == "" {
		writeErr(w, http.StatusBadRequest, -1, "reason is required")
		return
	}
	switch body.ReasonCode {
	case 0, 1, 3, 4, 5:
	default:
		writeErr(w, http.StatusBadRequest, -1, "unsupported reason code")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.sslIDBySerial(r.PathValue("serial"))
	if !ok {
		writeErr(w, http.StatusNotFound, -1, "certificate not found")
		return
	}
	if _, done := s.revoked[id]; done {
		writeErr(w, http.StatusBadRequest, -1, "certificate is already revoked")
		return
	}
	s.revoked[id] = body.ReasonCode
	w.WriteHeader(http.StatusNoContent)
}

// handleList mirrors GET /api/ssl/v1?serialNumber=...
func (s *Server) handleList(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []map[string]any{}
	if id, ok := s.sslIDBySerial(r.URL.Query().Get("serialNumber")); ok {
		out = append(out, map[string]any{"sslId": id})
	}
	writeJSON(w, http.StatusOK, out)
}

// handleDetail mirrors GET /api/ssl/v1/{sslID}'s status.
func (s *Server) handleDetail(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("sslID"))
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.certs[id]; err != nil || !ok {
		writeErr(w, http.StatusNotFound, -1, "certificate not found")
		return
	}
	status := "Issued"
	if _, done := s.revoked[id]; done {
		status = "Revoked"
	}
	writeJSON(w, http.StatusOK, map[string]any{"sslId": id, "status": status})
}
