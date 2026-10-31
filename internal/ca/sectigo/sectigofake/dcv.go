// SPDX-License-Identifier: BUSL-1.1

package sectigofake

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"

	"trstctl.com/trstctl/internal/crypto"
)

// dcvState is one domain's TXT validation in the fake SCM.
type dcvState struct {
	host, point string
	validated   bool
}

// RequireDCV makes enrollment wait for DNS TXT domain control validation the
// way a public SCM account does: a name enrolls only after its domain is
// validated, and a submitted validation passes only when resolve shows the
// started record's value at its host.
func (s *Server) RequireDCV(resolve func(name string) []string) {
	s.mu.Lock()
	s.resolve = resolve
	s.mu.Unlock()
}

func (s *Server) handleDCVStart(w http.ResponseWriter, r *http.Request) {
	domain, ok := dcvDomain(w, r)
	if !ok {
		return
	}
	b, err := crypto.RandomBytes(16)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, -1, "random")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	state := &dcvState{host: "_" + hex.EncodeToString(b[:8]) + "." + domain, point: hex.EncodeToString(b[8:])}
	s.dcv[domain] = state
	writeJSON(w, http.StatusOK, map[string]any{"host": state.host, "point": state.point})
}

func (s *Server) handleDCVSubmit(w http.ResponseWriter, r *http.Request) {
	domain, ok := dcvDomain(w, r)
	if !ok {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.dcv[domain]
	if state == nil || s.resolve == nil {
		writeErr(w, http.StatusBadRequest, -1, "no validation was started for this domain")
		return
	}
	for _, value := range s.resolve(state.host) {
		if value == state.point {
			state.validated = true
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "SUBMITTED"})
}

func (s *Server) handleDCVStatus(w http.ResponseWriter, r *http.Request) {
	domain, ok := dcvDomain(w, r)
	if !ok {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	status := "NOT_VALIDATED"
	if state := s.dcv[domain]; state != nil && state.validated {
		status = "VALIDATED"
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": status})
}

// unvalidated reports a requested name whose domain SCM has not validated; the
// caller holds mu.
func (s *Server) unvalidated(names string) string {
	if s.resolve == nil {
		return ""
	}
	for _, name := range strings.Split(names, ",") {
		name = strings.TrimPrefix(strings.TrimSpace(name), "*.")
		if name == "" {
			continue
		}
		if state := s.dcv[name]; state == nil || !state.validated {
			return name
		}
	}
	return ""
}

func dcvDomain(w http.ResponseWriter, r *http.Request) (string, bool) {
	var body struct {
		Domain string `json:"domain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Domain) == "" {
		writeErr(w, http.StatusBadRequest, -1, "domain is required")
		return "", false
	}
	return strings.ToLower(strings.TrimSpace(body.Domain)), true
}
