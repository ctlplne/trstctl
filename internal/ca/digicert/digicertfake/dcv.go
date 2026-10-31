// SPDX-License-Identifier: BUSL-1.1

package digicertfake

import (
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

// pendingDCV is an order waiting for its DNS TXT domain validation.
type pendingDCV struct {
	csr    []byte
	ttl    time.Duration
	names  []string
	random string
}

// RequireDCV makes new orders wait for DNS TXT domain validation the way a
// public CertCentral account does: an order that asks for dns-txt-token gets a
// random value, and check-dcv issues it only once resolve shows that value at
// _dnsauth.<name> for every name on the order.
func (s *Server) RequireDCV(resolve func(name string) []string) {
	s.mu.Lock()
	s.resolve = resolve
	s.mu.Unlock()
}

func dcvRandomValue() string {
	b, err := crypto.RandomBytes(16)
	if err != nil {
		return "dcv-random-value"
	}
	return hex.EncodeToString(b)
}

// handleCheckDCV mirrors PUT /services/v2/order/certificate/{orderID}/check-dcv.
func (s *Server) handleCheckDCV(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("orderID"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "not_found|order", "order not found")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	o, wait := s.orders[id], s.dcv[id]
	if o == nil || wait == nil || s.resolve == nil {
		writeErr(w, http.StatusBadRequest, "invalid_dcv", "the order has no pending DNS validation")
		return
	}
	for _, name := range wait.names {
		found := false
		for _, value := range s.resolve("_dnsauth." + strings.TrimPrefix(name, "*.")) {
			if value == wait.random {
				found = true
			}
		}
		if !found {
			writeJSON(w, http.StatusOK, map[string]any{"dcv_status": "pending", "order_status": o.status})
			return
		}
	}
	issued, err := s.authority.IssueFromCSR(wait.csr, wait.ttl)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "csr_invalid_cannot_parse", err.Error())
		return
	}
	s.seq++
	o.certID = s.seq
	o.status = "issued"
	s.certs[o.certID] = issued.CertificatePEM
	delete(s.dcv, id)
	writeJSON(w, http.StatusOK, map[string]any{"dcv_status": "complete", "order_status": "issued"})
}
