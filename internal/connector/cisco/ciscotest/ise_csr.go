// SPDX-License-Identifier: BUSL-1.1

package ciscotest

import "net/http"

// handleISECSR serves ISE's certificate-signing-request calls; handled is
// false for any other path.
func (s *Server) handleISECSR(w http.ResponseWriter, r *http.Request) bool {
	s.refuse(w, r, http.StatusNotFound, "no such resource")
	return true
}
