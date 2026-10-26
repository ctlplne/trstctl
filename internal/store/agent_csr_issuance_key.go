// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"strconv"
	"strings"
)

// AgentCSRJobID reads the renewal job an agent-CSR certificate was issued for
// from its issuance key, agentcsr:<job>:<slot>:<csr digest> (written by the
// signing path in internal/server). ok is false for any other key.
func AgentCSRJobID(issuanceKey string) (int64, bool) {
	rest, found := strings.CutPrefix(strings.TrimSpace(issuanceKey), "agentcsr:")
	if !found {
		return 0, false
	}
	idText, _, found := strings.Cut(rest, ":")
	if !found {
		return 0, false
	}
	id, err := strconv.ParseInt(idText, 10, 64)
	if err != nil || id <= 0 {
		return 0, false
	}
	return id, true
}
