// SPDX-License-Identifier: LicenseRef-trstctl-EE

package verify

import (
	"encoding/json"
	"testing"
)

// spliceValidity adds nbf/exp (when non-zero) to a JSON object without disturbing
// existing claims (including the AGID binding claim), so a workload-identity
// document carries its own short-TTL window that windowFromStandardClaims reads.
func spliceValidity(t *testing.T, objJSON []byte, nbf, exp int64) []byte {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(objJSON, &m); err != nil {
		t.Fatalf("unmarshal for splice: %v", err)
	}
	if nbf != 0 {
		m["nbf"] = json.RawMessage(itoa(nbf))
	}
	if exp != 0 {
		m["exp"] = json.RawMessage(itoa(exp))
	}
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal after splice: %v", err)
	}
	return out
}
