// SPDX-License-Identifier: MPL-2.0

package acme

import (
	"encoding/json"
	"testing"
)

func TestLegacyACMEOrderKeepsOriginalIssuanceBinding(t *testing.T) {
	// Old events omit issuance_key. Recomputing it during replay can mint a
	// duplicate if issuance committed just before the old process stopped.
	var event acmeOrderCreatedEvent
	if err := json.Unmarshal([]byte(`{"order":{"id":"2","account_url":"https://ca.test/acme/acct/1","status":"ready"}}`), &event); err != nil {
		t.Fatal(err)
	}
	srv := New(nil, nil)
	if err := srv.applyOrderCreatedEventLocked(event); err != nil {
		t.Fatal(err)
	}
	if srv.orders["2"].issuanceKey != "" {
		t.Fatal("legacy order acquired a different issuance binding during replay")
	}
}
