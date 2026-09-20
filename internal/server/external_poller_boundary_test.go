// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"os"
	"strings"
	"testing"
)

// AUD-45's negative architecture proof: the brain may schedule and ingest these
// observations, but it may not hold their bearer token or dial their endpoint.
// A future "temporary fallback" is the regression this catches.
func TestExternalPollersHaveNoControlPlaneHTTPExecutionPath(t *testing.T) {
	for _, name := range []string{"cmdb_reconcile.go", "mdm_poller.go", "ticket_intake.go"} {
		source, err := os.ReadFile(name) // #nosec G304 -- name comes only from the closed literal source-file list above (CWE-22)
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{"client.Do(", "resolveDiscoveryCredentialRef("} {
			if strings.Contains(string(source), forbidden) {
				t.Errorf("%s contains %q; scheduled external reads must be durable network-relay jobs", name, forbidden)
			}
		}
	}
}
