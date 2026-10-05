// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/store"
)

func TestEndpointReplacementGuidanceDoesNotSuggestRevokingOrRestoringRevokedSource(t *testing.T) {
	for _, state := range []string{"deployed", "revoked"} {
		t.Run(state, func(t *testing.T) {
			change, recovery := endpointReplacementGuidance(store.Identity{ID: "source-id", Status: state},
				"apache.partner-lab.example.com", "Lab owner", "owner-id")
			if !strings.Contains(change, "source-id") || !strings.Contains(change, "apache.partner-lab.example.com") {
				t.Fatalf("replacement description lost exact source or name: %q", change)
			}
			if state == "revoked" {
				if strings.Contains(change, "then revoke") || !strings.Contains(change, "already revoked") ||
					!strings.Contains(recovery, "Do not roll back") {
					t.Fatalf("revoked source guidance could restore exposure: change=%q recovery=%q", change, recovery)
				}
			} else if !strings.Contains(change, "then revoke and retire") {
				t.Fatalf("planned rotation lost original lifecycle guidance: %q", change)
			}
		})
	}
}
