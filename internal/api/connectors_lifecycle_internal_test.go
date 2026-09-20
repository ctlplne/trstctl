// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"encoding/json"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/plugincensus"
)

func TestRelayPluginResponseEntriesPreservesOpenAPIArrayShapes(t *testing.T) {
	t.Parallel()

	entries := relayPluginResponseEntries([]plugincensus.Entry{{
		Name: "empty-grants",
	}, {
		Name:   "unrestricted",
		Grants: []plugincensus.Grant{{Capability: "fs.write"}},
	}})
	body, err := json.Marshal(entries)
	if err != nil {
		t.Fatalf("marshal relay plugin response: %v", err)
	}
	got := string(body)
	for _, forbidden := range []string{`"grants":null`, `"constraints":null`} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("response %s violates array contract with %s", got, forbidden)
		}
	}
	if empty, err := json.Marshal(relayPluginResponseEntries(nil)); err != nil || string(empty) != "[]" {
		t.Fatalf("empty relay plugin response = %s, %v; want []", empty, err)
	}
}
