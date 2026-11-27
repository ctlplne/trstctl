// SPDX-License-Identifier: BUSL-1.1

package acme

import (
	"strings"
	"testing"
)

// FuzzParseOrderRequestBoundedIdentifiers verifies that accepted orders stay
// within the identifier limit and contain a distinct canonical identifier set.
func FuzzParseOrderRequestBoundedIdentifiers(f *testing.F) {
	f.Add([]byte(`{"identifiers":[{"type":"dns","value":"a.example.test"}]}`))
	f.Add([]byte(`{"identifiers":[{"type":"dns","value":"A.example.test"},{"type":"dns","value":"a.example.test"}]}`))
	f.Add([]byte(`{"identifiers":[{"type":"email","value":"user@example.test"}]}`))
	f.Fuzz(func(t *testing.T, payload []byte) {
		order, err := ParseOrderRequest(payload)
		if err != nil {
			return
		}
		if len(order.Identifiers) == 0 || len(order.Identifiers) > maxOrderIdentifiers {
			t.Fatalf("accepted order has %d identifiers", len(order.Identifiers))
		}
		seen := make(map[string]bool, len(order.Identifiers))
		for _, id := range order.Identifiers {
			canonical := strings.ToLower(strings.TrimSuffix(id.Value, "."))
			if id.Type == IdentifierEmail {
				canonical, err = NormalizeEmailIdentifier(id.Value)
				if err != nil {
					t.Fatalf("accepted email identifier is invalid: %v", err)
				}
			}
			key := id.Type + "|" + canonical
			if seen[key] {
				t.Fatal("accepted order repeats a canonical identifier")
			}
			seen[key] = true
		}
	})
}
