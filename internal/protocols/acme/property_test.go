// SPDX-License-Identifier: BUSL-1.1

package acme_test

import (
	"encoding/base64"
	"encoding/json"
	"math/rand"
	"reflect"
	"testing"
	"testing/quick"

	acmesrv "trstctl.com/trstctl/internal/protocols/acme"
)

const acmePropertySeed int64 = 81001

type acmeOrderPropertyInput struct {
	Domains  []string
	Replaces string
}

func (acmeOrderPropertyInput) Generate(r *rand.Rand, size int) reflect.Value {
	count := 1 + r.Intn(1+min(size, 5))
	domains := make([]string, count)
	for i := range domains {
		domains[i] = propertyDNSName(r)
	}
	var replaces string
	if r.Intn(2) == 1 {
		aki := propertyBytes(r, 1+r.Intn(16))
		serial := propertyBytes(r, 1+r.Intn(16))
		replaces = base64.RawURLEncoding.EncodeToString(aki) + "." + base64.RawURLEncoding.EncodeToString(serial)
	}
	return reflect.ValueOf(acmeOrderPropertyInput{Domains: domains, Replaces: replaces})
}

// TestPropertyACMEOrderRoundTripAndWireNormalization proves that generated RFC
// 8555 newOrder structures survive JSON encode/parse without identifier loss or
// reordering. Compact/indented JSON and unknown forward-compatible fields are
// different wire spellings of the same semantic request and must normalize to
// the same OrderRequest.
func TestPropertyACMEOrderRoundTripAndWireNormalization(t *testing.T) {
	prop := func(g acmeOrderPropertyInput) bool {
		identifiers := make([]map[string]string, len(g.Domains))
		for i, domain := range g.Domains {
			identifiers[i] = map[string]string{"type": "dns", "value": domain}
		}
		wire := map[string]any{
			"identifiers": identifiers,
			"replaces":    g.Replaces,
			"notBefore":   "2026-01-01T00:00:00Z", // tolerated RFC extension field
			"futureField": map[string]any{"ignored": true},
		}
		compact, err := json.Marshal(wire)
		if err != nil {
			t.Logf("marshal generated order: %v", err)
			return false
		}
		indented, err := json.MarshalIndent(wire, "", "  ")
		if err != nil {
			t.Logf("marshal indented generated order: %v", err)
			return false
		}
		first, err := acmesrv.ParseOrderRequest(compact)
		if err != nil {
			t.Logf("compact generated order rejected: %v; payload=%s", err, compact)
			return false
		}
		second, err := acmesrv.ParseOrderRequest(indented)
		if err != nil {
			t.Logf("indented generated order rejected: %v; payload=%s", err, indented)
			return false
		}
		if !reflect.DeepEqual(first, second) || first.Replaces != g.Replaces || !reflect.DeepEqual(first.Domains(), g.Domains) {
			t.Logf("semantic normalization drift: compact=%+v indented=%+v generated=%+v", first, second, g)
			return false
		}
		for i, id := range first.Identifiers {
			if id.Type != "dns" || id.Value != g.Domains[i] {
				t.Logf("identifier %d changed: got=%+v want=dns:%s", i, id, g.Domains[i])
				return false
			}
		}
		return true
	}

	if err := quick.Check(prop, &quick.Config{
		MaxCount: 1000,
		Rand:     rand.New(rand.NewSource(acmePropertySeed)), // #nosec G404 -- deterministic property-test stream, not security randomness (CWE-338)
	}); err != nil {
		t.Fatalf("ACME order round-trip/normalization property violated: %v", err)
	}
}

type acmeInvalidOrderPropertyInput struct {
	Kind   uint8
	Domain string
}

func (acmeInvalidOrderPropertyInput) Generate(r *rand.Rand, _ int) reflect.Value {
	return reflect.ValueOf(acmeInvalidOrderPropertyInput{
		Kind:   uint8(r.Intn(5)), // #nosec G115 -- test generator bounds the value to 0..4 (CWE-190)
		Domain: propertyDNSName(r),
	})
}

// TestPropertyACMEOrderRejectsInvalidCrossFields samples each fail-closed arm.
// Any invalid identifier/replaces combination must return BOTH an error and the
// zero request, so a caller can never accidentally act on a partially parsed order.
func TestPropertyACMEOrderRejectsInvalidCrossFields(t *testing.T) {
	prop := func(g acmeInvalidOrderPropertyInput) bool {
		var payload []byte
		switch g.Kind % 5 {
		case 0:
			payload = []byte(`{"identifiers":[]}`)
		case 1:
			payload, _ = json.Marshal(map[string]any{"identifiers": []map[string]string{{"type": "ip", "value": g.Domain}}})
		case 2:
			payload, _ = json.Marshal(map[string]any{"identifiers": []map[string]string{{"type": "dns", "value": ""}}})
		case 3:
			payload, _ = json.Marshal(map[string]any{
				"identifiers": []map[string]string{{"type": "dns", "value": g.Domain}},
				"replaces":    "not!base64url.not!base64url",
			})
		default:
			valid, _ := json.Marshal(map[string]any{"identifiers": []map[string]string{{"type": "dns", "value": g.Domain}}})
			payload = valid[:len(valid)-1] // deterministically malformed JSON
		}
		req, err := acmesrv.ParseOrderRequest(payload)
		if err == nil {
			t.Logf("invalid order accepted: kind=%d payload=%s req=%+v", g.Kind, payload, req)
			return false
		}
		if len(req.Identifiers) != 0 || req.Replaces != "" {
			t.Logf("invalid order returned partial state: kind=%d req=%+v err=%v", g.Kind, req, err)
			return false
		}
		return true
	}

	if err := quick.Check(prop, &quick.Config{
		MaxCount: 1000,
		Rand:     rand.New(rand.NewSource(acmePropertySeed + 1)), // #nosec G404 -- deterministic property-test stream, not security randomness (CWE-338)
	}); err != nil {
		t.Fatalf("ACME invalid-cross-field property violated: %v", err)
	}
}

func propertyDNSName(r *rand.Rand) string {
	labels := 2 + r.Intn(3)
	name := ""
	for i := 0; i < labels; i++ {
		if i > 0 {
			name += "."
		}
		n := 1 + r.Intn(10)
		label := make([]byte, n)
		for j := range label {
			label[j] = byte('a' + r.Intn(26)) // #nosec G115 -- generator output is bounded to ASCII a-z (CWE-190)
		}
		name += string(label)
	}
	return name
}

func propertyBytes(r *rand.Rand, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(r.Intn(256)) // #nosec G115 -- generator bounds the value to one byte (CWE-190)
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
