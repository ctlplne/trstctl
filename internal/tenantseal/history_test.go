// SPDX-License-Identifier: MPL-2.0

package tenantseal

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/crypto/seal"
)

func TestTenantKeyDomainHistoryRewrapsNestedContainersWithoutPlaintext(t *testing.T) {
	deployment := testKEK(t, 0x11)
	tenant := testKEK(t, 0x22)
	domain := []byte("tenant:11111111-1111-1111-1111-111111111111:generation:1")
	aad := []byte("row-specific-aad-unavailable-to-history-migrator")
	plaintext := []byte("event-history-secret")
	legacy, err := seal.Seal(deployment, plaintext, aad)
	if err != nil {
		t.Fatalf("Seal legacy: %v", err)
	}
	payloadBefore, err := seal.PayloadCiphertext(legacy)
	if err != nil {
		t.Fatalf("PayloadCiphertext: %v", err)
	}
	nested, err := json.Marshal(map[string]any{
		"format": "trstctl.connector.deploy.sealed",
		"sealed": legacy,
	})
	if err != nil {
		t.Fatalf("Marshal nested: %v", err)
	}
	eventData, err := json.Marshal(map[string]any{
		"side_effect": map[string]any{
			"destination": "connector.deploy",
			"payload":     nested,
		},
		"public": "unchanged",
	})
	if err != nil {
		t.Fatalf("Marshal event: %v", err)
	}

	rewriter, err := NewHistoryRewrapper(deployment, tenant, domain)
	if err != nil {
		t.Fatalf("NewHistoryRewrapper: %v", err)
	}
	rewritten, changed, err := rewriter.Transform("identity.deployed", 3, eventData)
	if err != nil {
		t.Fatalf("Transform: %v", err)
	}
	if !changed {
		t.Fatal("Transform reported no change for legacy nested container")
	}
	sealed := extractNestedSealed(t, rewritten)
	if err := seal.ValidateDomain(tenant, sealed, domain); err != nil {
		t.Fatalf("ValidateDomain: %v", err)
	}
	if _, err := seal.OpenDomain(deployment, sealed, aad, domain); err == nil {
		t.Fatal("rewritten history still opens with deployment KEK")
	}
	got, err := seal.OpenDomain(tenant, sealed, aad, domain)
	if err != nil {
		t.Fatalf("OpenDomain tenant: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("OpenDomain = %q, want %q", got, plaintext)
	}
	payloadAfter, err := seal.PayloadCiphertext(sealed)
	if err != nil {
		t.Fatalf("PayloadCiphertext rewritten: %v", err)
	}
	if !bytes.Equal(payloadAfter, payloadBefore) {
		t.Fatal("history rewrap changed the encrypted payload")
	}

	again, changed, err := rewriter.Transform("identity.deployed", 3, rewritten)
	if err != nil {
		t.Fatalf("Transform resumed: %v", err)
	}
	if changed {
		t.Fatal("resumed transform rewrote an authenticated destination-domain container")
	}
	if !bytes.Equal(again, rewritten) {
		t.Fatal("resumed transform changed canonical event bytes")
	}
}

func TestTenantKeyDomainHistoryRejectsUnknownCorruptAndLegacyEnvelope(t *testing.T) {
	deployment := testKEK(t, 0x33)
	tenant := testKEK(t, 0x44)
	other := testKEK(t, 0x55)
	domain := []byte("tenant:a:generation:1")
	rewriter, err := NewHistoryRewrapper(deployment, tenant, domain)
	if err != nil {
		t.Fatalf("NewHistoryRewrapper: %v", err)
	}
	unknown, err := seal.SealDomain(other, []byte("value"), nil, []byte("tenant:b:generation:1"))
	if err != nil {
		t.Fatalf("SealDomain unknown: %v", err)
	}

	cases := []struct {
		name string
		data []byte
		want error
	}{
		{
			name: "unknown domain",
			data: mustJSON(t, map[string]any{"sealed": unknown}),
			want: ErrUnexpectedDomain,
		},
		{
			name: "corrupt CSL container",
			data: mustJSON(t, map[string]any{"sealed": append([]byte("CSL1"), 2, 0, 50)}),
			want: ErrCorruptContainer,
		},
		{
			name: "legacy JSON envelope",
			data: mustJSON(t, map[string]any{"envelope": map[string]any{
				"format": "trstctl.crypto.envelope", "version": 1,
				"wrapped_dek": []byte("wrapped"), "dek_nonce": []byte("nonce"),
				"nonce": []byte("nonce"), "ciphertext": []byte("ciphertext"),
			}}),
			want: ErrLegacyEnvelope,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, changed, err := rewriter.Transform("secret.version.written", 1, tc.data)
			if !errors.Is(err, tc.want) {
				t.Fatalf("Transform error = %v, want %v", err, tc.want)
			}
			if changed {
				t.Fatal("failed transform reported changed")
			}
			if got != nil {
				t.Fatalf("failed transform returned replacement bytes: %x", got)
			}
		})
	}
}

func TestTenantKeyDomainHistoryLeavesNonContainerBytesUnchanged(t *testing.T) {
	rewriter, err := NewHistoryRewrapper(testKEK(t, 0x66), testKEK(t, 0x77), []byte("tenant:a:generation:1"))
	if err != nil {
		t.Fatalf("NewHistoryRewrapper: %v", err)
	}
	original := []byte(`{"public":"Q0xJMQ==","count":7,"items":["plain",null]}`)
	got, changed, err := rewriter.Transform("public.event", 1, original)
	if err != nil {
		t.Fatalf("Transform: %v", err)
	}
	if changed || !bytes.Equal(got, original) {
		t.Fatalf("non-container event changed: changed=%v got=%s", changed, got)
	}
}

func testKEK(t *testing.T, fill byte) *seal.LocalKEK {
	t.Helper()
	key := bytes.Repeat([]byte{fill}, 32)
	wrapper, err := seal.NewLocalKEK(key)
	if err != nil {
		t.Fatalf("NewLocalKEK: %v", err)
	}
	t.Cleanup(wrapper.Destroy)
	return wrapper
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	out, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return out
}

func extractNestedSealed(t *testing.T, data []byte) []byte {
	t.Helper()
	var outer struct {
		SideEffect struct {
			Payload []byte `json:"payload"`
		} `json:"side_effect"`
	}
	if err := json.Unmarshal(data, &outer); err != nil {
		t.Fatalf("Unmarshal outer: %v", err)
	}
	var inner struct {
		Sealed []byte `json:"sealed"`
	}
	if err := json.Unmarshal(outer.SideEffect.Payload, &inner); err != nil {
		t.Fatalf("Unmarshal inner: %v (%s)", err, base64.StdEncoding.EncodeToString(outer.SideEffect.Payload))
	}
	return inner.Sealed
}
