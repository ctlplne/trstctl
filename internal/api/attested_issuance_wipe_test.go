// SPDX-License-Identifier: MPL-2.0

package api

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
)

func attestedWireProofBytes(t *testing.T, wire attestedSVIDJSON) []byte {
	t.Helper()
	value := reflect.ValueOf(wire.PayloadBase64)
	if value.Kind() != reflect.Slice || value.Type().Elem().Kind() != reflect.Uint8 {
		t.Fatalf("attestation proof wire field is %s, want wipeable bytes, never an immutable string", value.Type())
	}
	return value.Bytes()
}

func requireAttestedProofZeroed(t *testing.T, value []byte) {
	t.Helper()
	if len(value) == 0 || !bytes.Equal(value, make([]byte, len(value))) {
		t.Fatal("proof backing buffer was not explicitly zeroed")
	}
}

func TestAttestedSVIDWireProofUsesWipeableBytesAndPreservesDecodedProof(t *testing.T) {
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	raw, err := json.Marshal(map[string]any{
		"method": "k8s_sat", "payload_base64": "cHJvb2Y=", "ttl_seconds": 600,
		"public_key_pem": string(crypto.MarshalPublicKeyPEM(key.Public().DER)),
	})
	if err != nil {
		t.Fatal(err)
	}
	var wire attestedSVIDJSON
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	encoded := attestedWireProofBytes(t, wire)
	command, err := attestedSVIDRequestFromJSON(wire)
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(command.Payload)
	requireAttestedProofZeroed(t, encoded)
	if !bytes.Equal(command.Payload, []byte("proof")) || command.Method != "k8s_sat" || command.TTLSeconds != 600 {
		t.Fatal("wiping the encoded copy changed the decoded issuance request")
	}
}

func TestAttestedSVIDWireProofIsWipedOnValidationErrors(t *testing.T) {
	for _, body := range []string{
		`{"method":"","payload_base64":"cHJvb2Y="}`,
		`{"method":"k8s_sat","payload_base64":"cHJ!b2Y="}`,
		`{"method":"k8s_sat","payload_base64":"cHJvb2Y=","public_key_pem":"invalid"}`,
	} {
		var wire attestedSVIDJSON
		if err := json.Unmarshal([]byte(body), &wire); err != nil {
			t.Fatal(err)
		}
		encoded := attestedWireProofBytes(t, wire)
		if _, err := attestedSVIDRequestFromJSON(wire); err == nil {
			t.Fatal("invalid request unexpectedly accepted")
		}
		requireAttestedProofZeroed(t, encoded)
	}
}

func TestAttestedSVIDWireProofReplacementAndPartialDecodeCleanup(t *testing.T) {
	var wire attestedSVIDJSON
	if err := json.Unmarshal([]byte(`{"payload_base64":"Zmlyc3Q="}`), &wire); err != nil {
		t.Fatal(err)
	}
	first := attestedWireProofBytes(t, wire)
	if err := json.Unmarshal([]byte(`{"payload_base64":"c2Vjb25k"}`), &wire); err != nil {
		t.Fatal(err)
	}
	requireAttestedProofZeroed(t, first)
	for _, body := range []string{
		`{"payload_base64":"cHJvb2Y=","ttl_seconds":"invalid"}`,
		`{"payload_base64":"cHJvb2Y="} {}`,
	} {
		retained := func() []byte {
			var partial attestedSVIDJSON
			wiper, ok := any(&partial).(interface{ wipeSecrets() })
			if !ok {
				t.Fatal("wire request lacks partial-decode cleanup")
			}
			defer wiper.wipeSecrets()
			if err := decodeJSON(httptest.NewRequest("POST", "/", strings.NewReader(body)), &partial); err == nil {
				t.Fatal("partial JSON decode unexpectedly succeeded")
			}
			return attestedWireProofBytes(t, partial)
		}()
		requireAttestedProofZeroed(t, retained)
	}
}
