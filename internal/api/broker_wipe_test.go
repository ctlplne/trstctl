// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/orchestrator"
)

func brokerWireSecret(t *testing.T, wire *brokerAgentIdentityJSON, field string) []byte {
	t.Helper()
	value := reflect.ValueOf(wire).Elem().FieldByName(field)
	if value.Kind() != reflect.Slice || value.Type().Elem().Kind() != reflect.Uint8 {
		t.Fatalf("%s is %s; proof and task authorization must use wipeable bytes, not immutable strings", field, value.Type())
	}
	return value.Bytes()
}

type brokerProofLifetimeProbe struct {
	t       *testing.T
	seen    BrokerAgentIdentityRequest
	failure error
}

func (p *brokerProofLifetimeProbe) capture(req BrokerAgentIdentityRequest) {
	p.t.Helper()
	if !bytes.Equal(req.Payload, []byte("proof")) || !bytes.Equal(req.TaskEnvelope, []byte("task")) {
		p.t.Fatal("decoded proof must be intact while the service is using it")
	}
	// Keep the original backing slices, not a copy: the assertion after the
	// HTTP handler returns observes whether its deferred wipe really ran.
	p.seen = req
}

func (p *brokerProofLifetimeProbe) PreviewBrokerAgentIdentity(_ context.Context, _, _ string, req BrokerAgentIdentityRequest) (BrokerAgentIdentityPreview, error) {
	p.capture(req)
	return BrokerAgentIdentityPreview{Ready: true, EffectFree: true}, p.failure
}

func (p *brokerProofLifetimeProbe) IssueBrokerAgentIdentity(_ context.Context, _, _ string, req BrokerAgentIdentityRequest) (BrokerAgentIdentity, error) {
	p.capture(req)
	return BrokerAgentIdentity{AgentID: req.AgentID}, p.failure
}

func TestBrokerHTTPHandlersWipeDecodedProofAfterServiceReturns(t *testing.T) {
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	body, err := json.Marshal(map[string]any{
		"agent_id": "agent-7", "method": "k8s_sat", "scopes": []string{"tool:inventory.read"},
		"payload_base64": "cHJvb2Y=", "task_envelope_base64": "dGFzaw==",
		"public_key_pem": string(crypto.MarshalPublicKeyPEM(key.Public().DER)),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, operation := range []string{"preview", "issue"} {
		for _, failure := range []error{nil, ErrBrokerRejected, context.Canceled} {
			t.Run(operation+"/"+fmt.Sprint(failure), func(t *testing.T) {
				probe := &brokerProofLifetimeProbe{t: t, failure: failure}
				a := New(nil, orchestrator.NewMemoryIdempotency(), nil, WithBroker(probe))
				path := "/api/v1/broker/agent-identities"
				if operation == "preview" {
					path += "/preview"
				}
				req := mutationBindingRequestWithBody("proof-owner", http.MethodPost, path, string(body))
				req.Header.Set("Idempotency-Key", "decoded-proof-lifetime")
				response := httptest.NewRecorder()
				if operation == "preview" {
					a.previewBrokerAgentIdentity(response, req)
				} else {
					a.issueBrokerAgentIdentity(response, req)
				}
				if failure == nil && response.Code >= 300 || failure != nil && response.Code < 400 {
					t.Fatalf("unexpected handler result: status=%d", response.Code)
				}
				for _, buffer := range [][]byte{probe.seen.Payload, probe.seen.TaskEnvelope} {
					if len(buffer) == 0 || !bytes.Equal(buffer, make([]byte, len(buffer))) {
						t.Fatal("decoded proof backing bytes survived HTTP handler return")
					}
				}
			})
		}
	}
}

func TestBrokerParserWipesEncodedProofOnEveryExit(t *testing.T) {
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	for _, fault := range []string{"", "agent", "method", "scopes", "proof", "key", "task", "blank-task"} {
		t.Run(fault, func(t *testing.T) {
			wire := brokerAgentIdentityJSON{AgentID: "agent-7", Method: "k8s_sat", Scopes: []string{"tool:inventory.read"},
				PayloadBase64: secretJSONBytes("cHJvb2Y="), PublicKeyPEM: string(crypto.MarshalPublicKeyPEM(key.Public().DER)), TaskEnvelopeBase64: secretJSONBytes("dGFzaw==")}
			switch fault {
			case "agent":
				wire.AgentID = " "
			case "method":
				wire.Method = " "
			case "scopes":
				wire.Scopes = nil
			case "proof":
				wire.PayloadBase64 = secretJSONBytes("cHJv!bad")
			case "key":
				wire.PublicKeyPEM = "not a public key"
			case "task":
				wire.TaskEnvelopeBase64 = secretJSONBytes("dGFz!bad")
			case "blank-task":
				wire.TaskEnvelopeBase64 = secretJSONBytes("   ")
			}
			encodedProof, encodedTask := wire.PayloadBase64, wire.TaskEnvelopeBase64
			command, err := brokerRequestFromJSON(wire)
			defer secret.Wipe(command.Payload)
			defer secret.Wipe(command.TaskEnvelope)
			if (err != nil) != (fault != "") {
				t.Fatalf("parser fault=%q err=%v", fault, err)
			}
			if err == nil && (!bytes.Equal(command.Payload, []byte("proof")) || !bytes.Equal(command.TaskEnvelope, []byte("task"))) {
				t.Fatal("parser changed decoded proof")
			}
			for _, value := range [][]byte{encodedProof, encodedTask} {
				if !bytes.Equal(value, make([]byte, len(value))) {
					t.Fatal("encoded proof survived parser return")
				}
			}
			if err != nil && (len(command.Payload) != 0 || len(command.TaskEnvelope) != 0) {
				t.Fatal("rejected parser returned partial proof")
			}
		})
	}
}

func TestBrokerWireSecretsUseWipeableBytesAndPartialDecodeCleanup(t *testing.T) {
	for _, field := range []string{"PayloadBase64", "TaskEnvelopeBase64"} {
		t.Run(field, func(t *testing.T) {
			var wire brokerAgentIdentityJSON
			if err := json.Unmarshal([]byte(`{"payload_base64":"cHJvb2Y=","task_envelope_base64":"dGFzaw=="}`), &wire); err != nil {
				t.Fatal(err)
			}
			original := brokerWireSecret(t, &wire, field)
			if err := json.Unmarshal([]byte(`{"payload_base64":"bmV3","task_envelope_base64":"bmV3"}`), &wire); err != nil {
				t.Fatal(err)
			}
			if len(original) == 0 || !bytes.Equal(original, make([]byte, len(original))) {
				t.Fatal("replaced proof backing bytes were not wiped")
			}
		})
	}
	for _, body := range []string{
		`{"payload_base64":"cHJvb2Y=","task_envelope_base64":"dGFzaw==","ttl_seconds":"bad"}`,
		`{"payload_base64":"cHJvb2Y=","task_envelope_base64":"dGFzaw=="} {}`,
	} {
		var preserved [][]byte
		func() {
			var wire brokerAgentIdentityJSON
			wiper, ok := any(&wire).(interface{ wipeSecrets() })
			if !ok {
				t.Fatal("broker wire request lacks partial-decode cleanup")
			}
			defer wiper.wipeSecrets()
			if err := decodeJSON(httptest.NewRequest("POST", "/", strings.NewReader(body)), &wire); err == nil {
				t.Fatal("partial request accepted")
			}
			for _, field := range []string{"PayloadBase64", "TaskEnvelopeBase64"} {
				preserved = append(preserved, brokerWireSecret(t, &wire, field))
			}
		}()
		for _, value := range preserved {
			if len(value) == 0 || !bytes.Equal(value, make([]byte, len(value))) {
				t.Fatal("partially decoded proof was not wiped")
			}
		}
	}
}
