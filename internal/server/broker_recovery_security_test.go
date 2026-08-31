// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

// The HTTP recorder already binds live cache entries to the exact caller/body.
// This test deliberately removes only that disposable fixture row to exercise
// the certificate's longer-lived recovery path after normal cache retention.
func TestServedBrokerRetryAfterCacheExpiryCannotRelabelCommand(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.AgentBroker = AgentBrokerConfig{Enabled: true, TrustDomain: "served.test", PolicyModule: servedBrokerAllowPolicy,
			Attestors: []attest.Attestor{servedBrokerAttestor{}}}
	})
	owner := seedScopedTokenSubject(t, h.store, h.tenant, "broker-original-requester", "certs:issue")
	other := seedScopedTokenSubject(t, h.store, h.tenant, "broker-different-requester", "certs:issue")
	signer := &countingEphemeralDigestSigner{DigestSigner: h.srv.agentBroker.caSigner}
	h.srv.agentBroker.caSigner = signer
	publicKey := servedAttestedPublicKeyPEM(t)
	for _, dimension := range []string{"scopes", "lifetime", "public-key", "requester", "agent", "method", "proof", "task"} {
		t.Run(dimension, func(t *testing.T) {
			key := "broker-retained-binding-" + dimension
			body := map[string]any{"agent_id": "agent-7", "method": "stub_broker", "payload_base64": "Z2VudWluZQ==",
				"public_key_pem": publicKey, "scopes": []string{"tool:inventory.read"}, "ttl_seconds": 120}
			original := servedBrokerIssue(t, h, owner, key, body, http.StatusCreated)
			expireBrokerTestCache(t, h, key)
			before := signer.calls.Load()
			changed := make(map[string]any, len(body))
			for k, v := range body {
				changed[k] = v
			}
			requester := owner
			switch dimension {
			case "scopes":
				changed["scopes"] = []string{"tool:inventory.write"}
			case "lifetime":
				changed["ttl_seconds"] = 900
			case "public-key":
				changed["public_key_pem"] = servedAttestedPublicKeyPEM(t)
			case "requester":
				requester = other
			case "agent":
				changed["agent_id"] = "agent-8"
			case "method":
				changed["method"] = "k8s_sat"
			case "proof":
				changed["payload_base64"] = "Y2hhbmdlZA=="
			case "task":
				changed["task_envelope_base64"] = "Y2hhbmdlZA=="
			}
			status, _ := secretsReqKey(t, h, http.MethodPost, "/api/v1/broker/agent-identities", requester, key, changed)
			if status != http.StatusConflict {
				t.Errorf("changed %s after cache retention returned %d; want 409, never a relabeled old credential", dimension, status)
			}
			if signer.calls.Load() != before {
				t.Fatal("changed command reached the signer")
			}
			// A rejected changed command must not poison the original recovery.
			if status == http.StatusConflict {
				retry := servedBrokerIssue(t, h, owner, key, body, http.StatusCreated)
				if retry.CertificateID != original.CertificateID || retry.CertificatePEM != original.CertificatePEM ||
					retry.AgentID != original.AgentID || retry.NodeID != original.NodeID || !retry.NotAfter.Equal(original.NotAfter) || signer.calls.Load() != before {
					t.Fatal("matching retry did not recover the original public certificate without signing")
				}
			}
		})
	}
}

func expireBrokerTestCache(t *testing.T, h *servedHarness, key string) {
	t.Helper()
	if err := h.store.WithTenant(t.Context(), h.tenant, func(tx pgx.Tx) error {
		tag, err := tx.Exec(t.Context(), `DELETE FROM idempotency_keys WHERE tenant_id = $1 AND key = $2`, h.tenant, key)
		if err == nil && tag.RowsAffected() != 1 {
			t.Fatalf("test setup removed %d cached commands, want exactly one", tag.RowsAffected())
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestServedBrokerIssuanceEventRetainsPublicCommandFactsOnly(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.AgentBroker = AgentBrokerConfig{Enabled: true, TrustDomain: "served.test", PolicyModule: servedBrokerAllowPolicy,
			Attestors: []attest.Attestor{servedBrokerAttestor{}}}
	})
	token := seedScopedTokenSubject(t, h.store, h.tenant, "broker-facts-requester", "certs:issue")
	issued := servedBrokerIssue(t, h, token, "broker-public-facts", map[string]any{
		"agent_id": "agent-7", "method": "stub_broker", "payload_base64": "Z2VudWluZQ==",
		"public_key_pem": servedAttestedPublicKeyPEM(t), "scopes": []string{"tool:inventory.read"}, "ttl_seconds": 120,
	}, http.StatusCreated)
	var matched int
	if err := h.log.Replay(t.Context(), 0, func(e events.Event) error {
		if e.TenantID != h.tenant || e.Type != projections.EventCertificateRecorded {
			return nil
		}
		var payload map[string]json.RawMessage
		if err := json.Unmarshal(e.Data, &payload); err != nil {
			return err
		}
		var id string
		_ = json.Unmarshal(payload["id"], &id)
		if id != issued.CertificateID {
			return nil
		}
		matched++
		if bytes.Contains(e.Data, []byte("genuine")) || bytes.Contains(e.Data, []byte("Z2VudWluZQ==")) {
			t.Error("issuance event retained raw or encoded attestation proof")
		}
		var metadata struct {
			AgentID             string   `json:"agent_id"`
			Subject             string   `json:"subject"`
			Method              string   `json:"method"`
			Scopes              []string `json:"scopes"`
			RequestedTTLSeconds int64    `json:"requested_ttl_seconds"`
			EffectiveTTLSeconds int64    `json:"effective_ttl_seconds"`
		}
		if json.Unmarshal(payload["broker_issuance"], &metadata) != nil || metadata.AgentID != issued.AgentID ||
			metadata.Subject != issued.Subject || metadata.Method != "stub_broker" || len(metadata.Scopes) != 1 || metadata.Scopes[0] != "tool:inventory.read" ||
			metadata.RequestedTTLSeconds != 120 || metadata.EffectiveTTLSeconds != 120 {
			t.Error("certificate event does not retain the broker command facts needed for trustworthy history")
		}
		var binding string
		if json.Unmarshal(payload["issuance_request_binding"], &binding) != nil || len(binding) != 64 {
			t.Error("certificate event has no durable authenticated command binding")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if matched != 1 {
		t.Fatalf("found %d issuance events, want one", matched)
	}
}

func TestServedBrokerRecoversMissingProjectionButNeverRecreatesErasedFacts(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.AgentBroker = AgentBrokerConfig{Enabled: true, TrustDomain: "served.test", PolicyModule: servedBrokerAllowPolicy,
			Attestors: []attest.Attestor{servedBrokerAttestor{}}}
	})
	token := seedScopedTokenSubject(t, h.store, h.tenant, "broker-recovery-owner", "certs:issue")
	signer := &countingEphemeralDigestSigner{DigestSigner: h.srv.agentBroker.caSigner}
	h.srv.agentBroker.caSigner = signer
	const key = "broker-event-only-recovery"
	body := map[string]any{"agent_id": "agent-7", "method": "stub_broker", "payload_base64": "Z2VudWluZQ==",
		"public_key_pem": servedAttestedPublicKeyPEM(t), "scopes": []string{"tool:inventory.read"}, "ttl_seconds": 120}
	original := servedBrokerIssue(t, h, token, key, body, http.StatusCreated)
	expireBrokerTestCache(t, h, key)
	// Deliberately remove only this fixture's derived row. The immutable signed
	// certificate event remains, as it would after append succeeded but the
	// certificate projection was lost. No live application data is touched.
	if err := h.store.WithTenant(t.Context(), h.tenant, func(tx pgx.Tx) error {
		tag, err := tx.Exec(t.Context(), `DELETE FROM certificates WHERE tenant_id = $1 AND id = $2`, h.tenant, original.CertificateID)
		if err == nil && tag.RowsAffected() != 1 {
			t.Fatal("missing-projection fixture did not remove exactly one row")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	recovered := servedBrokerIssue(t, h, token, key, body, http.StatusCreated)
	if recovered.CertificateID != original.CertificateID || recovered.CertificatePEM != original.CertificatePEM || signer.calls.Load() != 1 {
		t.Fatal("event-only retry did not recover the exact certificate without signing")
	}
	expireBrokerTestCache(t, h, key)
	selected, err := h.store.SelectPrivacySubjectErasure(t.Context(), h.tenant, "agent-7")
	if err != nil || len(selected.Selectors.CertificateRefs) != 1 {
		t.Fatalf("privacy fixture selection: %v", err)
	}
	if err := h.store.WithTenant(t.Context(), h.tenant, func(tx pgx.Tx) error {
		return h.store.ApplyPrivacySubjectErasedTx(t.Context(), tx, selected)
	}); err != nil {
		t.Fatal(err)
	}
	servedBrokerIssue(t, h, token, key, body, http.StatusConflict)
	cert, err := h.store.GetCertificate(t.Context(), h.tenant, original.CertificateID)
	if err != nil || cert.BrokerIssuance != nil || signer.calls.Load() != 1 {
		t.Fatal("retry reconstructed privacy-erased facts or signed a replacement")
	}
}
