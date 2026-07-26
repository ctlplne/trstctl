// SPDX-License-Identifier: LicenseRef-trstctl-EE

package delegation

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"trstctl.com/trstctl/ee/agentid/taskenv"
	"trstctl.com/trstctl/internal/crypto"
)

func signedEnvelope(t *testing.T, keyID string, window taskenv.Window) (taskenv.Envelope, []byte) {
	t.Helper()
	signer, err := crypto.NewSoftwareBackend().GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	env := taskenv.Envelope{
		RequesterID:  "requester-1",
		RequesterKey: taskenv.KeyRef{ID: keyID, Algorithm: string(crypto.ECDSAP256)},
		Task:         taskenv.TaskIntent{Description: "rotate the payments certificate"},
		Expiry:       window,
	}
	signed, err := env.Sign(signer)
	if err != nil {
		t.Fatalf("sign envelope: %v", err)
	}
	return signed, signer.Public().DER
}

func encode(t *testing.T, env taskenv.Envelope) []byte {
	t.Helper()
	body, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// B-7: the gate is what makes a broker task binding worth anything. Each of
// these is a way an attacker would try to get a credential bound to a task it
// was not authorized for.
func TestBrokerTaskEnvelopeGateVerifiesAndReturnsTheEnvelopeDigest(t *testing.T) {
	now := time.Now().UTC()
	env, publicDER := signedEnvelope(t, "req-key-1", taskenv.Window{NotBefore: now.Add(-time.Minute).Unix(), NotAfter: now.Add(time.Hour).Unix()})
	gate := NewBrokerTaskEnvelopeGate(func(keyID string) ([]byte, bool) {
		if keyID != "req-key-1" {
			return nil, false
		}
		return publicDER, true
	})

	digest, err := gate(context.Background(), "tenant-a", encode(t, env), now)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	want, err := env.Digest()
	if err != nil {
		t.Fatal(err)
	}
	// The bound digest must be the verified envelope's own digest, so the
	// caller can recompute it and confirm the scope it asked for.
	if string(digest) != string(want) {
		t.Fatal("gate returned a digest that is not the verified envelope's digest")
	}
}

func TestBrokerTaskEnvelopeGateRefusesUnknownRequesterKey(t *testing.T) {
	now := time.Now().UTC()
	env, _ := signedEnvelope(t, "req-key-1", taskenv.Window{NotBefore: now.Add(-time.Minute).Unix(), NotAfter: now.Add(time.Hour).Unix()})
	// A trust store that knows nobody: a validly-signed envelope from an
	// unregistered requester must still be refused.
	gate := NewBrokerTaskEnvelopeGate(func(string) ([]byte, bool) { return nil, false })

	if _, err := gate(context.Background(), "tenant-a", encode(t, env), now); err == nil {
		t.Fatal("an envelope from an unknown requester was accepted")
	}
}

func TestBrokerTaskEnvelopeGateRefusesForeignSignature(t *testing.T) {
	now := time.Now().UTC()
	env, _ := signedEnvelope(t, "req-key-1", taskenv.Window{NotBefore: now.Add(-time.Minute).Unix(), NotAfter: now.Add(time.Hour).Unix()})
	// The caller signed with its OWN key; the trust store holds a different
	// one for that id. This is the forgery the trust lookup exists to stop.
	_, otherDER := signedEnvelope(t, "req-key-1", taskenv.Window{NotBefore: now.Unix(), NotAfter: now.Add(time.Hour).Unix()})
	gate := NewBrokerTaskEnvelopeGate(func(string) ([]byte, bool) { return otherDER, true })

	if _, err := gate(context.Background(), "tenant-a", encode(t, env), now); err == nil {
		t.Fatal("an envelope signed by a key the trust store does not hold was accepted")
	}
}

func TestBrokerTaskEnvelopeGateRefusesExpiredEnvelope(t *testing.T) {
	now := time.Now().UTC()
	env, publicDER := signedEnvelope(t, "req-key-1", taskenv.Window{NotBefore: now.Add(-2 * time.Hour).Unix(), NotAfter: now.Add(-time.Hour).Unix()})
	gate := NewBrokerTaskEnvelopeGate(func(string) ([]byte, bool) { return publicDER, true })

	if _, err := gate(context.Background(), "tenant-a", encode(t, env), now); err == nil {
		t.Fatal("an expired envelope was accepted")
	}
}

func TestBrokerTaskEnvelopeGateRefusesWithoutTrustLookup(t *testing.T) {
	now := time.Now().UTC()
	env, _ := signedEnvelope(t, "req-key-1", taskenv.Window{NotBefore: now.Unix(), NotAfter: now.Add(time.Hour).Unix()})
	gate := NewBrokerTaskEnvelopeGate(nil)

	if _, err := gate(context.Background(), "tenant-a", encode(t, env), now); err == nil {
		t.Fatal("a gate with no trust lookup accepted an envelope")
	}
}

func TestBrokerTaskEnvelopeGateRefusesMalformedAndEmptyBodies(t *testing.T) {
	gate := NewBrokerTaskEnvelopeGate(func(string) ([]byte, bool) { return []byte("irrelevant"), true })
	now := time.Now().UTC()

	if _, err := gate(context.Background(), "tenant-a", []byte("not json"), now); err == nil {
		t.Fatal("a malformed envelope body was accepted")
	}
	if _, err := gate(context.Background(), "tenant-a", nil, now); err == nil {
		t.Fatal("an empty envelope body was accepted")
	}
}

// The trust store is operator-provisioned on disk: a key the operator never
// wrote must not resolve, and a traversal-shaped id must not escape the floor.
func TestDurableTaskEnvelopeTrustStoreResolvesOnlyProvisionedKeys(t *testing.T) {
	store := NewDurableTaskEnvelopeTrustStore(t.TempDir())

	if _, ok := store.TrustLookup("req-key-1"); ok {
		t.Fatal("an unprovisioned key resolved")
	}
	if err := store.PutRequesterKey(context.Background(), "req-key-1", []byte("public-der")); err != nil {
		t.Fatalf("provision: %v", err)
	}
	got, ok := store.TrustLookup("req-key-1")
	if !ok || string(got) != "public-der" {
		t.Fatalf("provisioned key = %q ok=%v", got, ok)
	}
	if _, ok := store.TrustLookup("../../etc/passwd"); ok {
		t.Fatal("a traversal-shaped key id resolved")
	}
	if err := store.PutRequesterKey(context.Background(), "req-key-2", nil); err == nil {
		t.Fatal("an empty public key was provisioned")
	}
}
