// SPDX-License-Identifier: MPL-2.0

package attest

import (
	"context"
	"testing"
)

type alwaysAttestor struct{}

func (alwaysAttestor) Method() string { return "always" }
func (alwaysAttestor) Attest(context.Context, []byte) (Attestation, error) {
	return Attestation{Subject: "s"}, nil // accepts everything — must fail Conform
}

type noSubjectAttestor struct{}

func (noSubjectAttestor) Method() string { return "nosub" }
func (noSubjectAttestor) Attest(context.Context, []byte) (Attestation, error) {
	return Attestation{}, nil // genuine but no subject established
}

func TestNewVerifierValidation(t *testing.T) {
	if _, err := NewVerifier(Config{}); err == nil {
		t.Error("empty TenantID accepted")
	}
	if _, err := NewVerifier(Config{TenantID: "t1", Attestors: []Attestor{stubAttestor{}, stubAttestor{}}}); err == nil {
		t.Error("duplicate attestor method accepted")
	}
}

func TestVerifyUnknownMethodAndBindValidation(t *testing.T) {
	v, _ := NewVerifier(Config{TenantID: "t1", Attestors: []Attestor{stubAttestor{}}})
	if _, err := v.Verify(context.Background(), "unknown", nil); err == nil {
		t.Error("Verify with an unregistered method should error")
	}
	if err := v.Bind(context.Background(), Attestation{}, "cred"); err == nil {
		t.Error("Bind without an attestation id should error")
	}
}

func TestConformRejectsBadAttestors(t *testing.T) {
	if err := Conform(nil, nil, nil); err == nil {
		t.Error("Conform accepted a nil attestor")
	}
	if err := Conform(alwaysAttestor{}, []byte("g"), []byte("forged")); err == nil {
		t.Error("Conform accepted an attestor that accepts forgeries")
	}
	if err := Conform(noSubjectAttestor{}, []byte("g"), []byte("f")); err == nil {
		t.Error("Conform accepted an attestor that establishes no subject")
	}
}
