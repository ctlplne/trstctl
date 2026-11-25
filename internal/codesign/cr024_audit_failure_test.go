// SPDX-License-Identifier: BUSL-1.1

package codesign

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/crypto"
)

func TestCR024CodeSigningWithholdsUnauditedSignatures(t *testing.T) {
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	appendErr := errors.New("injected code-signing audit append failure")
	for _, tc := range []struct {
		name      string
		eventType string
		keyless   bool
	}{
		{name: "managed-key", eventType: "codesign.signed"},
		{name: "keyless", eventType: "codesign.keyless.signed", keyless: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			audit := auditsink.AuditorFunc(func(_ context.Context, eventType, _ string, _ []byte) error {
				if eventType == tc.eventType {
					return appendErr
				}
				return nil
			})
			svc, err := New(Config{TenantID: "t1", Keys: keyMap{m: map[string]crypto.DigestSigner{"release": key}}, Audit: audit})
			if err != nil {
				t.Fatal(err)
			}
			digest := crypto.SHA256Sum([]byte("fixture artifact"))
			if tc.keyless {
				sig, err := svc.SignKeyless(t.Context(), KeylessRequest{
					Principal: "builder", Ephemeral: key, Digest: digest,
					Identity: attest.Attestation{Method: "oidc", Subject: "builder@example.test",
						Claims: map[string]string{"oidc_issuer": "https://issuer.example.test"}, VerifiedAt: time.Now()},
				})
				if !errors.Is(err, appendErr) || !errors.Is(err, ErrAuditUnavailable) || len(sig.Value) != 0 ||
					strings.Contains(err.Error(), "injected") {
					t.Fatalf("keyless signing returned unaudited signature: present=%t err=%v", len(sig.Value) != 0, err)
				}
				return
			}
			sig, err := svc.Sign(t.Context(), SignRequest{Principal: "builder", KeyID: "release", Digest: digest})
			if !errors.Is(err, appendErr) || !errors.Is(err, ErrAuditUnavailable) || len(sig.Value) != 0 ||
				strings.Contains(err.Error(), "injected") {
				t.Fatalf("managed signing returned unaudited signature: present=%t err=%v", len(sig.Value) != 0, err)
			}
		})
	}
}

func TestCR024CodeSigningRefusalExposesAuditOutage(t *testing.T) {
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	appendErr := errors.New("injected refusal audit append failure")
	audit := auditsink.AuditorFunc(func(_ context.Context, eventType, _ string, _ []byte) error {
		if eventType == "codesign.refused" || eventType == "codesign.keyless.refused" {
			return appendErr
		}
		return nil
	})
	gate := gateFn(func(context.Context, string, string, string, string) (bool, string) {
		return false, "policy denies signing"
	})
	svc, err := New(Config{TenantID: "t1", Keys: keyMap{m: map[string]crypto.DigestSigner{"release": key}}, Gate: gate, Audit: audit})
	if err != nil {
		t.Fatal(err)
	}
	digest := crypto.SHA256Sum([]byte("fixture artifact"))
	if _, err := svc.Sign(t.Context(), SignRequest{Principal: "builder", KeyID: "release", Digest: digest}); !errors.Is(err, appendErr) || !errors.Is(err, ErrAuditUnavailable) || strings.Contains(err.Error(), "injected") {
		t.Fatalf("managed refusal hid audit outage: %v", err)
	}
	if _, err := svc.SignKeyless(t.Context(), KeylessRequest{
		Principal: "builder", Ephemeral: key, Digest: digest,
		Identity: attest.Attestation{Method: "oidc", Subject: "builder@example.test",
			Claims: map[string]string{"oidc_issuer": "https://issuer.example.test"}, VerifiedAt: time.Now()},
	}); !errors.Is(err, appendErr) || !errors.Is(err, ErrAuditUnavailable) || strings.Contains(err.Error(), "injected") {
		t.Fatalf("keyless refusal hid audit outage: %v", err)
	}
}
