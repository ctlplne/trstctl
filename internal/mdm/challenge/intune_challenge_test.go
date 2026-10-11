// SPDX-License-Identifier: BUSL-1.1

package challenge_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	mdmchallenge "trstctl.com/trstctl/internal/mdm/challenge"
)

func TestIntuneChallengeValidatesTenantAndCSRClaims(t *testing.T) {
	now := time.Unix(1_900_000_000, 0).UTC()
	signer, err := crypto.GenerateLockedKey(crypto.RSA2048)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(signer.Destroy)
	trustDER, err := crypto.SelfSignedCACert(signer, "Intune Connector", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	csrDER := newIntuneCSR(t, "device-1", []string{"device-1.example.test"})
	challenge := signedIntuneChallenge(t, signer, map[string]any{
		"iss":         "connector-1",
		"sub":         "device-guid-1",
		"aud":         "https://ca.example.test/scep",
		"iat":         now.Add(-time.Minute).Unix(),
		"exp":         now.Add(time.Minute).Unix(),
		"nonce":       "nonce-1",
		"device_name": "device-1",
		"san_dns":     []string{"device-1.example.test"},
	})

	validator := mdmchallenge.NewIntuneChallengeValidator("tenant-a", [][]byte{trustDER},
		mdmchallenge.WithIntuneAudience("https://ca.example.test/scep"),
		mdmchallenge.WithIntuneClock(func() time.Time { return now }),
		mdmchallenge.WithIntuneNonceConsumer(testIntuneNonceConsumer()),
	)
	if err := validator.Validate(context.Background(), mdmchallenge.IntuneChallengeRequest{
		TenantID:  "tenant-a",
		Challenge: challenge,
		CSRDER:    csrDER,
	}); err != nil {
		t.Fatalf("valid Intune challenge rejected: %v", err)
	}

	if err := validator.Validate(context.Background(), mdmchallenge.IntuneChallengeRequest{
		TenantID:  "tenant-b",
		Challenge: challenge,
		CSRDER:    csrDER,
	}); err == nil {
		t.Fatal("cross-tenant Intune challenge must be rejected")
	}
}

func TestIntuneChallengeReturnsProfileOfVerifiedPolicy(t *testing.T) {
	now := time.Unix(1_900_000_000, 0).UTC()
	signer, err := crypto.GenerateLockedKey(crypto.RSA2048)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(signer.Destroy)
	trustDER, err := crypto.SelfSignedCACert(signer, "MDM Profile Signer", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	csrDER := newIntuneCSR(t, "device-profile-1", nil)
	challenge := signedIntuneChallenge(t, signer, map[string]any{
		"aud": "https://mdm.example.test/scep", "iat": now.Add(-time.Minute).Unix(),
		"exp": now.Add(time.Minute).Unix(), "nonce": "profile-nonce",
		"device_name": "device-profile-1",
	})
	validator := mdmchallenge.NewIntuneChallengeValidator("tenant-a", nil,
		mdmchallenge.WithIntuneClock(func() time.Time { return now }),
		mdmchallenge.WithIntuneNonceConsumer(testIntuneNonceConsumer()),
		mdmchallenge.WithIntuneTrustConfigResolver(func(context.Context, mdmchallenge.IntuneChallengeRequest) ([]mdmchallenge.IntuneTrustConfig, error) {
			return []mdmchallenge.IntuneTrustConfig{{TrustAnchorsDER: [][]byte{trustDER}, ExpectedAudience: "https://mdm.example.test/scep", ProfileName: "scep-intune-mobile-7d"}}, nil
		}),
	)
	profile, err := validator.ValidateProfile(context.Background(), mdmchallenge.IntuneChallengeRequest{
		TenantID: "tenant-a", Challenge: challenge, CSRDER: csrDER,
	})
	if err != nil {
		t.Fatal(err)
	}
	if profile != "scep-intune-mobile-7d" {
		t.Fatalf("profile = %q", profile)
	}
	missingAudience := signedIntuneChallenge(t, signer, map[string]any{
		"iat": now.Add(-time.Minute).Unix(), "exp": now.Add(time.Minute).Unix(),
		"nonce": "missing-audience-nonce", "device_name": "device-profile-1",
	})
	if _, err := validator.ValidateProfile(context.Background(), mdmchallenge.IntuneChallengeRequest{
		TenantID: "tenant-a", Challenge: missingAudience, CSRDER: csrDER,
	}); !errors.Is(err, crypto.ErrIntuneChallengeWrongAudience) {
		t.Fatalf("missing required audience = %v, want ErrIntuneChallengeWrongAudience", err)
	}
	ambiguous := mdmchallenge.NewIntuneChallengeValidator("tenant-a", nil,
		mdmchallenge.WithIntuneClock(func() time.Time { return now }),
		mdmchallenge.WithIntuneNonceConsumer(testIntuneNonceConsumer()),
		mdmchallenge.WithIntuneTrustConfigResolver(func(context.Context, mdmchallenge.IntuneChallengeRequest) ([]mdmchallenge.IntuneTrustConfig, error) {
			return []mdmchallenge.IntuneTrustConfig{
				{TrustAnchorsDER: [][]byte{trustDER}, ExpectedAudience: "https://mdm.example.test/scep", ProfileName: "mobile-a"},
				{TrustAnchorsDER: [][]byte{trustDER}, ExpectedAudience: "https://mdm.example.test/scep", ProfileName: "mobile-b"},
			}, nil
		}),
	)
	if _, err := ambiguous.ValidateProfile(context.Background(), mdmchallenge.IntuneChallengeRequest{
		TenantID: "tenant-a", Challenge: challenge, CSRDER: csrDER,
	}); !errors.Is(err, mdmchallenge.ErrIntuneChallengeAmbiguousProfile) {
		t.Fatalf("ambiguous matching policies = %v, want refusal", err)
	}
}

func TestIntuneChallengeRejectsMissingInvalidAndMismatchedClaims(t *testing.T) {
	now := time.Unix(1_900_000_000, 0).UTC()
	signer, err := crypto.GenerateLockedKey(crypto.RSA2048)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(signer.Destroy)
	trustDER, err := crypto.SelfSignedCACert(signer, "Intune Connector", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	validator := mdmchallenge.NewIntuneChallengeValidator("tenant-a", [][]byte{trustDER},
		mdmchallenge.WithIntuneClock(func() time.Time { return now }),
		mdmchallenge.WithIntuneNonceConsumer(testIntuneNonceConsumer()),
	)
	csrDER := newIntuneCSR(t, "device-1", []string{"device-1.example.test"})
	for _, req := range []mdmchallenge.IntuneChallengeRequest{
		{TenantID: "tenant-a", CSRDER: csrDER},
		{TenantID: "tenant-a", Challenge: "not.a.valid.jws", CSRDER: csrDER},
		{
			TenantID: "tenant-a",
			Challenge: signedIntuneChallenge(t, signer, map[string]any{
				"iat":         now.Add(-time.Minute).Unix(),
				"exp":         now.Add(time.Minute).Unix(),
				"nonce":       "nonce-2",
				"device_name": "other-device",
			}),
			CSRDER: csrDER,
		},
	} {
		if err := validator.Validate(context.Background(), req); err == nil {
			t.Fatalf("Intune request %+v must be rejected", req)
		}
	}
}

func TestIntuneChallengeReplayRejectedAndAudited(t *testing.T) {
	now := time.Unix(1_900_000_000, 0).UTC()
	log := openMDMEventLog(t)
	signer, err := crypto.GenerateLockedKey(crypto.RSA2048)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(signer.Destroy)
	trustDER, err := crypto.SelfSignedCACert(signer, "Intune Connector", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	csrDER := newIntuneCSR(t, "device-1", nil)
	validator := mdmchallenge.NewIntuneChallengeValidator("tenant-a", [][]byte{trustDER},
		mdmchallenge.WithIntuneClock(func() time.Time { return now }),
		mdmchallenge.WithIntuneEventLog(log),
		mdmchallenge.WithIntuneNonceConsumer(testIntuneNonceConsumer()),
	)
	challenge := signedIntuneChallenge(t, signer, map[string]any{
		"iat":         now.Add(-time.Minute).Unix(),
		"exp":         now.Add(time.Minute).Unix(),
		"nonce":       "replay-nonce",
		"device_name": "device-1",
	})
	req := mdmchallenge.IntuneChallengeRequest{TenantID: "tenant-a", Challenge: challenge, CSRDER: csrDER, TransactionID: "txn-replay"}
	if err := validator.Validate(context.Background(), req); err != nil {
		t.Fatalf("first challenge use rejected: %v", err)
	}
	if !mdmEventExists(t, log, "mdm.intune_scep_challenge", "tenant-a") {
		t.Fatal("accepted challenge did not emit a tenant-scoped decision event")
	}
	if err := validator.Validate(context.Background(), req); !errors.Is(err, mdmchallenge.ErrIntuneChallengeReplay) {
		t.Fatalf("replayed challenge error = %v, want ErrIntuneChallengeReplay", err)
	}
	if !mdmEventExists(t, log, "mdm.intune_scep_challenge.replay_rejected", "tenant-a") {
		t.Fatal("replay rejection did not emit a tenant-scoped replay event")
	}

	distinct := signedIntuneChallenge(t, signer, map[string]any{
		"iat":         now.Add(-time.Minute).Unix(),
		"exp":         now.Add(time.Minute).Unix(),
		"nonce":       "fresh-nonce",
		"device_name": "device-1",
	})
	if err := validator.Validate(context.Background(), mdmchallenge.IntuneChallengeRequest{TenantID: "tenant-a", Challenge: distinct, CSRDER: csrDER}); err != nil {
		t.Fatalf("distinct challenge rejected: %v", err)
	}
}

func TestIntuneChallengeFailsClosedWithoutDurableFenceOrExpiry(t *testing.T) {
	now := time.Unix(1_900_000_000, 0).UTC()
	signer, err := crypto.GenerateLockedKey(crypto.RSA2048)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(signer.Destroy)
	trustDER, err := crypto.SelfSignedCACert(signer, "Intune Connector", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	csrDER := newIntuneCSR(t, "device-1", nil)
	request := mdmchallenge.IntuneChallengeRequest{
		TenantID: "tenant-a", CSRDER: csrDER,
		Challenge: signedIntuneChallenge(t, signer, map[string]any{
			"iat": now.Add(-time.Minute).Unix(), "exp": now.Add(time.Minute).Unix(),
			"nonce": "unfenced", "device_name": "device-1",
		}),
	}
	unfenced := mdmchallenge.NewIntuneChallengeValidator("tenant-a", [][]byte{trustDER},
		mdmchallenge.WithIntuneClock(func() time.Time { return now }))
	if err := unfenced.Validate(context.Background(), request); !errors.Is(err, mdmchallenge.ErrIntuneChallengeNonceStoreUnavailable) {
		t.Fatalf("missing durable fence = %v", err)
	}
	request.Challenge = signedIntuneChallenge(t, signer, map[string]any{
		"iat": now.Add(-time.Minute).Unix(), "nonce": "no-expiry", "device_name": "device-1",
	})
	withFence := mdmchallenge.NewIntuneChallengeValidator("tenant-a", [][]byte{trustDER},
		mdmchallenge.WithIntuneClock(func() time.Time { return now }),
		mdmchallenge.WithIntuneNonceConsumer(testIntuneNonceConsumer()))
	if err := withFence.Validate(context.Background(), request); !errors.Is(err, mdmchallenge.ErrIntuneChallengeNoExpiry) {
		t.Fatalf("unbounded JWS lifetime = %v", err)
	}
}

func newIntuneCSR(t *testing.T, cn string, dns []string) []byte {
	t.Helper()
	signer, err := crypto.GenerateLockedKey(crypto.RSA2048)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(signer.Destroy)
	csrDER, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{
		CommonName: cn,
		DNSNames:   dns,
	}, signer)
	if err != nil {
		t.Fatal(err)
	}
	return csrDER
}

func signedIntuneChallenge(t *testing.T, signer crypto.DigestSigner, payload map[string]any) string {
	t.Helper()
	enc := base64.RawURLEncoding.EncodeToString
	mustJSON := func(v any) string {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return enc(b)
	}
	protected := mustJSON(map[string]any{"alg": "RS256", "typ": "JWT"})
	body := mustJSON(payload)
	signingInput := protected + "." + body
	sig, err := crypto.SignMessage(signer, []byte(signingInput))
	if err != nil {
		t.Fatal(err)
	}
	return signingInput + "." + enc(sig)
}

func testIntuneNonceConsumer() mdmchallenge.IntuneNonceConsumer {
	var mu sync.Mutex
	seen := map[string]struct{}{}
	return func(_ context.Context, tenantID, nonce string, _ time.Time) (bool, error) {
		mu.Lock()
		defer mu.Unlock()
		key := tenantID + "\x00" + nonce
		if _, exists := seen[key]; exists {
			return false, nil
		}
		seen[key] = struct{}{}
		return true, nil
	}
}

func openMDMEventLog(t *testing.T) *events.Log {
	t.Helper()
	log, err := events.Open(context.Background(), config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("open event log: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })
	return log
}

func mdmEventExists(t *testing.T, log *events.Log, eventType, tenantID string) bool {
	t.Helper()
	found := false
	if err := log.Replay(context.Background(), 0, func(e events.Event) error {
		if e.Type == eventType && e.TenantID == tenantID {
			found = true
		}
		return nil
	}); err != nil {
		t.Fatalf("replay mdm events: %v", err)
	}
	return found
}
