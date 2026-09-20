// SPDX-License-Identifier: BUSL-1.1

package challenge_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	mdmchallenge "trstctl.com/trstctl/internal/mdm/challenge"
)

// TestNoncelessChallengeIsRejectedRatherThanReplayable is the regression guard
// for replay protection that silently did not apply.
//
// consumeOnce returned nil — success — for an empty nonce. The payload field is
// `nonce,omitempty` and nothing upstream requires it, so a properly signed
// challenge carrying no nonce was never recorded in the replay set and could be
// presented an unlimited number of times. For a SCEP enrollment challenge that
// means one captured challenge mints certificates indefinitely.
//
// The nonce is what replay protection is keyed on, so a challenge without one
// cannot be made single-use and must fail closed.
func TestNoncelessChallengeIsRejectedRatherThanReplayable(t *testing.T) {
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

	// Identical to the happy-path fixture except that "nonce" is absent.
	nonceless := signedIntuneChallenge(t, signer, map[string]any{
		"iss":         "connector-1",
		"sub":         "device-guid-1",
		"aud":         "https://ca.example.test/scep",
		"iat":         now.Add(-time.Minute).Unix(),
		"exp":         now.Add(time.Minute).Unix(),
		"device_name": "device-1",
		"san_dns":     []string{"device-1.example.test"},
	})

	validator := mdmchallenge.NewIntuneChallengeValidator("tenant-a", [][]byte{trustDER},
		mdmchallenge.WithIntuneAudience("https://ca.example.test/scep"),
		mdmchallenge.WithIntuneClock(func() time.Time { return now }),
	)
	req := mdmchallenge.IntuneChallengeRequest{
		TenantID: "tenant-a", Challenge: nonceless, CSRDER: csrDER,
	}

	// Present it repeatedly. Every attempt must be refused — the defect was that
	// all of them succeeded.
	for i := 0; i < 3; i++ {
		err := validator.Validate(context.Background(), req)
		if err == nil {
			t.Fatalf("attempt %d: a nonce-less challenge validated; it is not recorded for replay "+
				"detection, so it can be presented forever and mint certificates each time", i+1)
		}
		if !errors.Is(err, mdmchallenge.ErrIntuneChallengeNoNonce) {
			t.Fatalf("attempt %d: refused with %v, want ErrIntuneChallengeNoNonce", i+1, err)
		}
	}
}

// TestNoncedChallengeStillValidatesExactlyOnce keeps the working behaviour
// intact: a challenge WITH a nonce must be accepted once and refused after.
func TestNoncedChallengeStillValidatesExactlyOnce(t *testing.T) {
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
		"nonce":       "single-use-nonce",
		"device_name": "device-1",
		"san_dns":     []string{"device-1.example.test"},
	})

	validator := mdmchallenge.NewIntuneChallengeValidator("tenant-a", [][]byte{trustDER},
		mdmchallenge.WithIntuneAudience("https://ca.example.test/scep"),
		mdmchallenge.WithIntuneClock(func() time.Time { return now }),
	)
	req := mdmchallenge.IntuneChallengeRequest{
		TenantID: "tenant-a", Challenge: challenge, CSRDER: csrDER,
	}
	if err := validator.Validate(context.Background(), req); err != nil {
		t.Fatalf("a valid nonced challenge was rejected on first use: %v", err)
	}
	if err := validator.Validate(context.Background(), req); !errors.Is(err, mdmchallenge.ErrIntuneChallengeReplay) {
		t.Fatalf("second use returned %v, want ErrIntuneChallengeReplay", err)
	}
}
