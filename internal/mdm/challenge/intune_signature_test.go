// SPDX-License-Identifier: MPL-2.0

package challenge_test

import (
	"context"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	mdmchallenge "trstctl.com/trstctl/internal/mdm/challenge"
)

// TestIntuneChallengeRejectsUntrustedSigner is the negative-path guard for the
// one property that makes the Intune challenge an authentication gate: the JWS
// must be signed by the configured Intune connector trust anchor.
//
// /scep is otherwise unauthenticated — a PKIOperation with no challenge is
// refused, and a validly signed one mints a certificate from the tenant CA — so
// this signature check is the only barrier between an anonymous POST and
// issuance. Every pre-existing case signed its JWS with the SAME key whose
// self-signed certificate was the trust anchor, so the check could be deleted
// with the suite still green. The claim-matching case below is signed by a key
// the deployment never trusted, which is exactly the forged-challenge attack.
func TestIntuneChallengeRejectsUntrustedSigner(t *testing.T) {
	now := time.Unix(1_900_000_000, 0).UTC()

	trusted, err := crypto.GenerateLockedKey(crypto.RSA2048)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(trusted.Destroy)
	trustDER, err := crypto.SelfSignedCACert(trusted, "Intune Connector", time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	// The attacker's own key. Never presented to the deployment as an anchor.
	forged, err := crypto.GenerateLockedKey(crypto.RSA2048)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(forged.Destroy)

	validator := mdmchallenge.NewIntuneChallengeValidator("tenant-a", [][]byte{trustDER},
		mdmchallenge.WithIntuneClock(func() time.Time { return now }),
	)
	csrDER := newIntuneCSR(t, "device-1", []string{"device-1.example.test"})

	// Every claim matches the CSR and the clock. The ONLY thing wrong is the
	// signing key, so this fails if and only if the trust-anchor check runs.
	claims := map[string]any{
		"iat":         now.Add(-time.Minute).Unix(),
		"exp":         now.Add(time.Minute).Unix(),
		"nonce":       "nonce-forged",
		"device_name": "device-1",
	}
	if err := validator.Validate(context.Background(), mdmchallenge.IntuneChallengeRequest{
		TenantID:  "tenant-a",
		Challenge: signedIntuneChallenge(t, forged, claims),
		CSRDER:    csrDER,
	}); err == nil {
		t.Fatal("an Intune challenge signed by an untrusted key was accepted; a forged challenge enrolls any device against the tenant CA")
	}

	// Control: the identical claim set signed by the configured anchor is
	// accepted, so the guard above cannot be satisfied by rejecting everything.
	accepted := map[string]any{
		"iat":         now.Add(-time.Minute).Unix(),
		"exp":         now.Add(time.Minute).Unix(),
		"nonce":       "nonce-trusted",
		"device_name": "device-1",
	}
	if err := validator.Validate(context.Background(), mdmchallenge.IntuneChallengeRequest{
		TenantID:  "tenant-a",
		Challenge: signedIntuneChallenge(t, trusted, accepted),
		CSRDER:    csrDER,
	}); err != nil {
		t.Fatalf("a challenge signed by the configured anchor must be accepted: %v", err)
	}
}
