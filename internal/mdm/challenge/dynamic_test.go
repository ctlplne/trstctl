// SPDX-License-Identifier: BUSL-1.1

package challenge_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/mdm/challenge"
)

const (
	dynTenant = "6d0c5a4e-3b2a-4c1d-9e8f-7a6b5c4d3e2f"
	dynPolicy = "0b1c2d3e-4f5a-4b6c-8d7e-9f0a1b2c3d4e"
)

func dynamicPolicy(credential string) challenge.DynamicPolicy {
	return challenge.DynamicPolicy{PolicyID: dynPolicy, SCEPProfile: "mac-device", RotationVersion: 1, Credential: []byte(credential)}
}

// fence is an in-memory stand-in for the durable PostgreSQL nonce fence.
type fence struct {
	mu   sync.Mutex
	seen map[string]bool
}

func (f *fence) consume(_ context.Context, tenantID, nonce string, _ time.Time) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.seen == nil {
		f.seen = map[string]bool{}
	}
	key := tenantID + "/" + nonce
	if f.seen[key] {
		return false, nil
	}
	f.seen[key] = true
	return true, nil
}

// tamper changes one MAC character so the token stays well formed.
func tamper(token string) string {
	b := []byte(token)
	i := len(b) - 5
	if b[i] == 'A' {
		b[i] = 'B'
	} else {
		b[i] = 'A'
	}
	return string(b)
}

func TestDynamicChallengeIsBoundToTenantPolicyProfileAndRotation(t *testing.T) {
	now := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	policy := dynamicPolicy("jamf:correct horse")
	token, expires, err := challenge.IssueDynamic(dynTenant, policy, now)
	if err != nil {
		t.Fatal(err)
	}
	if !challenge.IsDynamic(token) || len(token) > 255 || !expires.Equal(now.Add(challenge.DynamicTTL)) {
		t.Fatalf("token %q (%d chars) expires %v", token, len(token), expires)
	}
	if id, err := challenge.DynamicPolicyID(token); err != nil || id != dynPolicy {
		t.Fatalf("policy id = %q %v", id, err)
	}
	if _, _, err := challenge.VerifyDynamic(dynTenant, policy, token, now.Add(time.Minute)); err != nil {
		t.Fatalf("verify own challenge: %v", err)
	}
	for name, probe := range map[string]struct {
		tenant string
		policy challenge.DynamicPolicy
		token  string
		at     time.Time
		want   error
	}{
		"other tenant":          {"7e1d6b5f-4c3b-4d2e-8f9a-0b1c2d3e4f5a", policy, token, now, challenge.ErrDynamicChallengeAuthentication},
		"other profile":         {dynTenant, challenge.DynamicPolicy{PolicyID: dynPolicy, SCEPProfile: "server", RotationVersion: 1, Credential: policy.Credential}, token, now, challenge.ErrDynamicChallengeAuthentication},
		"rotated":               {dynTenant, challenge.DynamicPolicy{PolicyID: dynPolicy, SCEPProfile: "mac-device", RotationVersion: 2, Credential: policy.Credential}, token, now, challenge.ErrDynamicChallengeAuthentication},
		"other credential":      {dynTenant, dynamicPolicy("jamf:wrong"), token, now, challenge.ErrDynamicChallengeAuthentication},
		"other policy":          {dynTenant, challenge.DynamicPolicy{PolicyID: "1c2d3e4f-5a6b-4c7d-8e9f-0a1b2c3d4e5f", Credential: policy.Credential}, token, now, challenge.ErrDynamicChallengePolicy},
		"expired":               {dynTenant, policy, token, now.Add(challenge.DynamicTTL + time.Second), challenge.ErrDynamicChallengeExpired},
		"tampered":              {dynTenant, policy, tamper(token), now, challenge.ErrDynamicChallengeAuthentication},
		"static challenge":      {dynTenant, policy, "static-jamf-secret", now, challenge.ErrDynamicChallengeMalformed},
		"over the PKCS#9 bound": {dynTenant, policy, token + strings.Repeat("A", 200), now, challenge.ErrDynamicChallengeMalformed},
	} {
		if _, _, err := challenge.VerifyDynamic(probe.tenant, probe.policy, probe.token, probe.at); !errors.Is(err, probe.want) {
			t.Errorf("%s: err = %v; want %v", name, err, probe.want)
		}
	}
}

func TestDynamicChallengeValidatorConsumesOnceAndReturnsThePolicyProfile(t *testing.T) {
	now := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	token, _, err := challenge.IssueDynamic(dynTenant, dynamicPolicy("jamf:correct horse"), now)
	if err != nil {
		t.Fatal(err)
	}
	resolved := 0
	resolve := func(_ context.Context, tenantID, policyID string) (challenge.DynamicPolicy, error) {
		resolved++
		if tenantID != dynTenant || policyID != dynPolicy {
			return challenge.DynamicPolicy{}, challenge.ErrDynamicChallengePolicy
		}
		return dynamicPolicy("jamf:correct horse"), nil
	}
	f := &fence{}
	v := challenge.NewDynamicChallengeValidator(dynTenant, resolve, f.consume, nil, func() time.Time { return now })
	profile, err := v.ValidateProfile(context.Background(), challenge.IntuneChallengeRequest{TenantID: dynTenant, Challenge: token, TransactionID: "tx-1"})
	if err != nil || profile != "mac-device" {
		t.Fatalf("first use = %q %v; want the policy's profile", profile, err)
	}
	if _, err := v.ValidateProfile(context.Background(), challenge.IntuneChallengeRequest{TenantID: dynTenant, Challenge: token, TransactionID: "tx-2"}); !errors.Is(err, challenge.ErrIntuneChallengeReplay) {
		t.Fatalf("replay = %v; want refused", err)
	}
	if _, err := v.ValidateProfile(context.Background(), challenge.IntuneChallengeRequest{TenantID: "7e1d6b5f-4c3b-4d2e-8f9a-0b1c2d3e4f5a", Challenge: token}); !errors.Is(err, challenge.ErrIntuneChallengeTenant) {
		t.Fatalf("other tenant's endpoint = %v; want refused", err)
	}
	unfenced := challenge.NewDynamicChallengeValidator(dynTenant, resolve, nil, nil, func() time.Time { return now })
	fresh, _, err := challenge.IssueDynamic(dynTenant, dynamicPolicy("jamf:correct horse"), now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unfenced.ValidateProfile(context.Background(), challenge.IntuneChallengeRequest{TenantID: dynTenant, Challenge: fresh}); !errors.Is(err, challenge.ErrIntuneChallengeNonceStoreUnavailable) {
		t.Fatalf("no durable fence = %v; want refused", err)
	}
	if resolved != 3 {
		t.Fatalf("policy resolved %d times; want once per same-tenant attempt", resolved)
	}
}
