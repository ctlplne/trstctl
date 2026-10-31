// SPDX-License-Identifier: BUSL-1.1

package challenge

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/events"
)

// A154: a policy-bound dynamic challenge. An MDM that speaks the dynamic
// challenge page (Jamf Pro's "Dynamic-Microsoft CA" SCEP payload, and the
// third-party CAs that serve the same shape) fetches one challenge per device
// with the policy's username and password, and the device puts it in its SCEP
// challengePassword. The challenge names its policy, is MAC-bound to the
// tenant, the policy, the policy's SCEP profile and rotation version, expires,
// and is consumed once in the durable nonce fence, so a replay is refused even
// after a restart. Rotating the policy's credential or its rotation version
// invalidates every outstanding challenge.

// DynamicPrefix marks a dynamic challenge in a challengePassword.
const DynamicPrefix = "h1."

// DynamicTTL is how long a fetched challenge stays usable: the one-hour window
// the challenge pages MDMs already speak advertise.
const DynamicTTL = time.Hour

const dynamicDomain = "trstctl.mdm.hmac-dynamic.v1"

var (
	// ErrDynamicChallengeMalformed is a challenge that is not the dynamic shape.
	ErrDynamicChallengeMalformed = errors.New("mdm: dynamic challenge is malformed")
	// ErrDynamicChallengePolicy is a challenge whose policy is not an enabled
	// hmac-dynamic policy of this tenant.
	ErrDynamicChallengePolicy = errors.New("mdm: dynamic challenge names no enabled hmac-dynamic policy of this tenant")
	// ErrDynamicChallengeAuthentication is a challenge whose MAC does not verify
	// for its tenant, policy, profile and rotation version.
	ErrDynamicChallengeAuthentication = errors.New("mdm: dynamic challenge authentication failed")
	// ErrDynamicChallengeExpired is a challenge past its expiry.
	ErrDynamicChallengeExpired = errors.New("mdm: dynamic challenge expired")
)

// DynamicPolicy is the policy state a dynamic challenge is checked against.
// Credential is the policy's challenge credential; the resolver's caller wipes
// it after use.
type DynamicPolicy struct {
	PolicyID        string
	SCEPProfile     string
	RotationVersion int
	Credential      []byte
}

// DynamicPolicyResolver loads one enabled hmac-dynamic policy of the tenant.
// It returns ErrDynamicChallengePolicy for any other policy.
type DynamicPolicyResolver func(ctx context.Context, tenantID, policyID string) (DynamicPolicy, error)

// IsDynamic reports whether a challengePassword has the dynamic shape.
func IsDynamic(token string) bool { return strings.HasPrefix(token, DynamicPrefix) }

// IssueDynamic returns a fresh challenge for the tenant's policy and its expiry.
func IssueDynamic(tenantID string, policy DynamicPolicy, now time.Time) (string, time.Time, error) {
	if tenantID == "" || policy.PolicyID == "" || strings.Contains(policy.PolicyID, ".") || len(policy.Credential) == 0 {
		return "", time.Time{}, ErrDynamicChallengePolicy
	}
	nonce, err := crypto.RandomBytes(12)
	if err != nil {
		return "", time.Time{}, err
	}
	expires := now.Add(DynamicTTL).UTC().Truncate(time.Second)
	expb := make([]byte, 8)
	binary.BigEndian.PutUint64(expb, uint64(expires.Unix())) // #nosec G115 -- unix-epoch seconds; in int64 range until year 292e9 (CWE-190)
	enc := base64.RawURLEncoding.EncodeToString
	mac := dynamicMAC(tenantID, policy, expb, nonce)
	return DynamicPrefix + policy.PolicyID + "." + enc(expb) + "." + enc(nonce) + "." + enc(mac), expires, nil
}

// DynamicPolicyID returns the policy a dynamic challenge names, before any
// verification, so the caller can load that policy's credential.
func DynamicPolicyID(token string) (string, error) {
	parts, err := dynamicParts(token)
	if err != nil {
		return "", err
	}
	return parts[1], nil
}

// VerifyDynamic checks a challenge against its tenant and policy: well formed,
// MAC-authentic and unexpired. It returns the nonce for the single-use fence
// and the expiry the fence entry must outlive.
func VerifyDynamic(tenantID string, policy DynamicPolicy, token string, now time.Time) (string, time.Time, error) {
	parts, err := dynamicParts(token)
	if err != nil {
		return "", time.Time{}, err
	}
	if parts[1] != policy.PolicyID || len(policy.Credential) == 0 {
		return "", time.Time{}, ErrDynamicChallengePolicy
	}
	dec := base64.RawURLEncoding.DecodeString
	expb, err1 := dec(parts[2])
	nonce, err2 := dec(parts[3])
	mac, err3 := dec(parts[4])
	if err1 != nil || err2 != nil || err3 != nil || len(expb) != 8 || len(nonce) != 12 {
		return "", time.Time{}, ErrDynamicChallengeMalformed
	}
	if !crypto.ConstantTimeEqual(mac, dynamicMAC(tenantID, policy, expb, nonce)) {
		return "", time.Time{}, ErrDynamicChallengeAuthentication
	}
	expires := time.Unix(int64(binary.BigEndian.Uint64(expb)), 0).UTC() // #nosec G115 -- unix-epoch seconds round-trip (CWE-190)
	if now.After(expires) {
		return "", time.Time{}, ErrDynamicChallengeExpired
	}
	return parts[3], expires, nil
}

func dynamicParts(token string) ([]string, error) {
	if !IsDynamic(token) || len(token) > 255 {
		return nil, ErrDynamicChallengeMalformed
	}
	parts := strings.Split(token, ".")
	if len(parts) != 5 || parts[1] == "" {
		return nil, ErrDynamicChallengeMalformed
	}
	return parts, nil
}

func dynamicMAC(tenantID string, policy DynamicPolicy, expb, nonce []byte) []byte {
	msg := []byte(dynamicDomain + "\x00" + tenantID + "\x00" + policy.PolicyID + "\x00" + policy.SCEPProfile + "\x00" + strconv.Itoa(policy.RotationVersion) + "\x00")
	msg = append(msg, expb...)
	msg = append(msg, nonce...)
	return crypto.HMACSHA256(policy.Credential, msg)
}

// DynamicChallengeValidator validates dynamic challenges for one tenant's
// served SCEP endpoint and records each decision with the same MDM challenge
// decision events the Intune path writes.
type DynamicChallengeValidator struct {
	tenantID     string
	resolve      DynamicPolicyResolver
	consumeNonce IntuneNonceConsumer
	log          *events.Log
	clock        func() time.Time
}

// NewDynamicChallengeValidator returns a validator for tenantID's policies.
func NewDynamicChallengeValidator(tenantID string, resolve DynamicPolicyResolver, consume IntuneNonceConsumer, log *events.Log, clock func() time.Time) *DynamicChallengeValidator {
	if clock == nil {
		clock = time.Now
	}
	return &DynamicChallengeValidator{tenantID: tenantID, resolve: resolve, consumeNonce: consume, log: log, clock: clock}
}

// ValidateProfile consumes one valid dynamic challenge and returns the SCEP
// profile of the policy that issued it.
func (v *DynamicChallengeValidator) ValidateProfile(ctx context.Context, req IntuneChallengeRequest) (string, error) {
	recorder := &IntuneChallengeValidator{tenantID: v.tenantID, log: v.log}
	profile, nonce, err := v.validate(ctx, req)
	switch {
	case errors.Is(err, ErrIntuneChallengeReplay):
		recorder.emitEvent(ctx, "mdm.intune_scep_challenge.replay_rejected", req, "deny", err.Error(), nonce)
	case err != nil:
		recorder.emit(ctx, req, "deny", err.Error(), nonce)
	default:
		recorder.emit(ctx, req, "allow", "", nonce)
	}
	return profile, err
}

func (v *DynamicChallengeValidator) validate(ctx context.Context, req IntuneChallengeRequest) (string, string, error) {
	if req.TenantID == "" || req.TenantID != v.tenantID {
		return "", "", ErrIntuneChallengeTenant
	}
	policyID, err := DynamicPolicyID(req.Challenge)
	if err != nil {
		return "", "", err
	}
	if v.resolve == nil {
		return "", "", ErrDynamicChallengePolicy
	}
	policy, err := v.resolve(ctx, req.TenantID, policyID)
	if err != nil {
		return "", "", err
	}
	defer secret.Wipe(policy.Credential)
	nonce, expires, err := VerifyDynamic(req.TenantID, policy, req.Challenge, v.clock().UTC())
	if err != nil {
		return "", "", err
	}
	if v.consumeNonce == nil {
		return "", nonce, ErrIntuneChallengeNonceStoreUnavailable
	}
	claimed, err := v.consumeNonce(ctx, req.TenantID, "hmac-dynamic:"+policy.PolicyID+":"+nonce, expires)
	if err != nil {
		return "", nonce, fmt.Errorf("%w: %v", ErrIntuneChallengeNonceStoreUnavailable, err)
	}
	if !claimed {
		return "", nonce, ErrIntuneChallengeReplay
	}
	return policy.SCEPProfile, nonce, nil
}
