// SPDX-License-Identifier: BUSL-1.1

package challenge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
)

var (
	ErrIntuneChallengeTenant           = errors.New("mdm: Intune challenge tenant mismatch")
	ErrIntuneChallengeReplay           = errors.New("mdm: Intune challenge replay")
	ErrIntuneChallengeTrust            = errors.New("mdm: Intune challenge trust anchors unavailable")
	ErrIntuneChallengeAmbiguousProfile = errors.New("mdm: Intune challenge matches multiple enrollment profiles")
	// ErrIntuneChallengeNoNonce is returned for a signed challenge that carries no
	// nonce. Replay protection is keyed on the nonce, so a challenge without one
	// cannot be consumed once — it would be reusable forever.
	ErrIntuneChallengeNoNonce               = errors.New("mdm: Intune challenge carries no nonce, so it cannot be single-use")
	ErrIntuneChallengeNoExpiry              = errors.New("mdm: Intune challenge carries no expiry, so its replay fence cannot expire")
	ErrIntuneChallengeNonceStoreUnavailable = errors.New("mdm: durable Intune challenge nonce fence unavailable")
)

// IntuneChallengeRequest is the tenant-bound SCEP challenge decision input. The
// challenge is copied from the CSR's challengePassword attribute; CSRDER is the
// signed PKCS#10 request whose subject/SANs must match the verified claim.
type IntuneChallengeRequest struct {
	TenantID      string
	Challenge     string
	CSRDER        []byte
	TransactionID string
}

// IntuneChallengeValidator validates Microsoft Intune dynamic SCEP challenges.
type IntuneChallengeValidator struct {
	tenantID         string
	trustAnchorsDER  [][]byte
	expectedAudience string
	trustConfigs     IntuneTrustConfigResolver
	clock            func() time.Time
	clockSkew        time.Duration
	log              *events.Log
	consumeNonce     IntuneNonceConsumer
}

// IntuneNonceConsumer is a durable tenant-scoped atomic uniqueness fence.
// A false claim means another request already consumed this signed nonce.
type IntuneNonceConsumer func(context.Context, string, string, time.Time) (bool, error)

type IntuneOption func(*IntuneChallengeValidator)

// IntuneTrustConfig is one trusted Intune/JAMF challenge-signing configuration.
// TrustAnchorsDER holds public certificate DER bytes; ExpectedAudience optionally
// overrides the validator-level audience for this policy/config.
type IntuneTrustConfig struct {
	TrustAnchorsDER  [][]byte
	ExpectedAudience string
	// ProfileName is the certificate profile bound to this verified MDM policy.
	// The caller must not substitute a deployment-wide default after validation.
	ProfileName string
}

// IntuneTrustConfigResolver resolves live trust configurations for a tenant-bound
// SCEP challenge decision. It lets the served control plane hot-swap policy-backed
// trust anchors without rebuilding the SCEP handler.
type IntuneTrustConfigResolver func(context.Context, IntuneChallengeRequest) ([]IntuneTrustConfig, error)

func WithIntuneAudience(audience string) IntuneOption {
	return func(v *IntuneChallengeValidator) { v.expectedAudience = audience }
}

func WithIntuneTrustConfigResolver(resolve IntuneTrustConfigResolver) IntuneOption {
	return func(v *IntuneChallengeValidator) { v.trustConfigs = resolve }
}

func WithIntuneClock(clock func() time.Time) IntuneOption {
	return func(v *IntuneChallengeValidator) { v.clock = clock }
}

func WithIntuneClockSkewTolerance(tolerance time.Duration) IntuneOption {
	return func(v *IntuneChallengeValidator) { v.clockSkew = tolerance }
}

func WithIntuneEventLog(log *events.Log) IntuneOption {
	return func(v *IntuneChallengeValidator) { v.log = log }
}

func WithIntuneNonceConsumer(consume IntuneNonceConsumer) IntuneOption {
	return func(v *IntuneChallengeValidator) { v.consumeNonce = consume }
}

func NewIntuneChallengeValidator(tenantID string, trustAnchorsDER [][]byte, opts ...IntuneOption) *IntuneChallengeValidator {
	v := &IntuneChallengeValidator{
		tenantID:        tenantID,
		trustAnchorsDER: cloneDERSet(trustAnchorsDER),
		clock:           time.Now,
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

func (v *IntuneChallengeValidator) Validate(ctx context.Context, req IntuneChallengeRequest) error {
	_, err := v.ValidateProfile(ctx, req)
	return err
}

// ValidateProfile consumes one valid challenge and returns the profile of the
// policy whose trust anchor and audience authenticated it. Empty means the
// configured static bootstrap anchor, which uses the SCEP endpoint default.
func (v *IntuneChallengeValidator) ValidateProfile(ctx context.Context, req IntuneChallengeRequest) (string, error) {
	if req.TenantID == "" || req.TenantID != v.tenantID {
		err := ErrIntuneChallengeTenant
		v.emit(ctx, req, "deny", err.Error(), "")
		return "", err
	}
	now := v.now()
	claim, profile, err := v.validateAgainstTrustConfigs(ctx, req, now)
	if err != nil {
		v.emit(ctx, req, "deny", err.Error(), "")
		return "", err
	}
	if err := v.consumeOnce(ctx, req.TenantID, claim.Nonce, claim.ExpiresAt); err != nil {
		if errors.Is(err, ErrIntuneChallengeReplay) {
			v.emitEvent(ctx, "mdm.intune_scep_challenge.replay_rejected", req, "deny", err.Error(), claim.Nonce)
		} else {
			v.emit(ctx, req, "deny", err.Error(), claim.Nonce)
		}
		return "", err
	}
	v.emit(ctx, req, "allow", "", claim.Nonce)
	return profile, nil
}

func (v *IntuneChallengeValidator) validateAgainstTrustConfigs(ctx context.Context, req IntuneChallengeRequest, now time.Time) (crypto.IntuneChallengeClaim, string, error) {
	configs := make([]IntuneTrustConfig, 0, 2)
	if v.trustConfigs != nil {
		dynamic, err := v.trustConfigs(ctx, req)
		if err != nil {
			return crypto.IntuneChallengeClaim{}, "", err
		}
		configs = append(configs, dynamic...)
	}
	if len(v.trustAnchorsDER) > 0 {
		configs = append(configs, IntuneTrustConfig{TrustAnchorsDER: v.trustAnchorsDER, ExpectedAudience: v.expectedAudience})
	}
	var last error
	var matched bool
	var matchedClaim crypto.IntuneChallengeClaim
	var matchedProfile string
	for _, cfg := range configs {
		if len(cfg.TrustAnchorsDER) == 0 {
			continue
		}
		audience := cfg.ExpectedAudience
		if audience == "" {
			audience = v.expectedAudience
		}
		claim, err := crypto.ValidateIntuneSCEPChallenge(req.Challenge, req.CSRDER, crypto.IntuneChallengeOptions{
			TrustAnchorsDER:    cfg.TrustAnchorsDER,
			ExpectedAudience:   audience,
			Now:                now,
			ClockSkewTolerance: v.clockSkew,
		})
		if err == nil {
			if matched && cfg.ProfileName == "" {
				// Static anchors are a bootstrap fallback, never a way to
				// override an already verified tenant policy.
				continue
			}
			if matched && matchedProfile != cfg.ProfileName {
				return crypto.IntuneChallengeClaim{}, "", ErrIntuneChallengeAmbiguousProfile
			}
			matched, matchedClaim, matchedProfile = true, claim, cfg.ProfileName
			continue
		}
		last = err
	}
	if matched {
		return matchedClaim, matchedProfile, nil
	}
	if last != nil {
		return crypto.IntuneChallengeClaim{}, "", last
	}
	return crypto.IntuneChallengeClaim{}, "", ErrIntuneChallengeTrust
}

func (v *IntuneChallengeValidator) now() time.Time {
	if v.clock != nil {
		return v.clock().UTC()
	}
	return time.Now().UTC()
}

func (v *IntuneChallengeValidator) consumeOnce(ctx context.Context, tenantID, nonce string, expiresAt time.Time) error {
	// An absent nonce used to return nil — success — which quietly turned this
	// function into a no-op. The payload field is `nonce,omitempty` and nothing
	// upstream requires it, so a properly signed challenge with no nonce was
	// never recorded and could be presented an unlimited number of times. For a
	// SCEP enrollment challenge that means one captured challenge mints
	// certificates indefinitely. Replay protection is keyed on the nonce, so a
	// challenge without one cannot be made single-use and must not validate.
	if nonce == "" {
		return ErrIntuneChallengeNoNonce
	}
	if expiresAt.IsZero() {
		return ErrIntuneChallengeNoExpiry
	}
	if v.consumeNonce == nil {
		return ErrIntuneChallengeNonceStoreUnavailable
	}
	tolerance := v.clockSkew
	if tolerance < 0 {
		tolerance = -tolerance
	}
	claimed, err := v.consumeNonce(ctx, tenantID, nonce, expiresAt.Add(tolerance))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrIntuneChallengeNonceStoreUnavailable, err)
	}
	if !claimed {
		return ErrIntuneChallengeReplay
	}
	return nil
}

func (v *IntuneChallengeValidator) emit(ctx context.Context, req IntuneChallengeRequest, decision, reason, nonce string) {
	v.emitEvent(ctx, "mdm.intune_scep_challenge", req, decision, reason, nonce)
}

func (v *IntuneChallengeValidator) emitEvent(ctx context.Context, eventType string, req IntuneChallengeRequest, decision, reason, nonce string) {
	if v.log == nil {
		return
	}
	tenantID := req.TenantID
	if tenantID == "" {
		tenantID = v.tenantID
	}
	payload, _ := json.Marshal(struct {
		Decision      string `json:"decision"`
		Reason        string `json:"reason,omitempty"`
		TransactionID string `json:"transaction_id,omitempty"`
		Nonce         string `json:"nonce,omitempty"`
	}{Decision: decision, Reason: reason, TransactionID: req.TransactionID, Nonce: nonce})
	_ = auditsink.Emit(ctx, auditsink.AuditorFunc(func(ctx context.Context, et, tid string, d []byte) error {
		_, err := v.log.Append(ctx, events.Event{Type: et, TenantID: tid, Data: d})
		return err
	}), nil, eventType, tenantID, payload)
}

func cloneDERSet(in [][]byte) [][]byte {
	out := make([][]byte, 0, len(in))
	for _, der := range in {
		out = append(out, append([]byte(nil), der...))
	}
	return out
}
