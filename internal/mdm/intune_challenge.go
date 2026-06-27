package mdm

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
)

var (
	ErrIntuneChallengeTenant = errors.New("mdm: Intune challenge tenant mismatch")
	ErrIntuneChallengeReplay = errors.New("mdm: Intune challenge replay")
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
	clock            func() time.Time
	clockSkew        time.Duration
	log              *events.Log

	mu     sync.Mutex
	replay map[string]time.Time
}

type IntuneOption func(*IntuneChallengeValidator)

func WithIntuneAudience(audience string) IntuneOption {
	return func(v *IntuneChallengeValidator) { v.expectedAudience = audience }
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

func NewIntuneChallengeValidator(tenantID string, trustAnchorsDER [][]byte, opts ...IntuneOption) *IntuneChallengeValidator {
	v := &IntuneChallengeValidator{
		tenantID:        tenantID,
		trustAnchorsDER: cloneDERSet(trustAnchorsDER),
		clock:           time.Now,
		replay:          make(map[string]time.Time),
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

func (v *IntuneChallengeValidator) Validate(ctx context.Context, req IntuneChallengeRequest) error {
	if req.TenantID == "" || req.TenantID != v.tenantID {
		err := ErrIntuneChallengeTenant
		v.emit(ctx, req, "deny", err.Error(), "")
		return err
	}
	now := v.now()
	claim, err := crypto.ValidateIntuneSCEPChallenge(req.Challenge, req.CSRDER, crypto.IntuneChallengeOptions{
		TrustAnchorsDER:    v.trustAnchorsDER,
		ExpectedAudience:   v.expectedAudience,
		Now:                now,
		ClockSkewTolerance: v.clockSkew,
	})
	if err != nil {
		v.emit(ctx, req, "deny", err.Error(), "")
		return err
	}
	if err := v.consumeOnce(req.TenantID, claim.Nonce, claim.ExpiresAt, now); err != nil {
		v.emitEvent(ctx, "mdm.intune_scep_challenge.replay_rejected", req, "deny", err.Error(), claim.Nonce)
		return err
	}
	v.emit(ctx, req, "allow", "", claim.Nonce)
	return nil
}

func (v *IntuneChallengeValidator) now() time.Time {
	if v.clock != nil {
		return v.clock().UTC()
	}
	return time.Now().UTC()
}

func (v *IntuneChallengeValidator) consumeOnce(tenantID, nonce string, expiresAt, now time.Time) error {
	if nonce == "" {
		return nil
	}
	key := tenantID + "\x00" + nonce
	if expiresAt.IsZero() {
		expiresAt = now.Add(5 * time.Minute)
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	for k, exp := range v.replay {
		if !now.Before(exp) {
			delete(v.replay, k)
		}
	}
	if exp, ok := v.replay[key]; ok && now.Before(exp) {
		return ErrIntuneChallengeReplay
	}
	v.replay[key] = expiresAt
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
