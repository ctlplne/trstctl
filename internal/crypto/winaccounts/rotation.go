// SPDX-License-Identifier: BUSL-1.1
package winaccounts

import (
	"context"
	"crypto/subtle"
	"errors"
	"github.com/google/uuid"
	"time"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"unicode/utf16"
	"unicode/utf8"
)

var ErrRotationInvalid = errors.New("windows local accounts: rotation precondition refused")
var ErrRotationUncertain = errors.New("windows local accounts: started rotation requires explicit recovery")
var ErrCredentialRejected = errors.New("windows local accounts: credential rejected")

// ErrRotationNotApplied reports a begun generation that was never applied:
// the predecessor password still signs in as the account and the prepared
// one does not (A268-O1).
var ErrRotationNotApplied = errors.New("windows local accounts: begun rotation was not applied")

// RotationBinding is public native identity, never a mutable name alone.
type RotationBinding struct {
	Machine Machine `json:"machine"`
	Account Account `json:"account"`
}

func (b RotationBinding) Validate() error {
	if err := (Inventory{Machine: b.Machine, Accounts: []Account{b.Account}}).Validate(); err != nil {
		return err
	}
	if !b.Account.Enabled || b.Account.Locked || !b.Account.PasswordRequired {
		return ErrRotationInvalid
	}
	return nil
}

type RotationState struct {
	Binding               RotationBinding
	MinimumPasswordLength uint32
	LockoutThreshold      uint32
	BadPasswordCount      uint32
}
type RotationProof struct {
	Binding          RotationBinding `json:"binding"`
	GenerationID     string          `json:"generation_id"`
	NewAuthenticated bool            `json:"new_authenticated"`
	OldRefused       bool            `json:"old_refused"`
	ObservedAt       time.Time       `json:"observed_at"`
}

// RotationFence must persist Begin before returning fresh=true. A begun attempt
// is never released for a blind repeat. Complete must durably retain the exact
// public proof; failure leaves the operation uncertain, with no vault publication.
// The host journal supplies this contract; it must contain no plaintext password.
type RotationFence interface {
	Begin(context.Context, RotationBinding, string) (fresh bool, err error)
	Complete(context.Context, RotationProof) error
}
type rotationDriver interface {
	Inspect(context.Context, RotationBinding) (RotationState, error)
	SetPassword(context.Context, RotationBinding, []byte) error
	Authenticate(context.Context, RotationBinding, []byte) (string, error)
}
type Rotator struct{ driver rotationDriver }

func NewRotator() Rotator { return Rotator{driver: newNativeRotationDriver()} }
func rotationBudget(s RotationState) bool {
	if s.BadPasswordCount == ^uint32(0) {
		return false
	}
	return s.LockoutThreshold == 0 || uint64(s.BadPasswordCount)+1 < uint64(s.LockoutThreshold)
}
func (r Rotator) inspect(ctx context.Context, b RotationBinding) (RotationState, error) {
	var none RotationState
	if err := ctx.Err(); err != nil {
		return none, err
	}
	if r.driver == nil {
		return none, ErrUnsupported
	}
	state, err := r.driver.Inspect(ctx, b)
	if err != nil {
		return none, err
	}
	if state.Binding != b || state.Binding.Validate() != nil {
		return none, ErrRotationInvalid
	}
	return state, nil
}

// Rotate performs one native reset and at most two network logons: exact new
// token SID, then one predecessor refusal. Native name APIs are checked before
// and after effects; they are not claimed to provide an atomic SID compare/set.
// Caller retains sealed generations and supplies the durable host fence.
func (r Rotator) Rotate(ctx context.Context, b RotationBinding, generation string, old, next []byte, fence RotationFence) (RotationProof, error) {
	var none RotationProof
	if err := ctx.Err(); err != nil {
		return none, err
	}
	id, err := uuid.Parse(generation)
	if err != nil || id == uuid.Nil || id.String() != generation || b.Validate() != nil || fence == nil || !validPrivatePassword(old) || !crypto.ValidAccountPassword(next, 24) || len(next) > 256 || subtle.ConstantTimeCompare(old, next) == 1 {
		return none, ErrRotationInvalid
	}
	state, err := r.inspect(ctx, b)
	if err != nil {
		return none, err
	}
	if !rotationBudget(state) || int64(len(next)) < int64(state.MinimumPasswordLength) {
		return none, ErrRotationInvalid
	}
	// Private copies are locked before any native mutation or authentication.
	oldBuffer, err := secret.NewFrom(old)
	if err != nil {
		return none, err
	}
	defer oldBuffer.Destroy()
	nextBuffer, err := secret.NewFrom(next)
	if err != nil {
		return none, err
	}
	defer nextBuffer.Destroy()
	fresh, err := fence.Begin(ctx, b, generation)
	if err != nil || !fresh {
		return none, ErrRotationUncertain
	}
	state, err = r.inspect(ctx, b)
	if err != nil || !rotationBudget(state) || int64(len(next)) < int64(state.MinimumPasswordLength) {
		return none, ErrRotationUncertain
	}
	if err = nextBuffer.Use(func(value []byte) error { return r.driver.SetPassword(ctx, b, value) }); err != nil {
		return none, ErrRotationUncertain
	}
	state, err = r.inspect(ctx, b)
	if err != nil || !rotationBudget(state) {
		return none, ErrRotationUncertain
	}
	// A failed/new-token mismatch cannot authorize an old-password guess.
	if err = nextBuffer.Use(func(value []byte) error {
		sid, err := r.driver.Authenticate(ctx, b, value)
		if err != nil || sid != b.Account.SID {
			return ErrRotationUncertain
		}
		return nil
	}); err != nil {
		return none, ErrRotationUncertain
	}
	state, err = r.inspect(ctx, b)
	if err != nil || !rotationBudget(state) {
		return none, ErrRotationUncertain
	}
	if err = oldBuffer.Use(func(value []byte) error {
		sid, err := r.driver.Authenticate(ctx, b, value)
		if sid != "" || !errors.Is(err, ErrCredentialRejected) {
			return ErrRotationUncertain
		}
		return nil
	}); err != nil {
		return none, ErrRotationUncertain
	}
	// Native password calls have finished. Release private copies before the
	// final public-state read and durable proof persistence perform any I/O.
	oldBuffer.Destroy()
	nextBuffer.Destroy()
	// No further authentication follows this read: a bad-count increment is
	// retained, never reset or hidden by changing flags or lockout policy.
	state, err = r.inspect(ctx, b)
	if err != nil || state.BadPasswordCount == ^uint32(0) {
		return none, ErrRotationUncertain
	}
	proof := RotationProof{Binding: b, GenerationID: generation, NewAuthenticated: true, OldRefused: true, ObservedAt: time.Now().UTC()}
	if err := ctx.Err(); err != nil {
		return none, ErrRotationUncertain
	}
	if err := fence.Complete(ctx, proof); err != nil {
		return none, ErrRotationUncertain
	}
	return proof, nil
}

// Recover settles a begun generation whose outcome is unknown (A268-O1). It
// changes no password and signs in at most twice, each only while one more
// failure stays below the lockout threshold. The prepared password goes
// first. If it signs in as the account's exact SID, the predecessor must
// then be refused, and the fence completes the same proof Rotate would. If
// the prepared password is refused and the predecessor signs in as the
// account, the generation was never applied (ErrRotationNotApplied). Anything
// else stays uncertain: a foreign SID, a native error, both refused, or no
// lockout budget for the next sign-in.
func (r Rotator) Recover(ctx context.Context, b RotationBinding, generation string, old, next []byte, fence RotationFence) (RotationProof, error) {
	var none RotationProof
	if err := ctx.Err(); err != nil {
		return none, err
	}
	id, err := uuid.Parse(generation)
	if err != nil || id == uuid.Nil || id.String() != generation || b.Validate() != nil || fence == nil || !validPrivatePassword(old) || !crypto.ValidAccountPassword(next, 24) || len(next) > 256 || subtle.ConstantTimeCompare(old, next) == 1 {
		return none, ErrRotationInvalid
	}
	oldBuffer, err := secret.NewFrom(old)
	if err != nil {
		return none, err
	}
	defer oldBuffer.Destroy()
	nextBuffer, err := secret.NewFrom(next)
	if err != nil {
		return none, err
	}
	defer nextBuffer.Destroy()
	signIn := func(value *secret.Buffer) (string, error) {
		state, err := r.inspect(ctx, b)
		if err != nil || !rotationBudget(state) {
			return "", ErrRotationUncertain
		}
		var sid string
		err = value.Use(func(v []byte) error {
			var e error
			sid, e = r.driver.Authenticate(ctx, b, v)
			return e
		})
		return sid, err
	}
	sid, err := signIn(nextBuffer)
	switch {
	case err == nil && sid == b.Account.SID:
		// Applied: the predecessor must be refused, exactly as Rotate proves.
		if sid, err := signIn(oldBuffer); sid != "" || !errors.Is(err, ErrCredentialRejected) {
			return none, ErrRotationUncertain
		}
		oldBuffer.Destroy()
		nextBuffer.Destroy()
		state, err := r.inspect(ctx, b)
		if err != nil || state.BadPasswordCount == ^uint32(0) {
			return none, ErrRotationUncertain
		}
		proof := RotationProof{Binding: b, GenerationID: generation, NewAuthenticated: true, OldRefused: true, ObservedAt: time.Now().UTC()}
		if err := ctx.Err(); err != nil {
			return none, ErrRotationUncertain
		}
		if err := fence.Complete(ctx, proof); err != nil {
			return none, ErrRotationUncertain
		}
		return proof, nil
	case sid == "" && errors.Is(err, ErrCredentialRejected):
		if sid, err := signIn(oldBuffer); err == nil && sid == b.Account.SID {
			return none, ErrRotationNotApplied
		}
		return none, ErrRotationUncertain
	}
	return none, ErrRotationUncertain
}

func validPrivatePassword(value []byte) bool {
	if len(value) == 0 || len(value) > 4096 || !utf8.Valid(value) {
		return false
	}
	units := 0
	for rest := value; len(rest) > 0; {
		r, n := utf8.DecodeRune(rest)
		if r == 0 {
			return false
		}
		units += utf16.RuneLen(r)
		if units > 256 {
			return false
		}
		rest = rest[n:]
	}

	return true
}
