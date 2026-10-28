// SPDX-License-Identifier: BUSL-1.1

package objectstore

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

// A208: S3 Object Lock on the archives trstctl writes. Object Lock is a
// bucket property set when the bucket is created; trstctl never enables or
// changes it. With an ObjectLock in Options, every object trstctl creates
// carries that retention. A legal hold is a person's decision about one
// object; it is set or cleared and then read back.

// ObjectLock is the retention every new object carries.
type ObjectLock struct {
	// Mode is GOVERNANCE or COMPLIANCE.
	Mode string
	// Retention is how long after its creation an object cannot be deleted.
	Retention time.Duration
}

// Validate checks the mode and a retention of at least a day.
func (l ObjectLock) Validate() error {
	switch strings.ToUpper(l.Mode) {
	case string(types.ObjectLockModeGovernance), string(types.ObjectLockModeCompliance):
	default:
		return fmt.Errorf("objectstore: object lock mode %q is not GOVERNANCE or COMPLIANCE", l.Mode)
	}
	if l.Retention < 24*time.Hour {
		return errors.New("objectstore: object lock retention is at least 24h")
	}
	return nil
}

// ErrLocked is a removal the store's Object Lock forbids: a retention not yet
// expired or a legal hold. Until is when the retention expires (zero for a
// legal hold, which lasts until a person releases it).
type ErrLocked struct {
	Name      string
	Until     time.Time
	LegalHold bool
}

func (e *ErrLocked) Error() string {
	if e.LegalHold {
		return "objectstore: " + e.Name + " is under an S3 legal hold"
	}
	return "objectstore: " + e.Name + " is under S3 Object Lock retention until " + e.Until.UTC().Format(time.RFC3339)
}

// BucketLockEnabled reports whether the bucket has S3 Object Lock enabled.
func (s *S3) BucketLockEnabled(ctx context.Context) (bool, error) {
	enabled := false
	err := s.call(ctx, 0, func(ctx context.Context) error {
		out, err := s.client.GetObjectLockConfiguration(ctx, &s3.GetObjectLockConfigurationInput{Bucket: awssdk.String(s.bucket)})
		switch {
		case noLockConfiguration(err):
			return nil
		case err != nil:
			return classify(err, "")
		}
		enabled = out.ObjectLockConfiguration != nil &&
			out.ObjectLockConfiguration.ObjectLockEnabled == types.ObjectLockEnabledEnabled
		return nil
	})
	return enabled, err
}

// LockConfigured reports whether this store writes objects under Object Lock.
func (s *S3) LockConfigured() bool { return s.lock != nil }

// LockState is one object's lock as the store reports it.
type LockState struct {
	Mode        string
	RetainUntil *time.Time
	LegalHold   bool
}

// Locked reports whether the store would refuse deleting the object at now.
func (l LockState) Locked(now time.Time) bool {
	return l.LegalHold || (l.RetainUntil != nil && now.Before(*l.RetainUntil))
}

// Locker is a store that supports S3 Object Lock.
type Locker interface {
	SetLegalHold(ctx context.Context, name string, on bool) error
	Lock(ctx context.Context, name string) (LockState, error)
}

var _ Locker = (*S3)(nil)

// ErrNoObjectLock is a legal hold asked of a bucket without S3 Object Lock.
var ErrNoObjectLock = errors.New("objectstore: the bucket does not have S3 Object Lock enabled")

// SetLegalHold turns one object's legal hold on or off.
func (s *S3) SetLegalHold(ctx context.Context, name string, on bool) error {
	key, err := s.key(name)
	if err != nil {
		return err
	}
	status := types.ObjectLockLegalHoldStatusOff
	if on {
		status = types.ObjectLockLegalHoldStatusOn
	}
	return s.call(ctx, 0, func(ctx context.Context) error {
		_, err := s.client.PutObjectLegalHold(ctx, &s3.PutObjectLegalHoldInput{
			Bucket: awssdk.String(s.bucket), Key: awssdk.String(key),
			LegalHold:         &types.ObjectLockLegalHold{Status: status},
			ChecksumAlgorithm: types.ChecksumAlgorithmSha256,
		})
		if noLockConfiguration(err) {
			return ErrNoObjectLock
		}
		return classify(err, name)
	})
}

// Lock reads an object's retention and legal hold. An object with neither
// reads as unlocked.
func (s *S3) Lock(ctx context.Context, name string) (LockState, error) {
	key, err := s.key(name)
	if err != nil {
		return LockState{}, err
	}
	var out LockState
	err = s.call(ctx, 0, func(ctx context.Context) error {
		hold, err := s.client.GetObjectLegalHold(ctx, &s3.GetObjectLegalHoldInput{Bucket: awssdk.String(s.bucket), Key: awssdk.String(key)})
		switch {
		case noLockConfiguration(err):
		case err != nil:
			return classify(err, name)
		case hold.LegalHold != nil:
			out.LegalHold = hold.LegalHold.Status == types.ObjectLockLegalHoldStatusOn
		}
		retention, err := s.client.GetObjectRetention(ctx, &s3.GetObjectRetentionInput{Bucket: awssdk.String(s.bucket), Key: awssdk.String(key)})
		switch {
		case noLockConfiguration(err):
		case err != nil:
			return classify(err, name)
		case retention.Retention != nil:
			out.Mode = string(retention.Retention.Mode)
			out.RetainUntil = retention.Retention.RetainUntilDate
		}
		return nil
	})
	return out, err
}

// noLockConfiguration is the store saying there is no lock of that kind: the
// object has none, or its bucket has no Object Lock at all (S3 and MinIO
// answer an error, not an empty element).
func noLockConfiguration(err error) bool {
	var api smithy.APIError
	if !errors.As(err, &api) {
		return false
	}
	switch api.ErrorCode() {
	case "NoSuchObjectLockConfiguration", "ObjectLockConfigurationNotFoundError":
		return true
	case "InvalidRequest":
		message := strings.ToLower(strings.ReplaceAll(api.ErrorMessage(), " ", ""))
		return strings.Contains(message, "objectlockconfiguration")
	}
	return false
}
