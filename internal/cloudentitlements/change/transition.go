// SPDX-License-Identifier: BUSL-1.1
package change

import "errors"

// ValidateProgress refuses completion without the public native postcondition
// and, for replacement, the exact separately projected consumer source receipt.
func ValidateProgress(current Record, state string, result *Result) error {
	if state == Queued {
		if current.State != AwaitingApproval {
			return errors.New("cloud change is not awaiting approval")
		}
		return nil
	}
	if result == nil || result.CheckedAt.IsZero() {
		return errors.New("cloud phase has no dated result")
	}
	if state == Failed {
		if current.State != Queued && current.State != Preparing && current.State != WaitingAdoption {
			return errors.New("cloud change is already terminal")
		}
		if result.Error == "" {
			return errors.New("cloud failure has no explanation")
		}
		return nil
	}
	if current.Intent.Action != ReplaceKey {
		if (current.Intent.Action != RevokeKey && current.Intent.Action != TightenPolicy) || state != Verified || current.State != Queued || result.EffectUncertain || result.Error != "" || (current.Intent.Action == RevokeKey && !result.KeyAbsent) || (current.Intent.Action == TightenPolicy && !result.PolicyMatches) {
			return errors.New("cloud change lacks a verified native postcondition")
		}
		return nil
	}
	switch state {
	case Preparing:
		if current.State == Queued && result.ReplacementCommandID != "" {
			return nil
		}
	case WaitingAdoption:
		if current.State == Preparing && result.ReplacementLeaseID != "" && result.ReplacementVersion == current.Intent.ReplacementExpectedVersion+1 && result.ReplacementNativeRoleID == current.Intent.ReplacementRoleID && result.ReplacementExpiresAt != nil && result.ReplacementExpiresAt.After(result.CheckedAt) {
			return nil
		}
	case Verified:
		receipt := current.Adoption
		if current.State == WaitingAdoption && receipt != nil && receipt.EventID != "" && receipt.Sequence > 0 && !receipt.VerifiedAt.IsZero() && receipt.Subject == current.Intent.ConsumerSubject && receipt.Consumer == current.Intent.Consumer && receipt.Name == current.Intent.ReplacementRole && receipt.Version == current.Intent.ReplacementExpectedVersion+1 && result.ReplacementVersion == receipt.Version && result.ReplacementNativeRoleID == current.Intent.ReplacementRoleID && result.KeyAbsent && !result.EffectUncertain && result.Error == "" {
			return nil
		}
	}
	return errors.New("replacement phase or exact consumer/native evidence is incomplete")
}
