// SPDX-License-Identifier: BUSL-1.1

package tenancy_test

import (
	"errors"
	"fmt"
	"testing"

	"trstctl.com/trstctl/internal/tenancy"
)

// A refusal answers callers exactly as ErrServiceUnavailable always did,
// whatever its condition, and keeps that condition for the server.
func TestRefusalReadsAsTheSentinelAndKeepsItsReason(t *testing.T) {
	const reason = "the tenant's erasure is pending"
	for name, err := range map[string]error{
		"bare":    tenancy.Refused(reason),
		"wrapped": fmt.Errorf("enroll: %w", tenancy.Refused(reason)),
	} {
		if !errors.Is(err, tenancy.ErrServiceUnavailable) {
			t.Errorf("%s: %v is not ErrServiceUnavailable", name, err)
		}
		if got := tenancy.RefusalReason(err); got != reason {
			t.Errorf("%s: reason %q, want %q", name, got, reason)
		}
	}
	if got := tenancy.Refused(reason).Error(); got != tenancy.ErrServiceUnavailable.Error() {
		t.Errorf("a refusal reads %q; want %q", got, tenancy.ErrServiceUnavailable.Error())
	}
	if got := tenancy.RefusalReason(tenancy.ErrServiceUnavailable); got != "" {
		t.Errorf("the bare sentinel names reason %q; want none", got)
	}
	if got := tenancy.RefusalReason(errors.New("registry unavailable")); got != "" {
		t.Errorf("an unrelated error names reason %q; want none", got)
	}
}
