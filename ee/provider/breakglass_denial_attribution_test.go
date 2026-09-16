// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"context"
	"errors"
	"testing"
)

// TestBreakGlassDenialRequiresAnAttributableSubject is the regression guard for
// the anonymous veto.
//
// The approve path refused an empty subject; the denial path, which runs first,
// did not. So a caller with no identity could kill a break-glass grant and the
// record would show DeniedBy blank. Denial is the cheap direction — one refusal
// is enough to stop emergency access even after someone has approved — which
// makes an unattributable denial during an incident the more dangerous of the
// two, not the less.
func TestBreakGlassDenialRequiresAnAttributableSubject(t *testing.T) {
	ctx := context.Background()
	svc := breakGlassService(t)
	grant := requestGrant(t, svc)

	for _, subject := range []string{"", "   "} {
		if _, err := svc.ConsentBreakGlass(ctx, providerOperator(subject), "tenant-x", grant.ID, false); !errors.Is(err, ErrForbidden) {
			t.Fatalf("denial with subject %q returned %v, want ErrForbidden; "+
				"emergency access can be vetoed by nobody in particular", subject, err)
		}
	}

	// The grant must be untouched — a rejected denial must not have half-applied.
	after, err := svc.store.BreakGlassGrant(ctx, grant.ID)
	if err != nil {
		t.Fatalf("reload grant: %v", err)
	}
	if !after.DeniedAt.IsZero() || after.DeniedBy != "" {
		t.Fatalf("the refused denial still marked the grant denied: DeniedAt=%v DeniedBy=%q",
			after.DeniedAt, after.DeniedBy)
	}

	// A named approver must still be able to deny — the fix must not break the
	// property that one refusal stops emergency access.
	denied, err := svc.ConsentBreakGlass(ctx, providerOperator("approver-a"), "tenant-x", grant.ID, false)
	if err != nil {
		t.Fatalf("a named approver could not deny: %v", err)
	}
	if denied.DeniedBy != "approver-a" || denied.DeniedAt.IsZero() {
		t.Fatalf("denial was not attributed: DeniedBy=%q DeniedAt=%v", denied.DeniedBy, denied.DeniedAt)
	}
}
