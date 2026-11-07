// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/store"
)

// TestFreshSignInWindowA277 is the gate every high-risk release passes
// through (sessions, emergency sessions, check-out reveals): only a sign-in
// inside the template's window counts; an API token (no sign-in time), a
// stale sign-in and one dated in the future are refused with the window as
// the challenge's max_age, and a template that is not high-risk asks for
// nothing.
func TestFreshSignInWindowA277(t *testing.T) {
	now := time.Date(2026, 11, 8, 1, 0, 0, 0, time.UTC)
	s := &pamService{clock: func() time.Time { return now }}
	window := 5 * time.Minute
	for _, tc := range []struct {
		name       string
		signedInAt time.Time
		ok         bool
	}{
		{"an API token", time.Time{}, false},
		{"a sign-in two hours ago", now.Add(-2 * time.Hour), false},
		{"a sign-in just past the window", now.Add(-window - time.Second), false},
		{"a sign-in dated in the future", now.Add(2 * time.Minute), false},
		{"a sign-in four minutes ago", now.Add(-4 * time.Minute), true},
		{"a sign-in just now", now, true},
	} {
		err := s.requireFreshSignIn(window, tc.signedInAt)
		var reauth *api.PAMReauthenticationRequired
		switch {
		case tc.ok && err != nil:
			t.Errorf("%s: refused: %v", tc.name, err)
		case !tc.ok && (!errors.As(err, &reauth) || reauth.MaxAge != window):
			t.Errorf("%s: %v, want the step-up refusal with a five-minute max age", tc.name, err)
		}
	}
	if err := s.requireFreshSignIn(0, time.Time{}); err != nil {
		t.Fatalf("a template that is not high-risk asked for a sign-in: %v", err)
	}
	if got := pamTemplateReauthWindow(&store.PAMAccessTemplate{ReauthenticateWithinSeconds: 600}); got != 10*time.Minute {
		t.Fatalf("a 600-second template window = %s", got)
	}
	if got := pamTemplateReauthWindow(nil); got != 0 {
		t.Fatalf("no template = %s", got)
	}
}
