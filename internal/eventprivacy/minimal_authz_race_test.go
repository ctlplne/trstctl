// SPDX-License-Identifier: BUSL-1.1

package eventprivacy_test

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/eventprivacy"
	"trstctl.com/trstctl/internal/eventprotect"
	"trstctl.com/trstctl/internal/events"
)

// Deterministic selection-versus-admission transition with real retained source
// and file custody. The local lock is a parser fixture, not SQL session proof.
func TestMinimalAuthzSelectedBeforeActivationCannotAppendAfterActivation(t *testing.T) {
	policy, log, _, _ := sourceFixture(t, nil)
	appendSource(t, log, "minimal-race-old-offboard", "tenant.offboarded", time.Now().UTC(), struct {
		RowsDeleted int `json:"rows_deleted"`
	}{0})
	registration := appendSource(t, log, "minimal-race-registration", "tenant.registered", time.Now().UTC(), struct {
		Name string `json:"name"`
	}{"new fixture"})
	request, err := eventprivacy.NewRequested(sourceTenant, registration.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	requested := appendSource(t, log, eventprivacy.RequestedEventID(request), eventprivacy.EventRequested, time.Now().UTC(), request)
	selected, minimal, err := policy.MinimalAuthzEvent(t.Context(), sourceTenant, "owners:write", "deny")
	if err != nil || !minimal {
		t.Fatalf("select preparing audit: %v", err)
	}
	admission := eventprivacy.SourceAdmission{Policy: policy}
	if decision, err := admission.EventProtectionFor(t.Context(), selected); err != nil || decision.Mode != events.EventProtectionPublicControl {
		t.Fatalf("preparing source did not admit its exact closed state: %v", err)
	}
	base := t.TempDir()
	keys, err := eventprotect.NewFileAuthority(eventprotect.FileAuthorityConfig{Directory: filepath.Join(base, "keys"), BackupRoots: []string{filepath.Join(base, "history")}, Locker: &sourceFixtureLocker{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = keys.Close() })
	ref := eventprotect.KeyRef{TenantID: sourceTenant, ID: request.KeyID}
	if err := keys.Provision(t.Context(), ref); err != nil {
		t.Fatal(err)
	}
	creation, err := keys.CreationEvidence(t.Context(), ref)
	if err != nil {
		t.Fatal(err)
	}
	appendSource(t, log, request.KeyID, eventprivacy.EventActivated, time.Now().UTC(), eventprivacy.Activated{RegistrationIdentity: registration.ID, OperationID: request.KeyID, KeyID: request.KeyID, RetentionNanos: request.RetentionNanos, RequestedEventID: requested.ID, RequestedSequence: requested.Sequence, RequestedAt: requested.Time, Creation: creation})
	before, err := log.LastSequence(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admission.EventProtectionFor(t.Context(), selected); !errors.Is(err, eventprivacy.ErrSource) {
		t.Fatal("stale preparing audit survived activation admission")
	}
	after, err := log.LastSequence(t.Context())
	if err != nil || after != before {
		t.Fatal("failed audit admission appended a different fallback")
	}
	if _, minimal, err := policy.MinimalAuthzEvent(t.Context(), sourceTenant, "owners:write", "deny"); err != nil || minimal {
		t.Fatal("active tenant stayed on the closed preparing schema")
	}
}
