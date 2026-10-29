// SPDX-License-Identifier: BUSL-1.1

package eventprivacy_test

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/eventprivacy"
	"trstctl.com/trstctl/internal/eventprotect"
)

// Source/parser plus current NEW-key readback only. The signed old claim is a
// fixture: it is not elapsed-retention or actual old-key-removal evidence.
func TestSourceLateOldCompletionPreservesReregisteredLifetime(t *testing.T) {
	policy, log, _, oldActivation := sourceFixture(t, nil)
	offboard := appendSource(t, log, "privacy-old-offboard", "tenant.offboarded", oldActivation.Creation.CreatedAt.Add(time.Nanosecond), struct {
		RowsDeleted int `json:"rows_deleted"`
	}{0})
	oldLife, err := policy.LatestLifetime(t.Context(), sourceTenant)
	if err != nil {
		t.Fatal(err)
	}
	oldRequest, err := eventprivacy.NewDestructionRequest(oldLife)
	if err != nil {
		t.Fatal(err)
	}
	registration := appendSource(t, log, "privacy-new-registration", "tenant.registered", offboard.Time.Add(time.Nanosecond), struct {
		Name string `json:"name"`
	}{"new tenant lifetime"})
	request, err := eventprivacy.NewRequested(sourceTenant, registration.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	requested := appendSource(t, log, eventprivacy.RequestedEventID(request), eventprivacy.EventRequested, registration.Time.Add(time.Nanosecond), request)
	base := t.TempDir()
	keys, err := eventprotect.NewFileAuthority(eventprotect.FileAuthorityConfig{Directory: filepath.Join(base, "new-independent-keys"), BackupRoots: []string{filepath.Join(base, "not-custody")}, Locker: &sourceFixtureLocker{}})
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
	activation := eventprivacy.Activated{RegistrationIdentity: registration.ID, OperationID: request.OperationID, KeyID: request.KeyID, RetentionNanos: request.RetentionNanos, RequestedEventID: requested.ID, RequestedSequence: requested.Sequence, RequestedAt: requested.Time, Creation: creation}
	appendSource(t, log, request.KeyID, eventprivacy.EventActivated, creation.CreatedAt, activation)
	signer, err := jose.GenerateRSASigningKey("late-source-fixture")
	if err != nil {
		t.Fatal(err)
	}
	claims := eventprotect.DestructionClaims{Schema: "trstctl.event-key-destruction/v1", Request: oldRequest, RemovedAt: oldRequest.NotBefore}
	wire, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := signer.SignArtifact(jose.ArtifactEventKeyDestruction, wire)
	if err != nil {
		t.Fatal(err)
	}
	policy.Trust = signer.JWKS()
	appendSource(t, log, "privacy-late-old-completion", eventprivacy.EventDestroyed, claims.RemovedAt, eventprivacy.Destroyed{JWS: receipt})
	latest, err := policy.LatestLifetime(t.Context(), sourceTenant)
	if err != nil || latest.Registration.ID != registration.ID || latest.Activation == nil || latest.Activation.Body.KeyID != ref.ID || latest.Offboard != nil || latest.Completion != nil {
		t.Fatalf("old completion poisoned the new registration: %+v %v", latest, err)
	}
	old, found, err := policy.LifetimeForKey(t.Context(), oldRequest.Ref)
	if err != nil || !found || old.Completion == nil || old.Completion.JWS != receipt {
		t.Fatalf("old completion lost its historical lifetime: %v", err)
	}
	after, err := keys.CreationEvidence(t.Context(), ref)
	if err != nil || after.Digest() != creation.Digest() {
		t.Fatalf("old completion changed current key custody: %v", err)
	}
}
