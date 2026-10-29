// SPDX-License-Identifier: BUSL-1.1

package eventprivacy_test

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/eventprivacy"
	"trstctl.com/trstctl/internal/eventprotect"
)

func TestSourceDestructionReceiptRequiresExplicitHistoricalTrustAfterSignerRotation(t *testing.T) {
	policy, log, _, activation := sourceFixture(t, nil)
	appendSource(t, log, "privacy-offboard-source", "tenant.offboarded", activation.Creation.CreatedAt.Add(time.Nanosecond), struct {
		RowsDeleted int `json:"rows_deleted"`
	}{0})
	life, err := policy.LatestLifetime(t.Context(), sourceTenant)
	if err != nil {
		t.Fatal(err)
	}
	request, err := eventprivacy.NewDestructionRequest(life)
	if err != nil {
		t.Fatal(err)
	}
	oldKey, err := jose.GenerateRSASigningKey("historical-source-fixture")
	if err != nil {
		t.Fatal(err)
	}
	currentKey, err := jose.GenerateRSASigningKey("rotated-source-fixture")
	if err != nil {
		t.Fatal(err)
	}
	stranger, err := jose.GenerateRSASigningKey("untrusted-source-fixture")
	if err != nil {
		t.Fatal(err)
	}
	// This is source trust parsing only. It is not key removal, elapsed wall
	// time, current-custodian absence readback or production restore evidence.
	claims := eventprotect.DestructionClaims{Schema: "trstctl.event-key-destruction/v1", Request: request, RemovedAt: request.NotBefore}
	wire, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := oldKey.SignArtifact(jose.ArtifactEventKeyDestruction, wire)
	if err != nil {
		t.Fatal(err)
	}
	appendSource(t, log, "privacy-completed-source", eventprivacy.EventDestroyed, claims.RemovedAt, eventprivacy.Destroyed{JWS: receipt})
	policy.Trust = currentKey.JWKS()
	if _, err := policy.LatestLifetime(t.Context(), sourceTenant); !errors.Is(err, eventprivacy.ErrSource) {
		t.Fatalf("receipt granted trust to its embedded former signer: %v", err)
	}
	policy.VerificationKeys = stranger.JWKS()
	if _, err := policy.LatestLifetime(t.Context(), sourceTenant); !errors.Is(err, eventprivacy.ErrSource) {
		t.Fatalf("unrelated historical pin accepted receipt: %v", err)
	}
	policy.VerificationKeys = oldKey.JWKS()
	got, err := policy.LatestLifetime(t.Context(), sourceTenant)
	if err != nil || got.Completion == nil || got.Completion.JWS != receipt {
		t.Fatalf("explicit historical pin failed after rotation: %v", err)
	}
}
