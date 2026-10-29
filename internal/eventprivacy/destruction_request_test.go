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

func TestSourceCompletionBindsExactDestructionCommand(t *testing.T) {
	for _, changed := range []bool{false, true} {
		t.Run(map[bool]string{false: "exact", true: "changed-operation"}[changed], func(t *testing.T) {
			policy, log, _, activation := sourceFixture(t, nil)
			appendSource(t, log, "privacy-offboard-source", "tenant.offboarded", activation.Creation.CreatedAt.Add(time.Nanosecond), struct {
				RowsDeleted int `json:"rows_deleted"`
			}{0})
			lifetime, err := policy.LatestLifetime(t.Context(), sourceTenant)
			if err != nil {
				t.Fatal(err)
			}
			request, err := eventprivacy.NewDestructionRequest(lifetime)
			if err != nil {
				t.Fatal(err)
			}
			if changed {
				request.OperationID = "262844c2-dc6b-446c-a1c4-042b2dca5285"
			}
			key, err := jose.GenerateRSASigningKey("source-completion-fixture")
			if err != nil {
				t.Fatal(err)
			}
			// This tests signature/source binding only. No key was removed and
			// a production status must still verify current custody readback.
			claims := eventprotect.DestructionClaims{Schema: "trstctl.event-key-destruction/v1", Request: request, RemovedAt: request.NotBefore}
			wire, err := json.Marshal(claims)
			if err != nil {
				t.Fatal(err)
			}
			receipt, err := key.SignArtifact(jose.ArtifactEventKeyDestruction, wire)
			if err != nil {
				t.Fatal(err)
			}
			policy.Trust = key.JWKS()
			appendSource(t, log, "privacy-completed-source", eventprivacy.EventDestroyed, claims.RemovedAt, eventprivacy.Destroyed{JWS: receipt})
			got, err := policy.LatestLifetime(t.Context(), sourceTenant)
			if changed {
				if !errors.Is(err, eventprivacy.ErrSource) {
					t.Fatalf("different signed command gained authority: %v", err)
				}
			} else if err != nil || got.Completion == nil || got.Completion.JWS != receipt {
				t.Fatalf("exact signed command lost source binding: %v", err)
			}
		})
	}
}
