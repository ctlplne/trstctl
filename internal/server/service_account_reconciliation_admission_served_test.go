// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"context"
	"net/http"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/store"
)

func TestServedReconciliationExpiryNeverGuessesDriftedPredecessorA267(t *testing.T) {
	servedDependentRotationScenario(t, nil, false, dependentRotationOptions{Reconcile: true, ExpireBeforeApply: true})
}
func TestServedReconciliationRejectsUnrecoverableStoredGenerationA267(t *testing.T) {
	servedDependentRotationScenario(t, nil, false, dependentRotationOptions{Reconcile: true, InvalidRecovery: true})
}
func storedDependentFixtureValue(old []byte, invalid bool) []byte {
	if invalid {
		return []byte(`{"bind_dn":"CN=foreign,DC=example,DC=test","password":"owned-wrong-target-recovery"}`)
	}
	return old
}
func assertDependentNoEffectAdmission(t *testing.T, h *roleHarness, directory *dependentDirectoryBoundary, root, token, commandID string, expires time.Time, expired bool) {
	t.Helper()
	directory.mu.Lock()
	initial, err := secret.NewFrom(directory.current.Bytes())
	directory.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	defer initial.Destroy()
	if expired {
		timer := time.NewTimer(time.Until(expires.Add(50 * time.Millisecond)))
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-t.Context().Done():
			t.Fatal(t.Context().Err())
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	advanceErr := h.srv.api.AdvanceStaticSecretRotation(ctx, h.tenant, commandID, 1)
	command, err := h.store.GetSecretStaticRotationCommand(ctx, h.tenant, commandID)
	if err != nil {
		t.Fatal(err)
	}
	directory.mu.Lock()
	same := bytes.Equal(directory.current.Bytes(), initial.Bytes())
	applied, restored := directory.applied, directory.restored
	directory.mu.Unlock()
	if !same || applied != 0 || restored != 0 || command.Phase != store.SecretStaticRotationFailed || command.ResultVersion != 0 {
		t.Fatalf("pre-effect refusal changed or guessed the unknown directory generation: unchanged=%v applied=%d restored=%d phase=%s version=%d err=%v", same, applied, restored, command.Phase, command.ResultVersion, advanceErr)
	}
	status, raw := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/secrets/store/app/dependent", token, nil)
	if status != http.StatusOK || !bytes.Contains(raw, []byte(`"version":1`)) {
		t.Fatal("pre-effect refusal changed vault generation")
	}
}
