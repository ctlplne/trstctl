// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/eventprivacy"
	"trstctl.com/trstctl/internal/eventprotect"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

// Public operator request and actual bounded preparation worker. The signer is
// an explicit local fixture; final shipped-process/image proof is separate.
func TestServedEventProtectionPreviewEnableAndCurrentStatus(t *testing.T) {
	st := newServerTestStore(t)
	cfg := eventProtectionRuntimeConfigFixture(t)
	key := testAuditSigningKey(t)
	log, runtime, err := openConfiguredEventSource(t.Context(), cfg, st, key, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	t.Cleanup(func() { _ = log.Close() })
	const tenant = "9bf28bb0-5e5f-46c7-a085-879ae87ec3cc"
	registration, err := log.Append(t.Context(), events.Event{Type: projections.EventTenantRegistered, TenantID: tenant, Data: []byte(`{"name":"operator controls"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if err := projections.New(st, runtime.projectionOptions()...).Rebuild(t.Context(), log); err != nil {
		t.Fatal(err)
	}
	token := seedServedAPIToken(t, t.Context(), st, tenant, "privacy-operator@example.invalid", []string{string(authz.PrivacyRead), string(authz.PrivacyWrite)})
	denied := seedServedAPIToken(t, t.Context(), st, tenant, "ordinary-reader@example.invalid", []string{string(authz.OwnersRead)})
	other := seedServedAPIToken(t, t.Context(), st, tenant, "other-privacy-operator@example.invalid", []string{string(authz.PrivacyRead), string(authz.PrivacyWrite)})
	srv, err := Build(t.Context(), Deps{Store: st, Log: log, AuditSigningKey: key, eventProtection: runtime})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Shutdown(t.Context()) }()
	call := func(method, path, credential, body, idempotency string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(method, path, bytes.NewBufferString(body))
		request.Header.Set("Authorization", "Bearer "+credential)
		request.Header.Set("Content-Type", "application/json")
		if idempotency != "" {
			request.Header.Set("Idempotency-Key", idempotency)
		}
		response := httptest.NewRecorder()
		srv.Handler().ServeHTTP(response, request)
		return response
	}
	const endpoint = "/api/v1/privacy/event-protection"
	state := call(http.MethodGet, endpoint, token, "", "")
	if state.Code != http.StatusOK {
		t.Fatalf("initial status HTTP=%d body=%s", state.Code, state.Body.String())
	}
	var status struct {
		State                string `json:"state"`
		RegistrationIdentity string `json:"registration_identity"`
	}
	if err := json.Unmarshal(state.Body.Bytes(), &status); err != nil || status.State != "not_enabled" || status.RegistrationIdentity != registration.ID {
		t.Fatalf("initial current status=%+v err=%v", status, err)
	}
	requested, err := eventprivacy.NewRequested(tenant, registration.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	countRequests := func() int {
		head, err := log.LastSequence(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		count := 0
		if err := log.ReplayTenantMetadataTypesThrough(t.Context(), tenant, 1, head, []string{eventprivacy.EventRequested}, func(events.EnvelopeMetadata) error { count++; return nil }); err != nil {
			t.Fatal(err)
		}
		return count
	}
	assertNoPreparation := func() {
		if countRequests() != 0 {
			t.Fatal("preview/refusal wrote a protection request")
		}
		_, found, err := runtime.custody.LookupKeyState(t.Context(), eventprotect.KeyRef{TenantID: tenant, ID: requested.KeyID})
		if err != nil || found {
			t.Fatalf("preview/refusal created custody: found=%v err=%v", found, err)
		}
	}
	body := `{"registration_identity":"` + registration.ID + `","retention":"1h0m0s"}`
	for i := 0; i < 2; i++ {
		preview := call(http.MethodPost, endpoint+"/preview", token, body, "")
		if preview.Code != http.StatusOK {
			t.Fatalf("preview HTTP=%d body=%s", preview.Code, preview.Body.String())
		}
		var plan struct {
			Ready              bool   `json:"ready"`
			EffectFree         bool   `json:"effect_free"`
			RequestFingerprint string `json:"request_fingerprint"`
		}
		if err := json.Unmarshal(preview.Body.Bytes(), &plan); err != nil || !plan.Ready || !plan.EffectFree || plan.RequestFingerprint == "" {
			t.Fatalf("preview=%+v err=%v", plan, err)
		}
		assertNoPreparation()
	}
	if response := call(http.MethodPost, endpoint, denied, body, "forbidden-enable"); response.Code != http.StatusForbidden {
		t.Fatalf("forbidden enable HTTP=%d", response.Code)
	}
	if response := call(http.MethodPost, endpoint, token, body, ""); response.Code != http.StatusBadRequest {
		t.Fatalf("missing key HTTP=%d", response.Code)
	}
	stale := `{"registration_identity":"stale-registration","retention":"1h0m0s"}`
	if response := call(http.MethodPost, endpoint, token, stale, "stale-enable"); response.Code != http.StatusConflict {
		t.Fatalf("stale registration HTTP=%d body=%s", response.Code, response.Body.String())
	}
	assertNoPreparation()
	accepted := call(http.MethodPost, endpoint, token, body, "enable-exact-policy")
	if accepted.Code != http.StatusAccepted {
		t.Fatalf("enable HTTP=%d body=%s", accepted.Code, accepted.Body.String())
	}
	var result struct {
		OperationID          string `json:"operation_id"`
		RegistrationIdentity string `json:"registration_identity"`
	}
	if err := json.Unmarshal(accepted.Body.Bytes(), &result); err != nil || result.OperationID != requested.OperationID || result.RegistrationIdentity != registration.ID {
		t.Fatalf("accepted=%+v err=%v", result, err)
	}
	if countRequests() != 1 {
		t.Fatal("enable did not retain exactly one request")
	}
	if err := srv.Drain(t.Context()); err != nil {
		t.Fatal(err)
	}
	life, err := runtime.policy.LatestLifetime(t.Context(), tenant)
	if err != nil || life.Activation == nil || life.Activation.Body.Creation.Ref.ID != requested.KeyID {
		t.Fatalf("actual preparation worker did not activate: %v", err)
	}
	state = call(http.MethodGet, endpoint, token, "", "")
	if err := json.Unmarshal(state.Body.Bytes(), &status); err != nil || state.Code != http.StatusOK || status.State != "active" {
		t.Fatalf("active status HTTP=%d state=%+v err=%v", state.Code, status, err)
	}
	replay := call(http.MethodPost, endpoint, token, body, "enable-exact-policy")
	if replay.Code != accepted.Code || !bytes.Equal(replay.Body.Bytes(), accepted.Body.Bytes()) {
		t.Fatal("same request did not replay exact accepted result")
	}
	changed := `{"registration_identity":"` + registration.ID + `","retention":"2h0m0s"}`
	for _, attempt := range []struct{ credential, body, key string }{{other, body, "enable-exact-policy"}, {token, changed, "enable-exact-policy"}, {token, changed, "different-key-changed-policy"}} {
		response := call(http.MethodPost, endpoint, attempt.credential, attempt.body, attempt.key)
		if response.Code != http.StatusConflict {
			t.Fatalf("changed caller/policy HTTP=%d body=%s", response.Code, response.Body.String())
		}
	}
	if countRequests() != 1 {
		t.Fatal("retry/conflict created another protection request")
	}
	originalCreation := life.Activation.Body.Creation.Digest()
	originalPath := filepath.Join(cfg.Privacy.EventProtection.KeyDirectory, tenant, requested.KeyID+".key")
	parked := filepath.Join(t.TempDir(), "original.key")
	if err := os.Rename(originalPath, parked); err != nil {
		t.Fatal(err)
	}
	restored := false
	defer func() {
		if !restored {
			_ = os.Rename(parked, originalPath)
		}
	}()
	unavailable := call(http.MethodGet, endpoint, token, "", "")
	if unavailable.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing current key HTTP=%d", unavailable.Code)
	}
	for _, private := range []string{cfg.Privacy.EventProtection.KeyDirectory, "privacy-operator@example.invalid", token} {
		if bytes.Contains(unavailable.Body.Bytes(), []byte(private)) {
			t.Fatal("unavailable public status leaked custody/private diagnostics")
		}
	}
	if err := os.Rename(parked, originalPath); err != nil {
		t.Fatal(err)
	}
	restored = true
	state = call(http.MethodGet, endpoint, token, "", "")
	if err := json.Unmarshal(state.Body.Bytes(), &status); err != nil || state.Code != http.StatusOK || status.State != "active" {
		t.Fatalf("original key recovery HTTP=%d state=%+v err=%v", state.Code, status, err)
	}
	life, err = runtime.policy.LatestLifetime(t.Context(), tenant)
	if err != nil || life.Activation.Body.Creation.Digest() != originalCreation {
		t.Fatal("status/recovery regenerated custody")
	}
}
