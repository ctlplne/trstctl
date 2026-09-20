// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"net/url"
	"reflect"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// TestServedProfileRestoreIsReviewedVersionedAndReplaySafe is the F53 recovery
// oracle. Recovery must never reactivate or rewrite a historical row. It first
// returns an exact, effect-free receipt, then copies the reviewed historical spec
// into one new event-sourced active version. The expected-active-version fence
// makes a stale browser receipt fail closed instead of rolling back over a newer
// operator decision.
func TestServedProfileRestoreIsReviewedVersionedAndReplaySafe(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	registerServedTenant(t, h, "profile recovery tenant")
	admin := seedScopedToken(t, h.store, h.tenant, "profiles:read", "profiles:write")

	v1 := createServedProfileVersion(t, h, admin, "web-tls", map[string]any{
		"allowed_key_algorithms": []string{"ECDSA"},
		"allowed_ekus":           []string{"serverAuth"},
		"allowed_protocols":      []string{"api", "acme"},
		"max_validity":           "24h",
	})
	v2 := createServedProfileVersion(t, h, admin, "web-tls", map[string]any{
		"allowed_key_algorithms": []string{"ECDSA"},
		"allowed_ekus":           []string{"serverAuth"},
		"allowed_protocols":      []string{"api"},
		"max_validity":           "1h",
	})
	if v1.Version != 1 || v2.Version != 2 || !v2.Active {
		t.Fatalf("profile setup versions = (%+v, %+v), want historical v1 and active v2", v1, v2)
	}

	beforePreview, err := h.log.LastSequence(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	restorePath := "/api/v1/profiles/" + url.PathEscape(v1.Name) + "/versions/1/restore"
	req := map[string]any{
		"expected_active_version": 2,
		"reason":                  "Recover the known-good 24-hour web TLS rule",
	}
	status, body := secretsReq(t, h, http.MethodPost, restorePath+"/preview", admin, req)
	if status != http.StatusOK {
		t.Fatalf("profile restore preview status=%d body=%s, want 200", status, body)
	}
	var preview struct {
		Capability             string          `json:"capability"`
		Operation              string          `json:"operation"`
		Ready                  bool            `json:"ready"`
		Name                   string          `json:"name"`
		SourceVersion          int             `json:"source_version"`
		ActiveVersion          int             `json:"active_version"`
		NextVersion            int             `json:"next_version"`
		Reason                 string          `json:"reason"`
		SourceSpecDigest       string          `json:"source_spec_digest"`
		RequestFingerprint     string          `json:"request_fingerprint"`
		RequiredPermission     string          `json:"required_permission"`
		Changes                []string        `json:"changes"`
		Risks                  []string        `json:"risks"`
		VerificationSteps      []string        `json:"verification_steps"`
		PreviewWrites          []string        `json:"preview_writes"`
		PreviewExternalEffects []string        `json:"preview_external_effects"`
		SourceSpec             json.RawMessage `json:"source_spec"`
	}
	if err := json.Unmarshal(body, &preview); err != nil {
		t.Fatal(err)
	}
	if !preview.Ready || preview.Capability != "certificate_profile_recovery" || preview.Operation != "restore_as_new_version" ||
		preview.Name != "web-tls" || preview.SourceVersion != 1 || preview.ActiveVersion != 2 || preview.NextVersion != 3 ||
		preview.Reason != req["reason"] || preview.RequiredPermission != "profiles:write" || preview.RequestFingerprint == "" ||
		preview.SourceSpecDigest != store.ProfileSpecDigest(v1.Spec) {
		t.Fatalf("profile restore preview identity = %+v; expected reason=%v digest=%s", preview, req["reason"], store.ProfileSpecDigest(v1.Spec))
	}
	if preview.PreviewWrites == nil || len(preview.PreviewWrites) != 0 ||
		preview.PreviewExternalEffects == nil || len(preview.PreviewExternalEffects) != 0 ||
		len(preview.Changes) == 0 || len(preview.Risks) == 0 || len(preview.VerificationSteps) == 0 {
		t.Fatalf("profile restore preview is not explicit/effect-free: %+v", preview)
	}
	assertJSONValueEqual(t, preview.SourceSpec, v1.Spec)
	if afterPreview, lastErr := h.log.LastSequence(t.Context()); lastErr != nil || afterPreview != beforePreview {
		t.Fatalf("preview event sequence = (%d, %v), want unchanged %d", afterPreview, lastErr, beforePreview)
	}
	active, err := h.store.GetActiveProfile(t.Context(), h.tenant, v1.Name)
	if err != nil || active.Version != 2 {
		t.Fatalf("active profile after preview = (%+v, %v), want v2", active, err)
	}

	status, body = secretsReqKey(t, h, http.MethodPost, restorePath, admin, "f53-profile-restore-v1", req)
	if status != http.StatusCreated {
		t.Fatalf("profile restore status=%d body=%s, want 201", status, body)
	}
	var restored servedProfileVersion
	if err := json.Unmarshal(body, &restored); err != nil {
		t.Fatal(err)
	}
	if restored.Version != 3 || !restored.Active || restored.Name != v1.Name {
		t.Fatalf("restored profile = %+v, want active v3", restored)
	}
	assertJSONValueEqual(t, restored.Spec, v1.Spec)

	status, retryBody := secretsReqKey(t, h, http.MethodPost, restorePath, admin, "f53-profile-restore-v1", req)
	if status != http.StatusCreated || string(retryBody) != string(body) {
		t.Fatalf("idempotent restore retry = status %d body %s, want original %s", status, retryBody, body)
	}
	if _, err := h.store.GetProfileVersion(t.Context(), h.tenant, v1.Name, 4); !store.IsNotFound(err) {
		t.Fatalf("idempotent retry created v4: %v", err)
	}
	for version := 1; version <= 2; version++ {
		historical, getErr := h.store.GetProfileVersion(t.Context(), h.tenant, v1.Name, version)
		if getErr != nil || historical.Active {
			t.Fatalf("historical v%d after restore = (%+v, %v), want retained inactive", version, historical, getErr)
		}
	}

	status, staleBody := secretsReqKey(t, h, http.MethodPost, restorePath, admin, "f53-profile-restore-stale", req)
	if status != http.StatusConflict {
		t.Fatalf("stale restore status=%d body=%s, want 409", status, staleBody)
	}
	if _, err := h.store.GetProfileVersion(t.Context(), h.tenant, v1.Name, 4); !store.IsNotFound(err) {
		t.Fatalf("stale restore created v4: %v", err)
	}

	var restorationEvidence struct {
		RestoredFromVersion int    `json:"restored_from_version"`
		RestoreReason       string `json:"restore_reason"`
		ExpectedActive      int    `json:"expected_active_version"`
	}
	if err := h.log.Replay(t.Context(), beforePreview+1, func(event events.Event) error {
		if event.Type != projections.EventProfileUpdated {
			return nil
		}
		return json.Unmarshal(event.Data, &restorationEvidence)
	}); err != nil {
		t.Fatal(err)
	}
	if restorationEvidence.RestoredFromVersion != 1 || restorationEvidence.ExpectedActive != 2 || restorationEvidence.RestoreReason != req["reason"] {
		t.Fatalf("profile restore event evidence = %+v", restorationEvidence)
	}
}

type servedProfileVersion struct {
	ID      string          `json:"id"`
	Name    string          `json:"name"`
	Version int             `json:"version"`
	Active  bool            `json:"active"`
	Spec    json.RawMessage `json:"spec"`
}

func createServedProfileVersion(t *testing.T, h *servedHarness, token, name string, spec map[string]any) servedProfileVersion {
	t.Helper()
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/profiles", token, "f53-create-"+name+"-"+spec["max_validity"].(string), map[string]any{
		"name": name,
		"spec": spec,
	})
	if status != http.StatusCreated {
		t.Fatalf("create profile %s status=%d body=%s", name, status, body)
	}
	var result servedProfileVersion
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func assertJSONValueEqual(t *testing.T, left, right json.RawMessage) {
	t.Helper()
	var leftValue, rightValue any
	if err := json.Unmarshal(left, &leftValue); err != nil {
		t.Fatalf("decode left JSON: %v", err)
	}
	if err := json.Unmarshal(right, &rightValue); err != nil {
		t.Fatalf("decode right JSON: %v", err)
	}
	if !reflect.DeepEqual(leftValue, rightValue) {
		t.Fatalf("JSON values differ:\nleft:  %s\nright: %s", left, right)
	}
}
