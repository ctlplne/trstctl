// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/store"
)

type placedStaticRotationProvider struct {
	*staticRotationProviderDouble
	environment string
}

func (p *placedStaticRotationProvider) DynamicSecretEnvironment() string { return p.environment }

// CR-231: the provider environment has its own write grant, even when the
// application secret being rotated belongs to an unrestricted path.
func TestServedStaticRotationRequiresProviderEnvironmentWrite(t *testing.T) {
	provider := &placedStaticRotationProvider{
		staticRotationProviderDouble: &staticRotationProviderDouble{name: "rotation-provider-scope", role: "shared/rotation-scope"},
		environment:                  "rotation-scope/prod",
	}
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.TenantDynamicSecretProviders = DynamicSecretProviderRegistry{servedTestTenant: {provider}}
	})
	registerServedTenant(t, h, "rotation authority tenant")
	writer := seedScopedTokenSubject(t, h.store, h.tenant, "rotation-authorized", "secrets:read", "secrets:write")
	viewer := seedScopedTokenSubject(t, h.store, h.tenant, "rotation-read-only", "secrets:read", "secrets:write")
	outsider := seedScopedTokenSubject(t, h.store, h.tenant, "rotation-other", "secrets:read", "secrets:write")
	admin := seedScopedTokenSubject(t, h.store, h.tenant, "rotation-admin", "secrets:read", "secrets:write", "access:write")
	call := func(token, method, path, idem string, body any, want int) []byte {
		t.Helper()
		status, raw := secretsReqKey(t, h, method, path, token, idem, body)
		if status != want {
			t.Fatalf("%s %s = %d, want %d", method, path, status, want)
		}
		return raw
	}
	call(admin, http.MethodPost, "/api/v1/secrets/projects", "rotation-scope-project", map[string]any{
		"slug": "rotation-scope", "environments": []map[string]any{{"slug": "prod", "restricted": true}},
	}, http.StatusCreated)
	for _, member := range []struct{ subject, role string }{
		{"rotation-authorized", "developer"}, {"rotation-read-only", "viewer"},
	} {
		call(admin, http.MethodPut, "/api/v1/secrets/projects/rotation-scope/members/"+member.subject,
			"rotation-scope-grant-"+member.subject, map[string]any{"role": member.role, "environments": []string{"prod"}}, http.StatusOK)
	}
	call(writer, http.MethodPost, "/api/v1/secrets/store", "rotation-scope-seed",
		map[string]any{"name": provider.role, "value": "fixture-value"}, http.StatusCreated)
	const rotations = "/api/v1/secrets/rotations"
	const schedules = "/api/v1/secrets/rotation-schedules"
	makeSchedule := func(suffix string, enabled bool) string {
		t.Helper()
		raw := call(writer, http.MethodPost, schedules, "rotation-scope-create-"+suffix, map[string]any{
			"name": "scope-" + suffix, "provider": provider.name, "key": provider.role,
			"old_ref": "none", "interval_seconds": 3600, "enabled": enabled,
		}, http.StatusCreated)
		var schedule struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(raw, &schedule); err != nil || schedule.ID == "" {
			t.Fatalf("schedule receipt missing id: %v", err)
		}
		return schedule.ID
	}
	for _, tc := range []struct {
		name, token string
		want        int
	}{
		{"viewer", viewer, http.StatusForbidden}, {"hidden", outsider, http.StatusNotFound},
	} {
		t.Run(tc.name+"/manual", func(t *testing.T) {
			status, _ := secretsReqKey(t, h, http.MethodPost, rotations, tc.token, "rotation-scope-"+tc.name+"-manual",
				map[string]any{"provider": provider.name, "key": provider.role, "old_ref": "none"})
			if status != tc.want {
				t.Fatalf("manual rotation status = %d, want %d", status, tc.want)
			}
		})
		t.Run(tc.name+"/schedule", func(t *testing.T) {
			status, _ := secretsReqKey(t, h, http.MethodPost, schedules, tc.token, "rotation-scope-"+tc.name+"-schedule",
				map[string]any{"name": "scope-" + tc.name, "provider": provider.name, "key": provider.role, "old_ref": "none", "interval_seconds": 3600})
			if status != tc.want {
				t.Fatalf("schedule creation status = %d, want %d", status, tc.want)
			}
		})
		for _, action := range []string{"pause", "resume", "retire"} {
			t.Run(tc.name+"/"+action, func(t *testing.T) {
				suffix := tc.name + "-" + action
				id := makeSchedule(suffix, action != "resume")
				status, _ := secretsReqKey(t, h, http.MethodPost, schedules+"/"+id+"/"+action, tc.token, "rotation-scope-control-"+suffix, nil)
				if status != tc.want {
					t.Fatalf("schedule control status = %d, want %d", status, tc.want)
				}
			})
		}
	}
	t.Run("archived-controls-need-current-provider-scope", func(t *testing.T) {
		for _, version := range []int{0, 1} {
			for _, tc := range []struct {
				subject, token string
				want           int
			}{
				{"rotation-authorized", writer, http.StatusOK},
				{"rotation-read-only", viewer, http.StatusForbidden},
				{"rotation-other", outsider, http.StatusNotFound},
			} {
				t.Run(fmt.Sprintf("version-%d/%s", version, tc.subject), func(t *testing.T) {
					id := uuid.NewString()
					path := schedules + "/" + id + "/pause"
					key := fmt.Sprintf("rotation-scope-archive-%d-%s", version, tc.subject)
					binding := crypto.SHA256Hex([]byte(`{"domain":"trstctl.api.mutation-route-binding.v1","principal":"` + tc.subject + `","method":"POST","escaped_path":"` + path + `"}`))
					_, err := h.srv.idem.DoDurableEffectBound(t.Context(), h.tenant, key, binding, func(context.Context) ([]byte, error) {
						return json.Marshal(map[string]any{"s": http.StatusOK, "h": binding, "r": version,
							"b": map[string]any{"id": id, "provider": provider.name, "enabled": false}})
					})
					if err != nil {
						t.Fatal(err)
					}
					status, body := secretsReqKey(t, h, http.MethodPost, path, tc.token, key, nil)
					if status != tc.want || bytes.Contains(body, []byte(id)) != (tc.want == http.StatusOK) {
						t.Errorf("archived result status = %d, want %d, receipt identity included = %t", status, tc.want, bytes.Contains(body, []byte(id)))
					}
					call(writer, http.MethodPost, path, key+"-fresh", nil, http.StatusNotFound)
				})
			}
		}
	})
	t.Run("missing-control-does-not-claim-key", func(t *testing.T) {
		const key = "rotation-scope-uncached-control"
		livePath := schedules + "/" + makeSchedule("reusable-key", true) + "/pause"
		missingPath := schedules + "/" + uuid.NewString() + "/pause"
		call(writer, http.MethodPost, missingPath, key, nil, http.StatusNotFound)
		call(writer, http.MethodPost, livePath, key, nil, http.StatusOK)
	})
	t.Run("missing-control-keeps-not-found-for-reserved-key", func(t *testing.T) {
		const key = store.TenantOffboardReceiverKeyPrefix + "fixture-schedule-control"
		livePath := schedules + "/" + makeSchedule("reserved-key", true) + "/pause"
		missingPath := schedules + "/" + uuid.NewString() + "/pause"
		call(writer, http.MethodPost, missingPath, key, nil, http.StatusNotFound)
		call(writer, http.MethodPost, livePath, key, nil, http.StatusConflict)
	})
	t.Run("retained-receipts-need-current-provider-scope", func(t *testing.T) {
		create := map[string]any{"name": "scope-replay", "provider": provider.name, "key": provider.role,
			"old_ref": "none", "interval_seconds": 3600, "enabled": true}
		raw := call(writer, http.MethodPost, schedules, "rotation-scope-replay-create", create, http.StatusCreated)
		var schedule struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(raw, &schedule); err != nil || schedule.ID == "" {
			t.Fatalf("schedule receipt missing id: %v", err)
		}
		pause := schedules + "/" + schedule.ID + "/pause"
		call(writer, http.MethodPost, pause, "rotation-scope-replay-pause", nil, http.StatusOK)
		call(admin, http.MethodDelete, "/api/v1/secrets/projects/rotation-scope/members/rotation-authorized",
			"rotation-scope-revoke-grant", nil, http.StatusOK)
		for _, tc := range []struct {
			path, idem string
			body       any
		}{
			{schedules, "rotation-scope-replay-create", create},
			{pause, "rotation-scope-replay-pause", nil},
		} {
			status, _ := secretsReqKey(t, h, http.MethodPost, tc.path, writer, tc.idem, tc.body)
			if status != http.StatusNotFound {
				t.Errorf("%s replay after grant removal = %d, want 404", tc.path, status)
			}
		}
	})
	if minted, revoked, _ := provider.snapshot(); len(minted) != 0 || len(revoked) != 0 {
		t.Fatal("authorization test reached provider operations")
	}
}

// CR-231: a well-formed request cannot point a newly imported native secret at
// an opaque reference for which neither the vault nor the provider has evidence.
func TestServedStaticRotationRejectsAnUnboundPredecessor(t *testing.T) {
	provider := &staticRotationProviderDouble{name: "rotation-predecessor", role: "shared/rotation-predecessor"}
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.TenantDynamicSecretProviders = DynamicSecretProviderRegistry{servedTestTenant: {provider}}
	})
	registerServedTenant(t, h, "rotation predecessor tenant")
	token := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")
	status, _ := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store", token, "rotation-predecessor-seed",
		map[string]any{"name": provider.role, "value": "fixture-value"})
	if status != http.StatusCreated {
		t.Fatalf("seed secret status = %d", status)
	}
	request := map[string]any{"provider": provider.name, "key": provider.role, "old_ref": "unbound-reference"}
	t.Run("preview", func(t *testing.T) {
		status, raw := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/rotations/preview", token, request)
		var preview struct {
			Ready    bool     `json:"ready"`
			Blockers []string `json:"blockers"`
		}
		if err := json.Unmarshal(raw, &preview); status != http.StatusOK || err != nil || preview.Ready || len(preview.Blockers) == 0 {
			t.Fatalf("unbound predecessor preview: status=%d ready=%t blockers=%d err=%v", status, preview.Ready, len(preview.Blockers), err)
		}
	})
	t.Run("manual", func(t *testing.T) {
		status, _ := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/rotations", token, "rotation-predecessor-manual", request)
		if status != http.StatusConflict {
			t.Fatalf("unbound predecessor rotation status = %d, want 409", status)
		}
	})
	t.Run("schedule", func(t *testing.T) {
		status, _ := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/rotation-schedules", token, "rotation-predecessor-schedule",
			map[string]any{"name": "unbound-predecessor", "provider": provider.name, "key": provider.role, "old_ref": "unbound-reference", "interval_seconds": 3600})
		if status != http.StatusConflict {
			t.Fatalf("unbound predecessor schedule status = %d, want 409", status)
		}
	})
	if minted, revoked, _ := provider.snapshot(); len(minted) != 0 || len(revoked) != 0 {
		t.Fatal("predecessor admission test reached provider operations")
	}
}

// CR-231: a replacement vault key can have the same numeric version as an
// earlier rotation. The earlier publication cannot authorize its predecessor.
func TestServedStaticRotationBindsThePublishedSecretIncarnation(t *testing.T) {
	provider := &staticRotationProviderDouble{name: "incarnation-fixture", role: "incarnation-fixture"}
	h := newOperatingServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.TenantDynamicSecretProviders = DynamicSecretProviderRegistry{servedTestTenant: {provider}}
	})
	token := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")
	write := func(idempotencyKey string) {
		t.Helper()
		status, _ := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store", token, idempotencyKey,
			map[string]any{"name": provider.role, "value": idempotencyKey})
		if status != http.StatusCreated && status != http.StatusOK {
			t.Fatalf("write fixture secret = %d", status)
		}
	}
	const rotations = "/api/v1/secrets/rotations"
	write("incarnation-original")
	command := map[string]any{"provider": provider.name, "key": provider.role, "old_ref": "none"}
	status, raw := secretsReqKey(t, h, http.MethodPost, rotations, token, "incarnation-first-rotation", command)
	var queued struct {
		ID string `json:"command_id"`
	}
	if err := json.Unmarshal(raw, &queued); status != http.StatusOK || err != nil || queued.ID == "" {
		t.Fatalf("queue original fixture status=%d err=%v", status, err)
	}
	ctx := t.Context()
	deadline := time.Now().Add(15 * time.Second)
	var completed staticRotationCommandView
	for time.Now().Before(deadline) {
		h.srv.dispatchOnce(ctx)
		status, raw = secretsReq(t, h, http.MethodGet, rotations+"/"+queued.ID, token, nil)
		if err := json.Unmarshal(raw, &completed); status != http.StatusOK || err != nil {
			t.Fatalf("read original fixture status=%d err=%v", status, err)
		}
		if completed.Terminal {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if completed.Phase != "completed" || completed.NewRef == "" || completed.ResultVersion != 2 {
		t.Fatalf("original fixture did not publish its successor: phase=%s version=%d", completed.Phase, completed.ResultVersion)
	}
	before, err := h.store.GetSecret(ctx, h.tenant, provider.role)
	if err != nil {
		t.Fatal(err)
	}
	status, _ = secretsReqKey(t, h, http.MethodDelete, "/api/v1/secrets/store/"+provider.role, token, "incarnation-remove", nil)
	if status != http.StatusNoContent && status != http.StatusOK {
		t.Fatalf("remove fixture secret status=%d", status)
	}
	write("incarnation-replacement")
	status, _ = secretsReqKey(t, h, http.MethodPut, "/api/v1/secrets/store/"+provider.role, token, "incarnation-replacement-version-two",
		map[string]any{"value": "fixture-replacement"})
	if status != http.StatusOK {
		t.Fatalf("update replacement fixture status=%d", status)
	}
	after, err := h.store.GetSecret(ctx, h.tenant, provider.role)
	if err != nil || before.ID == after.ID || before.Version != after.Version {
		t.Fatalf("fixture needs separate incarnations with the same version: err=%v original=%d replacement=%d", err, before.Version, after.Version)
	}
	command["old_ref"] = completed.NewRef
	status, _ = secretsReqKey(t, h, http.MethodPost, rotations, token, "incarnation-replacement-rotation", command)
	if status != http.StatusConflict {
		t.Fatalf("stale incarnation reference status=%d, want 409", status)
	}
	if minted, revoked, _ := provider.snapshot(); len(minted) != 1 || len(revoked) != 0 {
		t.Fatal("replacement admission called its inert provider")
	}

	provider.mu.Lock()
	provider.verifyFail = true
	provider.mu.Unlock()
	command["old_ref"] = "none"
	status, raw = secretsReqKey(t, h, http.MethodPost, rotations, token, "incarnation-incomplete-rotation", command)
	queued.ID = ""
	if err := json.Unmarshal(raw, &queued); status != http.StatusOK || err != nil || queued.ID == "" {
		t.Fatalf("queue incomplete fixture status=%d err=%v", status, err)
	}
	if err := h.srv.api.AdvanceStaticSecretRotation(ctx, h.tenant, queued.ID, 1); err == nil {
		t.Fatal("inert fixture verification should leave a cutover awaiting retry")
	}
	cutover, err := h.store.GetSecretStaticRotationCommand(ctx, h.tenant, queued.ID)
	if err != nil || cutover.Phase != store.SecretStaticRotationCutover || cutover.ResultVersion != 3 {
		t.Fatalf("fixture did not commit the cutover: phase=%s version=%d err=%v", cutover.Phase, cutover.ResultVersion, err)
	}
	status, _ = secretsReqKey(t, h, http.MethodDelete, "/api/v1/secrets/store/"+provider.role, token, "incarnation-cutover-remove", nil)
	if status != http.StatusNoContent && status != http.StatusOK {
		t.Fatalf("remove cutover fixture status=%d", status)
	}
	write("incarnation-cutover-replacement")
	for _, idem := range []string{"incarnation-cutover-second", "incarnation-cutover-third"} {
		status, _ = secretsReqKey(t, h, http.MethodPut, "/api/v1/secrets/store/"+provider.role, token, idem,
			map[string]any{"value": idem})
		if status != http.StatusOK {
			t.Fatalf("update cutover replacement status=%d", status)
		}
	}
	if err := h.srv.api.AdvanceStaticSecretRotation(ctx, h.tenant, queued.ID, 3); err != nil {
		t.Fatal(err)
	}
	failed, err := h.store.GetSecretStaticRotationCommand(ctx, h.tenant, queued.ID)
	if err != nil || failed.Phase != store.SecretStaticRotationRollbackFailed {
		t.Fatalf("rollback applied to a different vault incarnation: phase=%s err=%v", failed.Phase, err)
	}
	replacement, err := h.store.GetSecret(ctx, h.tenant, provider.role)
	if err != nil || replacement.Version != cutover.ResultVersion {
		t.Fatalf("rollback changed the replacement's live generation: version=%d err=%v", replacement.Version, err)
	}
}
