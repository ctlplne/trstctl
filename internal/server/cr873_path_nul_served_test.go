// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
)

// VL-174 (SW-NULC-PATH, SW-NUL-11): a percent-encoded %00 in a path segment is decoded by
// net/http's ServeMux into a real NUL byte in r.PathValue. For each event-appending route that
// copies a free-text path value into its event payload, post %00 through the served route and
// report whether the event is retained although the request is refused (or the projection fails).
func TestCR873PathValueNULCannotPoisonLog(t *testing.T) {
	ctx := t.Context()
	h := newOperatingServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil))
	second := uuid.NewString()
	registerServedTenantID(t, h, second, "VL174 victim tenant")
	admin := seedScopedTokenSubject(t, h.store, h.tenant, "vl174-admin", "access:write", "access:read", "access:role.assign", "secrets:write", "secrets:read")

	// Fixtures and controls (clean requests).
	if st, b := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/projects", admin, "vl174-fx-proj",
		map[string]any{"slug": "vl174", "environments": []any{map[string]any{"slug": "dev"}}}); st != http.StatusCreated {
		t.Fatalf("project fixture: %d %s", st, b)
	}
	if st, b := secretsReqKey(t, h, http.MethodPut, "/api/v1/access/members/vl174-clean", admin, "vl174-ctl-member",
		map[string]any{"display_name": "Clean", "email": "clean@example.test", "roles": []string{}}); st != http.StatusOK {
		t.Fatalf("control member: %d %s", st, b)
	}
	if st, b := secretsReqKey(t, h, http.MethodPut, "/api/v1/secrets/projects/vl174/members/vl174-clean2", admin, "vl174-ctl-pm",
		map[string]any{"role": "viewer"}); st != http.StatusOK {
		t.Fatalf("control project member: %d %s", st, b)
	}

	// A project admin (secrets:write only, admin role inside the project) is a lower caller class than access:write.
	padmin := seedScopedTokenSubject(t, h.store, h.tenant, "vl174-padmin", "secrets:read", "secrets:write")
	if st, b := secretsReqKey(t, h, http.MethodPut, "/api/v1/secrets/projects/vl174/members/vl174-padmin", admin, "vl174-fx-padmin",
		map[string]any{"role": "admin"}); st != http.StatusOK {
		t.Fatalf("project admin fixture: %d %s", st, b)
	}
	type attack struct {
		name, method, path, key string
		body                    any
		tok                     string
	}
	attacks := []attack{
		{"access member upsert {subject}", http.MethodPut, "/api/v1/access/members/vl174%00member", "vl174-a1",
			map[string]any{"display_name": "Clean", "email": "m@example.test", "roles": []string{}}, ""},
		{"access member offboard {subject}", http.MethodPost, "/api/v1/access/members/vl174%00member2/offboard", "vl174-a2",
			map[string]any{"reason": "clean"}, ""},
		{"secret project member grant {subject}", http.MethodPut, "/api/v1/secrets/projects/vl174/members/vl174%00sub", "vl174-a3",
			map[string]any{"role": "viewer"}, ""},
		{"secret project member revoke {subject}", http.MethodDelete, "/api/v1/secrets/projects/vl174/members/vl174%00sub2", "vl174-a4", nil, ""},
		{"custom role define {name}", http.MethodPut, "/api/v1/access/roles/vl174%00role", "vl174-a5",
			map[string]any{"description": "clean", "permissions": []string{"access:read"}}, ""},
		{"access folder save {name}", http.MethodPut, "/api/v1/access/folders/vl174%00folder", "vl174-a6",
			map[string]any{"description": "clean"}, ""},
		{"secret project {project} grant", http.MethodPut, "/api/v1/secrets/projects/vl174%00proj/members/vl174-ok", "vl174-a7",
			map[string]any{"role": "viewer"}, ""},
	}
	attacks = append(attacks, attack{"PROJECT-ADMIN secret project grant {subject}", http.MethodPut, "/api/v1/secrets/projects/vl174/members/vl174%00padm", "vl174-a8",
		map[string]any{"role": "viewer"}, padmin})
	for _, a := range attacks {
		tok := a.tok
		if tok == "" {
			tok = admin
		}
		before, err := h.log.LastSequence(ctx)
		if err != nil {
			t.Fatal(err)
		}
		st, b := secretsReqKey(t, h, a.method, a.path, tok, a.key, a.body)
		after, err := h.log.LastSequence(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var types []string
		_ = h.log.Replay(ctx, before, func(e events.Event) error {
			if e.Sequence > before {
				types = append(types, e.Type)
			}
			return nil
		})
		t.Logf("VL174 %-40s status=%d appended=%d types=%v body=%.140s", a.name, st, after-before, types, strings.TrimSpace(string(b)))
		if st != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", a.name, st)
		}
		if after != before {
			t.Errorf("%s: request retained %d event(s) %v", a.name, after-before, types)
		}
	}
	h.ts.Close()
	restarted, err := Build(ctx, Deps{Store: h.store, Log: h.log, Signer: h.signer, SignAuthorizer: h.authz, CACertFile: h.caFile, Protocols: config.Protocols{}})
	if err != nil {
		t.Errorf("restart Build failed after refused NUL paths: %v", err)
		return
	}
	cleanupServedServer(t, restarted)
}
