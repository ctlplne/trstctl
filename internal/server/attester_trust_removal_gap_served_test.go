// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func TestAttesterTrustRevokeRetainedEventDeniesNewSVID(t *testing.T) {
	fixture := servedDynamicK8sTrustFixture(t, "ar9-revoke-gap")
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.AttestedIssuance = AttestedIssuanceConfig{
			Enabled: true, TrustDomain: "served.test", DefaultTTL: 10 * time.Minute, MaxTTL: time.Hour,
		}
	})
	token := seedScopedTokenSubject(t, h.store, h.tenant, "ar9-trust-admin@example.test",
		"certs:issue", "certs:read", "issuers:read", "issuers:write")
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/workloads/attester-trust-sources",
		token, "ar9-create-trust", map[string]any{
			"name": "ar9-k8s", "method": "k8s_sat", "issuer": "https://kubernetes.default.svc",
			"audience": "trstctl", "jwks": fixture.JWKS,
		})
	if status != http.StatusCreated {
		t.Fatalf("create trust source: %d %s", status, body)
	}
	var created servedWorkloadTrustSourceResponse
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatal(err)
	}
	if _, err := uuid.Parse(created.ID); err != nil {
		t.Fatalf("created source ID is not a UUID: %v", err)
	}

	const trigger = "qa_ar9_attester_revoke_projection_gap"
	const function = "qa_ar9_attester_revoke_projection_gap_fn"
	clearFault := func() {
		if _, err := h.store.SystemPool().Exec(context.Background(),
			"DROP TRIGGER IF EXISTS "+trigger+" ON workload_attester_trust_sources; DROP FUNCTION IF EXISTS "+function+"()"); err != nil {
			t.Errorf("clear owned attester projection fault: %v", err)
		}
	}
	defer clearFault()
	_, err := h.store.SystemPool().Exec(t.Context(), fmt.Sprintf(`
		CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			IF NEW.tenant_id = '%s'::uuid AND NEW.id = '%s'::uuid AND NEW.enabled = false THEN
				RAISE EXCEPTION 'owned attester trust revoke projection fault';
			END IF;
			RETURN NEW;
		END $$;
		CREATE TRIGGER %s BEFORE UPDATE ON workload_attester_trust_sources
		FOR EACH ROW EXECUTE FUNCTION %s()`, function, h.tenant, created.ID, trigger, function))
	if err != nil {
		t.Fatalf("install owned attester projection fault: %v", err)
	}
	status, body = secretsReqKey(t, h, http.MethodPost,
		"/api/v1/workloads/attester-trust-sources/"+created.ID+"/revoke", token,
		"ar9-revoke-gap", map[string]any{"reason": "remove compromised local trust"})
	if status < 500 {
		t.Fatalf("faulted revoke reported %d %s, want retryable 5xx", status, body)
	}
	if !h.hasEvent(t, projections.EventWorkloadAttesterTrustSourceRevoked) {
		t.Fatal("faulted revoke did not retain its source event")
	}
	projected, err := h.store.GetWorkloadAttesterTrustSource(t.Context(), h.tenant, created.ID)
	if err != nil || !projected.Enabled {
		t.Fatalf("fault precondition: projected source is not still enabled: %+v err=%v", projected, err)
	}
	command, err := h.store.WorkloadAttesterTrustCommand(t.Context(), h.tenant, created.ID)
	if err != nil || command.Status != "pending" || !command.TargetDisabled {
		t.Fatalf("revocation denial command did not survive projection fault: %+v err=%v", command, err)
	}
	status, body = secretsReqKey(t, h, http.MethodGet,
		"/api/v1/workloads/attester-trust-sources/"+created.ID, token, "", nil)
	var effective struct {
		Enabled          bool `json:"enabled"`
		AuthorityPending bool `json:"authority_pending"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &effective) != nil ||
		effective.Enabled || !effective.AuthorityPending {
		t.Fatalf("GET hid retained removal: status=%d body=%s", status, body)
	}
	status, body = secretsReqKey(t, h, http.MethodGet,
		"/api/v1/workloads/attester-trust-sources", token, "", nil)
	var listing struct {
		Items []struct {
			ID               string `json:"id"`
			Enabled          bool   `json:"enabled"`
			AuthorityPending bool   `json:"authority_pending"`
		} `json:"items"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &listing) != nil ||
		len(listing.Items) != 1 || listing.Items[0].ID != created.ID ||
		listing.Items[0].Enabled || !listing.Items[0].AuthorityPending {
		t.Fatalf("LIST hid retained removal: status=%d body=%s", status, body)
	}
	if attestors, err := resolveWorkloadAttestors(t.Context(), h.store, nil, h.tenant, "k8s_sat"); err != nil || len(attestors) != 0 {
		t.Fatalf("PAM/shared resolver kept removed trust: count=%d err=%v", len(attestors), err)
	}
	status, body = secretsReqKey(t, h, http.MethodPost,
		"/api/v1/workloads/attested-issuance/preview", token, "", map[string]any{
			"method": "k8s_sat", "payload_base64": base64.StdEncoding.EncodeToString([]byte(fixture.SAT)),
			"public_key_pem": servedAttestedPublicKeyPEM(t), "ttl_seconds": 600,
		})
	var preview api.AttestedSVIDPreview
	if status != http.StatusOK || json.Unmarshal(body, &preview) != nil || preview.Ready {
		t.Fatalf("retained revocation still admitted trust: status=%d preview=%+v body=%s", status, preview, body)
	}
	servedAttestedIssue(t, h, token, "ar9-after-retained-revoke", "k8s_sat",
		[]byte(fixture.SAT), servedAttestedPublicKeyPEM(t), http.StatusUnprocessableEntity)
	clearFault()
	if healed, err := reconcilePendingWorkloadAttesterTrustCommands(t.Context(), h.store, h.log); err != nil || healed != 1 {
		t.Fatalf("recover retained revoke: healed=%d err=%v", healed, err)
	}
	command, err = h.store.WorkloadAttesterTrustCommand(t.Context(), h.tenant, created.ID)
	if err != nil || command.Status != "completed" || !command.TargetDisabled || len(command.Event.Data) != 0 {
		t.Fatalf("recovered command did not retain opaque denial: %+v err=%v", command, err)
	}
	status, body = secretsReqKey(t, h, http.MethodGet,
		"/api/v1/workloads/attester-trust-sources/"+created.ID, token, "", nil)
	if status != http.StatusOK || json.Unmarshal(body, &effective) != nil ||
		effective.Enabled || effective.AuthorityPending {
		t.Fatalf("GET failed to clear pending after recovery: status=%d body=%s", status, body)
	}
	status, body = secretsReqKey(t, h, http.MethodPost,
		"/api/v1/workloads/attester-trust-sources/"+created.ID+"/revoke", token,
		"ar9-revoke-gap", map[string]any{"reason": "remove compromised local trust"})
	if status != http.StatusOK {
		t.Fatalf("recovered revoke did not replay its first result: %d %s", status, body)
	}
	projected, err = h.store.GetWorkloadAttesterTrustSource(t.Context(), h.tenant, created.ID)
	if err != nil || projected.Enabled {
		t.Fatalf("recovered revoke did not disable read model: %+v err=%v", projected, err)
	}
	if healed, err := reconcilePendingWorkloadAttesterTrustCommands(t.Context(), h.store, h.log); err != nil || healed != 0 {
		t.Fatalf("second recovery emitted duplicate work: healed=%d err=%v", healed, err)
	}
	if n := servedEventCount(t, h, projections.EventWorkloadAttesterTrustSourceRevoked); n != 1 {
		t.Fatalf("retained revoke event count=%d, want one", n)
	}
}

func TestAttesterTrustPreappendCommandRecoversExactEvent(t *testing.T) {
	fixture := servedDynamicK8sTrustFixture(t, "ar9-preappend")
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.AttestedIssuance = AttestedIssuanceConfig{
			Enabled: true, TrustDomain: "served.test", DefaultTTL: 10 * time.Minute, MaxTTL: time.Hour,
		}
	})
	token := seedScopedTokenSubject(t, h.store, h.tenant, "ar9-preappend@example.test",
		"certs:issue", "certs:read", "issuers:read", "issuers:write")
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/workloads/attester-trust-sources",
		token, "ar9-preappend-create", map[string]any{
			"name": "ar9-preappend", "method": "k8s_sat", "issuer": "https://kubernetes.default.svc",
			"audience": "trstctl", "jwks": fixture.JWKS,
		})
	if status != http.StatusCreated {
		t.Fatalf("create source: %d %s", status, body)
	}
	var created servedWorkloadTrustSourceResponse
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(projections.WorkloadAttesterTrustSourceRevoked{
		ID: created.ID, Reason: "preappend crash recovery",
	})
	if err != nil {
		t.Fatal(err)
	}
	event := events.Event{ID: uuid.NewString(), TenantID: h.tenant,
		Type:          projections.EventWorkloadAttesterTrustSourceRevoked,
		SchemaVersion: events.DefaultSchemaVersion,
		Time:          time.Now().UTC().Truncate(time.Microsecond), Data: payload}
	command, err := h.store.ClaimWorkloadAttesterTrustCommand(t.Context(), store.WorkloadAttesterTrustCommand{
		SourceID: created.ID, Event: event, TargetDisabled: true,
		BindingSHA256: strings.Repeat("a", 64), RequestBinding: strings.Repeat("b", 64),
	})
	if err != nil || command.Status != "pending" {
		t.Fatalf("preappend claim: %+v err=%v", command, err)
	}
	second := event
	second.ID = uuid.NewString()
	if _, err := h.store.ClaimWorkloadAttesterTrustCommand(t.Context(), store.WorkloadAttesterTrustCommand{
		SourceID: created.ID, Event: second, TargetDisabled: true,
		BindingSHA256: strings.Repeat("c", 64), RequestBinding: strings.Repeat("d", 64),
	}); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("a different command replaced the pending first writer: %v", err)
	}
	if _, found, err := h.log.EventByID(t.Context(), event.ID); err != nil || found {
		t.Fatalf("preappend setup already has source event: found=%t err=%v", found, err)
	}
	servedAttestedIssue(t, h, token, "ar9-preappend-deny", "k8s_sat",
		[]byte(fixture.SAT), servedAttestedPublicKeyPEM(t), http.StatusUnprocessableEntity)
	if healed, err := reconcilePendingWorkloadAttesterTrustCommands(t.Context(), h.store, h.log); err != nil || healed != 1 {
		t.Fatalf("recover preappend command: healed=%d err=%v", healed, err)
	}
	if retained, found, err := h.log.EventByID(t.Context(), event.ID); err != nil || !found ||
		retained.Type != event.Type || retained.TenantID != event.TenantID {
		t.Fatalf("recovered event differs from preappend command: %+v found=%t err=%v", retained, found, err)
	}
	if healed, err := reconcilePendingWorkloadAttesterTrustCommands(t.Context(), h.store, h.log); err != nil || healed != 0 {
		t.Fatalf("repeated preappend recovery: healed=%d err=%v", healed, err)
	}
	if n := servedEventCount(t, h, projections.EventWorkloadAttesterTrustSourceRevoked); n != 1 {
		t.Fatalf("recovered revocation events=%d, want one", n)
	}
}

func TestAttesterTrustNarrowingRouteFamilyRetainedEvents(t *testing.T) {
	for _, tc := range []struct {
		name, eventType string
		method          string
	}{
		{"rotate", projections.EventWorkloadAttesterTrustSourceRotated, http.MethodPost},
		{"disable", projections.EventWorkloadAttesterTrustSourceUpserted, http.MethodPut},
		{"delete", projections.EventWorkloadAttesterTrustSourceDeleted, http.MethodDelete},
	} {
		t.Run(tc.name, func(t *testing.T) {
			first := servedDynamicK8sTrustFixture(t, "ar9-"+tc.name+"-old")
			rotated := servedDynamicK8sTrustFixture(t, "ar9-"+tc.name+"-new")
			h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
				d.AttestedIssuance = AttestedIssuanceConfig{
					Enabled: true, TrustDomain: "served.test", DefaultTTL: 10 * time.Minute, MaxTTL: time.Hour,
				}
			})
			token := seedScopedTokenSubject(t, h.store, h.tenant, "ar9-"+tc.name+"@example.test",
				"certs:issue", "certs:read", "issuers:read", "issuers:write")
			status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/workloads/attester-trust-sources",
				token, "ar9-"+tc.name+"-create", map[string]any{
					"name": "ar9-" + tc.name, "method": "k8s_sat",
					"issuer": "https://kubernetes.default.svc", "audience": "trstctl", "jwks": first.JWKS,
				})
			if status != http.StatusCreated {
				t.Fatalf("create trust source: %d %s", status, body)
			}
			var created servedWorkloadTrustSourceResponse
			if err := json.Unmarshal(body, &created); err != nil {
				t.Fatal(err)
			}
			function := "qa_ar9_narrow_" + tc.name + "_fn"
			trigger := "qa_ar9_narrow_" + tc.name
			clearFault := func() {
				if _, err := h.store.SystemPool().Exec(context.Background(),
					"DROP TRIGGER IF EXISTS "+trigger+" ON workload_attester_trust_sources; DROP FUNCTION IF EXISTS "+function+"()"); err != nil {
					t.Errorf("clear owned narrowing fault: %v", err)
				}
			}
			defer clearFault()
			_, err := h.store.SystemPool().Exec(t.Context(), fmt.Sprintf(`
				CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$
				BEGIN
					IF TG_OP = 'DELETE' THEN
						IF OLD.tenant_id = '%s'::uuid AND OLD.id = '%s'::uuid THEN
							RAISE EXCEPTION 'owned attester narrowing projection fault';
						END IF;
						RETURN OLD;
					END IF;
					IF NEW.tenant_id = '%s'::uuid AND NEW.id = '%s'::uuid THEN
						RAISE EXCEPTION 'owned attester narrowing projection fault';
					END IF;
					RETURN NEW;
				END $$;
				CREATE TRIGGER %s BEFORE UPDATE OR DELETE ON workload_attester_trust_sources
				FOR EACH ROW EXECUTE FUNCTION %s()`, function, h.tenant, created.ID,
				h.tenant, created.ID, trigger, function))
			if err != nil {
				t.Fatalf("install owned narrowing fault: %v", err)
			}
			path := "/api/v1/workloads/attester-trust-sources/" + created.ID
			var request any
			switch tc.name {
			case "rotate":
				path += "/rotate"
				request = map[string]any{"issuer": "https://kubernetes.default.svc",
					"audience": "trstctl", "jwks": rotated.JWKS, "reason": "replace old key"}
			case "disable":
				request = map[string]any{"name": "ar9-disable", "method": "k8s_sat",
					"issuer": "https://kubernetes.default.svc", "audience": "trstctl",
					"jwks": first.JWKS, "enabled": false}
			}
			status, body = secretsReqKey(t, h, tc.method, path, token,
				"ar9-"+tc.name+"-narrow", request)
			if status < 500 {
				t.Fatalf("faulted %s reported %d %s, want retryable 5xx", tc.name, status, body)
			}
			if !h.hasEvent(t, tc.eventType) {
				t.Fatalf("faulted %s did not retain source event", tc.name)
			}
			command, err := h.store.WorkloadAttesterTrustCommand(t.Context(), h.tenant, created.ID)
			if err != nil || command.Status != "pending" {
				t.Fatalf("%s command did not survive SQL fault: %+v err=%v", tc.name, command, err)
			}
			servedAttestedIssue(t, h, token, "ar9-"+tc.name+"-denied", "k8s_sat",
				[]byte(first.SAT), servedAttestedPublicKeyPEM(t), http.StatusUnprocessableEntity)
			clearFault()
			if healed, err := reconcilePendingWorkloadAttesterTrustCommands(t.Context(), h.store, h.log); err != nil || healed != 1 {
				t.Fatalf("recover %s: healed=%d err=%v", tc.name, healed, err)
			}
			if command, err := h.store.WorkloadAttesterTrustCommand(t.Context(), h.tenant, created.ID); err != nil || command.Status != "completed" {
				t.Fatalf("recovered %s command: %+v err=%v", tc.name, command, err)
			}
			replayStatus, replayBody := secretsReqKey(t, h, tc.method, path, token,
				"ar9-"+tc.name+"-narrow", request)
			wantReplayStatus := http.StatusOK
			if tc.name == "delete" {
				wantReplayStatus = http.StatusNoContent
			}
			if replayStatus != wantReplayStatus {
				t.Fatalf("%s lost-response retry: status=%d body=%s, want %d", tc.name,
					replayStatus, replayBody, wantReplayStatus)
			}
			wantEvents := 1
			if tc.name == "disable" {
				wantEvents = 2 // create and disable are both upsert events.
			}
			if n := servedEventCount(t, h, tc.eventType); n != wantEvents {
				t.Fatalf("%s retry appended %d source events, want %d", tc.name, n, wantEvents)
			}
			if tc.name == "rotate" {
				servedAttestedIssue(t, h, token, "ar9-rotate-old-rejected", "k8s_sat",
					[]byte(first.SAT), servedAttestedPublicKeyPEM(t), http.StatusForbidden)
				servedAttestedIssue(t, h, token, "ar9-rotate-new-accepted", "k8s_sat",
					[]byte(rotated.SAT), servedAttestedPublicKeyPEM(t), http.StatusCreated)
			} else {
				servedAttestedIssue(t, h, token, "ar9-"+tc.name+"-still-denied", "k8s_sat",
					[]byte(first.SAT), servedAttestedPublicKeyPEM(t), http.StatusUnprocessableEntity)
			}
			if err := h.srv.proj.Rebuild(t.Context(), h.log); err != nil {
				t.Fatalf("cold %s projection rebuild: %v", tc.name, err)
			}
			if tc.name == "rotate" {
				servedAttestedIssue(t, h, token, "ar9-rotate-cold-new-accepted", "k8s_sat",
					[]byte(rotated.SAT), servedAttestedPublicKeyPEM(t), http.StatusCreated)
			} else {
				servedAttestedIssue(t, h, token, "ar9-"+tc.name+"-cold-denied", "k8s_sat",
					[]byte(first.SAT), servedAttestedPublicKeyPEM(t), http.StatusUnprocessableEntity)
			}
		})
	}
}

func TestAttesterTrustLostRotationResponseSurvivesNewerRotation(t *testing.T) {
	first := servedDynamicK8sTrustFixture(t, "ar9-history-first")
	second := servedDynamicK8sTrustFixture(t, "ar9-history-second")
	third := servedDynamicK8sTrustFixture(t, "ar9-history-third")
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.AttestedIssuance = AttestedIssuanceConfig{Enabled: true, TrustDomain: "served.test",
			DefaultTTL: 10 * time.Minute, MaxTTL: time.Hour}
	})
	token := seedScopedTokenSubject(t, h.store, h.tenant, "ar9-history@example.test",
		"certs:issue", "certs:read", "issuers:read", "issuers:write")
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/workloads/attester-trust-sources",
		token, "ar9-history-create", map[string]any{"name": "ar9-history", "method": "k8s_sat",
			"issuer": "https://kubernetes.default.svc", "audience": "trstctl", "jwks": first.JWKS})
	if status != http.StatusCreated {
		t.Fatalf("create source: %d %s", status, body)
	}
	var created servedWorkloadTrustSourceResponse
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatal(err)
	}
	const function = "qa_ar9_history_projection_gap_fn"
	const trigger = "qa_ar9_history_projection_gap"
	clearFault := func() {
		if _, err := h.store.SystemPool().Exec(context.Background(),
			"DROP TRIGGER IF EXISTS "+trigger+" ON workload_attester_trust_sources; DROP FUNCTION IF EXISTS "+function+"()"); err != nil {
			t.Errorf("clear owned history fault: %v", err)
		}
	}
	defer clearFault()
	if _, err := h.store.SystemPool().Exec(t.Context(), fmt.Sprintf(`
		CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			IF NEW.tenant_id='%s'::uuid AND NEW.id='%s'::uuid AND NEW.rotation_version=2 THEN
				RAISE EXCEPTION 'owned history projection fault';
			END IF;
			RETURN NEW;
		END $$;
		CREATE TRIGGER %s BEFORE UPDATE ON workload_attester_trust_sources
		FOR EACH ROW EXECUTE FUNCTION %s()`, function, h.tenant, created.ID, trigger, function)); err != nil {
		t.Fatal(err)
	}
	path := "/api/v1/workloads/attester-trust-sources/" + created.ID + "/rotate"
	firstRequest := map[string]any{"issuer": "https://kubernetes.default.svc", "audience": "trstctl",
		"jwks": second.JWKS, "reason": "first replacement"}
	status, body = secretsReqKey(t, h, http.MethodPost, path, token, "ar9-history-lost", firstRequest)
	if status < 500 {
		t.Fatalf("faulted first rotation: %d %s", status, body)
	}
	clearFault()
	if healed, err := reconcilePendingWorkloadAttesterTrustCommands(t.Context(), h.store, h.log); err != nil || healed != 1 {
		t.Fatalf("recover first rotation: healed=%d err=%v", healed, err)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, path, token, "ar9-history-newer",
		map[string]any{"issuer": "https://kubernetes.default.svc", "audience": "trstctl",
			"jwks": third.JWKS, "reason": "second replacement"})
	if status != http.StatusOK {
		t.Fatalf("newer rotation: %d %s", status, body)
	}
	if err := h.srv.proj.Rebuild(t.Context(), h.log); err != nil {
		t.Fatalf("cold read-model rebuild before old response replay: %v", err)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, path, token, "ar9-history-lost", firstRequest)
	var replay struct {
		TrustSource struct {
			RotationVersion int             `json:"rotation_version"`
			JWKS            json.RawMessage `json:"jwks"`
		} `json:"trust_source"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &replay) != nil ||
		replay.TrustSource.RotationVersion != 2 {
		t.Fatalf("old result did not survive newer rotation: %d %s", status, body)
	}
	if n := servedEventCount(t, h, projections.EventWorkloadAttesterTrustSourceRotated); n != 2 {
		t.Fatalf("old retry appended a third rotation: events=%d", n)
	}
	status, body = secretsReqKey(t, h, http.MethodGet,
		"/api/v1/workloads/attester-trust-sources/"+created.ID, token, "", nil)
	var current struct {
		RotationVersion int `json:"rotation_version"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &current) != nil || current.RotationVersion != 3 {
		t.Fatalf("old retry changed current trust: %d %s", status, body)
	}
}
