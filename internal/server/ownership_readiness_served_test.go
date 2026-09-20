// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// TestServedOwnershipDepthRoundTripsAUD44 starts at the assembled HTTP surface.
// The SQL row already had these fields before AUD-44; the defect is that the
// event-backed command and response dropped every one of them. Keeping this as
// a served test prevents a future storage-only repair from making the same false
// claim again.
func TestServedOwnershipDepthRoundTripsAUD44(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	token := seedScopedTokenSubject(t, h.store, h.tenant, "ownership-admin@example.test",
		"owners:read", "owners:write")

	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/owners", token,
		"aud44-owner-create", map[string]any{
			"kind":             "service",
			"name":             "payments production",
			"email":            "payments@example.test",
			"application_id":   "APP-0044",
			"service":          "payments-api",
			"business_unit":    "commerce",
			"environment":      "production",
			"escalation_chain": []string{"payments-oncall@example.test", "security@example.test"},
		})
	if status != http.StatusCreated {
		t.Fatalf("create deep owner: status %d body %s", status, body)
	}
	var owner struct {
		ID                string   `json:"id"`
		ApplicationID     string   `json:"application_id"`
		Service           string   `json:"service"`
		BusinessUnit      string   `json:"business_unit"`
		Environment       string   `json:"environment"`
		EscalationChain   []string `json:"escalation_chain"`
		OwnershipComplete bool     `json:"ownership_complete"`
		OwnershipCurrent  bool     `json:"ownership_current"`
	}
	if err := json.Unmarshal(body, &owner); err != nil {
		t.Fatalf("decode deep owner: %v (%s)", err, body)
	}
	if owner.ID == "" || owner.ApplicationID != "APP-0044" || owner.Service != "payments-api" ||
		owner.BusinessUnit != "commerce" || owner.Environment != "production" ||
		len(owner.EscalationChain) != 2 || !owner.OwnershipComplete || owner.OwnershipCurrent {
		t.Fatalf("owner depth did not round-trip before attestation: %+v body=%s", owner, body)
	}
}

// TestServedOwnershipReadinessEnforcementAUD44 is the accepted I1 journey. It
// proves that ownership is lifecycle authority rather than a decorative row:
// a current attributed decision or one narrow expiring exception is required,
// the same stale edge is notified once under scheduler races, a neighbor tenant
// cannot see or revoke it, and cold replay reconstructs the evidence.
func TestServedOwnershipReadinessEnforcementAUD44(t *testing.T) {
	const cadence = time.Second
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.OwnershipAttestationCadence = cadence
	})
	ctx := context.Background()
	token := seedScopedTokenSubject(t, h.store, h.tenant, "ownership-admin@example.test",
		"owners:read", "owners:write", "identities:read", "identities:write", "certs:issue")

	ownerID := servedCreateID(t, h, token, "aud44-ready-owner", "/api/v1/owners", map[string]any{
		"kind": "service", "name": "payments production", "email": "payments@example.test",
		"application_id": "APP-0044", "service": "payments-api", "business_unit": "commerce",
		"environment": "production", "escalation_chain": []string{"payments-oncall@example.test"},
	})
	identityID := aud44CreateIssuedIdentity(t, h, token, ownerID, "aud44-unattested")

	status, body := aud44Transition(t, h, token, identityID, "aud44-deploy-before-attestation", "deployed")
	if status != http.StatusConflict || !strings.Contains(string(body), "ownership") {
		t.Fatalf("unattested deploy = %d %s, want ownership 409", status, body)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/owners/"+ownerID+"/attest", token,
		"aud44-attest-current-owner", map[string]any{})
	if status != http.StatusOK {
		t.Fatalf("attest owner = %d: %s", status, body)
	}
	var attested struct {
		VerifiedBy string `json:"ownership_verified_by"`
		Current    bool   `json:"ownership_current"`
	}
	if err := json.Unmarshal(body, &attested); err != nil {
		t.Fatal(err)
	}
	if attested.VerifiedBy != "ownership-admin@example.test" || !attested.Current {
		t.Fatalf("attestation is not attributed/current: %+v body=%s", attested, body)
	}
	attestationResponse := append([]byte(nil), body...)
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/owners/"+ownerID+"/attest", token,
		"aud44-attest-current-owner", map[string]any{})
	if status != http.StatusOK || string(body) != string(attestationResponse) ||
		aud44EventCount(t, h, projections.EventOwnershipAttested) != 1 {
		t.Fatalf("attestation replay changed response or event count: status=%d body=%s", status, body)
	}
	status, body = aud44Transition(t, h, token, identityID, "aud44-deploy-current-owner", "deployed")
	if status != http.StatusOK {
		t.Fatalf("current owner deploy = %d: %s", status, body)
	}

	staleIdentityID := aud44CreateIssuedIdentity(t, h, token, ownerID, "aud44-stale")
	time.Sleep(cadence + 75*time.Millisecond)
	status, body = aud44Transition(t, h, token, staleIdentityID, "aud44-deploy-stale-owner", "deployed")
	if status != http.StatusConflict || !strings.Contains(string(body), "stale") {
		t.Fatalf("stale owner deploy = %d %s, want stale 409", status, body)
	}
	status, body = aud44Transition(t, h, token, identityID, "aud44-start-renewal-stale-owner", "renewing")
	if status != http.StatusOK {
		t.Fatalf("start renewal before steady-state ownership gate = %d: %s", status, body)
	}
	status, body = aud44Transition(t, h, token, identityID, "aud44-complete-renewal-stale-owner", "deployed")
	if status != http.StatusConflict || !strings.Contains(string(body), "stale") {
		t.Fatalf("stale owner completed renewal = %d %s, want stale 409", status, body)
	}
	status, body = secretsReqKey(t, h, http.MethodGet, "/api/v1/owners/unowned", token, "", nil)
	if status != http.StatusOK || !strings.Contains(string(body), store.UnownedStale) {
		t.Fatalf("stale owner absent from unowned queue: %d %s", status, body)
	}

	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := h.srv.RunLifecycleOnce(ctx)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("ownership cadence sweep: %v", err)
		}
	}
	if got := servedOutboxDestinationCount(t, h, notify.DestinationOwnership); got != 1 {
		t.Fatalf("ownership notification outbox rows under two scheduler races = %d, want 1", got)
	}
	if got := aud44EventCount(t, h, projections.EventOwnerReattestationRequested); got != 1 {
		t.Fatalf("immutable re-attestation request events under race = %d, want 1", got)
	}
	var alert notify.Alert
	if err := h.store.SystemPool().QueryRow(ctx, `
		SELECT payload FROM outbox
		 WHERE tenant_id = $1 AND destination = $2`, h.tenant, notify.DestinationOwnership).Scan(&body); err != nil {
		t.Fatalf("read ownership notification intent: %v", err)
	}
	if err := json.Unmarshal(body, &alert); err != nil {
		t.Fatalf("decode ownership notification intent: %v (%s)", err, body)
	}
	if alert.Kind != notify.KindOwnershipReattestation || alert.OwnerID != ownerID ||
		alert.OwnerEmail != "payments@example.test" || len(alert.EscalationRecipients) != 2 {
		t.Fatalf("ownership notification lost exact owner/escalation evidence: %+v", alert)
	}

	incompleteOwnerID := servedCreateID(t, h, token, "aud44-incomplete-owner", "/api/v1/owners",
		map[string]any{"kind": "team", "name": "legacy operations", "email": "legacy@example.test"})
	exceptionIdentityID := aud44CreateIssuedIdentity(t, h, token, incompleteOwnerID, "aud44-active-exception")
	exceptionExpiry := time.Now().UTC().Add(2 * time.Second)
	exceptionID := aud44GrantException(t, h, token, exceptionIdentityID, "legacy owner cleanup in progress", exceptionExpiry, "aud44-active-exception-grant")
	status, body = secretsReqKey(t, h, http.MethodPost,
		"/api/v1/identities/"+exceptionIdentityID+"/ownership-exceptions", token, "aud44-active-exception-grant",
		map[string]any{"reason": "legacy owner cleanup in progress", "expires_at": exceptionExpiry})
	var replayedException struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &replayedException) != nil || replayedException.ID != exceptionID ||
		aud44EventCount(t, h, projections.EventOwnershipExceptionGranted) != 1 {
		t.Fatalf("exception replay changed authority or event count: status=%d body=%s", status, body)
	}
	status, body = aud44Transition(t, h, token, exceptionIdentityID, "aud44-deploy-active-exception", "deployed")
	if status != http.StatusOK {
		t.Fatalf("active attributed exception deploy = %d: %s", status, body)
	}

	expiredIdentityID := aud44CreateIssuedIdentity(t, h, token, incompleteOwnerID, "aud44-expired-exception")
	_ = aud44GrantException(t, h, token, expiredIdentityID, "short emergency window", time.Now().UTC().Add(500*time.Millisecond), "aud44-expiring-exception-grant")
	time.Sleep(600 * time.Millisecond)
	status, body = aud44Transition(t, h, token, expiredIdentityID, "aud44-deploy-expired-exception", "deployed")
	if status != http.StatusConflict {
		t.Fatalf("expired exception deploy = %d: %s, want 409", status, body)
	}

	const tenantB = "22222222-2222-2222-2222-222222222244"
	if err := h.store.UpsertTenant(ctx, store.Tenant{TenantID: tenantB, Name: "AUD-44 neighbor"}); err != nil {
		t.Fatal(err)
	}
	tokenB := seedScopedTokenSubject(t, h.store, tenantB, "neighbor@example.test", "owners:read", "owners:write")
	status, body = secretsReqKey(t, h, http.MethodGet,
		"/api/v1/identities/"+exceptionIdentityID+"/ownership-exceptions", tokenB, "", nil)
	if status != http.StatusOK || !strings.Contains(string(body), `"items":[]`) {
		t.Fatalf("neighbor exception list = %d %s, want empty tenant-local list", status, body)
	}
	status, body = secretsReqKey(t, h, http.MethodPost,
		"/api/v1/identities/"+exceptionIdentityID+"/ownership-exceptions/"+exceptionID+"/revoke",
		tokenB, "aud44-neighbor-revoke", map[string]any{"reason": "neighbor must not mutate"})
	if status != http.StatusNotFound {
		t.Fatalf("neighbor exception revoke = %d %s, want 404", status, body)
	}

	// Race owner model edits against deployments repeatedly. The projection lock
	// makes event order agree with the SQL authority order: either deployment wins
	// with valid v6 evidence, or the edit wins and deployment fails closed. A cold
	// replay below rejects any forbidden edit-before-deploy event ordering.
	lastApplicationID := ""
	for i := range 12 {
		applicationID := "APP-RACE-" + time.Now().UTC().Format("150405.000000000")
		aud44UpdateOwner(t, h, token, ownerID, "aud44-race-reset-"+string(rune('a'+i)), applicationID)
		status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/owners/"+ownerID+"/attest", token,
			"aud44-race-attest-"+string(rune('a'+i)), map[string]any{})
		if status != http.StatusOK {
			t.Fatalf("race attestation %d = %d: %s", i, status, body)
		}
		raceIdentityID := aud44CreateIssuedIdentity(t, h, token, ownerID, "aud44-race-"+string(rune('a'+i)))
		type raceResult struct {
			kind   string
			status int
			body   []byte
		}
		start := make(chan struct{})
		results := make(chan raceResult, 2)
		go func(iteration int) {
			<-start
			status, body := secretsReqKey(t, h, http.MethodPut, "/api/v1/owners/"+ownerID, token,
				"aud44-race-edit-"+strconv.Itoa(iteration), map[string]any{
					"kind": "service", "name": "payments production", "email": "payments@example.test",
					"application_id": applicationID + "-EDITED", "service": "payments-api", "business_unit": "commerce",
					"environment": "production", "escalation_chain": []string{"payments-oncall@example.test"},
				})
			results <- raceResult{kind: "edit", status: status, body: body}
		}(i)
		go func(iteration int) {
			<-start
			status, body := aud44Transition(t, h, token, raceIdentityID,
				"aud44-race-deploy-"+strconv.Itoa(iteration), "deployed")
			results <- raceResult{kind: "deploy", status: status, body: body}
		}(i)
		close(start)
		for range 2 {
			result := <-results
			switch result.kind {
			case "edit":
				if result.status != http.StatusOK {
					t.Fatalf("raced owner edit %d = %d: %s", i, result.status, result.body)
				}
			case "deploy":
				if result.status != http.StatusOK && result.status != http.StatusConflict {
					t.Fatalf("raced deploy %d = %d: %s", i, result.status, result.body)
				}
			}
		}
		lastApplicationID = applicationID + "-EDITED"
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/owners/"+ownerID+"/attest", token,
		"aud44-final-attest-after-races", map[string]any{})
	if status != http.StatusOK {
		t.Fatalf("final attestation after races = %d: %s", status, body)
	}

	if err := h.srv.proj.Rebuild(ctx, h.log); err != nil {
		t.Fatalf("cold ownership-readiness replay: %v", err)
	}
	rebuiltOwner, err := h.store.GetOwner(ctx, h.tenant, ownerID)
	if err != nil || rebuiltOwner.ApplicationID != lastApplicationID || rebuiltOwner.OwnershipVerifiedBy == "" {
		t.Fatalf("rebuilt owner authority = %+v err=%v", rebuiltOwner, err)
	}
	rebuiltException, err := h.store.GetOwnershipException(ctx, h.tenant, exceptionID)
	if err != nil || rebuiltException.IdentityID != exceptionIdentityID || rebuiltException.GrantedBy != "ownership-admin@example.test" {
		t.Fatalf("rebuilt exception authority = %+v err=%v", rebuiltException, err)
	}
}

func aud44UpdateOwner(t *testing.T, h *servedHarness, token, ownerID, key, applicationID string) {
	t.Helper()
	status, body := secretsReqKey(t, h, http.MethodPut, "/api/v1/owners/"+ownerID, token, key, map[string]any{
		"kind": "service", "name": "payments production", "email": "payments@example.test",
		"application_id": applicationID, "service": "payments-api", "business_unit": "commerce",
		"environment": "production", "escalation_chain": []string{"payments-oncall@example.test"},
	})
	if status != http.StatusOK {
		t.Fatalf("update owner = %d: %s", status, body)
	}
}

func aud44CreateIssuedIdentity(t *testing.T, h *servedHarness, token, ownerID, stem string) string {
	t.Helper()
	id := servedCreateID(t, h, token, stem+"-create", "/api/v1/identities", map[string]any{
		"kind": "x509_certificate", "name": stem + ".example.test", "owner_id": ownerID,
	})
	status, body := aud44Transition(t, h, token, id, stem+"-issue", "issued")
	if status != http.StatusOK {
		t.Fatalf("issue %s = %d: %s", stem, status, body)
	}
	return id
}

func aud44Transition(t *testing.T, h *servedHarness, token, identityID, key, to string) (int, []byte) {
	t.Helper()
	return secretsReqKey(t, h, http.MethodPost, "/api/v1/identities/"+identityID+"/transitions",
		token, key, map[string]any{"to": to})
}

func aud44GrantException(t *testing.T, h *servedHarness, token, identityID, reason string, expiresAt time.Time, key string) string {
	t.Helper()
	status, body := secretsReqKey(t, h, http.MethodPost,
		"/api/v1/identities/"+identityID+"/ownership-exceptions", token, key,
		map[string]any{"reason": reason, "expires_at": expiresAt})
	if status != http.StatusCreated {
		t.Fatalf("grant ownership exception = %d: %s", status, body)
	}
	var out struct {
		ID        string `json:"id"`
		GrantedBy string `json:"granted_by"`
		Reason    string `json:"reason"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	if out.ID == "" || out.GrantedBy != "ownership-admin@example.test" || out.Reason != reason {
		t.Fatalf("exception is not attributed/reasoned: %+v body=%s", out, body)
	}
	return out.ID
}

func aud44EventCount(t *testing.T, h *servedHarness, eventType string) int {
	t.Helper()
	count := 0
	if err := h.log.Replay(context.Background(), 0, func(event events.Event) error {
		if event.TenantID == h.tenant && event.Type == eventType {
			count++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return count
}
