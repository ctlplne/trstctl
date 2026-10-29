// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/secrettext"
)

type splunkScaffoldResult struct {
	Model     string `json:"model"`
	Execution string `json:"execution"`
	Fired     bool   `json:"fired"`
	Rows      []struct {
		TenantID   string   `json:"tenant_id"`
		IdentityID string   `json:"identity_id"`
		EventCount int      `json:"event_count"`
		EventIDs   []string `json:"event_ids"`
	} `json:"rows"`
}

// This opt-in journey uses the real API, PostgreSQL, immutable NATS audit log,
// scheduler and outbox against an owned scaffold. Only the lab input events
// are seeded: it does not qualify upstream CA behavior or Splunk's SPL engine.
func TestSplunkAppScaffoldConsumesProductAuditFeed(t *testing.T) {
	if os.Getenv("TRSTCTL_REQUIRE_SPLUNK_SCAFFOLD") != "1" {
		t.Skip("owned loopback20489 scaffold not requested; vendor runtime is not tested here")
	}
	// This test addresses only its reserved owned-fixture port. It accepts no
	// request URL, host, path, query or proxy configuration from the environment.
	const endpoint = "http://127.0.0.1:20489"
	root, err := os.OpenRoot(os.Getenv("TRSTCTL_A231_SCAFFOLD_DIR"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	fixtureToken, err := root.Open("scaffold-token.bin")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fixtureToken.Close() }()
	tokenBytes, err := io.ReadAll(io.LimitReader(fixtureToken, 4097))
	if err != nil || len(tokenBytes) > 4096 {
		t.Fatal("fixture credential unreadable or outside size bound")
	}
	tokenBytes = bytes.TrimSpace(tokenBytes)
	defer secret.Wipe(tokenBytes)
	if len(tokenBytes) == 0 {
		t.Fatal("empty scaffold fixture credential")
	}
	// Give this run its own reference; never overwrite an operator's env slot.
	fixtureEnvName := "TRSTCTL_A231_FIXTURE_" + strings.ReplaceAll(uuid.NewString(), "-", "_")
	fixtureRef := "env:" + fixtureEnvName
	t.Setenv(fixtureEnvName, string(tokenBytes))
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	request := func(path string, body any, result any) {
		t.Helper()
		var wire []byte
		if body != nil {
			var err error
			wire, err = json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
		}
		method := http.MethodGet
		if body != nil {
			method = http.MethodPost
		}
		req, err := http.NewRequestWithContext(t.Context(), method, endpoint+path, bytes.NewReader(wire))
		if err != nil {
			t.Fatal(err)
		}
		if path != "/health" {
			req.Header.Set("Authorization", secrettext.Prefixed("Splunk ", tokenBytes))
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("owned scaffold %s HTTP%d", path, resp.StatusCode)
		}
		if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(result); err != nil {
			t.Fatal(err)
		}
	}
	var health struct {
		Model string `json:"model"`
		Ready bool   `json:"ready"`
	}
	request("/health", nil, &health)
	if health.Model != "trstctl-owned-scaffold-v1" || !health.Ready {
		t.Fatal("endpoint is not the owned scaffold")
	}
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) { d.OutboundEnvCredentialRefs = []string{fixtureRef} })
	h.tenant = uuid.NewString()
	registerServedTenant(t, h, "A231 isolated audit feed")
	identityID, otherTenant := uuid.NewString(), uuid.NewString()
	wanted := map[string][]string{}
	for _, tenant := range []string{h.tenant, otherTenant} {
		for _, kind := range []string{projections.EventIdentityRenewalFailed, projections.EventCertificateRevoked} {
			count := 3
			if kind == projections.EventCertificateRevoked {
				count = 5
			}
			for i := range count {
				var data []byte
				if kind == projections.EventIdentityRenewalFailed {
					data, err = json.Marshal(map[string]any{"identity_id": identityID, "from": "renewing", "to": "renewal_failed", "reason": "A231 lab CA unreachable"})
				} else {
					data, err = json.Marshal(projections.CertificateRevoked{Fingerprint: crypto.SHA256Hex([]byte(fmt.Sprintf("a231/%s/%d", tenant, i))), Serial: fmt.Sprint(i + 1), Reason: "cessationOfOperation", ReasonCode: 5, RevokedAt: time.Now().UTC()})
				}
				if err != nil {
					t.Fatal(err)
				}
				event, err := h.log.Append(t.Context(), events.Event{Type: kind, TenantID: tenant, Data: data})
				if err != nil {
					t.Fatal(err)
				}
				if tenant == h.tenant {
					wanted[kind] = append(wanted[kind], event.ID)
				}
			}
		}
	}
	searches := map[string]string{projections.EventIdentityRenewalFailed: "trstctl - Repeated renewal failures", projections.EventCertificateRevoked: "trstctl - Certificate revocation burst"}
	query := func(name, tenant string) splunkScaffoldResult {
		t.Helper()
		var result splunkScaffoldResult
		request("/scaffold/search", map[string]any{"name": name, "index": "trstctl_lab", "tenant_id": tenant, "now": float64(time.Now().Add(time.Second).UnixNano()) / float64(time.Second)}, &result)
		if result.Model != "trstctl-owned-scaffold-v1" || result.Execution != "ad_hoc_contract" {
			t.Fatal("query did not identify its contract model")
		}
		return result
	}
	for _, name := range searches {
		if query(name, h.tenant).Fired {
			t.Fatal("search fired before outbox delivery")
		}
	}
	token := seedServedAPIToken(t, t.Context(), h.store, h.tenant, "a231-audit-operator", []string{string(authz.AuditRead), string(authz.AuditWrite), string(authz.PrivateEgress)})
	const feedID = "31313131-3131-4313-8313-313131313131"
	putAuditFeedAUD52(t, h, token, feedID, map[string]any{
		"name": "A231 owned HEC contract scaffold", "provider": "splunk-hec", "endpoint_url": endpoint + "/services/collector/event", "token_ref": fixtureRef, "interval_seconds": 60, "batch_size": 100, "enabled": true, "allow_private_endpoint": true, "private_egress_cidrs": []string{serviceNowSinkCIDR(t, endpoint)},
	})
	queued, err := h.srv.RunAuditFeedSchedulerOnce(t.Context())
	if err != nil || queued != 1 {
		t.Fatalf("queue exact audit batch: %d %v", queued, err)
	}
	for _, name := range searches {
		if query(name, h.tenant).Fired {
			t.Fatal("configuration/scheduler performed inline delivery")
		}
	}
	processed, err := h.srv.outbox.Dispatch(t.Context(), h.srv.obHandler)
	if err != nil || processed != 1 {
		t.Fatalf("dispatch exact audit batch: %d %v", processed, err)
	}
	var state string
	for _, feed := range getAuditFeedsAUD52(t, h, token).Items {
		if feed.ID == feedID {
			state = feed.Status
		}
	}
	ackLost := state == "retrying"
	if os.Getenv("TRSTCTL_A231_EXPECT_ACK_LOSS") == "1" && !ackLost {
		t.Fatalf("fixture did not exercise acknowledgment loss: %s", state)
	}
	if ackLost {
		assertAuditFeedStatusAUD52(t, getAuditFeedsAUD52(t, h, token), feedID, "retrying", 0)
		if _, err := h.store.SystemPool().Exec(t.Context(), `UPDATE outbox SET next_attempt_at=now()-interval '1 second' WHERE tenant_id=$1 AND destination=$2 AND status='pending'`, h.tenant, orchestrator.DestinationAuditFeedSplunk); err != nil {
			t.Fatal(err)
		}
		processed, err = h.srv.outbox.Dispatch(t.Context(), h.srv.obHandler)
		if err != nil || processed != 1 {
			t.Fatalf("retry exact audit batch: %d %v", processed, err)
		}
	}
	assertAuditFeedStatusAUD52(t, getAuditFeedsAUD52(t, h, token), feedID, "delivered", 1)
	results := map[string]splunkScaffoldResult{}
	for kind, name := range searches {
		result := query(name, h.tenant)
		if !result.Fired || len(result.Rows) != 1 {
			t.Fatalf("owned correlation did not fire: %s %+v", name, result)
		}
		row := result.Rows[0]
		sort.Strings(row.EventIDs)
		sort.Strings(wanted[kind])
		if row.TenantID != h.tenant || row.EventCount != len(wanted[kind]) || !reflect.DeepEqual(row.EventIDs, wanted[kind]) {
			t.Fatalf("correlation does not bind exact deduplicated tenant events: %+v", row)
		}
		if kind == projections.EventIdentityRenewalFailed && row.IdentityID != identityID {
			t.Fatal("renewal correlation lost identity")
		}
		if query(name, otherTenant).Fired {
			t.Fatal("feed leaked the other tenant's sufficient matching event set")
		}
		results[kind] = result
	}
	proof := struct {
		Model           string                          `json:"model"`
		AckLossObserved bool                            `json:"ack_loss_observed"`
		TenantID        string                          `json:"tenant_id"`
		Results         map[string]splunkScaffoldResult `json:"results"`
	}{health.Model, ackLost, h.tenant, results}
	wire, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	// The retained native test log is the evidence channel. This helper has no
	// caller-selected filesystem write surface; only public lab facts are logged.
	t.Logf("A231_PUBLIC_PROOF=%s", wire)
	t.Logf("owned scaffold correlations fired on exact %d renewal/%d revocation audit IDs; acknowledgment-loss retry=%v; vendor runtime untested", len(wanted[projections.EventIdentityRenewalFailed]), len(wanted[projections.EventCertificateRevoked]), ackLost)
}
