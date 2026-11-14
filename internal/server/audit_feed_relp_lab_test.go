// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
)

// P5-L3 against a stock receiver: rsyslog with its RELP input, running the
// shipped receiver content (deploy/rsyslog/trstctl-audit-relp.conf), takes
// the syslog feed over RELP on TLS. The feed counts the batch delivered only
// once rsyslog has acknowledged every message, and rsyslog writes each audit
// record as one parsed JSON object, in sequence order, with the batch's
// trailer. Run by runners/p5l3-lab-proof.sh; skipped otherwise.
func TestRsyslogRELPContentTakesTheFeedP5L3(t *testing.T) {
	relpURL, caFile, outFile := os.Getenv("TRSTCTL_P5L3_LAB_RELP"), os.Getenv("TRSTCTL_P5L3_LAB_CA_FILE"), os.Getenv("TRSTCTL_P5L3_LAB_OUT")
	if relpURL == "" || caFile == "" || outFile == "" {
		t.Skip("run runners/p5l3-lab-proof.sh (stock rsyslog with the shipped RELP receiver content)")
	}
	caPEM, err := os.ReadFile(caFile) // #nosec G304 G703 -- the runner's lab CA (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.OutboundEnvCredentialRefs = []string{"env:TRSTCTL_P5L3_LAB_CA"}
	})
	t.Setenv("TRSTCTL_P5L3_LAB_CA", string(caPEM))
	token := seedServedAPIToken(t, t.Context(), h.store, h.tenant, "p5l3-lab-operator", []string{
		string(authz.AuditRead), string(authz.AuditWrite), string(authz.OwnersWrite), string(authz.PrivateEgress),
	})
	const feedID = "50505050-5050-4505-8505-505050505541"
	putAuditFeedAUD52(t, h, token, feedID, map[string]any{
		"name": "P5-L3 lab rsyslog RELP", "provider": "syslog", "endpoint_url": relpURL,
		"token_ref": "env:TRSTCTL_P5L3_LAB_CA", "interval_seconds": 300, "batch_size": 100, "enabled": true, // #nosec G101 -- token_ref is a non-secret environment locator (CWE-798)
		"allow_private_endpoint": true, "private_egress_cidrs": []string{"127.0.0.1/32", "::1/128"},
	})
	for i := 0; i < 3; i++ {
		name := fmt.Sprintf("P5-L3 lab team %d", time.Now().UnixNano())
		if status, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/owners", token, "p5l3-lab-"+name, map[string]any{
			"kind": "team", "name": name, "email": "p5l3-lab@example.test",
		}); status != http.StatusCreated && status != http.StatusOK {
			t.Fatalf("seed an audit record: HTTP %d %s", status, body)
		}
	}
	if _, err := h.store.SystemPool().Exec(t.Context(),
		`UPDATE audit_feed_destinations SET next_run_at = now() - interval '1 second' WHERE tenant_id = $1`, h.tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := h.srv.RunAuditFeedSchedulerOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := h.srv.outbox.Dispatch(t.Context(), h.srv.obHandler); err != nil {
		t.Fatal(err)
	}
	assertAuditFeedStatusAUD52(t, getAuditFeedsAUD52(t, h, token), feedID, "delivered", 1)

	type parsed struct {
		Sequence  uint64          `json:"sequence"`
		Type      string          `json:"type"`
		ChainHash string          `json:"chain_hash"`
		Data      json.RawMessage `json:"data"`
	}
	var records []parsed
	trailers := 0
	for deadline := time.Now().Add(15 * time.Second); ; {
		raw, _ := os.ReadFile(outFile) // #nosec G304 G703 -- the runner's lab output file (CWE-22)
		records, trailers = records[:0], 0
		for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
			var rec parsed
			if strings.TrimSpace(line) == "" || json.Unmarshal([]byte(line), &rec) != nil {
				continue
			}
			if rec.Type == "trstctl.audit.chain_trailer" {
				trailers++
				continue
			}
			records = append(records, rec)
		}
		if (len(records) > 0 && trailers > 0) || time.Now().After(deadline) {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if len(records) == 0 || trailers == 0 {
		t.Fatalf("rsyslog wrote %d parsed records and %d trailers", len(records), trailers)
	}
	for i, rec := range records {
		if rec.Sequence == 0 || rec.Type == "" || rec.ChainHash == "" || (i > 0 && rec.Sequence <= records[i-1].Sequence) {
			t.Fatalf("parsed record %d = %+v", i, rec)
		}
	}
	t.Logf("P5L3_LAB_RELP_OK rsyslog acknowledged and parsed %d audit records (sequences %d..%d) and %d trailers",
		len(records), records[0].Sequence, records[len(records)-1].Sequence, trailers)
}
