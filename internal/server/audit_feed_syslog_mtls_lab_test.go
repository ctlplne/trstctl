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

// P5-L2 against a stock receiver: rsyslog over TLS with mutual TLS
// (x509/certvalid) takes the feed that presents a client certificate its
// lab CA issued, and refuses the one that presents none, which then reads
// retrying instead of delivered. Run by runners/p5l2-lab-proof.sh; skipped
// otherwise.
func TestSyslogFeedMutualTLSAgainstRsyslogP5L2(t *testing.T) {
	syslogURL, caFile, clientFile, outFile := os.Getenv("TRSTCTL_P5L2_LAB_SYSLOG"), os.Getenv("TRSTCTL_P5L2_LAB_CA_FILE"),
		os.Getenv("TRSTCTL_P5L2_LAB_CLIENT_FILE"), os.Getenv("TRSTCTL_P5L2_LAB_OUT")
	if syslogURL == "" || caFile == "" || clientFile == "" || outFile == "" {
		t.Skip("run runners/p5l2-lab-proof.sh (stock rsyslog requiring mutual TLS)")
	}
	caPEM, err := os.ReadFile(caFile) // #nosec G304 G703 -- the runner's lab CA (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := os.ReadFile(clientFile) // #nosec G304 G703 -- the runner's lab client certificate and key (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.OutboundEnvCredentialRefs = []string{"env:TRSTCTL_P5L2_LAB_CA", "env:TRSTCTL_P5L2_LAB_CLIENT"}
	})
	t.Setenv("TRSTCTL_P5L2_LAB_CA", string(caPEM))
	t.Setenv("TRSTCTL_P5L2_LAB_CLIENT", string(bundle))
	token := seedServedAPIToken(t, t.Context(), h.store, h.tenant, "p5l2-lab-operator", []string{
		string(authz.AuditRead), string(authz.AuditWrite), string(authz.OwnersWrite), string(authz.PrivateEgress),
	})
	const withCert, withoutCert = "50505050-5050-4505-8505-505050505511", "50505050-5050-4505-8505-505050505512"
	for id, clientRef := range map[string]string{withCert: "env:TRSTCTL_P5L2_LAB_CLIENT", withoutCert: ""} {
		body := map[string]any{
			"name": "P5-L2 lab " + id[len(id)-2:], "provider": "syslog", "endpoint_url": syslogURL,
			"token_ref": "env:TRSTCTL_P5L2_LAB_CA", "interval_seconds": 300, "batch_size": 100, "enabled": true, // #nosec G101 -- token_ref is a non-secret environment locator (CWE-798)
			"allow_private_endpoint": true, "private_egress_cidrs": []string{"127.0.0.1/32", "::1/128"},
		}
		if clientRef != "" {
			body["client_cert_ref"] = clientRef
		}
		putAuditFeedAUD52(t, h, token, id, body)
	}
	for i := 0; i < 3; i++ {
		name := fmt.Sprintf("P5-L2 lab team %d", time.Now().UnixNano())
		if status, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/owners", token, "p5l2-lab-"+name, map[string]any{
			"kind": "team", "name": name, "email": "p5l2-lab@example.test",
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
	list := getAuditFeedsAUD52(t, h, token)
	assertAuditFeedStatusAUD52(t, list, withCert, "delivered", 1)
	assertAuditFeedStatusAUD52(t, list, withoutCert, "retrying", 0)

	// rsyslog wrote what it accepted; it accepted only the feed with a client
	// certificate, so every record it holds came once, in sequence order.
	var got []uint64
	for deadline := time.Now().Add(15 * time.Second); ; {
		raw, _ := os.ReadFile(outFile) // #nosec G304 G703 -- the runner's lab output file (CWE-22)
		got = got[:0]
		for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
			var rec struct {
				Sequence uint64 `json:"sequence"`
			}
			if json.Unmarshal([]byte(strings.TrimSpace(line)), &rec) == nil && rec.Sequence > 0 {
				got = append(got, rec.Sequence)
			}
		}
		if len(got) > 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if len(got) == 0 {
		t.Fatal("rsyslog wrote no record from the feed with a client certificate")
	}
	for i := 1; i < len(got); i++ {
		if got[i] <= got[i-1] {
			t.Fatalf("rsyslog holds a repeat or a reordering: %v", got)
		}
	}
	t.Logf("rsyslog (mutual TLS) holds %d records from the feed with a client certificate: %v", len(got), got)
}
