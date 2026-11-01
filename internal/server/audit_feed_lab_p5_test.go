// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
)

// P5 against stock receivers: a stock rsyslog over TLS and a local search
// engine with the Elasticsearch bulk API get the same audit records as a
// Splunk HEC collector, in order, with no gap across a restart of the syslog
// receiver. Run by runners/p5-lab-proof.sh, which starts both; skipped
// otherwise.
func TestAuditFeedsReachRsyslogAndASearchEngineP5(t *testing.T) {
	syslogURL, caFile, outFile, esURL, container := os.Getenv("TRSTCTL_P5_LAB_SYSLOG"), os.Getenv("TRSTCTL_P5_LAB_CA_FILE"),
		os.Getenv("TRSTCTL_P5_LAB_SYSLOG_OUT"), os.Getenv("TRSTCTL_P5_LAB_ES"), os.Getenv("TRSTCTL_P5_LAB_RSYSLOG_CONTAINER")
	if syslogURL == "" || caFile == "" || outFile == "" || esURL == "" || container == "" {
		t.Skip("run runners/p5-lab-proof.sh (stock rsyslog over TLS and a local search engine)")
	}
	caPEM, err := os.ReadFile(caFile) // #nosec G304 G703 -- the runner's lab CA (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	hec := newP5HEC(t)
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.OutboundEnvCredentialRefs = []string{"env:TRSTCTL_P5_HEC_TOKEN", "env:TRSTCTL_P5_ES_KEY", "env:TRSTCTL_P5_SYSLOG_CA"}
	})
	t.Setenv("TRSTCTL_P5_HEC_TOKEN", "p5-hec-token")
	t.Setenv("TRSTCTL_P5_ES_KEY", "p5-lab-key")
	t.Setenv("TRSTCTL_P5_SYSLOG_CA", string(caPEM))
	token := seedServedAPIToken(t, t.Context(), h.store, h.tenant, "p5-lab-operator", []string{
		string(authz.AuditRead), string(authz.AuditWrite), string(authz.OwnersWrite), string(authz.PrivateEgress),
	})
	loopback := []string{"127.0.0.1/32", "::1/128"}
	for id, body := range map[string]map[string]any{
		p5HECFeedID:     {"name": "Splunk", "provider": "splunk-hec", "endpoint_url": hec.server.URL + "/services/collector/event", "token_ref": "env:TRSTCTL_P5_HEC_TOKEN"}, // #nosec G101 -- token_ref is a non-secret environment locator (CWE-798)
		p5SyslogFeedID:  {"name": "rsyslog", "provider": "syslog", "endpoint_url": syslogURL, "token_ref": "env:TRSTCTL_P5_SYSLOG_CA"},                                       // #nosec G101 -- token_ref is a non-secret environment locator (CWE-798)
		p5ElasticFeedID: {"name": "search", "provider": "elastic", "endpoint_url": esURL + "/trstctl-audit/_bulk", "token_ref": "env:TRSTCTL_P5_ES_KEY"},                     // #nosec G101 -- token_ref is a non-secret environment locator (CWE-798)
	} {
		body["interval_seconds"], body["batch_size"], body["enabled"] = 300, 100, true
		body["allow_private_endpoint"], body["private_egress_cidrs"] = true, loopback
		putAuditFeedAUD52(t, h, token, id, body)
	}
	round := func(n int) {
		t.Helper()
		for i := 0; i < n; i++ {
			name := fmt.Sprintf("P5 lab team %d", time.Now().UnixNano())
			if status, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/owners", token, "p5-lab-"+name, map[string]any{
				"kind": "team", "name": name, "email": "p5-lab@example.test",
			}); status != http.StatusCreated && status != http.StatusOK {
				t.Fatalf("seed: HTTP %d %s", status, body)
			}
		}
		if _, err := h.store.SystemPool().Exec(t.Context(),
			`UPDATE audit_feed_destinations SET next_run_at = now() - interval '1 second' WHERE tenant_id = $1`, h.tenant); err != nil {
			t.Fatal(err)
		}
		if _, err := h.srv.RunAuditFeedSchedulerOnce(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	dispatch := func() {
		t.Helper()
		if _, err := h.store.SystemPool().Exec(t.Context(),
			`UPDATE outbox SET next_attempt_at = now() - interval '1 second' WHERE tenant_id = $1 AND status = 'pending'`, h.tenant); err != nil {
			t.Fatal(err)
		}
		if _, err := h.srv.outbox.Dispatch(t.Context(), h.srv.obHandler); err != nil {
			t.Fatal(err)
		}
	}
	syslogSeqs := func() []uint64 {
		t.Helper()
		f, err := os.Open(outFile) // #nosec G304 G703 -- the runner's mounted rsyslog output (CWE-22)
		if err != nil {
			return nil
		}
		defer func() { _ = f.Close() }()
		var out []uint64
		seen := map[uint64]bool{}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			var rec struct {
				Sequence uint64 `json:"sequence"`
			}
			if json.Unmarshal([]byte(strings.TrimSpace(sc.Text())), &rec) == nil && rec.Sequence > 0 && !seen[rec.Sequence] {
				seen[rec.Sequence] = true
				out = append(out, rec.Sequence)
			}
		}
		return out
	}
	esSeqs := func() []uint64 {
		t.Helper()
		client := &http.Client{Timeout: 30 * time.Second}
		if resp, err := client.Post(esURL+"/trstctl-audit/_refresh", "application/json", nil); err == nil { // #nosec G704 -- the runner's own lab search engine (CWE-918)
			_ = resp.Body.Close()
		}
		resp, err := client.Get(esURL + "/trstctl-audit/_search?size=500&sort=event.sequence:asc&q=event.sequence:*") // #nosec G704 -- the runner's own lab search engine (CWE-918)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		var res struct {
			Hits struct {
				Hits []struct {
					Source struct {
						Event struct {
							Sequence uint64 `json:"sequence"`
						} `json:"event"`
					} `json:"_source"`
				} `json:"hits"`
			} `json:"hits"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
			t.Fatalf("search: %v", err)
		}
		var out []uint64
		for _, hit := range res.Hits.Hits {
			if s := hit.Source.Event.Sequence; s > 0 {
				out = append(out, s)
			}
		}
		return out
	}
	syslogTrailers := func() []p5Trailer {
		t.Helper()
		f, err := os.Open(outFile) // #nosec G304 G703 -- the runner's mounted rsyslog output (CWE-22)
		if err != nil {
			return nil
		}
		defer func() { _ = f.Close() }()
		var out []p5Trailer
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			var rec struct {
				Type string          `json:"type"`
				Data json.RawMessage `json:"data"`
			}
			if json.Unmarshal([]byte(strings.TrimSpace(sc.Text())), &rec) == nil && rec.Type == "trstctl.audit.chain_trailer" {
				out = addTrailer(out, rec.Data)
			}
		}
		return out
	}
	esTrailers := func() []p5Trailer {
		t.Helper()
		resp, err := (&http.Client{Timeout: 30 * time.Second}).Get(esURL + `/trstctl-audit/_search?size=200&sort=@timestamp:asc&q=event.action:%22trstctl.audit.chain_trailer%22`) // #nosec G704 -- the runner's own lab search engine (CWE-918)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		var res struct {
			Hits struct {
				Hits []struct {
					Source struct {
						Trstctl struct {
							Data json.RawMessage `json:"data"`
						} `json:"trstctl"`
					} `json:"_source"`
				} `json:"hits"`
			} `json:"hits"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
			t.Fatalf("trailer search: %v", err)
		}
		var out []p5Trailer
		for _, hit := range res.Hits.Hits {
			out = addTrailer(out, hit.Source.Trstctl.Data)
		}
		return out
	}
	settle := func(want []uint64) {
		t.Helper()
		deadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(deadline) && (!slices.Equal(syslogSeqs(), want) || !slices.Equal(esSeqs(), want)) {
			time.Sleep(time.Second)
		}
	}

	round(3)
	dispatch()
	want := hec.sequences()
	settle(want)
	if len(want) == 0 || !slices.Equal(syslogSeqs(), want) || !slices.Equal(esSeqs(), want) {
		t.Fatalf("first round: HEC %v, rsyslog %v, search %v", want, syslogSeqs(), esSeqs())
	}
	t.Logf("round 1: %d records reached all three collectors in order (sequences %d..%d)", len(want), want[0], want[len(want)-1])

	// The syslog receiver goes down: its batch waits while the others deliver.
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "docker", "stop", container).CombinedOutput(); err != nil { // #nosec G204 G702 -- the runner's own lab container (CWE-78)
		t.Fatalf("stop rsyslog: %v %s", err, out)
	}
	round(2)
	dispatch()
	feeds := getAuditFeedsAUD52(t, h, token)
	assertAuditFeedStatusAUD52(t, feeds, p5SyslogFeedID, "retrying", 0)
	if out, err := exec.CommandContext(ctx, "docker", "start", container).CombinedOutput(); err != nil { // #nosec G204 G702 -- the runner's own lab container (CWE-78)
		t.Fatalf("start rsyslog: %v %s", err, out)
	}
	time.Sleep(3 * time.Second)
	dispatch()
	want = hec.sequences()
	settle(want)
	if !slices.Equal(syslogSeqs(), want) || !slices.Equal(esSeqs(), want) {
		t.Fatalf("after the receiver restart: HEC %v, rsyslog %v, search %v", want, syslogSeqs(), esSeqs())
	}
	assertNoGapP5(t, h, "rsyslog", syslogSeqs())
	for name, trailers := range map[string][]p5Trailer{"rsyslog": syslogTrailers(), "search engine": esTrailers()} {
		if len(trailers) != len(hec.trailers()) {
			t.Fatalf("%s received %d batch trailers, HEC %d", name, len(trailers), len(hec.trailers()))
		}
	}
	t.Logf("after the rsyslog restart: %d records, sequences %d..%d, identical at all three collectors with no gap", len(want), want[0], want[len(want)-1])
}
