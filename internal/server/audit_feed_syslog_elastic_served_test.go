// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
)

const (
	p5HECFeedID     = "50505050-5050-4505-8505-505050505001"
	p5SyslogFeedID  = "50505050-5050-4505-8505-505050505002"
	p5ElasticFeedID = "50505050-5050-4505-8505-505050505003"
)

// P5: a Splunk HEC collector, a syslog receiver over TLS and an Elasticsearch
// bulk endpoint receive the same audit records in the same order. A batch
// delivered again (a retry after a lost receipt) adds no second copy to the
// index. A stalled syslog receiver backs up only its own queue: the API stays
// fast and the other collectors keep receiving, and once the receiver
// recovers it gets every record it missed, in order, with no gap.
func TestServedAuditFeedsSyslogAndElasticMatchSplunkP5(t *testing.T) {
	restore := syslogFeedTimeout
	syslogFeedTimeout = 2 * time.Second
	t.Cleanup(func() { syslogFeedTimeout = restore })

	hec := newP5HEC(t)
	es := newP5Elastic(t)
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.OutboundEnvCredentialRefs = []string{"env:TRSTCTL_P5_HEC_TOKEN", "env:TRSTCTL_P5_ES_KEY", "env:TRSTCTL_P5_SYSLOG_CA"}
	})
	syslog := newP5Syslog(t, h)
	t.Setenv("TRSTCTL_P5_HEC_TOKEN", "p5-hec-token")
	t.Setenv("TRSTCTL_P5_ES_KEY", "p5-es-key")
	t.Setenv("TRSTCTL_P5_SYSLOG_CA", string(h.caPEM))
	token := seedServedAPIToken(t, t.Context(), h.store, h.tenant, "p5-operator", []string{
		string(authz.AuditRead), string(authz.AuditWrite), string(authz.OwnersWrite), string(authz.PrivateEgress),
	})
	loopback := []string{"127.0.0.1/32", "::1/128"}
	for id, body := range map[string]map[string]any{
		p5HECFeedID: {"name": "Splunk", "provider": "splunk-hec", "endpoint_url": hec.server.URL + "/services/collector/event",
			"token_ref": "env:TRSTCTL_P5_HEC_TOKEN"}, // #nosec G101 -- token_ref is a non-secret environment locator (CWE-798)
		p5SyslogFeedID: {"name": "rsyslog", "provider": "syslog", "endpoint_url": "syslog+tls://localhost:" + syslog.port,
			"token_ref": "env:TRSTCTL_P5_SYSLOG_CA"}, // #nosec G101 -- token_ref is a non-secret environment locator (CWE-798)
		p5ElasticFeedID: {"name": "Elastic", "provider": "elastic", "endpoint_url": es.server.URL + "/trstctl-audit/_bulk",
			"token_ref": "env:TRSTCTL_P5_ES_KEY"}, // #nosec G101 -- token_ref is a non-secret environment locator (CWE-798)
	} {
		body["interval_seconds"], body["batch_size"], body["enabled"] = 300, 100, true
		body["allow_private_endpoint"], body["private_egress_cidrs"] = true, loopback
		putAuditFeedAUD52(t, h, token, id, body)
	}
	if status, body := doBearer(t, h.ts, http.MethodPut, "/api/v1/audit/feeds/50505050-5050-4505-8505-505050505009", token, "p5-plain-syslog", map[string]any{
		"name": "plain", "provider": "syslog", "endpoint_url": "tcp://localhost:514", "token_ref": "",
		"interval_seconds": 300, "batch_size": 100, "enabled": true,
	}); status != http.StatusBadRequest {
		t.Fatalf("a syslog feed without TLS was accepted: HTTP %d %s", status, body)
	}
	seed := func(n int) {
		t.Helper()
		for i := 0; i < n; i++ {
			name := "P5 team " + strconv.Itoa(int(time.Now().UnixNano()))
			if status, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/owners", token, "p5-owner-"+name, map[string]any{
				"kind": "team", "name": name, "email": "p5@example.test",
			}); status != http.StatusCreated && status != http.StatusOK {
				t.Fatalf("seed audit record: HTTP %d %s", status, body)
			}
		}
	}
	due := func() {
		t.Helper()
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
		if _, err := h.srv.outbox.Dispatch(t.Context(), h.srv.obHandler); err != nil {
			t.Fatal(err)
		}
	}

	seed(3)
	due()
	dispatch()
	feeds := getAuditFeedsAUD52(t, h, token)
	for _, id := range []string{p5HECFeedID, p5SyslogFeedID, p5ElasticFeedID} {
		assertAuditFeedStatusAUD52(t, feeds, id, "delivered", 1)
	}
	if got := hec.last(); got.auth != "Splunk p5-hec-token" {
		t.Fatalf("HEC authorization = %q", got.auth)
	}
	if es.auth() != "ApiKey p5-es-key" || es.contentType() != "application/x-ndjson" {
		t.Fatalf("elastic headers: %q %q", es.auth(), es.contentType())
	}
	want := hec.sequences()
	if len(want) == 0 || !slices.Equal(syslog.sequences(), want) || !slices.Equal(es.sequences(), want) {
		t.Fatalf("collectors disagree: HEC %v, syslog %v, elastic %v", want, syslog.sequences(), es.sequences())
	}
	assertNoGapP5(t, h, "HEC", want)

	// A batch delivered again after its receipt was lost adds nothing to the
	// index; syslog and HEC carry the repeat with the same sequences.
	if _, err := h.store.SystemPool().Exec(t.Context(),
		`UPDATE outbox SET status = 'pending', next_attempt_at = now() - interval '1 second', attempts = 0
		  WHERE tenant_id = $1 AND destination = 'audit.feed.elastic'`, h.tenant); err != nil {
		t.Fatal(err)
	}
	dispatch()
	if !slices.Equal(es.sequences(), want) || es.conflicts() == 0 {
		t.Fatalf("a redelivered batch changed the index: %v (conflicts %d)", es.sequences(), es.conflicts())
	}

	// The syslog receiver stalls: its batch times out and waits, the API and
	// the other collectors carry on.
	syslog.stall(true)
	seed(2)
	due()
	done := make(chan struct{})
	go func() { defer close(done); _, _ = h.srv.outbox.Dispatch(t.Context(), h.srv.obHandler) }()
	var slowest time.Duration
	for i := 0; i < 10; i++ {
		start := time.Now()
		if status, _ := doBearer(t, h.ts, http.MethodGet, "/api/v1/audit/feeds", token, "", nil); status != http.StatusOK {
			t.Fatalf("API during the stall: HTTP %d", status)
		}
		slowest = max(slowest, time.Since(start))
		time.Sleep(50 * time.Millisecond)
	}
	<-done
	if slowest > time.Second {
		t.Fatalf("the API slowed to %s while the syslog receiver stalled", slowest)
	}
	feeds = getAuditFeedsAUD52(t, h, token)
	assertAuditFeedStatusAUD52(t, feeds, p5SyslogFeedID, "retrying", 0)
	want = hec.sequences()
	if !slices.Equal(es.sequences(), want) || len(syslog.sequences()) >= len(want) {
		t.Fatalf("during the stall: HEC %v, elastic %v, syslog %v", want, es.sequences(), syslog.sequences())
	}

	// The receiver recovers and catches up, in order, with no gap.
	syslog.stall(false)
	if _, err := h.store.SystemPool().Exec(t.Context(),
		`UPDATE outbox SET next_attempt_at = now() - interval '1 second' WHERE tenant_id = $1 AND status = 'pending'`, h.tenant); err != nil {
		t.Fatal(err)
	}
	dispatch()
	feeds = getAuditFeedsAUD52(t, h, token)
	assertAuditFeedStatusAUD52(t, feeds, p5SyslogFeedID, "delivered", 1)
	if got := syslog.sequences(); !slices.Equal(got, want) {
		t.Fatalf("syslog after recovery %v, want %v", got, want)
	}
	assertNoGapP5(t, h, "syslog", syslog.sequences())
	for name, trailers := range map[string][]p5Trailer{"syslog": syslog.trailers(), "elastic": es.trailers()} {
		if len(trailers) != len(hec.trailers()) {
			t.Fatalf("%s received %d batch trailers, HEC %d", name, len(trailers), len(hec.trailers()))
		}
	}
}

// p5Trailer is a batch's chain trailer as a collector received it.
type p5Trailer struct {
	BatchID   string `json:"batch_id"`
	PrevHash  string `json:"prev_hash"`
	ChainHead string `json:"chain_head"`
}

// assertNoGapP5 checks that the records a collector holds are exactly the
// tenant's exportable audit records (every type except the feeds' own
// audit.feed.* events) up to the last one delivered: nothing skipped, nothing
// reordered.
func assertNoGapP5(t *testing.T, h *servedHarness, name string, got []uint64) {
	t.Helper()
	if len(got) == 0 {
		t.Fatalf("%s received no audit record", name)
	}
	records, _, err := h.srv.audit.SearchWithSeed(t.Context(), audit.Query{
		TenantID: h.tenant, ExcludeTypePrefixes: []string{"audit.feed."}, Limit: 500,
	})
	if err != nil {
		t.Fatal(err)
	}
	var want []uint64
	for _, record := range records {
		if record.Sequence <= got[len(got)-1] {
			want = append(want, record.Sequence)
		}
	}
	if !slices.Equal(got, want) {
		t.Fatalf("%s holds %v; the exportable audit records up to its last are %v", name, got, want)
	}
}

// addTrailer keeps the first copy of each batch's trailer, in arrival order.
func addTrailer(list []p5Trailer, raw json.RawMessage) []p5Trailer {
	var tr p5Trailer
	if json.Unmarshal(raw, &tr) != nil || tr.BatchID == "" {
		return list
	}
	for _, have := range list {
		if have.BatchID == tr.BatchID {
			return list
		}
	}
	return append(list, tr)
}

// ---- Splunk HEC stand-in

type p5HECRequest struct {
	auth string
	body []byte
}

type p5HEC struct {
	server *httptest.Server
	mu     sync.Mutex
	reqs   []p5HECRequest
}

func newP5HEC(t *testing.T) *p5HEC {
	c := &p5HEC{}
	c.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 4<<20))
		c.mu.Lock()
		c.reqs = append(c.reqs, p5HECRequest{auth: r.Header.Get("Authorization"), body: raw})
		c.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(c.server.Close)
	return c
}

func (c *p5HEC) last() p5HECRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.reqs[len(c.reqs)-1]
}

// trailers lists the batch trailers received, first delivery of each.
func (c *p5HEC) trailers() []p5Trailer {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []p5Trailer
	for _, req := range c.reqs {
		dec := json.NewDecoder(bytes.NewReader(req.body))
		for dec.More() {
			var ev struct {
				Event struct {
					Type string          `json:"type"`
					Data json.RawMessage `json:"data"`
				} `json:"event"`
			}
			if dec.Decode(&ev) != nil {
				break
			}
			if ev.Event.Type == "trstctl.audit.chain_trailer" {
				out = addTrailer(out, ev.Event.Data)
			}
		}
	}
	return out
}

// sequences lists the audit sequences received, first delivery of each.
func (c *p5HEC) sequences() []uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []uint64
	seen := map[uint64]bool{}
	for _, req := range c.reqs {
		dec := json.NewDecoder(bytes.NewReader(req.body))
		for dec.More() {
			var ev struct {
				Event struct {
					Sequence uint64 `json:"sequence"`
				} `json:"event"`
			}
			if dec.Decode(&ev) != nil {
				break
			}
			if ev.Event.Sequence > 0 && !seen[ev.Event.Sequence] {
				seen[ev.Event.Sequence] = true
				out = append(out, ev.Event.Sequence)
			}
		}
	}
	return out
}

// ---- Elasticsearch bulk stand-in

type p5Elastic struct {
	server   *httptest.Server
	mu       sync.Mutex
	ids      map[string]bool
	seqs     []uint64
	trails   []p5Trailer
	conflict int
	lastAuth string
	lastType string
}

func newP5Elastic(t *testing.T) *p5Elastic {
	c := &p5Elastic{ids: map[string]bool{}}
	c.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/trstctl-audit/_bulk" {
			http.NotFound(w, r)
			return
		}
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 8<<20))
		lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
		type item map[string]map[string]int
		var items []item
		c.mu.Lock()
		c.lastAuth, c.lastType = r.Header.Get("Authorization"), r.Header.Get("Content-Type")
		for i := 0; i+1 < len(lines); i += 2 {
			var action struct {
				Create struct {
					ID string `json:"_id"`
				} `json:"create"`
			}
			var doc struct {
				Event struct {
					Sequence uint64 `json:"sequence"`
					Action   string `json:"action"`
				} `json:"event"`
				Trstctl struct {
					Data json.RawMessage `json:"data"`
				} `json:"trstctl"`
			}
			_ = json.Unmarshal([]byte(lines[i]), &action)
			_ = json.Unmarshal([]byte(lines[i+1]), &doc)
			if c.ids[action.Create.ID] {
				c.conflict++
				items = append(items, item{"create": {"status": http.StatusConflict}})
				continue
			}
			c.ids[action.Create.ID] = true
			if doc.Event.Sequence > 0 {
				c.seqs = append(c.seqs, doc.Event.Sequence)
			}
			if doc.Event.Action == "trstctl.audit.chain_trailer" {
				c.trails = addTrailer(c.trails, doc.Trstctl.Data)
			}
			items = append(items, item{"create": {"status": http.StatusCreated}})
		}
		c.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"errors": false, "items": items})
	}))
	t.Cleanup(c.server.Close)
	return c
}

func (c *p5Elastic) sequences() []uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]uint64(nil), c.seqs...)
}

func (c *p5Elastic) trailers() []p5Trailer {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]p5Trailer(nil), c.trails...)
}

func (c *p5Elastic) conflicts() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conflict
}

func (c *p5Elastic) auth() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastAuth
}

func (c *p5Elastic) contentType() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastType
}

// ---- syslog over TLS stand-in (RFC 5425 octet counting)

type p5Syslog struct {
	port    string
	mu      sync.Mutex
	stalled bool
	seqs    []uint64
	trails  []p5Trailer
	seen    map[uint64]bool
}

func newP5Syslog(t *testing.T, h *servedHarness) *p5Syslog {
	t.Helper()
	key, err := crypto.GenerateHostSubjectKey("localhost", []string{"localhost"})
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	certPEM, err := h.srv.IssueLeaf(t.Context(), key.CSRDER, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := key.PrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "syslog.crt"), filepath.Join(dir, "syslog.key")
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	cert, err := mtls.ServerCertFromFiles(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := cert.Listener(raw)
	t.Cleanup(func() { _ = ln.Close() })
	r := &p5Syslog{seen: map[uint64]bool{}}
	_, r.port, _ = net.SplitHostPort(raw.Addr().String())
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			r.mu.Lock()
			stalled := r.stalled
			r.mu.Unlock()
			if stalled {
				// Never handshake: the sender waits until its deadline.
				go func() { time.Sleep(5 * time.Second); _ = conn.Close() }()
				continue
			}
			go r.read(conn)
		}
	}()
	return r
}

func (r *p5Syslog) read(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	br := bufio.NewReader(conn)
	for {
		lenText, err := br.ReadString(' ')
		if err != nil {
			return
		}
		n, err := strconv.Atoi(strings.TrimSpace(lenText))
		if err != nil || n <= 0 || n > 1<<20 {
			return
		}
		msg := make([]byte, n)
		if _, err := io.ReadFull(br, msg); err != nil {
			return
		}
		_, body, ok := strings.Cut(string(msg), " trstctl-audit - ")
		if !ok || !strings.HasPrefix(string(msg), "<110>1 ") {
			return
		}
		var rec struct {
			Sequence uint64          `json:"sequence"`
			Type     string          `json:"type"`
			Data     json.RawMessage `json:"data"`
		}
		if json.Unmarshal([]byte(body), &rec) != nil {
			continue
		}
		r.mu.Lock()
		if rec.Sequence > 0 && !r.seen[rec.Sequence] {
			r.seen[rec.Sequence] = true
			r.seqs = append(r.seqs, rec.Sequence)
		}
		if rec.Type == "trstctl.audit.chain_trailer" {
			r.trails = addTrailer(r.trails, rec.Data)
		}
		r.mu.Unlock()
	}
}

func (r *p5Syslog) stall(on bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stalled = on
}

func (r *p5Syslog) trailers() []p5Trailer {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]p5Trailer(nil), r.trails...)
}

func (r *p5Syslog) sequences() []uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]uint64(nil), r.seqs...)
}
