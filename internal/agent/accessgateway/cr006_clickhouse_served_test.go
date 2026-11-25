// SPDX-License-Identifier: BUSL-1.1

// CR-006 exercises the gateway's ClickHouse path through its blocking reviewer
// and a recording upstream. The upstream records exact forwarded bytes; this
// test proves the gateway refuses the payload before forwarding it.
package accessgateway

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/agent/relay"
)

func TestCR006GatewayBlocksCRCommentedTruncateBeforeForwarding(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	type seen struct{ method, rawQuery, body, user string }
	var mu sync.Mutex
	var upstream []seen
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		upstream = append(upstream, seen{r.Method, r.URL.RawQuery, string(body), r.Header.Get("X-ClickHouse-User")})
		mu.Unlock()
		_, _ = io.WriteString(w, "ok\n")
	}))
	defer srv.Close()

	policy, digest := gatewayBlockPolicy(t, "clickhouse", []string{"ALTER", "DELETE", "DROP", "INSERT", "SET", "TRUNCATE", "UPDATE"})
	reviewer := &blockingReviewer{protocol: "clickhouse", sessionID: uuid.NewString(), digest: digest}
	g := &Gateway{cfg: Config{Logf: t.Logf}}
	client, gatewaySide := net.Pipe()
	guard := &commandConnection{gateway: g, sessionID: reviewer.sessionID, target: "ch-v1", protocol: "clickhouse", connectionID: uuid.NewString(),
		policyDigest: digest, job: relay.Job{JobID: 43, Attempt: 1}, policy: policy, reviewer: reviewer, expiresAt: time.Now().Add(time.Minute)}
	served := make(chan error, 1)
	go func() {
		served <- serveClickHouse(ctx, gatewaySide, []byte(`{"username":"fixture_session","password":"fixture"}`), httpUpstream{URL: srv.URL, TunnelCapability: localTunnelCapability("cr006-ticket")}, nil, nil, guard)
	}()
	defer func() { _ = client.Close(); <-served }()
	reader := bufio.NewReader(client)
	send := func(target, body string) (int, string) {
		t.Helper()
		_ = client.SetDeadline(time.Now().Add(20 * time.Second))
		request, err := http.NewRequest(http.MethodPost, "http://127.0.0.1:18080"+target, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("X-Trstctl-Tunnel-Token", localTunnelCapability("cr006-ticket"))
		if err := request.Write(client); err != nil {
			t.Fatal(err)
		}
		response, err := http.ReadResponse(reader, request)
		if err != nil {
			t.Fatal(err)
		}
		text, _ := io.ReadAll(response.Body)
		_ = response.Body.Close()
		return response.StatusCode, string(text)
	}
	forwarded := func() []seen { mu.Lock(); defer mu.Unlock(); return append([]seen(nil), upstream...) }

	// Control: the direct statement is refused and never reaches the target.
	if status, text := send("/", "TRUNCATE TABLE victim"); status != http.StatusForbidden || !strings.Contains(text, "TRSTCTL_COMMAND_REFUSED") || len(forwarded()) != 0 {
		t.Fatalf("control: direct TRUNCATE = %d %s, upstream saw %v", status, text, forwarded())
	}
	for _, attack := range []struct{ name, target, body string }{
		{"-- comment ended by CR", "/", "--\r'\nTRUNCATE TABLE victim\n--'"},
		{"// comment ended by CR", "/", "//\r'\nTRUNCATE TABLE victim\n//'"},
		{"# comment ended by CR", "/", "# \r'\nTRUNCATE TABLE victim\n# '"},
	} {
		before := len(forwarded())
		reviewer.mu.Lock()
		beforeReviews := len(reviewer.seen)
		reviewer.mu.Unlock()
		status, text := send(attack.target, attack.body)
		after := forwarded()
		reviewer.mu.Lock()
		observations := append([][]string(nil), reviewer.seen[beforeReviews:]...)
		reviewer.mu.Unlock()
		if status != http.StatusForbidden || !strings.Contains(text, "TRSTCTL_COMMAND_REFUSED") || len(after) != before ||
			len(observations) != 1 || !strings.Contains(strings.Join(observations[0], ","), "TRUNCATE") {
			t.Errorf("%s: status %d, body %s, forwarded %d new requests, reviews %v; want a blocked TRUNCATE review", attack.name, status, text, len(after)-before, observations)
		}
	}
	// ClickHouse treats QUERY as a setting, not the lowercase query parameter.
	// The gateway sends this ambiguous control request to its reviewer.
	before := len(forwarded())
	status, text := send("/?QUERY=TRUNCATE%20TABLE%20victim", "")
	reviewer.mu.Lock()
	var last []string
	if len(reviewer.seen) > 0 {
		last = append(last, reviewer.seen[len(reviewer.seen)-1]...)
	}
	reviewer.mu.Unlock()
	if status != http.StatusForbidden || !strings.Contains(text, "TRSTCTL_COMMAND_REFUSED") || len(forwarded()) != before || len(last) == 0 || last[0] != "control" {
		t.Errorf("QUERY setting: status %d, body %s, forwarded %d new requests, last review %v; want blocked control review", status, text, len(forwarded())-before, last)
	}
}
