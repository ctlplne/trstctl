// SPDX-License-Identifier: BUSL-1.1

package accessgateway

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/agent/relay"
)

func TestCR037CommandRuledClickHouseChecksOriginBeforeReviewAndForward(t *testing.T) {
	var forwarded atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded.Add(1)
		_, _ = io.WriteString(w, "1\n")
	}))
	defer upstream.Close()
	policy, digest := gatewayBlockPolicy(t, "clickhouse", []string{"DROP"})
	reviewer := &blockingReviewer{protocol: "clickhouse", sessionID: uuid.NewString(), digest: digest}
	guard := &commandConnection{gateway: &Gateway{cfg: Config{Logf: t.Logf}}, sessionID: reviewer.sessionID, target: "ch-cr037", protocol: "clickhouse", connectionID: uuid.NewString(),
		policyDigest: digest, job: relay.Job{JobID: 47, Attempt: 1}, policy: policy, reviewer: reviewer, expiresAt: time.Now().Add(time.Minute)}
	capability := localTunnelCapability("clickhouse-rule-ticket")
	client, server := net.Pipe()
	done := make(chan error, 1)
	go func() {
		done <- serveClickHouse(context.Background(), server, []byte(`{"username":"fixture","password":"fixture"}`), httpUpstream{URL: upstream.URL, TunnelCapability: capability}, nil, nil, guard)
	}()
	defer func() { _ = client.Close(); <-done }()
	reader := bufio.NewReader(client)
	send := func(origin string) int {
		t.Helper()
		_ = client.SetDeadline(time.Now().Add(10 * time.Second))
		req, err := http.NewRequest(http.MethodPost, "http://127.0.0.1:18080/", strings.NewReader("SELECT 1"))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("X-Trstctl-Tunnel-Token", capability)
		if origin != "" {
			req.Header.Set("Origin", origin)
			req.Header.Set("Sec-Fetch-Site", "cross-site")
		}
		if err := req.Write(client); err != nil {
			t.Fatal(err)
		}
		resp, err := http.ReadResponse(reader, req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	if status := send(""); status != http.StatusOK || forwarded.Load() != 1 {
		t.Fatalf("same-origin capability control: status %d forwarded %d", status, forwarded.Load())
	}
	if status := send("https://attacker.example"); status != http.StatusForbidden || forwarded.Load() != 1 {
		t.Fatalf("foreign-origin command-rule request: status %d forwarded %d", status, forwarded.Load())
	}
	reviewer.mu.Lock()
	defer reviewer.mu.Unlock()
	if len(reviewer.seen) != 0 {
		t.Fatalf("foreign-origin request reached the policy reviewer: %v", reviewer.seen)
	}
}
