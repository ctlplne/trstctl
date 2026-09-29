// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/orchestrator"
)

// RV23-14: /metrics is served without authentication on the API listener, which
// relying parties and (in a Provider deployment) every customer tenant can reach.
// It must not name tenants: a dead-lettered delivery shows up by destination, and
// the per-tenant detail stays behind the authenticated, tenant-scoped API.
func TestServedMetricsNameNoTenants(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	ctx := context.Background()
	ob := orchestrator.NewOutbox(h.store,
		orchestrator.WithMaxAttempts(1),
		orchestrator.WithBackoff(func(int) time.Duration { return 0 }),
	)
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		_, err := ob.Enqueue(ctx, tx, orchestrator.Entry{
			TenantID: h.tenant, Destination: "webhook.rv23-14", IdempotencyKey: "rv23-14-dead-letter", Payload: []byte(`{}`),
		})
		return err
	}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if _, err := ob.Dispatch(ctx, orchestrator.HandlerFunc(func(context.Context, orchestrator.Message) error {
		return errors.New("permanent downstream failure")
	})); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if err := h.srv.sampleOutboxDeadLetterDepth(ctx); err != nil {
		t.Fatalf("sample dead-letter depth: %v", err)
	}
	resp, err := http.Get(h.ts.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /metrics = %d", resp.StatusCode)
	}
	text := string(body)
	if !strings.Contains(text, `trstctl_outbox_deadletter_depth{destination="webhook.rv23-14"} 1`) {
		t.Errorf("dead-letter gauge does not report the failed destination:\n%s", grepLines(text, "trstctl_outbox_deadletter_depth"))
	}
	if strings.Contains(text, h.tenant) {
		t.Errorf("unauthenticated /metrics names tenant %s:\n%s", h.tenant, grepLines(text, h.tenant))
	}
}

func grepLines(text, needle string) string {
	var out []string
	for _, line := range strings.Split(text, "\n") {
		if strings.Contains(line, needle) {
			out = append(out, line)
		}
	}
	return strings.Join(out, "\n")
}
