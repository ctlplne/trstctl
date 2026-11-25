// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/config"
)

func TestCR024ServedAuditAppendFailuresAreVisibleWithoutTenantLabels(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	before := auditsink.DroppedEvents()
	const tenant = "99999999-9999-4999-8999-999999999999"
	err := auditsink.Emit(context.Background(), auditsink.AuditorFunc(func(context.Context, string, string, []byte) error {
		return errors.New("injected event-log append failure")
	}), nil, "transit.sign", tenant, []byte(`{"key":"fixture"}`))
	if err == nil || auditsink.DroppedEvents() != before+1 {
		t.Fatalf("audit failure was not counted: error=%v count=%d", err, auditsink.DroppedEvents())
	}
	resp, err := h.ts.Client().Get(h.ts.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("metrics response: status=%d err=%v", resp.StatusCode, err)
	}
	text := string(body)
	want := fmt.Sprintf("trstctl_audit_append_failures_total %d", before+1)
	if !strings.Contains(text, want) {
		t.Errorf("/metrics did not expose failed audit appends: want %q", want)
	}
	if strings.Contains(text, tenant) {
		t.Error("unauthenticated /metrics exposed the affected tenant ID")
	}
}
