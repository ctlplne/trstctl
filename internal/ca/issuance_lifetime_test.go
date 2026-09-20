// SPDX-License-Identifier: BUSL-1.1

package ca

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// An external authority decides the lifetime of what it issues. When that
// lifetime is shorter than the expiry alert window the operator gets an alert
// within a minute and no explanation; the WARN is the explanation (DP2-032).
func TestLifetimeWarningNamesTheTenantWhenTheCAIssuedInsideTheAlertWindow(t *testing.T) {
	var buf bytes.Buffer
	svc := &IssuanceService{outboxAuthorityID: "local-pebble"}
	WithLifetimeWarning(slog.New(slog.NewTextHandler(&buf, nil)), 14*24*time.Hour)(svc)

	svc.observeLifetime("tenant-a", Certificate{NotAfter: time.Now().Add(6 * 24 * time.Hour)})
	if out := buf.String(); !strings.Contains(out, "level=WARN") || !strings.Contains(out, "tenant_id=tenant-a") ||
		!strings.Contains(out, "authority_id=local-pebble") || !strings.Contains(out, "finding=DP2-032") {
		t.Fatalf("six-day certificate against a fourteen-day window logged %q, want a WARN naming tenant and authority", out)
	}

	buf.Reset()
	svc.observeLifetime("tenant-a", Certificate{NotAfter: time.Now().Add(90 * 24 * time.Hour)})
	if buf.Len() != 0 {
		t.Fatalf("ninety-day certificate logged %q, want nothing", buf.String())
	}

	// Disabled configurations must stay silent: nil logger, zero window, no expiry.
	quiet := &IssuanceService{}
	quiet.observeLifetime("tenant-a", Certificate{NotAfter: time.Now().Add(time.Hour)})
	WithLifetimeWarning(slog.New(slog.NewTextHandler(&buf, nil)), 0)(quiet)
	quiet.observeLifetime("tenant-a", Certificate{NotAfter: time.Now().Add(time.Hour)})
	WithLifetimeWarning(slog.New(slog.NewTextHandler(&buf, nil)), time.Hour)(quiet)
	quiet.observeLifetime("tenant-a", Certificate{})
	if buf.Len() != 0 {
		t.Fatalf("disabled configurations logged %q", buf.String())
	}
}
