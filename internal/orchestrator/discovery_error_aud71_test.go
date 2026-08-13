// SPDX-License-Identifier: MPL-2.0

package orchestrator

import (
	"strings"
	"testing"
)

func TestSanitizeDiscoveryRunErrorAUD71(t *testing.T) {
	t.Parallel()
	secret := "trst_" + strings.Repeat("s", 64)
	raw := "  ctmonitor: GET /ct/v1/get-sth: 404 Not Found; Authorization: Bearer " + secret + "\r\n" + strings.Repeat("x", 4096)

	got := sanitizeDiscoveryRunError(raw)
	if !strings.Contains(got, "404 Not Found") {
		t.Fatalf("safe diagnostic disappeared: %q", got)
	}
	if strings.Contains(got, secret) || strings.Contains(got, "\r") || strings.Contains(got, "\n") {
		t.Fatalf("secret or control character escaped into durable discovery error: %q", got)
	}
	if len([]byte(got)) > maxDiscoveryRunErrorBytes {
		t.Fatalf("durable discovery error has %d bytes, want <= %d", len([]byte(got)), maxDiscoveryRunErrorBytes)
	}
}

func TestSanitizeDiscoveryRunErrorAUD71RedactsHighEntropy(t *testing.T) {
	t.Parallel()
	got := sanitizeDiscoveryRunError("upstream echoed " + strings.Repeat("A", 80))
	if !strings.Contains(got, "[REDACTED]") || strings.Contains(got, strings.Repeat("A", 24)) {
		t.Fatalf("high-entropy detail was not safely redacted: %q", got)
	}
}
