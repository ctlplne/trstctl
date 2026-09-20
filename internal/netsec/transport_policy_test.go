// SPDX-License-Identifier: BUSL-1.1

package netsec

import (
	"context"
	"errors"
	"net/http"
	"testing"
)

func TestValidateHTTPSOrInsecureLoopbackURL(t *testing.T) {
	tests := []struct {
		name  string
		raw   string
		allow bool
		ok    bool
	}{
		{name: "production HTTPS", raw: "https://kms.example.com/v1", ok: true},
		{name: "public HTTP", raw: "http://kms.example.com/v1", allow: true},
		{name: "private HTTP", raw: "http://10.1.2.3/v1", allow: true},
		{name: "loopback requires opt in", raw: "http://127.0.0.1:8080/v1"},
		{name: "IPv4 loopback", raw: "http://127.9.8.7:8080/v1", allow: true, ok: true},
		{name: "IPv6 loopback", raw: "http://[::1]:8080/v1", allow: true, ok: true},
		{name: "localhost", raw: "http://localhost:8080/v1", allow: true, ok: true},
		{name: "localhost suffix", raw: "http://api.localhost:8080/v1", allow: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateHTTPSOrInsecureLoopbackURL(tt.raw, tt.allow)
			if (err == nil) != tt.ok {
				t.Fatalf("ValidateHTTPSOrInsecureLoopbackURL(%q, %v) = %v, want ok=%v", tt.raw, tt.allow, err, tt.ok)
			}
			if err != nil && !errors.Is(err, ErrSSRFBlocked) {
				t.Fatalf("error = %v, want ErrSSRFBlocked", err)
			}
		})
	}
}

func TestInsecureLoopbackDialerRejectsNonLoopbackBeforeConnecting(t *testing.T) {
	if _, err := dialLoopbackContext(context.Background(), "tcp", "10.1.2.3:8080"); !errors.Is(err, ErrSSRFBlocked) {
		t.Fatalf("private-network dial error = %v, want ErrSSRFBlocked", err)
	}
	if _, err := dialLoopbackContext(context.Background(), "tcp", "127.0.0.1:0"); errors.Is(err, ErrSSRFBlocked) {
		t.Fatalf("literal loopback was rejected by policy: %v", err)
	}
}

func TestInsecureLoopbackClientRejectsRedirectEscape(t *testing.T) {
	client := InsecureLoopbackClient(0)
	origin, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1:8080/start", nil)
	for _, target := range []string{
		"http://10.1.2.3:8080/private",
		"http://127.0.0.1:8081/other-origin",
		"https://public.example.test/escape",
	} {
		redirect, _ := http.NewRequest(http.MethodGet, target, nil)
		if err := client.CheckRedirect(redirect, []*http.Request{origin}); !errors.Is(err, ErrSSRFBlocked) {
			t.Fatalf("redirect to %q error = %v, want ErrSSRFBlocked", target, err)
		}
	}
}
