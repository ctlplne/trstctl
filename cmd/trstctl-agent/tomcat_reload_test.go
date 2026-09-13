// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTomcatReloadRequiresExactAcknowledgementAndNeverFollowsRedirects(t *testing.T) {
	passwordFile := filepath.Join(t.TempDir(), "manager-password")
	if err := os.WriteFile(passwordFile, []byte("qa-only-password\n"), 0600); err != nil {
		t.Fatal(err)
	}
	redirectCalls := 0
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirectCalls++ }))
	defer other.Close()
	for _, tc := range []struct {
		name, body string
		status     int
		ok         bool
	}{
		{"ack", "OK - Reloaded TLS configuration for [_default_]\n", 200, true},
		{"failure text", "FAIL - unknown TLS host", 200, false},
		{"wrong host", "OK - Reloaded TLS configuration for [different]", 200, false},
		{"empty", "", 200, false},
		{"unauthorized", "credentials-reflected-in-error", 401, false},
		{"redirect", "", 302, false},
		{"oversized", strings.Repeat("x", 4097), 200, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				user, password, ok := r.BasicAuth()
				if !ok || user != "manager" || password != "qa-only-password" || r.URL.Path != "/manager/text/sslReload" || r.URL.Query().Get("tlsHostName") != "_default_" || r.Method != "GET" {
					t.Error("wrong bounded Manager request")
				}
				if tc.status == 302 {
					w.Header().Set("Location", other.URL)
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			handled, err := runTomcatReload(context.Background(), tomcatReloadOptions{url: srv.URL + "/manager/text/sslReload", user: "manager", passwordFile: passwordFile, tlsHost: "_default_"})
			if !handled || (err == nil) != tc.ok || calls != 1 {
				t.Fatalf("handled=%v err=%v calls=%d", handled, err, calls)
			}
			if err != nil && strings.Contains(err.Error(), "credentials-reflected") {
				t.Fatal("Manager response leaked into error")
			}
		})
	}
	if redirectCalls != 0 {
		t.Fatal("authorization request followed a redirect")
	}
}

func TestTomcatReloadRefusesNonlocalTargetsAndUnsafePasswordCustody(t *testing.T) {
	for _, target := range []string{"http://example.com/manager/text/sslReload", "http://localhost/manager/text/sslReload", "http://10.0.0.1/manager/text/sslReload", "http://u:p@127.0.0.1/manager/text/sslReload", "http://127.0.0.1/manager/text/sslReload?tlsHostName=other", "http://127.0.0.1/manager/text/stop"} {
		if handled, err := runTomcatReload(context.Background(), tomcatReloadOptions{url: target, user: "manager", passwordFile: "/missing", tlsHost: "_default_"}); !handled || err == nil {
			t.Fatal("unsafe Manager URL accepted")
		}
	}
	if handled, err := runTomcatReload(context.Background(), tomcatReloadOptions{}); handled || err != nil {
		t.Fatal("default agent invocation tried to reload Tomcat")
	}
	passwordFile := filepath.Join(t.TempDir(), "unsafe-password")
	if err := os.WriteFile(passwordFile, []byte("qa-only-password"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(passwordFile, 0644); err != nil {
		t.Fatal(err)
	} // #nosec G302 -- deliberately public disposable password fixture must be rejected before any request (CWE-276).
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls++ }))
	defer srv.Close()
	_, err := runTomcatReload(context.Background(), tomcatReloadOptions{url: srv.URL + "/manager/text/sslReload", user: "manager", passwordFile: passwordFile, tlsHost: "_default_"})
	if err == nil || calls != 0 {
		t.Fatal("unsafe password file reached the network")
	}
}
