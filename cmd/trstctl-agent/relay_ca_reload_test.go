// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/mtls"
)

// A86: a change to --relay-ca-bundle takes effect without a relay restart.
// The relay re-reads the file when it changes, trusts the new bundle on the
// next request, keeps the previous bundle when the replacement is unusable,
// and reports the bundle it is actually using (digest, load time, last error)
// in its executor census so the console shows the truth rather than the file.

func relayTestHTTPSServer(t *testing.T) (url string, trustPEM []byte) {
	t.Helper()
	cert, err := mtls.SelfSignedServerCert([]string{"127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = cert.ServeHTTPS(srv, ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return "https://" + ln.Addr().String(), cert.TrustPEM
}

func TestRelayCABundleReloadsWithoutRestartA86(t *testing.T) {
	firstURL, firstPEM := relayTestHTTPSServer(t)
	secondURL, secondPEM := relayTestHTTPSServer(t)
	bundle := filepath.Join(t.TempDir(), "appliance-ca.pem")
	if err := os.WriteFile(bundle, firstPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	client, err := relayHTTPClient(bundle)
	if err != nil {
		t.Fatal(err)
	}
	reloading, ok := client.Transport.(*relayCATransport)
	if !ok {
		t.Fatalf("relay transport is %T, want the reloading CA transport", client.Transport)
	}
	reloading.checkEvery = 0 // every request looks at the file; production waits a few seconds between looks

	get := func(url string) error {
		resp, err := client.Get(url)
		if err != nil {
			return err
		}
		_ = resp.Body.Close()
		return nil
	}
	if err := get(firstURL); err != nil {
		t.Fatalf("first bundle did not trust the first appliance: %v", err)
	}
	if err := get(secondURL); err == nil {
		t.Fatal("first bundle trusted the second appliance")
	}
	before := reloading.Status()
	if before == nil || before.SHA256 == "" || before.LoadedAt.IsZero() || before.Error != "" {
		t.Fatalf("initial bundle status = %+v, want a digest, a load time and no error", before)
	}

	// The operator replaces the file: the next request trusts the new CA and
	// no longer the old one, with no restart.
	time.Sleep(20 * time.Millisecond) // a distinct mtime on coarse filesystems
	if err := os.WriteFile(bundle, secondPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := get(secondURL); err != nil {
		t.Fatalf("replaced bundle did not take effect without a restart: %v", err)
	}
	if err := get(firstURL); err == nil {
		t.Fatal("the replaced bundle still trusted the old appliance CA")
	}
	after := reloading.Status()
	if after.SHA256 == before.SHA256 || !after.LoadedAt.After(before.LoadedAt) || after.Error != "" {
		t.Fatalf("status after replacement = %+v (before %+v), want a new digest and load time", after, before)
	}

	// A broken replacement keeps the bundle that worked and says so.
	time.Sleep(20 * time.Millisecond)
	if err := os.WriteFile(bundle, []byte("not a CA"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := get(secondURL); err != nil {
		t.Fatalf("an unusable replacement broke the working trust: %v", err)
	}
	broken := reloading.Status()
	if broken.SHA256 != after.SHA256 || broken.Error == "" || !strings.Contains(broken.Error, "CA") {
		t.Fatalf("status after a broken replacement = %+v, want the previous digest and an error naming the bundle", broken)
	}

	// The census carries the same facts, so the console shows the bundle in
	// use and the operator's last mistake.
	report := executorCensus(agentOptions{relayClaim: true, relayCABundle: bundle}, reloading.Status)
	if report.RelayCABundle == nil || report.RelayCABundle.SHA256 != after.SHA256 || report.RelayCABundle.Error == "" {
		t.Fatalf("census relay_ca_bundle = %+v, want the transport's status", report.RelayCABundle)
	}
	if plain := executorCensus(agentOptions{}, nil); plain.RelayCABundle != nil {
		t.Fatalf("an agent without a relay bundle reported one: %+v", plain.RelayCABundle)
	}
}
