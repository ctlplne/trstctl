// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"trstctl.com/trstctl/internal/netsec"
)

func TestRelayHTTPClientTrustsOnlyExplicitPrivateCA(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	caPath := filepath.Join(t.TempDir(), "appliance-ca.pem")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(caPath, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	defaultClient, err := relayHTTPClient("", nil)
	if err != nil {
		t.Fatal(err)
	}
	if response, err := defaultClient.Get(server.URL); err == nil {
		if err := response.Body.Close(); err != nil {
			t.Fatal(err)
		}
		t.Fatal("relay trusted a private appliance without an operator CA")
	}

	privateClient, err := relayHTTPClient(caPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := privateClient.Get(server.URL)
	if err != nil {
		t.Fatalf("operator CA did not authenticate private appliance: %v", err)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", response.StatusCode)
	}
	if privateClient.Transport == nil {
		t.Fatal("relay did not install an explicit transport")
	}

	badPath := filepath.Join(t.TempDir(), "invalid.pem")
	if err := os.WriteFile(badPath, []byte("not a CA"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := relayHTTPClient(badPath, nil); err == nil {
		t.Fatal("invalid operator CA was accepted")
	}
	args := serviceArguments(agentOptions{relayClaim: true, relayCABundle: caPath, relayEgressAllow: "10.20.0.0/16,127.0.0.1"})
	found, egressKept := false, false
	for index := 0; index+1 < len(args); index++ {
		if args[index] == "--relay-ca-bundle" && args[index+1] == caPath {
			found = true
		}
		if args[index] == "--relay-egress-allow" && args[index+1] == "10.20.0.0/16,127.0.0.1" {
			egressKept = true
		}
	}
	if !found {
		t.Fatal("Windows service restart would lose appliance CA trust")
	}
	if !egressKept {
		t.Fatal("Windows service restart would lose the relay egress allowlist")
	}
}

// A190: the relay's appliance client follows the agent's egress policy, with
// or without an operator CA bundle: instance metadata is never requested, an
// unlisted appliance is refused before anything is sent, a listed one works.
func TestRelayHTTPClientFollowsTheEgressPolicy(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	caPath := filepath.Join(t.TempDir(), "appliance-ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	elsewhere, err := netsec.ParseRelayEgress([]string{"10.20.0.0/16"})
	if err != nil {
		t.Fatal(err)
	}
	listed, err := netsec.ParseRelayEgress([]string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	for _, bundle := range []string{"", caPath} {
		refusing, err := relayHTTPClient(bundle, elsewhere)
		if err != nil {
			t.Fatal(err)
		}
		for _, target := range []string{"http://169.254.169.254/latest/meta-data/", server.URL} {
			if _, err := refusing.Get(target); !errors.Is(err, netsec.ErrRelayEgressBlocked) {
				t.Fatalf("bundle %q: request to %s = %v, want refused by the egress policy", bundle, target, err)
			}
		}
	}
	allowed, err := relayHTTPClient(caPath, listed)
	if err != nil {
		t.Fatal(err)
	}
	response, err := allowed.Get(server.URL)
	if err != nil {
		t.Fatalf("a listed appliance was refused: %v", err)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := netsec.ParseRelayEgress([]string{"appliance.example.test"}); err == nil {
		t.Fatal("a host name was accepted as an egress allowlist entry")
	}
}

func TestRelayHTTPClientNeverFollowsCredentialRedirects(t *testing.T) {
	redirected := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		redirected = true
		w.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	client, err := relayHTTPClient("", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Get(source.URL)
	if err != nil {
		t.Fatal(err)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusTemporaryRedirect || redirected {
		t.Fatalf("redirect status=%d followed=%t", response.StatusCode, redirected)
	}
}
