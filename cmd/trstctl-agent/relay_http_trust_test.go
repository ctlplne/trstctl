// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
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

	defaultClient, err := relayHTTPClient("")
	if err != nil {
		t.Fatal(err)
	}
	if response, err := defaultClient.Get(server.URL); err == nil {
		if err := response.Body.Close(); err != nil {
			t.Fatal(err)
		}
		t.Fatal("relay trusted a private appliance without an operator CA")
	}

	privateClient, err := relayHTTPClient(caPath)
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
	if _, err := relayHTTPClient(badPath); err == nil {
		t.Fatal("invalid operator CA was accepted")
	}
	args := serviceArguments(agentOptions{relayClaim: true, relayCABundle: caPath})
	found := false
	for index := 0; index+1 < len(args); index++ {
		if args[index] == "--relay-ca-bundle" && args[index+1] == caPath {
			found = true
		}
	}
	if !found {
		t.Fatal("Windows service restart would lose appliance CA trust")
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
	client, err := relayHTTPClient("")
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
