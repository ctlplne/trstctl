// SPDX-License-Identifier: BUSL-1.1

package relay

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/connector"
)

func networkPQCIntent(t *testing.T, endpoint, verify string) PQCPostureIntent {
	t.Helper()
	config, err := json.Marshal(map[string]string{"endpoint": endpoint, "secret_name": "edge-secret", "vantage": "network"})
	if err != nil {
		t.Fatal(err)
	}
	return PQCPostureIntent{RunID: "run-n", AssetID: "finding-n", FindingKind: "protocol", TargetID: "target-n",
		TargetRevision: "revision-n", Target: "edge-listener", Connector: "envoy", TargetConfig: config,
		Desired:         connector.TLSPosture{MinimumVersion: "TLSv1.3", KeyExchangeGroups: []string{"X25519MLKEM768", "X25519"}},
		RequiredAgentID: "relay-1", VerifyAddress: verify, VerifyServerName: "edge.example.test", Vantage: "network"}
}

// A104: a network relay drives a remote Envoy, so a network intent's
// management origin and listener need not be loopback. Everything that could
// move the connector off the reviewed resource is still refused, the intent
// must match the executor the target declares, and host intents keep the
// loopback rule.
func TestNetworkPQCPostureIntentAcceptsARemoteEnvoyOnly(t *testing.T) {
	remote := networkPQCIntent(t, "http://192.0.2.10:19080", "192.0.2.10:11444")
	if err := ValidatePQCPostureIntent(remote); err != nil {
		t.Fatalf("remote Envoy network intent refused: %v", err)
	}
	if err := ValidatePQCPostureIntent(networkPQCIntent(t, "https://envoy-mgmt.example.test:9443", "edge.example.test:443")); err != nil {
		t.Fatalf("named remote Envoy network intent refused: %v", err)
	}
	for _, endpoint := range []string{
		"http://user:pass@192.0.2.10:19080", "http://192.0.2.10:19080/other", "http://192.0.2.10:19080?next=evil",
		"http://192.0.2.10:19080#fragment", "http://192.0.2.10", "ftp://192.0.2.10:19080", "http://192.0.2.10:0",
	} {
		if err := ValidatePQCPostureIntent(networkPQCIntent(t, endpoint, "192.0.2.10:11444")); err == nil {
			t.Errorf("network intent accepted management origin %q", endpoint)
		}
	}
	if err := ValidatePQCPostureIntent(networkPQCIntent(t, "http://192.0.2.10:19080", "192.0.2.10")); err == nil {
		t.Error("network intent accepted a listener without a port")
	}
	noSNI := remote
	noSNI.VerifyServerName = ""
	if err := ValidatePQCPostureIntent(noSNI); err == nil {
		t.Error("network intent accepted a listener without a server name")
	}
	undeclared := remote
	undeclared.TargetConfig = json.RawMessage(`{"endpoint":"http://192.0.2.10:19080","secret_name":"edge-secret"}`)
	if err := ValidatePQCPostureIntent(undeclared); err == nil || !strings.Contains(err.Error(), "declared executor") {
		t.Errorf("network intent for a target that does not declare vantage network = %v", err)
	}
	hostForDeclared := remote
	hostForDeclared.Vantage, hostForDeclared.VerifyAddress = "", "127.0.0.1:11444"
	hostForDeclared.TargetConfig = json.RawMessage(`{"endpoint":"http://127.0.0.1:19080","secret_name":"edge-secret","vantage":"network"}`)
	if err := ValidatePQCPostureIntent(hostForDeclared); err == nil || !strings.Contains(err.Error(), "declared executor") {
		t.Errorf("host intent for a target that declares vantage network = %v", err)
	}
	unknown := remote
	unknown.Vantage = "edge"
	if err := ValidatePQCPostureIntent(unknown); err == nil {
		t.Error("intent naming an unknown vantage accepted")
	}
	host := remote
	host.Vantage = ""
	host.TargetConfig = json.RawMessage(`{"endpoint":"http://192.0.2.10:19080","secret_name":"edge-secret"}`)
	if err := ValidatePQCPostureIntent(host); err == nil {
		t.Error("host intent accepted a non-loopback listener and management origin")
	}
}

// The relay executes a network intent the way a host executes its own: the
// predecessor is sealed in the relay's store before the change, the readback
// carries a TLS 1.3 hybrid handshake taken from the relay, and a cold rollback
// restores the exact predecessor from that store.
func TestNetworkPQCPostureAppliesAndRollsBackFromTheRelay(t *testing.T) {
	previous := connector.TLSPosture{MinimumVersion: "TLSv1.0", CipherSuites: []string{"TLS_RSA_WITH_3DES_EDE_CBC_SHA", "TLS_AES_256_GCM_SHA384"}, KeyExchangeGroups: []string{"X25519", "P-256"}}
	current := previous
	var mu sync.Mutex
	management := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/tls-posture/edge-listener" {
			http.NotFound(w, r)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		switch r.Method {
		case http.MethodGet:
			_ = json.NewEncoder(w).Encode(current)
		case http.MethodPut:
			if err := json.NewDecoder(r.Body).Decode(&current); err != nil {
				http.Error(w, "bad posture", http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "method", http.StatusMethodNotAllowed)
		}
	}))
	defer management.Close()
	listener := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer listener.Close()
	intent := networkPQCIntent(t, management.URL, listener.Listener.Addr().String())
	root := filepath.Join(t.TempDir(), "relay-rollbacks")
	store, err := NewHostRollbackStore(root, "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executeHostPQCPosture(context.Background(), intent, KindPQCPosture, nil, management.Client(), ""); err == nil ||
		!strings.Contains(err.Error(), "--host-rollback-dir") {
		t.Fatalf("a relay without its predecessor store = %v; want a refusal naming --host-rollback-dir", err)
	}
	applied, err := executeHostPQCPosture(context.Background(), intent, KindPQCPosture, store, management.Client(), "")
	if err != nil || !connector.EqualTLSPosture(current, intent.Desired) {
		t.Fatalf("apply = %+v, %v; current = %+v", applied, err, current)
	}
	if err := ValidatePQCPostureReport(intent, applied, applied.Digest(), KindPQCPosture); err != nil {
		t.Fatal(err)
	}
	if applied.Served.Address != intent.VerifyAddress || applied.Served.KeyExchangeGroup != "X25519MLKEM768" || applied.Served.LeafFingerprint == "" {
		t.Fatalf("served handshake from the relay is incomplete: %+v", applied.Served)
	}
	restarted, err := NewHostRollbackStore(root, "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	rolled, err := executeHostPQCPosture(context.Background(), intent, KindPQCPostureRollback, restarted, management.Client(), "")
	if err != nil || !connector.EqualTLSPosture(current, previous) {
		t.Fatalf("rollback = %+v, %v; current = %+v", rolled, err, current)
	}
	if err := ValidatePQCPostureReport(intent, rolled, rolled.Digest(), KindPQCPostureRollback); err != nil {
		t.Fatal(err)
	}
}
