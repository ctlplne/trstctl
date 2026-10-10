// SPDX-License-Identifier: BUSL-1.1

package relay

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/connector"
)

func TestHostPQCPostureApplySignedReadbackAndExactColdRollback(t *testing.T) {
	previous := connector.TLSPosture{MinimumVersion: "TLSv1.0", CipherSuites: []string{"TLS_RSA_WITH_3DES_EDE_CBC_SHA", "TLS_AES_256_GCM_SHA384"}, KeyExchangeGroups: []string{"X25519", "P-256"}}
	desired := connector.TLSPosture{MinimumVersion: "TLSv1.3", KeyExchangeGroups: []string{"X25519MLKEM768", "X25519"}}
	current := previous
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	defer server.Close()
	listener := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer listener.Close()
	config, err := json.Marshal(HostTargetConfig{Endpoint: server.URL, SecretName: "edge-secret"})
	if err != nil {
		t.Fatal(err)
	}
	intent := PQCPostureIntent{RunID: "run-1", AssetID: "finding-1", FindingKind: "protocol", TargetID: "target-1", TargetRevision: "revision-1", Target: "edge-listener", Connector: "envoy", TargetConfig: config, Desired: desired, RequiredAgentID: "host-1", VerifyAddress: listener.Listener.Addr().String(), VerifyServerName: "edge.example.test"}
	root := filepath.Join(t.TempDir(), "host-rollbacks")
	store, err := NewHostRollbackStore(root, "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	applied, err := executeHostPQCPosture(context.Background(), intent, KindPQCPosture, store, server.Client(), "")
	if err != nil || !connector.EqualTLSPosture(current, desired) {
		t.Fatalf("apply = %+v, %v; current = %+v", applied, err, current)
	}
	if err := ValidatePQCPostureReport(intent, applied, applied.Digest(), KindPQCPosture); err != nil {
		t.Fatal(err)
	}
	if err := ValidatePQCPostureReport(intent, applied, "wrong digest", KindPQCPosture); err == nil {
		t.Fatal("changed report digest accepted")
	}
	if applied.Served.TLSVersion == 0 || applied.Served.KeyExchangeGroup != "X25519MLKEM768" || applied.Served.LeafFingerprint == "" {
		t.Fatalf("served handshake is incomplete: %+v", applied.Served)
	}
	restarted, err := NewHostRollbackStore(root, "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	rolled, err := executeHostPQCPosture(context.Background(), intent, KindPQCPostureRollback, restarted, server.Client(), "")
	if err != nil || !connector.EqualTLSPosture(current, previous) {
		t.Fatalf("rollback = %+v, %v; current = %+v", rolled, err, current)
	}
	if err := ValidatePQCPostureReport(intent, rolled, rolled.Digest(), KindPQCPostureRollback); err != nil {
		t.Fatal(err)
	}
	if err := restarted.PreparePosture("run-2", "target-1", "revision-2", previous, desired); err != nil {
		t.Fatalf("after verified rollback a new run should be possible: %v", err)
	}
}

func TestPQCPostureManagementOriginRefusesDNSPathsAndRedirects(t *testing.T) {
	for _, endpoint := range []string{
		"http://localhost:19080", "http://127.0.0.1:19080/other",
		"http://127.0.0.1:19080?next=evil", "http://127.0.0.1:19080#fragment",
		"http://127.0.0.1:0", "http://192.0.2.1:19080",
	} {
		if err := validatePQCEnvoyEndpoint(endpoint); err == nil {
			t.Errorf("accepted unbound management origin %q", endpoint)
		}
	}
	redirected := false
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		redirected = true
		w.WriteHeader(http.StatusOK)
	}))
	defer evil.Close()
	managementRead := false
	management := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		managementRead = true
		http.Redirect(w, r, evil.URL, http.StatusTemporaryRedirect)
	}))
	defer management.Close()
	intent := PQCPostureIntent{TargetConfig: json.RawMessage(`{"endpoint":"` + management.URL + `","secret_name":"edge"}`)}
	registry, err := hostPQCPostureRegistry(intent, management.Client())
	if err != nil {
		t.Fatal(err)
	}
	_, err = registry.ReadTLSPosture(context.Background(), connector.TLSPostureMutation{
		RunID: "run-1", FindingID: "asset-1", TargetID: "target-1", TargetRevision: "revision-1",
		Target: "edge", Connector: "envoy", TenantID: "tenant-a",
	})
	if err == nil || redirected || !managementRead {
		t.Fatalf("redirect accepted or test did not reach receiver: err=%v read=%v redirected=%v", err, managementRead, redirected)
	}
}
