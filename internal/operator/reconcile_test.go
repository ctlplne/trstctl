package operator

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestDecideActionDiff pins the pure desired-vs-actual diff at the heart of the
// reconcile (OPS-004): the controller must CREATE when no Deployment exists,
// UPDATE when the live replicas or image drift from the spec, and do NOTHING
// when they already match. This is the decision a real controller makes; pinning
// it here proves the operator is a genuine reconcile, not a stub.
func TestDecideActionDiff(t *testing.T) {
	spec := ControlPlaneSpec{Replicas: 3, Image: "ghcr.io/ctlplne/trstctl:v1.2.3"}

	cases := []struct {
		name string
		live deploymentState
		want Action
	}{
		{"missing deployment -> create", deploymentState{exists: false}, ActionCreate},
		{"replica drift -> update", deploymentState{exists: true, replicas: 1, image: "ghcr.io/ctlplne/trstctl:v1.2.3"}, ActionUpdate},
		{"image drift -> update", deploymentState{exists: true, replicas: 3, image: "ghcr.io/ctlplne/trstctl:OLD"}, ActionUpdate},
		{"in sync -> none", deploymentState{exists: true, replicas: 3, image: "ghcr.io/ctlplne/trstctl:v1.2.3", configHash: spec.desiredConfigHash()}, ActionNone},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := decideAction(spec, tc.live); got != tc.want {
				t.Errorf("decideAction(%+v) = %q, want %q", tc.live, got, tc.want)
			}
		})
	}
}

// fakeCluster is an in-memory Kubernetes API server scoped to the verbs the
// operator uses: it serves a TrstctlControlPlane list and a Deployment GET, and
// records the operator's Deployment create/patch and the CR status patch so the
// test can assert what the controller actually DID over the wire.
type fakeCluster struct {
	mu sync.Mutex

	// tcps is the TrstctlControlPlane list the operator reconciles.
	tcps []map[string]any
	// secretSyncs is the TrstctlSecretSync list the operator reconciles.
	secretSyncs []map[string]any
	// secretInjections is the TrstctlSecretInjection list the operator reconciles.
	secretInjections []map[string]any
	// deployments maps name -> the live Deployment object (nil => 404, i.e. it
	// does not exist yet).
	deployments map[string]map[string]any
	// secrets maps name -> the live Kubernetes Secret object.
	secrets map[string]map[string]any
	// leases maps name -> coordination.k8s.io Lease object for leader election.
	leases map[string]map[string]any

	// Recorded effects:
	created         []map[string]any          // Deployment POST bodies
	patched         map[string][]byte         // Deployment name -> strategic-merge-patch body
	statusSet       map[string]map[string]any // CR name -> status patch
	createdSecrets  []map[string]any          // Secret POST bodies
	patchedSecrets  map[string][]byte         // Secret name -> merge-patch body
	secretStatusSet map[string]map[string]any
	injectStatusSet map[string]map[string]any
	leasePatches    int
}

func newFakeCluster() *fakeCluster {
	return &fakeCluster{
		deployments:     map[string]map[string]any{},
		secrets:         map[string]map[string]any{},
		leases:          map[string]map[string]any{},
		patched:         map[string][]byte{},
		statusSet:       map[string]map[string]any{},
		patchedSecrets:  map[string][]byte{},
		secretStatusSet: map[string]map[string]any{},
		injectStatusSet: map[string]map[string]any{},
	}
}

func (f *fakeCluster) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		path := r.URL.Path
		body, _ := io.ReadAll(r.Body)

		switch {
		// List TrstctlControlPlanes.
		case r.Method == http.MethodGet && strings.HasSuffix(path, "/"+tcpPlural):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"apiVersion": tcpAPIGroupVersion, "kind": "TrstctlControlPlaneList", "items": f.tcps,
			})

		// List TrstctlSecretSyncs.
		case r.Method == http.MethodGet && strings.HasSuffix(path, "/"+tssPlural):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"apiVersion": tcpAPIGroupVersion, "kind": "TrstctlSecretSyncList", "items": f.secretSyncs,
			})

		// List TrstctlSecretInjections.
		case r.Method == http.MethodGet && strings.HasSuffix(path, "/"+tsiPlural):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"apiVersion": tcpAPIGroupVersion, "kind": "TrstctlSecretInjectionList", "items": f.secretInjections,
			})

		// Patch a TrstctlControlPlane status subresource.
		case r.Method == http.MethodPatch && strings.HasSuffix(path, "/status") && strings.Contains(path, "/"+tcpPlural+"/"):
			name := tcpNameFromStatusPath(path)
			var obj map[string]any
			_ = json.Unmarshal(body, &obj)
			st, _ := obj["status"].(map[string]any)
			f.statusSet[name] = st
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(obj)

		// Patch a TrstctlSecretSync status subresource.
		case r.Method == http.MethodPatch && strings.HasSuffix(path, "/status") && strings.Contains(path, "/"+tssPlural+"/"):
			name := tcpNameFromStatusPath(path)
			var obj map[string]any
			_ = json.Unmarshal(body, &obj)
			st, _ := obj["status"].(map[string]any)
			f.secretStatusSet[name] = st
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(obj)

		// Patch a TrstctlSecretInjection status subresource.
		case r.Method == http.MethodPatch && strings.HasSuffix(path, "/status") && strings.Contains(path, "/"+tsiPlural+"/"):
			name := tcpNameFromStatusPath(path)
			var obj map[string]any
			_ = json.Unmarshal(body, &obj)
			st, _ := obj["status"].(map[string]any)
			f.injectStatusSet[name] = st
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(obj)

		// Get a Kubernetes Secret (404 when it does not exist).
		case r.Method == http.MethodGet && strings.Contains(path, "/api/v1/namespaces/") && strings.Contains(path, "/secrets/"):
			name := lastSegment(path)
			obj, ok := f.secrets[name]
			if !ok {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(obj)

		// Create a Kubernetes Secret.
		case r.Method == http.MethodPost && strings.HasSuffix(path, "/secrets"):
			var obj map[string]any
			_ = json.Unmarshal(body, &obj)
			f.createdSecrets = append(f.createdSecrets, obj)
			if meta, _ := obj["metadata"].(map[string]any); meta != nil {
				if name, _ := meta["name"].(string); name != "" {
					f.secrets[name] = obj
				}
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(obj)

		// Patch a Kubernetes Secret.
		case r.Method == http.MethodPatch && strings.Contains(path, "/api/v1/namespaces/") && strings.Contains(path, "/secrets/"):
			name := lastSegment(path)
			f.patchedSecrets[name] = body
			var patch map[string]any
			_ = json.Unmarshal(body, &patch)
			if live, ok := f.secrets[name]; ok {
				mergeMap(live, patch)
			} else {
				f.secrets[name] = patch
			}
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(f.secrets[name])

		// Get a Deployment (404 when it does not exist).
		case r.Method == http.MethodGet && strings.Contains(path, "/deployments/"):
			name := lastSegment(path)
			dep, ok := f.deployments[name]
			if !ok {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(dep)

		// Create a Deployment.
		case r.Method == http.MethodPost && strings.HasSuffix(path, "/deployments"):
			var obj map[string]any
			_ = json.Unmarshal(body, &obj)
			f.created = append(f.created, obj)
			// Make it live for any subsequent GET in the same test.
			if meta, _ := obj["metadata"].(map[string]any); meta != nil {
				if name, _ := meta["name"].(string); name != "" {
					f.deployments[name] = obj
				}
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(obj)

		// Patch a Deployment.
		case r.Method == http.MethodPatch && strings.Contains(path, "/deployments/"):
			name := lastSegment(path)
			f.patched[name] = body
			var patch map[string]any
			_ = json.Unmarshal(body, &patch)
			if live, ok := f.deployments[name]; ok {
				mergeMap(live, patch)
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"metadata":{"name":"` + name + `"}}`))

		// Get a Lease (404 when no operator has acquired it yet).
		case r.Method == http.MethodGet && strings.Contains(path, "/leases/"):
			name := lastSegment(path)
			lease, ok := f.leases[name]
			if !ok {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(lease)

		// Create the leader-election Lease.
		case r.Method == http.MethodPost && strings.HasSuffix(path, "/leases"):
			var obj map[string]any
			_ = json.Unmarshal(body, &obj)
			meta, _ := obj["metadata"].(map[string]any)
			name, _ := meta["name"].(string)
			if name == "" {
				http.Error(w, "missing lease name", http.StatusBadRequest)
				return
			}
			if _, exists := f.leases[name]; exists {
				http.Error(w, "already exists", http.StatusConflict)
				return
			}
			meta["resourceVersion"] = "1"
			f.leases[name] = obj
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(obj)

		// Patch the leader-election Lease.
		case r.Method == http.MethodPatch && strings.Contains(path, "/leases/"):
			name := lastSegment(path)
			lease, ok := f.leases[name]
			if !ok {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			var patch map[string]any
			_ = json.Unmarshal(body, &patch)
			mergeMap(lease, patch)
			if meta, _ := lease["metadata"].(map[string]any); meta != nil {
				f.leasePatches++
				meta["resourceVersion"] = "rv-patched"
			}
			_ = json.NewEncoder(w).Encode(lease)

		default:
			http.Error(w, "unexpected "+r.Method+" "+path, http.StatusNotImplemented)
		}
	})
}

func mergeMap(dst, patch map[string]any) {
	for k, v := range patch {
		pm, pok := v.(map[string]any)
		dm, dok := dst[k].(map[string]any)
		if pok && dok {
			mergeMap(dm, pm)
			continue
		}
		dst[k] = v
	}
}

func tcpNameFromStatusPath(path string) string {
	// .../trstctlcontrolplanes/<name>/status
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) >= 2 {
		return parts[len(parts)-2]
	}
	return ""
}

func lastSegment(path string) string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	return parts[len(parts)-1]
}

func tcpObject(name string, replicas int, image string) map[string]any {
	return map[string]any{
		"apiVersion": tcpAPIGroupVersion,
		"kind":       "TrstctlControlPlane",
		"metadata":   map[string]any{"name": name, "namespace": "trstctl-system"},
		"spec":       map[string]any{"replicas": replicas, "image": image},
	}
}

func tcpObjectFullConfig(name string) map[string]any {
	obj := tcpObject(name, 2, "ghcr.io/ctlplne/trstctl:v9")
	obj["spec"] = map[string]any{
		"replicas":   2,
		"image":      "ghcr.io/ctlplne/trstctl:v9",
		"signerMode": "sidecar",
		"postgres": map[string]any{
			"dsnSecret":    "trstctl-postgres",
			"dsnSecretKey": "dsn",
		},
		"nats": map[string]any{
			"url":                 "nats://trstctl-nats:4222",
			"replicas":            3,
			"allowSingleReplica":  false,
			"syncAlways":          true,
			"syncIntervalSeconds": 5,
		},
		"externalKMS": map[string]any{
			"enabled": false,
		},
	}
	return obj
}

func secretSyncObjectFixture(name string) map[string]any {
	return map[string]any{
		"apiVersion": tcpAPIGroupVersion,
		"kind":       "TrstctlSecretSync",
		"metadata":   map[string]any{"name": name, "namespace": "trstctl-system"},
		"spec": map[string]any{
			"controlPlane": map[string]any{
				"url":      "https://trstctl.example",
				"tenantID": "tenant-a",
				"tokenSecretRef": map[string]any{
					"name": "trstctl-secret-sync-token",
					"key":  "token",
				},
			},
			"target": map[string]any{"name": "payments-db", "type": "Opaque"},
			"data": []any{
				map[string]any{"key": "password", "remoteRef": map[string]any{"name": "sync/source"}},
				map[string]any{"key": "api-key", "remoteRef": map[string]any{"name": "sync/api-key"}},
			},
			"reload": map[string]any{
				"workloads": []any{
					map[string]any{"kind": "Deployment", "name": "payments-api"},
				},
			},
		},
	}
}

func secretInjectionObjectFixture(name string) map[string]any {
	return map[string]any{
		"apiVersion": tcpAPIGroupVersion,
		"kind":       "TrstctlSecretInjection",
		"metadata":   map[string]any{"name": name, "namespace": "trstctl-system"},
		"spec": map[string]any{
			"sourceSecretName": "payments-db",
			"mountPath":        "/etc/trstctl/secrets",
			"items": []any{
				map[string]any{"key": "password", "path": "db/password", "env": "DB_PASSWORD"},
				map[string]any{"key": "api-key", "path": "api/key", "env": "PAYMENTS_API_KEY"},
			},
			"workloads": []any{
				map[string]any{"kind": "Deployment", "name": "payments-api", "containers": []any{"app"}},
			},
		},
	}
}

func liveSyncedSecret(name, hash string) map[string]any {
	return map[string]any{
		"apiVersion": "v1",
		"kind":       "Secret",
		"metadata": map[string]any{
			"name":            name,
			"namespace":       "trstctl-system",
			"resourceVersion": "rv-" + hash,
			"annotations": map[string]any{
				kubernetesSecretHashAnnotation: hash,
			},
		},
		"type": "Opaque",
		"data": map[string]any{
			"password": base64.StdEncoding.EncodeToString([]byte("sync-v1")),
			"api-key":  base64.StdEncoding.EncodeToString([]byte("api-key-v1")),
		},
	}
}

func liveDeployment(name string, replicas int, image string) map[string]any {
	configHash := ControlPlaneSpec{Replicas: replicas, Image: image}.desiredConfigHash()
	return map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata": map[string]any{
			"name":            name,
			"namespace":       "trstctl-system",
			"resourceVersion": "100",
			"annotations":     map[string]any{"trstctl.com/config-hash": configHash},
		},
		"spec": map[string]any{
			"replicas": replicas,
			"template": map[string]any{
				"metadata": map[string]any{"annotations": map[string]any{"trstctl.com/config-hash": configHash}},
				"spec": map[string]any{
					"containers": []any{map[string]any{"name": "control-plane", "image": image}},
				},
			},
		},
	}
}

func liveReloadDeployment(name string) map[string]any {
	return map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata":   map[string]any{"name": name, "namespace": "trstctl-system"},
		"spec": map[string]any{
			"template": map[string]any{
				"metadata": map[string]any{"annotations": map[string]any{}},
				"spec": map[string]any{
					"containers": []any{map[string]any{"name": "app", "image": "example/payments:v1"}},
				},
			},
		},
	}
}

type mapSecretResolver map[string][]byte

func (m mapSecretResolver) ResolveSecret(_ context.Context, _ string, _ SecretSyncSpec, remoteName string) ([]byte, error) {
	value, ok := m[remoteName]
	if !ok {
		return nil, io.ErrUnexpectedEOF
	}
	return append([]byte(nil), value...), nil
}

// reconcilerForCluster wires a Reconciler to a fake cluster's httptest server.
func reconcilerForCluster(srv *httptest.Server) *Reconciler {
	return NewReconciler(NewClient(srv.URL, "fake-sa-token", srv.Client()))
}

// TestReconcileCreatesMissingDeployment drives the full reconcile against the
// fake API server: with a TrstctlControlPlane present but NO Deployment, the
// operator must POST a control-plane Deployment that matches the spec
// (replicas+image) and mark the CR status Reconciling. FAILS pre-fix (there was
// no operator at all).
func TestReconcileCreatesMissingDeployment(t *testing.T) {
	f := newFakeCluster()
	f.tcps = []map[string]any{tcpObject("prod", 2, "ghcr.io/ctlplne/trstctl:v9")}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()

	r := reconcilerForCluster(srv)
	actions, err := r.ReconcileNamespace(context.Background(), "trstctl-system")
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if actions["prod"] != ActionCreate {
		t.Fatalf("action for prod = %q, want %q", actions["prod"], ActionCreate)
	}
	if len(f.created) != 1 {
		t.Fatalf("expected exactly one Deployment created, got %d", len(f.created))
	}
	// The created Deployment must encode the spec's desired state.
	created := f.created[0]
	if got := deploymentReplicas(t, created); got != 2 {
		t.Errorf("created Deployment replicas = %d, want 2", got)
	}
	if got := deploymentImage(t, created); got != "ghcr.io/ctlplne/trstctl:v9" {
		t.Errorf("created Deployment image = %q, want the spec image", got)
	}
	if name := deploymentName(t, created); name != "prod-control-plane" {
		t.Errorf("created Deployment name = %q, want prod-control-plane", name)
	}
	// And the operator wrote a phase back to the CR status.
	if f.statusSet["prod"]["phase"] != "Reconciling" {
		t.Errorf("CR status.phase = %v, want Reconciling", f.statusSet["prod"]["phase"])
	}
}

// TestReconcileCreatesFullControlPlaneConfig is the DIST-07 served-path
// acceptance test for the broadened operator: the CRD fields for PostgreSQL,
// NATS, and signer topology must become real pod config in the managed
// Deployment, not dormant schema decorations.
func TestReconcileCreatesFullControlPlaneConfig(t *testing.T) {
	f := newFakeCluster()
	f.tcps = []map[string]any{tcpObjectFullConfig("prod")}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()

	r := reconcilerForCluster(srv)
	actions, err := r.ReconcileNamespace(context.Background(), "trstctl-system")
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if actions["prod"] != ActionCreate {
		t.Fatalf("action for prod = %q, want %q", actions["prod"], ActionCreate)
	}
	if len(f.created) != 1 {
		t.Fatalf("expected one configured Deployment, got %d", len(f.created))
	}
	created := f.created[0]
	env := controlPlaneEnv(t, created)
	if got := envLiteral(env, "TRSTCTL_POSTGRES_MODE"); got != "external" {
		t.Errorf("TRSTCTL_POSTGRES_MODE = %q, want external", got)
	}
	if got := envSecretName(env, "TRSTCTL_POSTGRES_DSN"); got != "trstctl-postgres" {
		t.Errorf("TRSTCTL_POSTGRES_DSN secret = %q, want trstctl-postgres", got)
	}
	if got := envSecretKey(env, "TRSTCTL_POSTGRES_DSN"); got != "dsn" {
		t.Errorf("TRSTCTL_POSTGRES_DSN key = %q, want dsn", got)
	}
	if got := envLiteral(env, "TRSTCTL_NATS_MODE"); got != "external" {
		t.Errorf("TRSTCTL_NATS_MODE = %q, want external", got)
	}
	if got := envLiteral(env, "TRSTCTL_NATS_URL"); got != "nats://trstctl-nats:4222" {
		t.Errorf("TRSTCTL_NATS_URL = %q", got)
	}
	if got := envLiteral(env, "TRSTCTL_NATS_REPLICAS"); got != "3" {
		t.Errorf("TRSTCTL_NATS_REPLICAS = %q, want 3", got)
	}
	if got := envLiteral(env, "TRSTCTL_NATS_SYNC_ALWAYS"); got != "true" {
		t.Errorf("TRSTCTL_NATS_SYNC_ALWAYS = %q, want true", got)
	}
	if got := envLiteral(env, "TRSTCTL_SIGNER_MODE"); got != "external" {
		t.Errorf("TRSTCTL_SIGNER_MODE = %q, want external for sidecar UDS signer", got)
	}
	if got := envLiteral(env, "TRSTCTL_SIGNER_SOCKET"); got != "/run/trstctl/signer.sock" {
		t.Errorf("TRSTCTL_SIGNER_SOCKET = %q, want shared UDS", got)
	}
	if !hasContainer(created, "signer") {
		t.Fatal("full sidecar config should render a signer container")
	}
	for _, volume := range []string{"signer-sock", "signer-keys", "signer-auth", "kek"} {
		if !hasVolume(created, volume) {
			t.Errorf("full sidecar config should render volume %q", volume)
		}
	}
}

// TestReconcileTrstctlSecretSyncCreatesSecretAndReloadsWorkloadCAPSECR04 proves
// CAP-SECR-04: a TrstctlSecretSync CRD resolves trstctl secret references, writes
// a Kubernetes Secret with base64 data, annotates an opted-in workload's pod
// template with the content hash for auto-reload, updates status, and converges
// idempotently until the source value rotates.
func TestReconcileTrstctlSecretSyncCreatesSecretAndReloadsWorkloadCAPSECR04(t *testing.T) {
	f := newFakeCluster()
	f.secretSyncs = []map[string]any{secretSyncObjectFixture("payments-db")}
	f.deployments["payments-api"] = liveReloadDeployment("payments-api")
	srv := httptest.NewServer(f.handler())
	defer srv.Close()

	resolver := mapSecretResolver{
		"sync/source":  []byte("sync-v1"),
		"sync/api-key": []byte("api-key-v1"),
	}
	r := reconcilerForCluster(srv)
	r.secretResolver = resolver
	actions, err := r.ReconcileSecretSyncNamespace(context.Background(), "trstctl-system")
	if err != nil {
		t.Fatalf("secret sync reconcile: %v", err)
	}
	if actions["payments-db"] != ActionCreate {
		t.Fatalf("secret sync action = %q, want %q", actions["payments-db"], ActionCreate)
	}
	if len(f.createdSecrets) != 1 {
		t.Fatalf("created Secrets = %d, want 1", len(f.createdSecrets))
	}
	created := f.createdSecrets[0]
	if name := secretName(t, created); name != "payments-db" {
		t.Fatalf("created Secret name = %q, want payments-db", name)
	}
	if got := secretDataValue(t, created, "password"); got != "sync-v1" {
		t.Fatalf("created Secret password = %q, want sync-v1", got)
	}
	if got := secretDataValue(t, created, "api-key"); got != "api-key-v1" {
		t.Fatalf("created Secret api-key = %q, want api-key-v1", got)
	}
	if strings.Contains(string(mustJSON(t, created)), "sync-v1") || strings.Contains(string(mustJSON(t, created)), "api-key-v1") {
		t.Fatal("Kubernetes Secret write body leaked raw secret value instead of base64 data")
	}
	hash := secretAnnotation(t, created, kubernetesSecretHashAnnotation)
	if hash == "" {
		t.Fatal("created Secret missing content-hash annotation")
	}
	if got := deploymentTemplateAnnotation(t, f.deployments["payments-api"], kubernetesSecretHashAnnotation); got != hash {
		t.Fatalf("reload annotation = %q, want content hash %q", got, hash)
	}
	if st := f.secretStatusSet["payments-db"]; st["phase"] != "Ready" || st["targetSecret"] != "payments-db" {
		t.Fatalf("secret sync status = %+v, want Ready payments-db", st)
	}

	f.createdSecrets = nil
	f.patchedSecrets = map[string][]byte{}
	f.patched = map[string][]byte{}
	actions, err = r.ReconcileSecretSyncNamespace(context.Background(), "trstctl-system")
	if err != nil {
		t.Fatalf("second secret sync reconcile: %v", err)
	}
	if actions["payments-db"] != ActionNone {
		t.Fatalf("second secret sync action = %q, want %q", actions["payments-db"], ActionNone)
	}
	if len(f.createdSecrets) != 0 || len(f.patchedSecrets) != 0 || len(f.patched) != 0 {
		t.Fatalf("idempotent reconcile mutated cluster: createdSecrets=%d patchedSecrets=%d workloadPatches=%d", len(f.createdSecrets), len(f.patchedSecrets), len(f.patched))
	}

	resolver["sync/source"] = []byte("sync-v2")
	actions, err = r.ReconcileSecretSyncNamespace(context.Background(), "trstctl-system")
	if err != nil {
		t.Fatalf("rotated secret sync reconcile: %v", err)
	}
	if actions["payments-db"] != ActionUpdate {
		t.Fatalf("rotated secret sync action = %q, want %q", actions["payments-db"], ActionUpdate)
	}
	if _, ok := f.patchedSecrets["payments-db"]; !ok {
		t.Fatal("rotated source did not patch the Kubernetes Secret")
	}
	if got := secretDataValue(t, f.secrets["payments-db"], "password"); got != "sync-v2" {
		t.Fatalf("patched Secret password = %q, want sync-v2", got)
	}
	newHash := secretAnnotation(t, f.secrets["payments-db"], kubernetesSecretHashAnnotation)
	if newHash == "" || newHash == hash {
		t.Fatalf("rotated content hash = %q, want changed from %q", newHash, hash)
	}
	if got := deploymentTemplateAnnotation(t, f.deployments["payments-api"], kubernetesSecretHashAnnotation); got != newHash {
		t.Fatalf("rotated reload annotation = %q, want %q", got, newHash)
	}
}

// TestReconcileTrstctlSecretInjectionPatchesWorkloadCAPSECR05 proves CAP-SECR-05:
// a TrstctlSecretInjection CRD patches a live workload with the shipped
// trstctl-agent secret-injection sidecar, app-container file mount, optional env
// valueFrom references, content-hash rollout annotations, status, and idempotence.
// The operator reads only source Secret metadata; the patch body must not contain
// raw or base64-encoded secret values.
func TestReconcileTrstctlSecretInjectionPatchesWorkloadCAPSECR05(t *testing.T) {
	f := newFakeCluster()
	f.secretInjections = []map[string]any{secretInjectionObjectFixture("payments-runtime")}
	f.secrets["payments-db"] = liveSyncedSecret("payments-db", "hash-v1")
	f.deployments["payments-api"] = liveReloadDeployment("payments-api")
	srv := httptest.NewServer(f.handler())
	defer srv.Close()

	r := reconcilerForCluster(srv)
	actions, err := r.ReconcileSecretInjectionNamespace(context.Background(), "trstctl-system")
	if err != nil {
		t.Fatalf("secret injection reconcile: %v", err)
	}
	if actions["payments-runtime"] != ActionUpdate {
		t.Fatalf("secret injection action = %q, want %q", actions["payments-runtime"], ActionUpdate)
	}
	patch := string(f.patched["payments-api"])
	for _, forbidden := range []string{"sync-v1", "api-key-v1", base64.StdEncoding.EncodeToString([]byte("sync-v1"))} {
		if strings.Contains(patch, forbidden) {
			t.Fatalf("secret injection patch leaked secret marker %q: %s", forbidden, patch)
		}
	}
	workload := f.deployments["payments-api"]
	if !hasContainer(workload, secretInjectionSidecarName) {
		t.Fatal("injected workload missing trstctl secret-injection sidecar")
	}
	if !hasVolume(workload, secretInjectionSourceVolume) || !hasVolume(workload, secretInjectionTargetVolume) {
		t.Fatal("injected workload missing source Secret or shared target volume")
	}
	if got := deploymentTemplateAnnotation(t, workload, secretInjectionSourceAnnotation); got != "payments-db" {
		t.Fatalf("source annotation = %q, want payments-db", got)
	}
	injectionHash := deploymentTemplateAnnotation(t, workload, secretInjectionHashAnnotation)
	if injectionHash == "" {
		t.Fatal("injected workload missing content hash annotation")
	}
	app := containerByName(t, workload, "app")
	if !containerHasMount(app, secretInjectionTargetVolume, "/etc/trstctl/secrets") {
		t.Fatal("app container missing injected secret mount")
	}
	env := containerEnv(app)
	if got := envSecretName(env, "DB_PASSWORD"); got != "payments-db" {
		t.Fatalf("DB_PASSWORD secret name = %q, want payments-db", got)
	}
	if got := envSecretKey(env, "DB_PASSWORD"); got != "password" {
		t.Fatalf("DB_PASSWORD secret key = %q, want password", got)
	}
	sidecar := containerByName(t, workload, secretInjectionSidecarName)
	args := strings.Join(containerArgs(sidecar), " ")
	if !strings.Contains(args, "--secret-inject") || !strings.Contains(args, "--secret-inject-map=api-key=api/key,password=db/password") {
		t.Fatalf("sidecar args do not run the secret injector with expected map: %s", args)
	}
	if st := f.injectStatusSet["payments-runtime"]; st["phase"] != "Ready" || st["sourceSecret"] != "payments-db" {
		t.Fatalf("secret injection status = %+v, want Ready payments-db", st)
	}

	f.patched = map[string][]byte{}
	actions, err = r.ReconcileSecretInjectionNamespace(context.Background(), "trstctl-system")
	if err != nil {
		t.Fatalf("second secret injection reconcile: %v", err)
	}
	if actions["payments-runtime"] != ActionNone {
		t.Fatalf("second secret injection action = %q, want %q", actions["payments-runtime"], ActionNone)
	}
	if len(f.patched) != 0 {
		t.Fatalf("idempotent injection reconcile patched workload again: %d patches", len(f.patched))
	}

	f.secrets["payments-db"] = liveSyncedSecret("payments-db", "hash-v2")
	actions, err = r.ReconcileSecretInjectionNamespace(context.Background(), "trstctl-system")
	if err != nil {
		t.Fatalf("rotated source secret injection reconcile: %v", err)
	}
	if actions["payments-runtime"] != ActionUpdate {
		t.Fatalf("rotated source injection action = %q, want %q", actions["payments-runtime"], ActionUpdate)
	}
	if got := deploymentTemplateAnnotation(t, f.deployments["payments-api"], secretInjectionHashAnnotation); got == "" || got == injectionHash {
		t.Fatalf("rotated injection hash = %q, want changed from %q", got, injectionHash)
	}
}

// TestReconcilePatchesDriftedDeployment proves the convergence action: when a
// Deployment exists but its replicas/image drifted from the spec, the operator
// PATCHes it back (it does not recreate) and marks the CR Reconciling.
func TestReconcilePatchesDriftedDeployment(t *testing.T) {
	f := newFakeCluster()
	f.tcps = []map[string]any{tcpObject("prod", 3, "ghcr.io/ctlplne/trstctl:NEW")}
	// Live deployment is drifted: 1 replica and an OLD image.
	f.deployments["prod-control-plane"] = liveDeployment("prod-control-plane", 1, "ghcr.io/ctlplne/trstctl:OLD")
	srv := httptest.NewServer(f.handler())
	defer srv.Close()

	r := reconcilerForCluster(srv)
	actions, err := r.ReconcileNamespace(context.Background(), "trstctl-system")
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if actions["prod"] != ActionUpdate {
		t.Fatalf("action = %q, want %q", actions["prod"], ActionUpdate)
	}
	if len(f.created) != 0 {
		t.Errorf("a drifted Deployment must be patched, not recreated; got %d creates", len(f.created))
	}
	patch, ok := f.patched["prod-control-plane"]
	if !ok {
		t.Fatal("operator did not PATCH the drifted Deployment")
	}
	var pj map[string]any
	if err := json.Unmarshal(patch, &pj); err != nil {
		t.Fatalf("patch body is not JSON: %v", err)
	}
	if got := deploymentReplicas(t, pj); got != 3 {
		t.Errorf("patch replicas = %d, want 3", got)
	}
	if got := deploymentImage(t, pj); got != "ghcr.io/ctlplne/trstctl:NEW" {
		t.Errorf("patch image = %q, want the spec image", got)
	}
}

// TestReconcileNoopWhenInSync proves the operator is idempotent and does not
// thrash: a Deployment already matching the spec yields no create and no patch,
// and the CR is marked Ready.
func TestReconcileNoopWhenInSync(t *testing.T) {
	f := newFakeCluster()
	f.tcps = []map[string]any{tcpObject("prod", 2, "ghcr.io/ctlplne/trstctl:v9")}
	f.deployments["prod-control-plane"] = liveDeployment("prod-control-plane", 2, "ghcr.io/ctlplne/trstctl:v9")
	srv := httptest.NewServer(f.handler())
	defer srv.Close()

	r := reconcilerForCluster(srv)
	actions, err := r.ReconcileNamespace(context.Background(), "trstctl-system")
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if actions["prod"] != ActionNone {
		t.Fatalf("action = %q, want %q", actions["prod"], ActionNone)
	}
	if len(f.created) != 0 || len(f.patched) != 0 {
		t.Errorf("in-sync reconcile must be a no-op; creates=%d patches=%d", len(f.created), len(f.patched))
	}
	if f.statusSet["prod"]["phase"] != "Ready" {
		t.Errorf("CR status.phase = %v, want Ready", f.statusSet["prod"]["phase"])
	}
}

// TestLeaderElectionAllowsExactlyOneActiveReplica is the DIST-07 leader election
// acceptance test: when two operator replicas contend for one Lease, only one is
// allowed to reconcile while the lease is fresh; the same leader can renew.
func TestLeaderElectionAllowsExactlyOneActiveReplica(t *testing.T) {
	f := newFakeCluster()
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	client := NewClient(srv.URL, "fake-sa-token", srv.Client())
	now := time.Date(2026, 6, 25, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	a := NewLeaseElector(client, "trstctl-system", "trstctl-operator", "operator-a", 15*time.Second, clock)
	b := NewLeaseElector(client, "trstctl-system", "trstctl-operator", "operator-b", 15*time.Second, clock)

	leaderA, err := a.TryAcquireOrRenew(context.Background())
	if err != nil {
		t.Fatalf("operator-a acquire: %v", err)
	}
	leaderB, err := b.TryAcquireOrRenew(context.Background())
	if err != nil {
		t.Fatalf("operator-b acquire: %v", err)
	}
	if !leaderA || leaderB {
		t.Fatalf("fresh lease leaders: operator-a=%v operator-b=%v, want exactly operator-a", leaderA, leaderB)
	}

	now = now.Add(5 * time.Second)
	leaderA, err = a.TryAcquireOrRenew(context.Background())
	if err != nil {
		t.Fatalf("operator-a renew: %v", err)
	}
	if !leaderA {
		t.Fatal("current leader could not renew its own lease")
	}
	if f.leasePatches == 0 {
		t.Fatal("leader renewal did not patch the Kubernetes Lease")
	}
}

// --- small typed extractors so the assertions read the real rendered objects ---

func deploymentReplicas(t *testing.T, obj map[string]any) int {
	t.Helper()
	spec, _ := obj["spec"].(map[string]any)
	switch v := spec["replicas"].(type) {
	case float64:
		return int(v)
	case int:
		return v
	default:
		t.Fatalf("spec.replicas missing/wrong type: %T", spec["replicas"])
		return 0
	}
}

func deploymentImage(t *testing.T, obj map[string]any) string {
	t.Helper()
	spec, _ := obj["spec"].(map[string]any)
	tmpl, _ := spec["template"].(map[string]any)
	pod, _ := tmpl["spec"].(map[string]any)
	conts, _ := pod["containers"].([]any)
	for _, c := range conts {
		m, _ := c.(map[string]any)
		if m["name"] == "control-plane" {
			img, _ := m["image"].(string)
			return img
		}
	}
	if len(conts) > 0 {
		m, _ := conts[0].(map[string]any)
		img, _ := m["image"].(string)
		return img
	}
	t.Fatal("no containers in deployment object")
	return ""
}

func deploymentName(t *testing.T, obj map[string]any) string {
	t.Helper()
	meta, _ := obj["metadata"].(map[string]any)
	name, _ := meta["name"].(string)
	return name
}

func controlPlaneEnv(t *testing.T, obj map[string]any) []any {
	t.Helper()
	spec, _ := obj["spec"].(map[string]any)
	tmpl, _ := spec["template"].(map[string]any)
	pod, _ := tmpl["spec"].(map[string]any)
	conts, _ := pod["containers"].([]any)
	for _, c := range conts {
		m, _ := c.(map[string]any)
		if m["name"] == "control-plane" {
			env, _ := m["env"].([]any)
			return env
		}
	}
	t.Fatal("no control-plane container")
	return nil
}

func envEntry(env []any, name string) map[string]any {
	for _, e := range env {
		m, _ := e.(map[string]any)
		if m["name"] == name {
			return m
		}
	}
	return nil
}

func envLiteral(env []any, name string) string {
	e := envEntry(env, name)
	if e == nil {
		return ""
	}
	v, _ := e["value"].(string)
	return v
}

func envSecretName(env []any, name string) string {
	e := envEntry(env, name)
	if e == nil {
		return ""
	}
	vf, _ := e["valueFrom"].(map[string]any)
	sr, _ := vf["secretKeyRef"].(map[string]any)
	v, _ := sr["name"].(string)
	return v
}

func envSecretKey(env []any, name string) string {
	e := envEntry(env, name)
	if e == nil {
		return ""
	}
	vf, _ := e["valueFrom"].(map[string]any)
	sr, _ := vf["secretKeyRef"].(map[string]any)
	v, _ := sr["key"].(string)
	return v
}

func hasContainer(obj map[string]any, name string) bool {
	spec, _ := obj["spec"].(map[string]any)
	tmpl, _ := spec["template"].(map[string]any)
	pod, _ := tmpl["spec"].(map[string]any)
	conts, _ := pod["containers"].([]any)
	for _, c := range conts {
		m, _ := c.(map[string]any)
		if m["name"] == name {
			return true
		}
	}
	return false
}

func hasVolume(obj map[string]any, name string) bool {
	spec, _ := obj["spec"].(map[string]any)
	tmpl, _ := spec["template"].(map[string]any)
	pod, _ := tmpl["spec"].(map[string]any)
	vols, _ := pod["volumes"].([]any)
	for _, v := range vols {
		m, _ := v.(map[string]any)
		if m["name"] == name {
			return true
		}
	}
	return false
}

func containerByName(t *testing.T, obj map[string]any, name string) map[string]any {
	t.Helper()
	spec, _ := obj["spec"].(map[string]any)
	tmpl, _ := spec["template"].(map[string]any)
	pod, _ := tmpl["spec"].(map[string]any)
	conts, _ := pod["containers"].([]any)
	for _, c := range conts {
		m, _ := c.(map[string]any)
		if m["name"] == name {
			return m
		}
	}
	t.Fatalf("container %q not found", name)
	return nil
}

func containerHasMount(container map[string]any, volumeName, mountPath string) bool {
	mounts, _ := container["volumeMounts"].([]any)
	for _, mount := range mounts {
		m, _ := mount.(map[string]any)
		if m["name"] == volumeName && m["mountPath"] == mountPath {
			return true
		}
	}
	return false
}

func containerEnv(container map[string]any) []any {
	env, _ := container["env"].([]any)
	return env
}

func containerArgs(container map[string]any) []string {
	args, _ := container["args"].([]any)
	out := make([]string, 0, len(args))
	for _, arg := range args {
		if s, _ := arg.(string); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func secretName(t *testing.T, obj map[string]any) string {
	t.Helper()
	meta, _ := obj["metadata"].(map[string]any)
	name, _ := meta["name"].(string)
	return name
}

func secretAnnotation(t *testing.T, obj map[string]any, key string) string {
	t.Helper()
	meta, _ := obj["metadata"].(map[string]any)
	annotations, _ := meta["annotations"].(map[string]any)
	value, _ := annotations[key].(string)
	return value
}

func secretDataValue(t *testing.T, obj map[string]any, key string) string {
	t.Helper()
	data, _ := obj["data"].(map[string]any)
	encoded, _ := data[key].(string)
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode Secret data[%s]: %v", key, err)
	}
	return string(raw)
}

func deploymentTemplateAnnotation(t *testing.T, obj map[string]any, key string) string {
	t.Helper()
	spec, _ := obj["spec"].(map[string]any)
	tmpl, _ := spec["template"].(map[string]any)
	meta, _ := tmpl["metadata"].(map[string]any)
	annotations, _ := meta["annotations"].(map[string]any)
	value, _ := annotations[key].(string)
	return value
}

func mustJSON(t *testing.T, obj any) []byte {
	t.Helper()
	data, err := json.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
