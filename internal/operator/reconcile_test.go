package operator

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// TestDecideActionDiff pins the pure desired-vs-actual diff at the heart of the
// reconcile (OPS-004): the controller must CREATE when no Deployment exists,
// UPDATE when the live replicas or image drift from the spec, and do NOTHING
// when they already match. This is the decision a real controller makes; pinning
// it here proves the operator is a genuine reconcile, not a stub.
func TestDecideActionDiff(t *testing.T) {
	spec := ControlPlaneSpec{Replicas: 3, Image: "ghcr.io/imfeelingtheagi/trstctl:v1.2.3"}

	cases := []struct {
		name string
		live deploymentState
		want Action
	}{
		{"missing deployment -> create", deploymentState{exists: false}, ActionCreate},
		{"replica drift -> update", deploymentState{exists: true, replicas: 1, image: "ghcr.io/imfeelingtheagi/trstctl:v1.2.3"}, ActionUpdate},
		{"image drift -> update", deploymentState{exists: true, replicas: 3, image: "ghcr.io/imfeelingtheagi/trstctl:OLD"}, ActionUpdate},
		{"in sync -> none", deploymentState{exists: true, replicas: 3, image: "ghcr.io/imfeelingtheagi/trstctl:v1.2.3"}, ActionNone},
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
	// deployments maps name -> the live Deployment object (nil => 404, i.e. it
	// does not exist yet).
	deployments map[string]map[string]any

	// Recorded effects:
	created   []map[string]any          // Deployment POST bodies
	patched   map[string][]byte         // Deployment name -> strategic-merge-patch body
	statusSet map[string]map[string]any // CR name -> status patch
}

func newFakeCluster() *fakeCluster {
	return &fakeCluster{
		deployments: map[string]map[string]any{},
		patched:     map[string][]byte{},
		statusSet:   map[string]map[string]any{},
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

		// Patch a TrstctlControlPlane status subresource.
		case r.Method == http.MethodPatch && strings.HasSuffix(path, "/status") && strings.Contains(path, "/"+tcpPlural+"/"):
			name := tcpNameFromStatusPath(path)
			var obj map[string]any
			_ = json.Unmarshal(body, &obj)
			st, _ := obj["status"].(map[string]any)
			f.statusSet[name] = st
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(obj)

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
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"metadata":{"name":"` + name + `"}}`))

		default:
			http.Error(w, "unexpected "+r.Method+" "+path, http.StatusNotImplemented)
		}
	})
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

func liveDeployment(name string, replicas int, image string) map[string]any {
	return map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata":   map[string]any{"name": name, "namespace": "trstctl-system", "resourceVersion": "100"},
		"spec": map[string]any{
			"replicas": replicas,
			"template": map[string]any{
				"spec": map[string]any{
					"containers": []any{map[string]any{"name": "control-plane", "image": image}},
				},
			},
		},
	}
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
	f.tcps = []map[string]any{tcpObject("prod", 2, "ghcr.io/imfeelingtheagi/trstctl:v9")}
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
	if got := deploymentImage(t, created); got != "ghcr.io/imfeelingtheagi/trstctl:v9" {
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

// TestReconcilePatchesDriftedDeployment proves the convergence action: when a
// Deployment exists but its replicas/image drifted from the spec, the operator
// PATCHes it back (it does not recreate) and marks the CR Reconciling.
func TestReconcilePatchesDriftedDeployment(t *testing.T) {
	f := newFakeCluster()
	f.tcps = []map[string]any{tcpObject("prod", 3, "ghcr.io/imfeelingtheagi/trstctl:NEW")}
	// Live deployment is drifted: 1 replica and an OLD image.
	f.deployments["prod-control-plane"] = liveDeployment("prod-control-plane", 1, "ghcr.io/imfeelingtheagi/trstctl:OLD")
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
	if got := deploymentImage(t, pj); got != "ghcr.io/imfeelingtheagi/trstctl:NEW" {
		t.Errorf("patch image = %q, want the spec image", got)
	}
}

// TestReconcileNoopWhenInSync proves the operator is idempotent and does not
// thrash: a Deployment already matching the spec yields no create and no patch,
// and the CR is marked Ready.
func TestReconcileNoopWhenInSync(t *testing.T) {
	f := newFakeCluster()
	f.tcps = []map[string]any{tcpObject("prod", 2, "ghcr.io/imfeelingtheagi/trstctl:v9")}
	f.deployments["prod-control-plane"] = liveDeployment("prod-control-plane", 2, "ghcr.io/imfeelingtheagi/trstctl:v9")
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
