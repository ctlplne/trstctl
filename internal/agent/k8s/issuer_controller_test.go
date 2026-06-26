package k8s_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/agent/k8s"
)

type fakeIssuerAPI struct {
	mu sync.Mutex

	clusterIssuers      []map[string]any
	issuers             []map[string]any
	certificateRequests []map[string]any

	clusterIssuerStatus map[string]map[string]any
	issuerStatus        map[string]map[string]any
	requestStatus       map[string]map[string]any
}

func newFakeIssuerAPI() *fakeIssuerAPI {
	return &fakeIssuerAPI{
		clusterIssuerStatus: map[string]map[string]any{},
		issuerStatus:        map[string]map[string]any{},
		requestStatus:       map[string]map[string]any{},
	}
}

func (f *fakeIssuerAPI) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()

		path := r.URL.Path
		body, _ := io.ReadAll(r.Body)
		switch {
		case r.Method == http.MethodGet && path == "/apis/trstctl.com/v1alpha1/clusterissuers":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"apiVersion": "trstctl.com/v1alpha1",
				"kind":       "ClusterIssuerList",
				"items":      f.clusterIssuers,
			})
		case r.Method == http.MethodPut && strings.HasPrefix(path, "/apis/trstctl.com/v1alpha1/clusterissuers/") && strings.HasSuffix(path, "/status"):
			name := nameBeforeStatus(path)
			var obj map[string]any
			_ = json.Unmarshal(body, &obj)
			f.clusterIssuerStatus[name] = obj
			_ = json.NewEncoder(w).Encode(obj)
		case r.Method == http.MethodGet && path == "/apis/trstctl.com/v1alpha1/namespaces/apps/issuers":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"apiVersion": "trstctl.com/v1alpha1",
				"kind":       "IssuerList",
				"items":      f.issuers,
			})
		case r.Method == http.MethodPut && strings.HasPrefix(path, "/apis/trstctl.com/v1alpha1/namespaces/apps/issuers/") && strings.HasSuffix(path, "/status"):
			name := nameBeforeStatus(path)
			var obj map[string]any
			_ = json.Unmarshal(body, &obj)
			f.issuerStatus[name] = obj
			_ = json.NewEncoder(w).Encode(obj)
		case r.Method == http.MethodGet && path == "/apis/cert-manager.io/v1/namespaces/apps/certificaterequests":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"apiVersion": "cert-manager.io/v1",
				"kind":       "CertificateRequestList",
				"items":      f.certificateRequests,
			})
		case r.Method == http.MethodPut && strings.HasPrefix(path, "/apis/cert-manager.io/v1/namespaces/apps/certificaterequests/") && strings.HasSuffix(path, "/status"):
			name := nameBeforeStatus(path)
			var obj map[string]any
			_ = json.Unmarshal(body, &obj)
			f.requestStatus[name] = obj
			_ = json.NewEncoder(w).Encode(obj)
		default:
			http.Error(w, "unexpected "+r.Method+" "+path, http.StatusNotImplemented)
		}
	})
}

func nameBeforeStatus(path string) string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) < 2 {
		return ""
	}
	return parts[len(parts)-2]
}

func trstctlClusterIssuer(name string) map[string]any {
	return map[string]any{
		"apiVersion": "trstctl.com/v1alpha1",
		"kind":       "ClusterIssuer",
		"metadata":   map[string]any{"name": name, "resourceVersion": "10"},
		"spec":       map[string]any{"signerURL": "https://trstctl.trstctl.svc/api/v1/issue"},
	}
}

func trstctlIssuer(name, namespace string) map[string]any {
	return map[string]any{
		"apiVersion": "trstctl.com/v1alpha1",
		"kind":       "Issuer",
		"metadata":   map[string]any{"name": name, "namespace": namespace, "resourceVersion": "11"},
		"spec":       map[string]any{"signerURL": "https://trstctl.trstctl.svc/api/v1/issue"},
	}
}

// TestIssuerControllerSignsRequestsBackedByClusterIssuer is the DIST-01
// acceptance core: a real external-issuer controller must make trstctl
// ClusterIssuer resources Ready and sign cert-manager CertificateRequests that
// name that resource, not merely bridge a hard-coded issuer name.
func TestIssuerControllerSignsRequestsBackedByClusterIssuer(t *testing.T) {
	signer, _ := caSigner(t)
	api := newFakeIssuerAPI()
	api.clusterIssuers = []map[string]any{trstctlClusterIssuer("trstctl")}
	api.certificateRequests = []map[string]any{func() map[string]any {
		cr := certRequest("cm-generated", "trstctl", "trstctl.com", false)
		cr["spec"].(map[string]any)["request"] = csrRequestField(t)
		cr["spec"].(map[string]any)["issuerRef"].(map[string]any)["kind"] = "ClusterIssuer"
		return cr
	}()}
	srv := httptest.NewServer(api.handler())
	defer srv.Close()

	controller := k8s.NewIssuerController(k8s.New(srv.URL, "tok", "apps", srv.Client()), signer, "trstctl.com")
	result, err := controller.Reconcile(context.Background(), "apps")
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if result.ClusterIssuersReady != 1 {
		t.Fatalf("ClusterIssuersReady = %d, want 1", result.ClusterIssuersReady)
	}
	if result.SignedRequests != 1 {
		t.Fatalf("SignedRequests = %d, want 1", result.SignedRequests)
	}

	status, _ := readyCondition(t, api.clusterIssuerStatus["trstctl"])
	if status != "True" {
		t.Fatalf("ClusterIssuer Ready = %q, want True", status)
	}
	ready, cert := readyCondition(t, api.requestStatus["cm-generated"])
	if ready != "True" {
		t.Fatalf("CertificateRequest Ready = %q, want True", ready)
	}
	decoded, err := base64.StdEncoding.DecodeString(cert)
	if err != nil {
		t.Fatalf("status.certificate is not base64: %v", err)
	}
	if block, _ := pem.Decode(decoded); block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("status.certificate does not contain a PEM certificate")
	}
}

func TestIssuerControllerSkipsRequestsWithoutBackingIssuerResource(t *testing.T) {
	signer, _ := caSigner(t)
	api := newFakeIssuerAPI()
	api.certificateRequests = []map[string]any{func() map[string]any {
		cr := certRequest("missing-issuer", "missing", "trstctl.com", false)
		cr["spec"].(map[string]any)["request"] = csrRequestField(t)
		cr["spec"].(map[string]any)["issuerRef"].(map[string]any)["kind"] = "ClusterIssuer"
		return cr
	}()}
	srv := httptest.NewServer(api.handler())
	defer srv.Close()

	controller := k8s.NewIssuerController(k8s.New(srv.URL, "tok", "apps", srv.Client()), signer, "trstctl.com")
	result, err := controller.Reconcile(context.Background(), "apps")
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if result.SignedRequests != 0 {
		t.Fatalf("SignedRequests = %d, want 0", result.SignedRequests)
	}
	if _, ok := api.requestStatus["missing-issuer"]; ok {
		t.Fatal("controller signed a request whose trstctl ClusterIssuer does not exist")
	}
}

func TestIssuerControllerSupportsNamespacedIssuer(t *testing.T) {
	signer, _ := caSigner(t)
	api := newFakeIssuerAPI()
	api.issuers = []map[string]any{trstctlIssuer("team-ca", "apps")}
	api.certificateRequests = []map[string]any{func() map[string]any {
		cr := certRequest("team-leaf", "team-ca", "trstctl.com", false)
		cr["spec"].(map[string]any)["request"] = csrRequestField(t)
		cr["spec"].(map[string]any)["issuerRef"].(map[string]any)["kind"] = "Issuer"
		return cr
	}()}
	srv := httptest.NewServer(api.handler())
	defer srv.Close()

	controller := k8s.NewIssuerController(k8s.New(srv.URL, "tok", "apps", srv.Client()), signer, "trstctl.com")
	result, err := controller.Reconcile(context.Background(), "apps")
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if result.IssuersReady != 1 || result.SignedRequests != 1 {
		t.Fatalf("result = %+v, want one ready Issuer and one signed request", result)
	}
	status, _ := readyCondition(t, api.issuerStatus["team-ca"])
	if status != "True" {
		t.Fatalf("Issuer Ready = %q, want True", status)
	}
	if api.requestStatus["team-leaf"] == nil {
		t.Fatal("namespaced Issuer request was not signed")
	}
}
