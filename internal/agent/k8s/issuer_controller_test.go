// SPDX-License-Identifier: BUSL-1.1

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
	"sync/atomic"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/k8s"
	"trstctl.com/trstctl/internal/crypto"
)

const testIssuerSignerURL = "https://trstctl.trstctl.svc/api/v1/issue"

func testIssuerController(t *testing.T, client *k8s.Client, signer k8s.Signer, group string) *k8s.IssuerController {
	t.Helper()
	controller, err := k8s.NewIssuerController(client, signer, group, testIssuerSignerURL)
	if err != nil {
		t.Fatal(err)
	}
	return controller
}

type fakeIssuerAPI struct {
	mu sync.Mutex

	clusterIssuers      []map[string]any
	issuers             []map[string]any
	certificateRequests []map[string]any
	certificates        []map[string]any
	kubernetesCSRs      []map[string]any
	trustBundles        []map[string]any

	clusterIssuerStatus   map[string]map[string]any
	issuerStatus          map[string]map[string]any
	issuerStatusPath      map[string]string
	requestStatus         map[string]map[string]any
	requestStatusPath     map[string]string
	certificateStatus     map[string]map[string]any
	certificateStatusPath map[string]string
	kubernetesCSRStatus   map[string]map[string]any
	trustBundleStatus     map[string]map[string]any
	secrets               map[string]map[string]any
	secretWritePath       map[string]string
	configMaps            map[string]map[string]any
}

func newFakeIssuerAPI() *fakeIssuerAPI {
	return &fakeIssuerAPI{
		clusterIssuerStatus:   map[string]map[string]any{},
		issuerStatus:          map[string]map[string]any{},
		issuerStatusPath:      map[string]string{},
		requestStatus:         map[string]map[string]any{},
		requestStatusPath:     map[string]string{},
		certificateStatus:     map[string]map[string]any{},
		certificateStatusPath: map[string]string{},
		kubernetesCSRStatus:   map[string]map[string]any{},
		trustBundleStatus:     map[string]map[string]any{},
		secrets:               map[string]map[string]any{},
		secretWritePath:       map[string]string{},
		configMaps:            map[string]map[string]any{},
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
		case r.Method == http.MethodGet && (path == "/apis/trstctl.com/v1alpha1/namespaces/apps/issuers" || path == "/apis/trstctl.com/v1alpha1/issuers"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"apiVersion": "trstctl.com/v1alpha1",
				"kind":       "IssuerList",
				"items":      f.issuers,
			})
		case r.Method == http.MethodPut && strings.HasPrefix(path, "/apis/trstctl.com/v1alpha1/namespaces/") && strings.Contains(path, "/issuers/") && strings.HasSuffix(path, "/status"):
			name := nameBeforeStatus(path)
			var obj map[string]any
			_ = json.Unmarshal(body, &obj)
			f.issuerStatus[name] = obj
			f.issuerStatusPath[name] = path
			_ = json.NewEncoder(w).Encode(obj)
		case r.Method == http.MethodGet && (path == "/apis/cert-manager.io/v1/namespaces/apps/certificaterequests" || path == "/apis/cert-manager.io/v1/certificaterequests"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"apiVersion": "cert-manager.io/v1",
				"kind":       "CertificateRequestList",
				"items":      f.certificateRequests,
			})
		case r.Method == http.MethodPut && strings.HasPrefix(path, "/apis/cert-manager.io/v1/namespaces/") && strings.Contains(path, "/certificaterequests/") && strings.HasSuffix(path, "/status"):
			name := nameBeforeStatus(path)
			var obj map[string]any
			_ = json.Unmarshal(body, &obj)
			f.requestStatus[name] = obj
			f.requestStatusPath[name] = path
			_ = json.NewEncoder(w).Encode(obj)
		case r.Method == http.MethodGet && path == "/apis/certificates.k8s.io/v1/certificatesigningrequests":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"apiVersion": "certificates.k8s.io/v1",
				"kind":       "CertificateSigningRequestList",
				"items":      f.kubernetesCSRs,
			})
		case r.Method == http.MethodPut && strings.HasPrefix(path, "/apis/certificates.k8s.io/v1/certificatesigningrequests/") && strings.HasSuffix(path, "/status"):
			name := nameBeforeStatus(path)
			var obj map[string]any
			_ = json.Unmarshal(body, &obj)
			obj["metadata"].(map[string]any)["resourceVersion"] = "21"
			f.kubernetesCSRStatus[name] = obj
			_ = json.NewEncoder(w).Encode(obj)
		case r.Method == http.MethodGet && path == "/apis/trstctl.com/v1alpha1/trustbundles":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"apiVersion": "trstctl.com/v1alpha1",
				"kind":       "TrustBundleList",
				"items":      f.trustBundles,
			})
		case r.Method == http.MethodPut && strings.HasPrefix(path, "/apis/trstctl.com/v1alpha1/trustbundles/") && strings.HasSuffix(path, "/status"):
			name := nameBeforeStatus(path)
			var obj map[string]any
			_ = json.Unmarshal(body, &obj)
			obj["metadata"].(map[string]any)["resourceVersion"] = "31"
			f.trustBundleStatus[name] = obj
			_ = json.NewEncoder(w).Encode(obj)
		case r.Method == http.MethodGet && (path == "/apis/trstctl.com/v1alpha1/namespaces/apps/certificates" || path == "/apis/trstctl.com/v1alpha1/certificates"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"apiVersion": "trstctl.com/v1alpha1",
				"kind":       "CertificateList",
				"items":      f.certificates,
			})
		case r.Method == http.MethodPut && strings.HasPrefix(path, "/apis/trstctl.com/v1alpha1/namespaces/") && strings.Contains(path, "/certificates/") && strings.HasSuffix(path, "/status"):
			name := nameBeforeStatus(path)
			var obj map[string]any
			_ = json.Unmarshal(body, &obj)
			f.certificateStatus[name] = obj
			f.certificateStatusPath[name] = path
			_ = json.NewEncoder(w).Encode(obj)
		case r.Method == http.MethodGet && strings.HasPrefix(path, "/api/v1/namespaces/") && strings.Contains(path, "/secrets/"):
			parts := strings.Split(strings.Trim(path, "/"), "/")
			name := parts[len(parts)-1]
			obj := f.secrets[name]
			if obj == nil {
				http.Error(w, `{"kind":"Status","code":404}`, http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(obj)
		case r.Method == http.MethodPost && strings.HasPrefix(path, "/api/v1/namespaces/") && strings.HasSuffix(path, "/secrets"):
			var obj map[string]any
			_ = json.Unmarshal(body, &obj)
			meta, _ := obj["metadata"].(map[string]any)
			name, _ := meta["name"].(string)
			if f.secrets[name] != nil {
				http.Error(w, `{"kind":"Status","code":409}`, http.StatusConflict)
				return
			}
			meta["resourceVersion"] = "1"
			f.secrets[name] = obj
			f.secretWritePath[name] = path
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(obj)
		case r.Method == http.MethodPut && strings.HasPrefix(path, "/api/v1/namespaces/") && strings.Contains(path, "/secrets/"):
			parts := strings.Split(strings.Trim(path, "/"), "/")
			name := parts[len(parts)-1]
			var obj map[string]any
			_ = json.Unmarshal(body, &obj)
			f.secrets[name] = obj
			f.secretWritePath[name] = path
			_ = json.NewEncoder(w).Encode(obj)
		case r.Method == http.MethodGet && strings.HasPrefix(path, "/api/v1/namespaces/") && strings.Contains(path, "/configmaps/"):
			key := configMapKeyFromPath(path)
			obj := f.configMaps[key]
			if obj == nil {
				http.Error(w, `{"kind":"Status","code":404}`, http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(obj)
		case r.Method == http.MethodPost && strings.HasPrefix(path, "/api/v1/namespaces/") && strings.HasSuffix(path, "/configmaps"):
			var obj map[string]any
			_ = json.Unmarshal(body, &obj)
			key := configMapKey(obj)
			if f.configMaps[key] != nil {
				http.Error(w, `{"kind":"Status","code":409}`, http.StatusConflict)
				return
			}
			meta, _ := obj["metadata"].(map[string]any)
			meta["resourceVersion"] = "1"
			f.configMaps[key] = obj
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(obj)
		case r.Method == http.MethodPut && strings.HasPrefix(path, "/api/v1/namespaces/") && strings.Contains(path, "/configmaps/"):
			var obj map[string]any
			_ = json.Unmarshal(body, &obj)
			f.configMaps[configMapKey(obj)] = obj
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

func configMapKeyFromPath(path string) string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) < 6 {
		return ""
	}
	return parts[3] + "/" + parts[len(parts)-1]
}

func configMapKey(obj map[string]any) string {
	meta, _ := obj["metadata"].(map[string]any)
	namespace, _ := meta["namespace"].(string)
	name, _ := meta["name"].(string)
	return namespace + "/" + name
}

func trstctlClusterIssuer(name string) map[string]any {
	return map[string]any{
		"apiVersion": "trstctl.com/v1alpha1",
		"kind":       "ClusterIssuer",
		"metadata":   map[string]any{"name": name, "resourceVersion": "10"},
		"spec":       map[string]any{"signerURL": testIssuerSignerURL},
	}
}

func trstctlIssuer(name, namespace string) map[string]any {
	return map[string]any{
		"apiVersion": "trstctl.com/v1alpha1",
		"kind":       "Issuer",
		"metadata":   map[string]any{"name": name, "namespace": namespace, "resourceVersion": "11"},
		"spec":       map[string]any{"signerURL": testIssuerSignerURL},
	}
}

func trstctlCertificate(name, namespace, secretName string) map[string]any {
	return map[string]any{
		"apiVersion": "trstctl.com/v1alpha1",
		"kind":       "Certificate",
		"metadata":   map[string]any{"name": name, "namespace": namespace, "resourceVersion": "12"},
		"spec": map[string]any{
			"secretName":   secretName,
			"commonName":   "web.apps.svc.cluster.local",
			"dnsNames":     []any{"web.apps.svc.cluster.local", "web.apps"},
			"keyAlgorithm": string(crypto.ECDSAP256),
			"issuerRef": map[string]any{
				"name":  "trstctl",
				"kind":  "ClusterIssuer",
				"group": "trstctl.com",
			},
		},
	}
}

func kubernetesCSR(name, signerName string, approved bool) map[string]any {
	csr := map[string]any{
		"apiVersion": "certificates.k8s.io/v1",
		"kind":       "CertificateSigningRequest",
		"metadata":   map[string]any{"name": name, "uid": "csr-uid-" + name, "resourceVersion": "20"},
		"spec": map[string]any{
			"signerName": signerName,
			"request":    "",
			"usages":     []any{"digital signature", "key encipherment", "server auth"},
		},
	}
	if approved {
		csr["status"] = map[string]any{"conditions": []any{
			map[string]any{"type": "Approved", "status": "True", "reason": "trstctl.test"},
		}}
	}
	return csr
}

func trstctlTrustBundle(name, caBundle string, namespaces ...string) map[string]any {
	targets := make([]any, 0, len(namespaces))
	for _, namespace := range namespaces {
		targets = append(targets, namespace)
	}
	return map[string]any{
		"apiVersion": "trstctl.com/v1alpha1",
		"kind":       "TrustBundle",
		"metadata":   map[string]any{"name": name, "uid": "bundle-uid-" + name, "resourceVersion": "30"},
		"spec": map[string]any{
			"caBundlePEM": caBundle,
			"target": map[string]any{
				"configMapName": "platform-ca-bundle",
				"key":           "ca-bundle.pem",
				"namespaces":    targets,
			},
		},
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
		return approveCertRequest(cr)
	}()}
	srv := httptest.NewServer(api.handler())
	defer srv.Close()

	controller := testIssuerController(t, k8s.New(srv.URL, "tok", "apps", srv.Client()), signer, "trstctl.com")
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

func TestClusterIssuerSignsApprovedRequestOutsideAgentNamespace(t *testing.T) {
	signer, _ := caSigner(t)
	api := newFakeIssuerAPI()
	api.clusterIssuers = []map[string]any{trstctlClusterIssuer("trstctl")}
	request := certRequest("remote-namespace", "trstctl", "trstctl.com", false)
	request["metadata"].(map[string]any)["namespace"] = "payments"
	request["spec"].(map[string]any)["request"] = csrRequestField(t)
	api.certificateRequests = []map[string]any{approveCertRequest(request)}
	srv := httptest.NewServer(api.handler())
	defer srv.Close()

	controller := testIssuerController(t, k8s.New(srv.URL, "tok", "apps", srv.Client()), signer, "trstctl.com")
	result, err := controller.Reconcile(context.Background(), "apps")
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if result.SignedRequests != 1 {
		t.Fatalf("signed %d remote CertificateRequests, want 1", result.SignedRequests)
	}
	if got := api.requestStatusPath["remote-namespace"]; got != "/apis/cert-manager.io/v1/namespaces/payments/certificaterequests/remote-namespace/status" {
		t.Fatalf("status written to %q, want originating payments namespace", got)
	}
}

func TestNamespacedIssuerSignsOnlyRequestsInItsOwnNamespace(t *testing.T) {
	signer, _ := caSigner(t)
	api := newFakeIssuerAPI()
	api.issuers = []map[string]any{trstctlIssuer("team-ca", "payments")}
	makeRequest := func(name, namespace string) map[string]any {
		request := certRequest(name, "team-ca", "trstctl.com", false)
		request["metadata"].(map[string]any)["namespace"] = namespace
		request["spec"].(map[string]any)["request"] = csrRequestField(t)
		request["spec"].(map[string]any)["issuerRef"].(map[string]any)["kind"] = "Issuer"
		return approveCertRequest(request)
	}
	api.certificateRequests = []map[string]any{makeRequest("same-namespace", "payments"), makeRequest("other-namespace", "apps")}
	srv := httptest.NewServer(api.handler())
	defer srv.Close()

	controller := testIssuerController(t, k8s.New(srv.URL, "tok", "apps", srv.Client()), signer, "trstctl.com")
	result, err := controller.Reconcile(context.Background(), "apps")
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if result.IssuersReady != 1 || result.SignedRequests != 1 || api.requestStatus["other-namespace"] != nil {
		t.Fatalf("namespace isolation failed: result=%+v statuses=%v", result, api.requestStatus)
	}
	if got := api.issuerStatusPath["team-ca"]; got != "/apis/trstctl.com/v1alpha1/namespaces/payments/issuers/team-ca/status" {
		t.Fatalf("Issuer status path %q, want payments namespace", got)
	}
	if got := api.requestStatusPath["same-namespace"]; got != "/apis/cert-manager.io/v1/namespaces/payments/certificaterequests/same-namespace/status" {
		t.Fatalf("CertificateRequest status path %q, want payments namespace", got)
	}
}

func TestIssuerControllerRefusesUnapprovedCertificateRequest(t *testing.T) {
	api := newFakeIssuerAPI()
	api.clusterIssuers = []map[string]any{trstctlClusterIssuer("trstctl")}
	api.certificateRequests = []map[string]any{func() map[string]any {
		cr := certRequest("unapproved", "trstctl", "trstctl.com", false)
		cr["spec"].(map[string]any)["request"] = csrRequestField(t)
		return cr
	}()}
	var calls int
	signer := k8s.SignerFunc(func(context.Context, []byte, time.Duration) ([]byte, error) {
		calls++
		return []byte("unexpected certificate"), nil
	})
	srv := httptest.NewServer(api.handler())
	defer srv.Close()
	controller := testIssuerController(t, k8s.New(srv.URL, "tok", "apps", srv.Client()), signer, "trstctl.com")
	result, err := controller.Reconcile(context.Background(), "apps")
	if err != nil || result.SignedRequests != 0 || calls != 0 || len(api.requestStatus) != 0 {
		t.Fatalf("unapproved request reached signer/status: result=%+v calls=%d status=%v err=%v", result, calls, api.requestStatus, err)
	}
}

func TestIssuerControllerRefusesMismatchedCAEndpoint(t *testing.T) {
	api := newFakeIssuerAPI()
	issuer := trstctlClusterIssuer("trstctl")
	issuer["spec"].(map[string]any)["signerURL"] = "https://other-ca.example.test/api/v1/ca/authorities/other/issue"
	api.clusterIssuers = []map[string]any{issuer}
	request := certRequest("wrong-ca", "trstctl", "trstctl.com", false)
	request["spec"].(map[string]any)["request"] = csrRequestField(t)
	api.certificateRequests = []map[string]any{approveCertRequest(request)}
	var signerCalls int
	signer := k8s.SignerFunc(func(context.Context, []byte, time.Duration) ([]byte, error) {
		signerCalls++
		return []byte("unexpected certificate"), nil
	})
	srv := httptest.NewServer(api.handler())
	defer srv.Close()
	controller := testIssuerController(t, k8s.New(srv.URL, "tok", "apps", srv.Client()), signer, "trstctl.com")
	result, err := controller.Reconcile(context.Background(), "apps")
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if result.ClusterIssuersReady != 0 || result.SignedRequests != 0 || signerCalls != 0 {
		t.Fatalf("mismatched CA was usable: ready=%d signed=%d signerCalls=%d", result.ClusterIssuersReady, result.SignedRequests, signerCalls)
	}
	if ready, _ := readyCondition(t, api.clusterIssuerStatus["trstctl"]); ready != "False" {
		t.Fatalf("mismatched ClusterIssuer Ready=%q, want False", ready)
	}
}

func TestIssuerTTLSecondsCapsRequestedDuration(t *testing.T) {
	api := newFakeIssuerAPI()
	issuer := trstctlClusterIssuer("trstctl")
	issuer["spec"].(map[string]any)["ttlSeconds"] = float64(1800)
	api.clusterIssuers = []map[string]any{issuer}
	request := certRequest("capped", "trstctl", "trstctl.com", false)
	request["spec"].(map[string]any)["request"] = csrRequestField(t)
	request["spec"].(map[string]any)["duration"] = "2h"
	api.certificateRequests = []map[string]any{approveCertRequest(request)}
	var gotTTL time.Duration
	baseSigner, _ := caSigner(t)
	signer := k8s.SignerFunc(func(ctx context.Context, csr []byte, ttl time.Duration) ([]byte, error) {
		gotTTL = ttl
		return baseSigner.Sign(ctx, csr, ttl)
	})
	srv := httptest.NewServer(api.handler())
	defer srv.Close()
	controller := testIssuerController(t, k8s.New(srv.URL, "tok", "apps", srv.Client()), signer, "trstctl.com")
	result, err := controller.Reconcile(context.Background(), "apps")
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if result.SignedRequests != 1 || gotTTL != 30*time.Minute {
		t.Fatalf("issuer ttlSeconds cap ignored: signed=%d ttl=%s, want 30m", result.SignedRequests, gotTTL)
	}
}

func TestIssuerRejectsUnsupportedOrInconsistentConfig(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(map[string]any)
		reason string
	}{
		{name: "missing-url", change: func(spec map[string]any) { delete(spec, "signerURL") }, reason: "SignerURLMismatch"},
		{name: "profile-not-served", change: func(spec map[string]any) { spec["profileName"] = "unwired-profile" }, reason: "UnsupportedProfile"},
		{name: "authority-id-mismatch", change: func(spec map[string]any) { spec["caAuthorityID"] = "other" }, reason: "CAAuthorityMismatch"},
		{name: "invalid-ttl", change: func(spec map[string]any) { spec["ttlSeconds"] = float64(0) }, reason: "InvalidTTLSeconds"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := newFakeIssuerAPI()
			issuer := trstctlClusterIssuer("trstctl")
			tc.change(issuer["spec"].(map[string]any))
			api.clusterIssuers = []map[string]any{issuer}
			request := certRequest("configured-request", "trstctl", "trstctl.com", false)
			request["spec"].(map[string]any)["request"] = csrRequestField(t)
			api.certificateRequests = []map[string]any{approveCertRequest(request)}
			var calls int
			signer := k8s.SignerFunc(func(context.Context, []byte, time.Duration) ([]byte, error) {
				calls++
				return nil, nil
			})
			srv := httptest.NewServer(api.handler())
			defer srv.Close()
			controller := testIssuerController(t, k8s.New(srv.URL, "tok", "apps", srv.Client()), signer, "trstctl.com")
			result, err := controller.Reconcile(context.Background(), "apps")
			if err != nil {
				t.Fatal(err)
			}
			if result.ClusterIssuersReady != 0 || result.SignedRequests != 0 || calls != 0 {
				t.Fatalf("invalid issuer became usable: ready=%d signed=%d calls=%d", result.ClusterIssuersReady, result.SignedRequests, calls)
			}
			condition, _ := api.clusterIssuerStatus["trstctl"]["status"].(map[string]any)
			conditions, _ := condition["conditions"].([]any)
			if len(conditions) == 0 {
				t.Fatal("invalid issuer has no Ready=False condition")
			}
			got := conditions[0].(map[string]any)
			if got["status"] != "False" || got["reason"] != tc.reason {
				t.Fatalf("issuer condition=%v, want False/%s", got, tc.reason)
			}
		})
	}
}

func TestIssuerTTLSecondsCapsNativeCSRAndCertificate(t *testing.T) {
	api := newFakeIssuerAPI()
	issuer := trstctlClusterIssuer("trstctl")
	issuer["spec"].(map[string]any)["ttlSeconds"] = float64(1800)
	api.clusterIssuers = []map[string]any{issuer}
	api.certificates = []map[string]any{trstctlCertificate("native-leaf", "apps", "native-leaf-tls")}
	csr := kubernetesCSR("native-csr-cap", "trstctl.com/trstctl", true)
	csr["spec"].(map[string]any)["request"] = csrDERRequestField(t)
	csr["spec"].(map[string]any)["expirationSeconds"] = float64(7200)
	api.kubernetesCSRs = []map[string]any{csr}
	baseSigner, _ := caSigner(t)
	var lifetimes []time.Duration
	signer := k8s.SignerFunc(func(ctx context.Context, csrDER []byte, ttl time.Duration) ([]byte, error) {
		lifetimes = append(lifetimes, ttl)
		return baseSigner.Sign(ctx, csrDER, ttl)
	})
	srv := httptest.NewServer(api.handler())
	defer srv.Close()
	controller := testIssuerController(t, k8s.New(srv.URL, "tok", "apps", srv.Client()), signer, "trstctl.com")
	result, err := controller.Reconcile(context.Background(), "apps")
	if err != nil {
		t.Fatal(err)
	}
	if result.NativeCertificatesIssued != 1 || result.KubernetesCSRsSigned != 1 || len(lifetimes) != 2 {
		t.Fatalf("native issuance incomplete: result=%+v lifetimes=%v", result, lifetimes)
	}
	for _, ttl := range lifetimes {
		if ttl != 30*time.Minute {
			t.Fatalf("native signer lifetime %s, want issuer 30m cap", ttl)
		}
	}
}

func TestIssuerControllerRequiresHTTPSOperatorEndpoint(t *testing.T) {
	for _, endpoint := range []string{"", "http://trstctl.local/issue", "https://user:pass@trstctl.local/issue", "https://trstctl.local/issue?token=secret", "https://trstctl.local/issue#fragment"} {
		if _, err := k8s.NewIssuerController(nil, nil, "trstctl.com", endpoint); err == nil {
			t.Fatalf("accepted unsafe signer endpoint %q", endpoint)
		}
	}
}

// A newly-started Kubernetes API server can reject a safe list request with
// 429 while its storage layer finishes initializing. The shipped controller
// must honor that backpressure and retry the read instead of turning a normal
// cluster startup into a failed certificate journey.
func TestIssuerControllerRetriesTransientSafeRead(t *testing.T) {
	api := newFakeIssuerAPI()
	api.clusterIssuers = []map[string]any{{
		"apiVersion": "trstctl.com/v1alpha1",
		"kind":       "ClusterIssuer",
		"metadata":   map[string]any{"name": "prod"},
		"spec":       map[string]any{"signerURL": testIssuerSignerURL},
	}}
	baseHandler := api.handler()
	var listAttempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/apis/trstctl.com/v1alpha1/clusterissuers" && listAttempts.Add(1) == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"kind":"Status","message":"storage is (re)initializing","code":429}`))
			return
		}
		baseHandler.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)

	controller := testIssuerController(t,
		k8s.New(srv.URL, "tok", "apps", srv.Client()),
		k8s.SignerFunc(func(_ context.Context, _ []byte, _ time.Duration) ([]byte, error) { return nil, nil }),
		"trstctl.com",
	)
	result, err := controller.Reconcile(context.Background(), "apps")
	if err != nil {
		t.Fatalf("reconcile after transient API pressure: %v", err)
	}
	if got := listAttempts.Load(); got != 2 {
		t.Fatalf("cluster issuer list attempts = %d, want exactly 2", got)
	}
	if result.ClusterIssuersReady != 1 {
		t.Fatalf("ready ClusterIssuers = %d, want 1", result.ClusterIssuersReady)
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

	controller := testIssuerController(t, k8s.New(srv.URL, "tok", "apps", srv.Client()), signer, "trstctl.com")
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
		return approveCertRequest(cr)
	}()}
	srv := httptest.NewServer(api.handler())
	defer srv.Close()

	controller := testIssuerController(t, k8s.New(srv.URL, "tok", "apps", srv.Client()), signer, "trstctl.com")
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

func TestIssuerControllerServesNativeCertificateCRDCAPK8S02(t *testing.T) {
	baseSigner, _ := caSigner(t)
	var gotCSR []byte
	signer := k8s.SignerFunc(func(ctx context.Context, csrDER []byte, ttl time.Duration) ([]byte, error) {
		gotCSR = append([]byte(nil), csrDER...)
		return baseSigner.Sign(ctx, csrDER, ttl)
	})
	api := newFakeIssuerAPI()
	api.clusterIssuers = []map[string]any{trstctlClusterIssuer("trstctl")}
	api.certificates = []map[string]any{trstctlCertificate("web", "apps", "web-tls")}
	srv := httptest.NewServer(api.handler())
	defer srv.Close()

	controller := testIssuerController(t, k8s.New(srv.URL, "tok", "apps", srv.Client()), signer, "trstctl.com")
	result, err := controller.Reconcile(context.Background(), "apps")
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if result.NativeCertificatesIssued != 1 {
		t.Fatalf("NativeCertificatesIssued = %d, want 1", result.NativeCertificatesIssued)
	}
	if len(gotCSR) == 0 {
		t.Fatal("native Certificate reconcile did not send a CSR to the signer")
	}
	info, err := crypto.InspectCSR(gotCSR)
	if err != nil {
		t.Fatalf("native Certificate CSR invalid: %v", err)
	}
	if info.CommonName != "web.apps.svc.cluster.local" || len(info.DNSNames) != 2 {
		t.Fatalf("CSR subject/SANs = CN %q DNS %v, want native Certificate spec values", info.CommonName, info.DNSNames)
	}

	ready, _ := readyCondition(t, api.certificateStatus["web"])
	if ready != "True" {
		t.Fatalf("native Certificate Ready = %q, want True", ready)
	}
	secretObj := api.secrets["web-tls"]
	if secretObj == nil {
		t.Fatal("native Certificate reconcile did not create Secret/web-tls")
	}
	certPEM := decodeSecretData(t, secretObj, "tls.crt")
	keyPEM := decodeSecretData(t, secretObj, "tls.key")
	if err := crypto.VerifyCertKeyMatchPEM(certPEM, keyPEM); err != nil {
		t.Fatalf("Secret/web-tls certificate and key do not match: %v", err)
	}
}

func TestClusterIssuerFulfillsNativeCertificateOutsideAgentNamespace(t *testing.T) {
	signer, _ := caSigner(t)
	api := newFakeIssuerAPI()
	api.clusterIssuers = []map[string]any{trstctlClusterIssuer("trstctl")}
	api.certificates = []map[string]any{trstctlCertificate("remote-native", "payments", "remote-native-tls")}
	srv := httptest.NewServer(api.handler())
	defer srv.Close()

	controller := testIssuerController(t, k8s.New(srv.URL, "tok", "apps", srv.Client()), signer, "trstctl.com")
	result, err := controller.Reconcile(context.Background(), "apps")
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if result.NativeCertificatesIssued != 1 {
		t.Fatalf("issued %d native Certificates, want 1", result.NativeCertificatesIssued)
	}
	if got := api.secretWritePath["remote-native-tls"]; got != "/api/v1/namespaces/payments/secrets" {
		t.Fatalf("Secret write path %q, want payments namespace", got)
	}
	if got := api.certificateStatusPath["remote-native"]; got != "/apis/trstctl.com/v1alpha1/namespaces/payments/certificates/remote-native/status" {
		t.Fatalf("Certificate status path %q, want payments namespace", got)
	}
}

func TestNativeKubernetesCSRRequiresExplicitNamespacedIssuerBinding(t *testing.T) {
	signer, _ := caSigner(t)
	api := newFakeIssuerAPI()
	api.issuers = []map[string]any{trstctlIssuer("team-ca", "payments")}
	makeCSR := func(name string, namespaceAnnotation bool) map[string]any {
		csr := kubernetesCSR(name, "trstctl.com/team-ca", true)
		csr["spec"].(map[string]any)["request"] = csrDERRequestField(t)
		annotations := map[string]any{"trstctl.com/issuer-kind": "Issuer"}
		if namespaceAnnotation {
			annotations["trstctl.com/issuer-namespace"] = "payments"
		}
		csr["metadata"].(map[string]any)["annotations"] = annotations
		return csr
	}
	api.kubernetesCSRs = []map[string]any{makeCSR("explicit-ns", true), makeCSR("missing-ns", false)}
	srv := httptest.NewServer(api.handler())
	defer srv.Close()

	controller := testIssuerController(t, k8s.New(srv.URL, "tok", "apps", srv.Client()), signer, "trstctl.com")
	result, err := controller.Reconcile(context.Background(), "apps")
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if result.KubernetesCSRsSigned != 1 || api.kubernetesCSRStatus["explicit-ns"] == nil || api.kubernetesCSRStatus["missing-ns"] != nil {
		t.Fatalf("native CSR namespace binding: signed=%d statuses=%v", result.KubernetesCSRsSigned, api.kubernetesCSRStatus)
	}
}

func TestNativeKubernetesCSRSignerNameCannotSelectAnotherIssuer(t *testing.T) {
	signer, _ := caSigner(t)
	api := newFakeIssuerAPI()
	api.clusterIssuers = []map[string]any{
		trstctlClusterIssuer("named-a"),
		trstctlClusterIssuer("named-b"),
		trstctlClusterIssuer("extra"),
	}
	makeCSR := func(name, signerName, annotatedName string) map[string]any {
		csr := kubernetesCSR(name, signerName, true)
		csr["spec"].(map[string]any)["request"] = csrDERRequestField(t)
		if annotatedName != "" {
			csr["metadata"].(map[string]any)["annotations"] = map[string]any{
				"trstctl.com/issuer-name": annotatedName,
			}
		}
		return csr
	}
	api.kubernetesCSRs = []map[string]any{
		makeCSR("annotation-cross-ca", "trstctl.com/named-a", "named-b"),
		makeCSR("extra-signer-path", "trstctl.com/named-a/extra", ""),
		makeCSR("matching-issuer", "trstctl.com/named-a", "named-a"),
	}
	srv := httptest.NewServer(api.handler())
	defer srv.Close()

	controller := testIssuerController(t, k8s.New(srv.URL, "tok", "apps", srv.Client()), signer, "trstctl.com")
	result, err := controller.Reconcile(context.Background(), "apps")
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if result.KubernetesCSRsSigned != 1 || len(api.kubernetesCSRStatus) != 1 || api.kubernetesCSRStatus["matching-issuer"] == nil {
		t.Fatalf("signer-name binding: signed=%d status_count=%d cross_ca=%t extra_path=%t matching=%t",
			result.KubernetesCSRsSigned, len(api.kubernetesCSRStatus),
			api.kubernetesCSRStatus["annotation-cross-ca"] != nil,
			api.kubernetesCSRStatus["extra-signer-path"] != nil,
			api.kubernetesCSRStatus["matching-issuer"] != nil)
	}
	postureByName := make(map[string]k8s.PostureResource, len(result.KubernetesCSRPosture))
	for _, resource := range result.KubernetesCSRPosture {
		postureByName[resource.Name] = resource
	}
	for name, reason := range map[string]string{
		"annotation-cross-ca": "issuer_binding_mismatch",
		"extra-signer-path":   "invalid_signer_name",
	} {
		resource := postureByName[name]
		if resource.State != "failed" || resource.Reason != reason {
			t.Errorf("%s posture = %s/%s, want failed/%s", name, resource.State, resource.Reason, reason)
		}
	}
}

func TestIssuerControllerSignsKubernetesCertificateSigningRequestsCAPK8S04(t *testing.T) {
	baseSigner, _ := caSigner(t)
	var gotTTL time.Duration
	signer := k8s.SignerFunc(func(ctx context.Context, csrDER []byte, ttl time.Duration) ([]byte, error) {
		gotTTL = ttl
		return baseSigner.Sign(ctx, csrDER, ttl)
	})
	api := newFakeIssuerAPI()
	api.clusterIssuers = []map[string]any{trstctlClusterIssuer("trstctl")}
	requestField := csrDERRequestField(t)
	api.kubernetesCSRs = []map[string]any{func() map[string]any {
		csr := kubernetesCSR("native-csr", "trstctl.com/trstctl", true)
		csr["spec"].(map[string]any)["request"] = requestField
		csr["spec"].(map[string]any)["expirationSeconds"] = float64(5400)
		return csr
	}()}
	srv := httptest.NewServer(api.handler())
	defer srv.Close()

	controller := testIssuerController(t, k8s.New(srv.URL, "tok", "apps", srv.Client()), signer, "trstctl.com")
	result, err := controller.Reconcile(context.Background(), "apps")
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if result.KubernetesCSRsSigned != 1 {
		t.Fatalf("KubernetesCSRsSigned = %d, want 1", result.KubernetesCSRsSigned)
	}
	if gotTTL != 90*time.Minute {
		t.Fatalf("signer TTL = %s, want 90m", gotTTL)
	}
	if !result.KubernetesCSRComplete || len(result.KubernetesCSRPosture) != 1 {
		t.Fatalf("Kubernetes CSR posture = %+v complete=%v, want one completed object", result.KubernetesCSRPosture, result.KubernetesCSRComplete)
	}
	csrPosture := result.KubernetesCSRPosture[0]
	if csrPosture.Name != "native-csr" || csrPosture.UID != "csr-uid-native-csr" || csrPosture.ResourceVersion != "21" || csrPosture.State != "ready" || csrPosture.Reason != "signed" || len(csrPosture.PublicHash) != 64 {
		t.Fatalf("Kubernetes CSR posture = %+v, want metadata-only signed receipt", csrPosture)
	}
	reportJSON, err := json.Marshal(result.PostureReport(controllerClusterID(), 30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(reportJSON), requestField) || strings.Contains(string(reportJSON), `"request":`) {
		t.Fatalf("controller posture report carried CSR bytes instead of its public hash: %s", reportJSON)
	}

	statusObject := api.kubernetesCSRStatus["native-csr"]
	approved, cert := conditionAndCertificate(t, statusObject, "Approved")
	if approved != "True" {
		t.Fatalf("CertificateSigningRequest Approved = %q, want preserved True", approved)
	}
	if ready, _ := conditionAndCertificate(t, statusObject, "Ready"); ready != "" {
		t.Fatalf("native CertificateSigningRequest wrote non-Kubernetes Ready condition %q", ready)
	}
	decoded, err := base64.StdEncoding.DecodeString(cert)
	if err != nil {
		t.Fatalf("status.certificate is not base64: %v", err)
	}
	if block, _ := pem.Decode(decoded); block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("status.certificate does not contain a PEM certificate")
	}
}

func conditionAndCertificate(t *testing.T, obj map[string]any, conditionType string) (string, string) {
	t.Helper()
	status, _ := obj["status"].(map[string]any)
	certificate, _ := status["certificate"].(string)
	conditions, _ := status["conditions"].([]any)
	for _, raw := range conditions {
		condition, _ := raw.(map[string]any)
		if condition["type"] == conditionType {
			value, _ := condition["status"].(string)
			return value, certificate
		}
	}
	return "", certificate
}

func TestIssuerControllerDistributesTrustBundlesCAPK8S07(t *testing.T) {
	signer, ca := caSigner(t)
	bundlePEM := string(ca.BundlePEM())
	api := newFakeIssuerAPI()
	api.trustBundles = []map[string]any{trstctlTrustBundle("platform-roots", bundlePEM, "apps", "payments")}
	srv := httptest.NewServer(api.handler())
	defer srv.Close()

	controller := testIssuerController(t, k8s.New(srv.URL, "tok", "apps", srv.Client()), signer, "trstctl.com")
	result, err := controller.Reconcile(context.Background(), "apps")
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if result.TrustBundlesDistributed != 2 {
		t.Fatalf("TrustBundlesDistributed = %d, want 2", result.TrustBundlesDistributed)
	}
	if !result.TrustBundleComplete || len(result.TrustBundlePosture) != 1 {
		t.Fatalf("TrustBundle posture = %+v complete=%v, want one completed object", result.TrustBundlePosture, result.TrustBundleComplete)
	}
	bundlePosture := result.TrustBundlePosture[0]
	if bundlePosture.Name != "platform-roots" || bundlePosture.UID != "bundle-uid-platform-roots" || bundlePosture.ResourceVersion != "31" || bundlePosture.State != "ready" || bundlePosture.Reason != "distributed" || len(bundlePosture.PublicHash) != 64 {
		t.Fatalf("TrustBundle posture = %+v, want metadata-only distribution receipt", bundlePosture)
	}
	report := result.PostureReport(controllerClusterID(), 30*time.Second)
	if report.CertificateSigning.Complete != result.KubernetesCSRComplete || !report.TrustBundles.Complete || report.ReconcileIntervalSeconds != 30 || report.ReportID == "" {
		t.Fatalf("controller posture report = %+v", report)
	}
	reportJSON, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(reportJSON), strings.TrimSpace(bundlePEM)) || strings.Contains(string(reportJSON), "BEGIN CERTIFICATE") || strings.Contains(string(reportJSON), "caBundlePEM") {
		t.Fatalf("controller posture report carried trust-bundle bytes instead of its public hash: %s", reportJSON)
	}

	for _, namespace := range []string{"apps", "payments"} {
		obj := api.configMaps[namespace+"/platform-ca-bundle"]
		if obj == nil {
			t.Fatalf("ConfigMap %s/platform-ca-bundle was not written", namespace)
		}
		data, _ := obj["data"].(map[string]any)
		if got, _ := data["ca-bundle.pem"].(string); got != bundlePEM {
			t.Fatalf("ConfigMap %s/platform-ca-bundle ca-bundle.pem = %q, want public CA bundle", namespace, got)
		}
		meta, _ := obj["metadata"].(map[string]any)
		labels, _ := meta["labels"].(map[string]any)
		if labels["trstctl.com/trust-bundle"] != "platform-roots" {
			t.Fatalf("ConfigMap %s labels = %+v, want trust-bundle owner label", namespace, labels)
		}
		if strings.Contains(strings.ToUpper(gotConfigMapData(t, obj, "ca-bundle.pem")), "PRIVATE KEY") {
			t.Fatalf("ConfigMap %s contains private-key material", namespace)
		}
	}
	ready, _ := readyCondition(t, api.trustBundleStatus["platform-roots"])
	if ready != "True" {
		t.Fatalf("TrustBundle Ready = %q, want True", ready)
	}
	status, _ := api.trustBundleStatus["platform-roots"]["status"].(map[string]any)
	if status["targets"] != float64(2) && status["targets"] != 2 {
		t.Fatalf("TrustBundle status targets = %#v, want 2", status["targets"])
	}
	if hash, _ := status["bundleSHA256"].(string); hash == "" {
		t.Fatalf("TrustBundle status missing bundleSHA256: %+v", status)
	}
}

func TestIssuerControllerRejectsPrivateKeyInTrustBundleCAPK8S07(t *testing.T) {
	signer, _ := caSigner(t)
	api := newFakeIssuerAPI()
	api.trustBundles = []map[string]any{trstctlTrustBundle("bad-roots", "-----BEGIN PRIVATE KEY-----\nS0VZ\n-----END PRIVATE KEY-----\n", "apps")}
	srv := httptest.NewServer(api.handler())
	defer srv.Close()

	controller := testIssuerController(t, k8s.New(srv.URL, "tok", "apps", srv.Client()), signer, "trstctl.com")
	result, err := controller.Reconcile(context.Background(), "apps")
	if err == nil || !strings.Contains(err.Error(), "only CERTIFICATE blocks") {
		t.Fatalf("Reconcile error = %v, want private-key rejection", err)
	}
	if len(api.configMaps) != 0 {
		t.Fatalf("private-key bundle wrote ConfigMaps: %+v", api.configMaps)
	}
	if api.trustBundleStatus["bad-roots"] != nil {
		t.Fatalf("private-key bundle was marked ready: %+v", api.trustBundleStatus["bad-roots"])
	}
	if result.TrustBundleComplete || result.TrustBundleFailureCode != "reconcile_failed" || len(result.TrustBundlePosture) != 1 || result.TrustBundlePosture[0].State != "failed" {
		t.Fatalf("failed TrustBundle posture = %+v complete=%v code=%q", result.TrustBundlePosture, result.TrustBundleComplete, result.TrustBundleFailureCode)
	}
}

func controllerClusterID() string {
	// Tests only need a valid public cluster identity; production obtains this from
	// Client.ClusterID(), which hashes the cluster trust anchor.
	return "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
}

func gotConfigMapData(t *testing.T, obj map[string]any, key string) string {
	t.Helper()
	data, ok := obj["data"].(map[string]any)
	if !ok {
		t.Fatal("ConfigMap has no data map")
	}
	value, ok := data[key].(string)
	if !ok {
		t.Fatalf("ConfigMap data missing %q", key)
	}
	return value
}
