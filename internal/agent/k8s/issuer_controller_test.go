// SPDX-License-Identifier: MPL-2.0

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

type fakeIssuerAPI struct {
	mu sync.Mutex

	clusterIssuers      []map[string]any
	issuers             []map[string]any
	certificateRequests []map[string]any
	certificates        []map[string]any
	kubernetesCSRs      []map[string]any
	trustBundles        []map[string]any

	clusterIssuerStatus map[string]map[string]any
	issuerStatus        map[string]map[string]any
	requestStatus       map[string]map[string]any
	certificateStatus   map[string]map[string]any
	kubernetesCSRStatus map[string]map[string]any
	trustBundleStatus   map[string]map[string]any
	secrets             map[string]map[string]any
	configMaps          map[string]map[string]any
}

func newFakeIssuerAPI() *fakeIssuerAPI {
	return &fakeIssuerAPI{
		clusterIssuerStatus: map[string]map[string]any{},
		issuerStatus:        map[string]map[string]any{},
		requestStatus:       map[string]map[string]any{},
		certificateStatus:   map[string]map[string]any{},
		kubernetesCSRStatus: map[string]map[string]any{},
		trustBundleStatus:   map[string]map[string]any{},
		secrets:             map[string]map[string]any{},
		configMaps:          map[string]map[string]any{},
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
		case r.Method == http.MethodGet && path == "/apis/trstctl.com/v1alpha1/namespaces/apps/certificates":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"apiVersion": "trstctl.com/v1alpha1",
				"kind":       "CertificateList",
				"items":      f.certificates,
			})
		case r.Method == http.MethodPut && strings.HasPrefix(path, "/apis/trstctl.com/v1alpha1/namespaces/apps/certificates/") && strings.HasSuffix(path, "/status"):
			name := nameBeforeStatus(path)
			var obj map[string]any
			_ = json.Unmarshal(body, &obj)
			f.certificateStatus[name] = obj
			_ = json.NewEncoder(w).Encode(obj)
		case r.Method == http.MethodGet && strings.HasPrefix(path, "/api/v1/namespaces/apps/secrets/"):
			parts := strings.Split(strings.Trim(path, "/"), "/")
			name := parts[len(parts)-1]
			obj := f.secrets[name]
			if obj == nil {
				http.Error(w, `{"kind":"Status","code":404}`, http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(obj)
		case r.Method == http.MethodPost && path == "/api/v1/namespaces/apps/secrets":
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
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(obj)
		case r.Method == http.MethodPut && strings.HasPrefix(path, "/api/v1/namespaces/apps/secrets/"):
			parts := strings.Split(strings.Trim(path, "/"), "/")
			name := parts[len(parts)-1]
			var obj map[string]any
			_ = json.Unmarshal(body, &obj)
			f.secrets[name] = obj
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

	controller := k8s.NewIssuerController(
		k8s.New(srv.URL, "tok", "apps", srv.Client()),
		k8s.SignerFunc(func(_ context.Context, _ []byte) ([]byte, error) { return nil, nil }),
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

func TestIssuerControllerServesNativeCertificateCRDCAPK8S02(t *testing.T) {
	baseSigner, _ := caSigner(t)
	var gotCSR []byte
	signer := k8s.SignerFunc(func(ctx context.Context, csrDER []byte) ([]byte, error) {
		gotCSR = append([]byte(nil), csrDER...)
		return baseSigner.Sign(ctx, csrDER)
	})
	api := newFakeIssuerAPI()
	api.clusterIssuers = []map[string]any{trstctlClusterIssuer("trstctl")}
	api.certificates = []map[string]any{trstctlCertificate("web", "apps", "web-tls")}
	srv := httptest.NewServer(api.handler())
	defer srv.Close()

	controller := k8s.NewIssuerController(k8s.New(srv.URL, "tok", "apps", srv.Client()), signer, "trstctl.com")
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

func TestIssuerControllerSignsKubernetesCertificateSigningRequestsCAPK8S04(t *testing.T) {
	signer, _ := caSigner(t)
	api := newFakeIssuerAPI()
	api.clusterIssuers = []map[string]any{trstctlClusterIssuer("trstctl")}
	requestField := csrDERRequestField(t)
	api.kubernetesCSRs = []map[string]any{func() map[string]any {
		csr := kubernetesCSR("native-csr", "trstctl.com/trstctl", true)
		csr["spec"].(map[string]any)["request"] = requestField
		return csr
	}()}
	srv := httptest.NewServer(api.handler())
	defer srv.Close()

	controller := k8s.NewIssuerController(k8s.New(srv.URL, "tok", "apps", srv.Client()), signer, "trstctl.com")
	result, err := controller.Reconcile(context.Background(), "apps")
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if result.KubernetesCSRsSigned != 1 {
		t.Fatalf("KubernetesCSRsSigned = %d, want 1", result.KubernetesCSRsSigned)
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

	controller := k8s.NewIssuerController(k8s.New(srv.URL, "tok", "apps", srv.Client()), signer, "trstctl.com")
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

	controller := k8s.NewIssuerController(k8s.New(srv.URL, "tok", "apps", srv.Client()), signer, "trstctl.com")
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
