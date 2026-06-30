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
		"metadata":   map[string]any{"name": name, "resourceVersion": "20"},
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
		"metadata":   map[string]any{"name": name, "resourceVersion": "30"},
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
	api.kubernetesCSRs = []map[string]any{func() map[string]any {
		csr := kubernetesCSR("native-csr", "trstctl.com/trstctl", true)
		csr["spec"].(map[string]any)["request"] = csrDERRequestField(t)
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

	ready, cert := readyCondition(t, api.kubernetesCSRStatus["native-csr"])
	if ready != "True" {
		t.Fatalf("CertificateSigningRequest Ready = %q, want True", ready)
	}
	decoded, err := base64.StdEncoding.DecodeString(cert)
	if err != nil {
		t.Fatalf("status.certificate is not base64: %v", err)
	}
	if block, _ := pem.Decode(decoded); block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("status.certificate does not contain a PEM certificate")
	}
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
	_, err := controller.Reconcile(context.Background(), "apps")
	if err == nil || !strings.Contains(err.Error(), "only CERTIFICATE blocks") {
		t.Fatalf("Reconcile error = %v, want private-key rejection", err)
	}
	if len(api.configMaps) != 0 {
		t.Fatalf("private-key bundle wrote ConfigMaps: %+v", api.configMaps)
	}
	if api.trustBundleStatus["bad-roots"] != nil {
		t.Fatalf("private-key bundle was marked ready: %+v", api.trustBundleStatus["bad-roots"])
	}
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
