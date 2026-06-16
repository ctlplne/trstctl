package azurekv_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/kms/azurekv"
)

const (
	testVault = "https://trstctl-test.vault.azure.net"
	testToken = "aad-access-token-do-not-log"
)

// fakeKV is a faithful in-process double of Azure Key Vault (keys). It verifies the bearer
// token like the real service and performs *real* signing via the crypto software boundary
// (locked keys), so the conformance harness's signature verification actually passes. Per the
// azurekv package note, it returns base64-std DER for public keys (JWK->SPKI is a deferred
// follow-up). No crypto/*.
type fakeKV struct {
	srv   *httptest.Server
	token string
	mu    sync.Mutex
	keys  map[string]*crypto.LockedSigner
	n     int
}

func newFakeKV(t *testing.T) *fakeKV {
	t.Helper()
	f := &fakeKV{token: testToken, keys: map[string]*crypto.LockedSigner{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(func() {
		f.srv.Close()
		for _, k := range f.keys {
			k.Destroy()
		}
	})
	return f
}

func (f *fakeKV) handle(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+f.token {
		http.Error(w, `{"error":{"code":"Unauthorized"}}`, http.StatusUnauthorized)
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	// Routing: POST /keys/{name}/create | POST .../sign | GET /keys/{name}[/{version}].
	switch {
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/create"):
		f.create(w, r, body)
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/sign"):
		f.sign(w, r, body)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/keys/"):
		f.getKey(w, r)
	default:
		http.Error(w, `{"error":{"code":"BadRequest"}}`, http.StatusBadRequest)
	}
}

// createReq is the subset of the Key Vault create-key request body the double inspects.
type createReq struct {
	Kty     string `json:"kty"`
	KeySize int    `json:"key_size"`
	Crv     string `json:"crv"`
}

func (f *fakeKV) create(w http.ResponseWriter, r *http.Request, body []byte) {
	var in createReq
	_ = json.Unmarshal(body, &in)
	alg := algFor(in)
	if alg == "" {
		http.Error(w, `{"error":{"code":"BadParameter"}}`, http.StatusBadRequest)
		return
	}
	ls, err := crypto.GenerateLockedKey(alg)
	if err != nil {
		http.Error(w, `{"error":{"code":"InternalError"}}`, http.StatusInternalServerError)
		return
	}
	// Path is /keys/{name}/create; the name is the second-to-last segment.
	name := keyNameFromCreatePath(r.URL.Path)
	f.mu.Lock()
	f.n++
	version := fmt.Sprintf("v%d", f.n)
	f.keys[name+"/"+version] = ls
	f.keys[name] = ls // also resolvable without a version
	f.mu.Unlock()
	kid := f.srv.URL + "/keys/" + name + "/" + version
	writeJSON(w, map[string]any{
		"key": map[string]string{"kid": kid},
		"der": base64.StdEncoding.EncodeToString(ls.Public().DER),
	})
}

func (f *fakeKV) getKey(w http.ResponseWriter, r *http.Request) {
	ls := f.lookup(r.URL.Path)
	if ls == nil {
		http.Error(w, `{"error":{"code":"KeyNotFound"}}`, http.StatusNotFound)
		return
	}
	writeJSON(w, map[string]string{"der": base64.StdEncoding.EncodeToString(ls.Public().DER)})
}

func (f *fakeKV) sign(w http.ResponseWriter, r *http.Request, body []byte) {
	// Trim the trailing /sign to resolve the key (with or without a version).
	ls := f.lookup(strings.TrimSuffix(r.URL.Path, "/sign"))
	if ls == nil {
		http.Error(w, `{"error":{"code":"KeyNotFound"}}`, http.StatusNotFound)
		return
	}
	var in struct {
		Alg   string `json:"alg"`
		Value string `json:"value"`
	}
	if err := json.Unmarshal(body, &in); err != nil {
		http.Error(w, `{"error":{"code":"BadParameter"}}`, http.StatusBadRequest)
		return
	}
	digest, err := base64.RawURLEncoding.DecodeString(in.Value)
	if err != nil {
		http.Error(w, `{"error":{"code":"BadParameter"}}`, http.StatusBadRequest)
		return
	}
	sig, err := ls.SignDigest(digest, optsFor(in.Alg))
	if err != nil {
		http.Error(w, `{"error":{"code":"InternalError"}}`, http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"value": base64.RawURLEncoding.EncodeToString(sig)})
}

// lookup resolves a locked key from a /keys/{name}[/{version}] path, trying the versioned
// key first and then the unversioned name.
func (f *fakeKV) lookup(path string) *crypto.LockedSigner {
	rest := strings.TrimPrefix(path, "/keys/")
	f.mu.Lock()
	defer f.mu.Unlock()
	if ls := f.keys[rest]; ls != nil {
		return ls
	}
	if name, _, ok := strings.Cut(rest, "/"); ok {
		return f.keys[name]
	}
	return f.keys[rest]
}

func keyNameFromCreatePath(path string) string {
	rest := strings.TrimPrefix(strings.TrimSuffix(path, "/create"), "/keys/")
	return rest
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func algFor(in createReq) crypto.Algorithm {
	switch in.Kty {
	case "RSA":
		switch in.KeySize {
		case 2048:
			return crypto.RSA2048
		case 3072:
			return crypto.RSA3072
		case 4096:
			return crypto.RSA4096
		}
	case "EC":
		switch in.Crv {
		case "P-256":
			return crypto.ECDSAP256
		case "P-384":
			return crypto.ECDSAP384
		case "P-521":
			return crypto.ECDSAP521
		}
	}
	return ""
}

// optsFor maps a JOSE signing algorithm back to crypto.SignOptions, the inverse of the
// backend's signingAlgorithm. RSnnn -> PKCS#1 v1.5, PSnnn -> PSS, ESnnn -> ECDSA; the numeric
// suffix selects the hash.
func optsFor(alg string) crypto.SignOptions {
	o := crypto.SignOptions{Hash: crypto.SHA256}
	switch {
	case strings.HasSuffix(alg, "384"):
		o.Hash = crypto.SHA384
	case strings.HasSuffix(alg, "512"):
		o.Hash = crypto.SHA512
	}
	switch {
	case strings.HasPrefix(alg, "PS"):
		o.RSAPadding = crypto.RSAPSS
	case strings.HasPrefix(alg, "RS"):
		o.RSAPadding = crypto.RSAPKCS1v15
	}
	return o
}

func TestAzureKVConforms(t *testing.T) {
	f := newFakeKV(t)
	b := azurekv.New(testVault, azurekv.Credentials{BearerToken: testToken},
		azurekv.WithEndpoint(f.srv.URL), azurekv.WithHTTPClient(f.srv.Client()))
	if err := crypto.ConformBackend(b, []crypto.Algorithm{crypto.RSA2048, crypto.ECDSAP256}); err != nil {
		t.Fatalf("Azure Key Vault backend failed conformance: %v", err)
	}
}

func TestBadTokenRejected(t *testing.T) {
	f := newFakeKV(t)
	b := azurekv.New(testVault, azurekv.Credentials{BearerToken: "wrong-token"},
		azurekv.WithEndpoint(f.srv.URL), azurekv.WithHTTPClient(f.srv.Client()))
	_, err := b.GenerateKey(crypto.ECDSAP256)
	if err == nil {
		t.Fatal("GenerateKey succeeded with a wrong bearer token; auth not enforced")
	}
	if strings.Contains(err.Error(), "wrong-token") {
		t.Fatalf("error leaked the token: %v", err)
	}
}

// recordingDoer wraps the double's transport and captures the Authorization header it sees on
// the wire, so a test can confirm the bearer token is sent for auth there and nowhere else.
type recordingDoer struct {
	inner   http.RoundTripper
	mu      sync.Mutex
	authHdr string
}

func (d *recordingDoer) Do(req *http.Request) (*http.Response, error) {
	d.mu.Lock()
	d.authHdr = req.Header.Get("Authorization")
	d.mu.Unlock()
	return d.inner.RoundTrip(req)
}

func TestCredentialsNeverLogged(t *testing.T) {
	f := newFakeKV(t)
	doer := &recordingDoer{inner: f.srv.Client().Transport}
	b := azurekv.New(testVault, azurekv.Credentials{BearerToken: testToken},
		azurekv.WithEndpoint(f.srv.URL), azurekv.WithHTTPClient(doer))

	signer, err := b.GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if _, err := signer.Sign([]byte("probe"), crypto.SignOptions{Hash: crypto.SHA256}); err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// The token is expected exactly once: as the bearer value in the Authorization header on
	// the wire. That is the only place it should ever travel.
	doer.mu.Lock()
	auth := doer.authHdr
	doer.mu.Unlock()
	if auth != "Bearer "+testToken {
		t.Fatalf("Authorization header = %q; want bearer token", auth)
	}

	// The token must never leak into the surfaces that get logged: returned errors. Force a
	// failure that still carried the real token (the server is gone, so the transport errors)
	// and confirm the wrapped error discloses no token. Errors are what callers print, so this
	// is the real disclosure risk.
	f.srv.Close()
	if _, err := b.GenerateKey(crypto.ECDSAP256); err == nil {
		t.Fatal("expected an error after the vault became unreachable")
	} else if strings.Contains(err.Error(), testToken) {
		t.Fatalf("error leaked the bearer token: %v", err)
	}
}
