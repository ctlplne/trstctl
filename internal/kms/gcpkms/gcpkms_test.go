package gcpkms_test

import (
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/kms/gcpkms"
)

const (
	testParent = "projects/p/locations/l/keyRings/r"
	testToken  = "ya29.gcp-access-token-do-not-log"
)

// fakeKMS is a faithful in-process double of Google Cloud KMS. It enforces OAuth2 Bearer
// auth like the real service and performs *real* signing via the crypto software boundary
// (locked keys), so the conformance harness's signature verification actually passes. It
// never imports crypto/*. Keys are stored by their key-version resource name.
type fakeKMS struct {
	srv   *httptest.Server
	token string
	mu    sync.Mutex
	keys  map[string]*crypto.LockedSigner // versionName -> signer
	algs  map[string]crypto.Algorithm     // versionName -> algorithm
}

func newFakeKMS(t *testing.T) *fakeKMS {
	t.Helper()
	f := &fakeKMS{
		token: testToken,
		keys:  map[string]*crypto.LockedSigner{},
		algs:  map[string]crypto.Algorithm{},
	}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(func() {
		f.srv.Close()
		for _, k := range f.keys {
			k.Destroy()
		}
	})
	return f
}

func (f *fakeKMS) handle(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+f.token {
		http.Error(w, `{"error":{"code":401,"status":"UNAUTHENTICATED"}}`, http.StatusUnauthorized)
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	// Real Cloud KMS serves under /v1/; the test endpoint may omit it. Normalize to a
	// leading-slash-free resource path so stored names match what real GCP returns.
	path := strings.TrimPrefix(r.URL.Path, "/v1/")
	path = strings.TrimPrefix(path, "/")

	switch {
	// Create crypto key: POST .../cryptoKeys?cryptoKeyId=ID
	case r.Method == http.MethodPost && strings.HasSuffix(path, "/cryptoKeys"):
		keyID := r.URL.Query().Get("cryptoKeyId")
		if keyID == "" {
			http.Error(w, `{"error":{"code":400,"status":"INVALID_ARGUMENT"}}`, http.StatusBadRequest)
			return
		}
		var in struct {
			Purpose         string `json:"purpose"`
			VersionTemplate struct {
				Algorithm string `json:"algorithm"`
			} `json:"versionTemplate"`
		}
		_ = json.Unmarshal(body, &in)
		alg := algFor(in.VersionTemplate.Algorithm)
		if in.Purpose != "ASYMMETRIC_SIGN" || alg == "" {
			http.Error(w, `{"error":{"code":400,"status":"INVALID_ARGUMENT"}}`, http.StatusBadRequest)
			return
		}
		ls, err := crypto.GenerateLockedKey(alg)
		if err != nil {
			http.Error(w, `{"error":{"code":500,"status":"INTERNAL"}}`, http.StatusInternalServerError)
			return
		}
		cryptoKey := path + "/" + keyID
		versionName := cryptoKey + "/cryptoKeyVersions/1"
		f.mu.Lock()
		f.keys[versionName] = ls
		f.algs[versionName] = alg
		f.mu.Unlock()
		writeJSON(w, map[string]string{"name": cryptoKey})

	// Get public key: GET .../cryptoKeyVersions/N/publicKey
	case r.Method == http.MethodGet && strings.HasSuffix(path, "/publicKey"):
		versionName := strings.TrimSuffix(path, "/publicKey")
		ls := f.key(versionName)
		if ls == nil {
			http.Error(w, `{"error":{"code":404,"status":"NOT_FOUND"}}`, http.StatusNotFound)
			return
		}
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: ls.Public().DER})
		writeJSON(w, map[string]string{"pem": string(pemBytes)})

	// Asymmetric sign: POST .../cryptoKeyVersions/N:asymmetricSign
	case r.Method == http.MethodPost && strings.HasSuffix(path, ":asymmetricSign"):
		versionName := strings.TrimSuffix(path, ":asymmetricSign")
		ls := f.key(versionName)
		if ls == nil {
			http.Error(w, `{"error":{"code":404,"status":"NOT_FOUND"}}`, http.StatusNotFound)
			return
		}
		var in struct {
			Digest map[string]string `json:"digest"`
		}
		_ = json.Unmarshal(body, &in)
		digest, hash, ok := decodeDigest(in.Digest)
		if !ok {
			http.Error(w, `{"error":{"code":400,"status":"INVALID_ARGUMENT"}}`, http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		alg := f.algs[versionName]
		f.mu.Unlock()
		sig, err := ls.SignDigest(digest, optsFor(alg, hash))
		if err != nil {
			http.Error(w, `{"error":{"code":500,"status":"INTERNAL"}}`, http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]string{"signature": base64.StdEncoding.EncodeToString(sig)})

	default:
		http.Error(w, `{"error":{"code":404,"status":"NOT_FOUND"}}`, http.StatusNotFound)
	}
}

func (f *fakeKMS) key(versionName string) *crypto.LockedSigner {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.keys[versionName]
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// decodeDigest reads the Cloud KMS Digest oneof (sha256/sha384/sha512) and returns the raw
// digest plus the hash it names. The signer and the double must agree on this field.
func decodeDigest(d map[string]string) ([]byte, crypto.Hash, bool) {
	var (
		enc  string
		hash crypto.Hash
	)
	switch {
	case d["sha256"] != "":
		enc, hash = d["sha256"], crypto.SHA256
	case d["sha384"] != "":
		enc, hash = d["sha384"], crypto.SHA384
	case d["sha512"] != "":
		enc, hash = d["sha512"], crypto.SHA512
	default:
		return nil, "", false
	}
	raw, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return nil, "", false
	}
	return raw, hash, true
}

func algFor(gcpAlg string) crypto.Algorithm {
	switch gcpAlg {
	case "RSA_SIGN_PKCS1_2048_SHA256":
		return crypto.RSA2048
	case "RSA_SIGN_PKCS1_3072_SHA256":
		return crypto.RSA3072
	case "RSA_SIGN_PKCS1_4096_SHA256":
		return crypto.RSA4096
	case "EC_SIGN_P256_SHA256":
		return crypto.ECDSAP256
	case "EC_SIGN_P384_SHA384":
		return crypto.ECDSAP384
	}
	return ""
}

// optsFor mirrors the signing scheme bound to the key version: RSA versions are PKCS#1
// v1.5; the hash is whichever the request named.
func optsFor(alg crypto.Algorithm, hash crypto.Hash) crypto.SignOptions {
	o := crypto.SignOptions{Hash: hash}
	switch alg {
	case crypto.RSA2048, crypto.RSA3072, crypto.RSA4096:
		o.RSAPadding = crypto.RSAPKCS1v15
	}
	return o
}

func TestGCPKMSConforms(t *testing.T) {
	f := newFakeKMS(t)
	b := gcpkms.New(testParent, gcpkms.Credentials{BearerToken: testToken},
		gcpkms.WithEndpoint(f.srv.URL), gcpkms.WithHTTPClient(f.srv.Client()))
	if err := crypto.ConformBackend(b, []crypto.Algorithm{crypto.RSA2048, crypto.ECDSAP256}); err != nil {
		t.Fatalf("GCP KMS backend failed conformance: %v", err)
	}
}

func TestBadTokenRejected(t *testing.T) {
	f := newFakeKMS(t)
	b := gcpkms.New(testParent, gcpkms.Credentials{BearerToken: "wrong-token"},
		gcpkms.WithEndpoint(f.srv.URL), gcpkms.WithHTTPClient(f.srv.Client()))
	_, err := b.GenerateKey(crypto.ECDSAP256)
	if err == nil {
		t.Fatal("GenerateKey succeeded with a wrong token; Bearer auth not enforced")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Fatalf("expected a 401 fail-closed error, got: %v", err)
	}
}

// TestCredentialsNeverLogged checks that no error surfaced by the backend ever embeds the
// access token, even when the remote rejects the call.
func TestCredentialsNeverLogged(t *testing.T) {
	f := newFakeKMS(t)
	b := gcpkms.New(testParent, gcpkms.Credentials{BearerToken: testToken},
		gcpkms.WithEndpoint(f.srv.URL), gcpkms.WithHTTPClient(f.srv.Client()))

	// A successful round trip first, to exercise the signing path.
	signer, err := b.GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if _, err := signer.Sign([]byte("probe"), crypto.SignOptions{Hash: crypto.SHA256}); err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Now force an error and confirm the token does not leak into it.
	bad := gcpkms.New(testParent, gcpkms.Credentials{BearerToken: testToken},
		gcpkms.WithEndpoint(f.srv.URL), gcpkms.WithHTTPClient(f.srv.Client()))
	if _, err := bad.GenerateKey(crypto.Algorithm("bogus-alg")); err == nil {
		t.Fatal("GenerateKey accepted an unsupported algorithm")
	} else if strings.Contains(err.Error(), testToken) {
		t.Fatalf("error leaked the access token: %v", err)
	}
}
