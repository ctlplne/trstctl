package awskms_test

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"trustctl.io/trustctl/internal/crypto"
	"trustctl.io/trustctl/internal/kms/awskms"
)

const (
	testAK = "AKIAKMSTEST"
	testSK = "kms-secret-do-not-log"
)

// fakeKMS is a faithful in-process double of AWS KMS. It verifies SigV4 like the real
// service and performs *real* signing via the crypto software boundary (locked keys), so
// the conformance harness's signature verification actually passes. No crypto/*.
type fakeKMS struct {
	srv      *httptest.Server
	ak       string
	sk       string
	mu       sync.Mutex
	keys     map[string]*crypto.LockedSigner
	disabled map[string]bool // KMS DisableKey: a disabled key refuses to sign
	deleted  map[string]bool // KMS ScheduleKeyDeletion: PendingDeletion, refuses to sign
	n        int
}

func newFakeKMS(t *testing.T) *fakeKMS {
	t.Helper()
	f := &fakeKMS{ak: testAK, sk: testSK, keys: map[string]*crypto.LockedSigner{}, disabled: map[string]bool{}, deleted: map[string]bool{}}
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
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if !verifySigV4(r, body, f.ak, f.sk) {
		http.Error(w, `{"__type":"SignatureDoesNotMatch"}`, http.StatusForbidden)
		return
	}
	// Decode into RawMessage so a request mixing string and numeric fields (e.g.
	// ScheduleKeyDeletion's PendingWindowInDays) decodes; KeyId is then read as a
	// string. This faithfully models the KMS JSON 1.1 wire shape.
	var raw map[string]json.RawMessage
	_ = json.Unmarshal(body, &raw)
	in := map[string]string{}
	for k, v := range raw {
		var s string
		if json.Unmarshal(v, &s) == nil {
			in[k] = s
		}
	}
	switch r.Header.Get("X-Amz-Target") {
	case "TrentService.CreateKey":
		alg := algFor(in["KeySpec"])
		if alg == "" {
			http.Error(w, `{"__type":"ValidationException"}`, http.StatusBadRequest)
			return
		}
		ls, err := crypto.GenerateLockedKey(alg)
		if err != nil {
			http.Error(w, `{"__type":"KMSInternalException"}`, http.StatusInternalServerError)
			return
		}
		f.mu.Lock()
		f.n++
		id := "key-" + hex.EncodeToString([]byte{byte(f.n)})
		f.keys[id] = ls
		f.mu.Unlock()
		writeJSON(w, map[string]any{"KeyMetadata": map[string]string{"KeyId": id}})
	case "TrentService.GetPublicKey":
		ls := f.key(in["KeyId"])
		if ls == nil {
			http.Error(w, `{"__type":"NotFoundException"}`, http.StatusBadRequest)
			return
		}
		writeJSON(w, map[string]string{"PublicKey": base64.StdEncoding.EncodeToString(ls.Public().DER)})
	case "TrentService.Sign":
		ls := f.key(in["KeyId"])
		if ls == nil {
			http.Error(w, `{"__type":"NotFoundException"}`, http.StatusBadRequest)
			return
		}
		// A disabled or pending-deletion key cannot sign — KMS returns
		// KMSInvalidStateException. This is what makes Revoke/Zeroize fail-closed.
		f.mu.Lock()
		bad := f.disabled[in["KeyId"]] || f.deleted[in["KeyId"]]
		f.mu.Unlock()
		if bad {
			http.Error(w, `{"__type":"KMSInvalidStateException"}`, http.StatusBadRequest)
			return
		}
		digest, err := base64.StdEncoding.DecodeString(in["Message"])
		if err != nil {
			http.Error(w, `{"__type":"ValidationException"}`, http.StatusBadRequest)
			return
		}
		sig, err := ls.SignDigest(digest, optsFor(in["SigningAlgorithm"]))
		if err != nil {
			http.Error(w, `{"__type":"KMSInternalException"}`, http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]string{"Signature": base64.StdEncoding.EncodeToString(sig)})
	case "TrentService.DisableKey":
		if f.key(in["KeyId"]) == nil {
			http.Error(w, `{"__type":"NotFoundException"}`, http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		f.disabled[in["KeyId"]] = true
		f.mu.Unlock()
		writeJSON(w, map[string]any{})
	case "TrentService.ScheduleKeyDeletion":
		if f.key(in["KeyId"]) == nil {
			http.Error(w, `{"__type":"NotFoundException"}`, http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		f.deleted[in["KeyId"]] = true
		f.mu.Unlock()
		writeJSON(w, map[string]any{"KeyId": in["KeyId"], "DeletionDate": 0})
	default:
		http.Error(w, `{"__type":"UnknownOperationException"}`, http.StatusBadRequest)
	}
}

func (f *fakeKMS) key(id string) *crypto.LockedSigner {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.keys[id]
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	_ = json.NewEncoder(w).Encode(v)
}

func algFor(spec string) crypto.Algorithm {
	switch spec {
	case "RSA_2048":
		return crypto.RSA2048
	case "RSA_3072":
		return crypto.RSA3072
	case "RSA_4096":
		return crypto.RSA4096
	case "ECC_NIST_P256":
		return crypto.ECDSAP256
	case "ECC_NIST_P384":
		return crypto.ECDSAP384
	case "ECC_NIST_P521":
		return crypto.ECDSAP521
	}
	return ""
}

func optsFor(sa string) crypto.SignOptions {
	o := crypto.SignOptions{Hash: crypto.SHA256}
	switch {
	case strings.HasSuffix(sa, "SHA_384"):
		o.Hash = crypto.SHA384
	case strings.HasSuffix(sa, "SHA_512"):
		o.Hash = crypto.SHA512
	}
	switch {
	case strings.Contains(sa, "PSS"):
		o.RSAPadding = crypto.RSAPSS
	case strings.HasPrefix(sa, "RSASSA"):
		o.RSAPadding = crypto.RSAPKCS1v15
	}
	return o
}

// verifySigV4 reconstructs the canonical request and recomputes the signature under the
// test secret, exactly like the real service. Reads service/region from the cred scope.
func verifySigV4(r *http.Request, body []byte, ak, sk string) bool {
	auth := r.Header.Get("Authorization")
	const algo = "AWS4-HMAC-SHA256 "
	if !strings.HasPrefix(auth, algo) {
		return false
	}
	cred, signedHeaders, sig := "", "", ""
	for _, f := range strings.Split(auth[len(algo):], ",") {
		f = strings.TrimSpace(f)
		switch {
		case strings.HasPrefix(f, "Credential="):
			cred = strings.TrimPrefix(f, "Credential=")
		case strings.HasPrefix(f, "SignedHeaders="):
			signedHeaders = strings.TrimPrefix(f, "SignedHeaders=")
		case strings.HasPrefix(f, "Signature="):
			sig = strings.TrimPrefix(f, "Signature=")
		}
	}
	scope := strings.SplitN(cred, "/", 2)
	if len(scope) != 2 || signedHeaders == "" || sig == "" {
		return false
	}
	cs := strings.Split(scope[1], "/")
	if scope[0] != ak || len(cs) != 4 || cs[3] != "aws4_request" {
		return false
	}
	date, region, svc := cs[0], cs[1], cs[2]
	var canonHeaders strings.Builder
	for _, h := range strings.Split(signedHeaders, ";") {
		v := strings.TrimSpace(r.Header.Get(h))
		if h == "host" {
			v = r.Host
		}
		canonHeaders.WriteString(h + ":" + v + "\n")
	}
	canonicalRequest := strings.Join([]string{
		r.Method, r.URL.EscapedPath(), "", canonHeaders.String(), signedHeaders, crypto.SHA256Hex(body),
	}, "\n")
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256", r.Header.Get("X-Amz-Date"), scope[1], crypto.SHA256Hex([]byte(canonicalRequest)),
	}, "\n")
	kDate := crypto.HMACSHA256([]byte("AWS4"+sk), []byte(date))
	kRegion := crypto.HMACSHA256(kDate, []byte(region))
	kService := crypto.HMACSHA256(kRegion, []byte(svc))
	kSigning := crypto.HMACSHA256(kService, []byte("aws4_request"))
	want := hex.EncodeToString(crypto.HMACSHA256(kSigning, []byte(stringToSign)))
	return want == sig
}

func TestAWSKMSConforms(t *testing.T) {
	f := newFakeKMS(t)
	b := awskms.New("us-east-1", awskms.Credentials{AccessKeyID: testAK, SecretAccessKey: testSK},
		awskms.WithEndpoint(f.srv.URL), awskms.WithHTTPClient(f.srv.Client()))
	if err := crypto.ConformBackend(b, []crypto.Algorithm{crypto.RSA2048, crypto.ECDSAP256, crypto.ECDSAP384}); err != nil {
		t.Fatalf("AWS KMS backend failed conformance: %v", err)
	}
}

func TestAWSKMSBadCredentialsRejected(t *testing.T) {
	f := newFakeKMS(t)
	b := awskms.New("us-east-1", awskms.Credentials{AccessKeyID: testAK, SecretAccessKey: "wrong"},
		awskms.WithEndpoint(f.srv.URL), awskms.WithHTTPClient(f.srv.Client()))
	_, err := b.GenerateKey(crypto.ECDSAP256)
	if err == nil {
		t.Fatal("GenerateKey succeeded with a wrong secret; SigV4 not enforced")
	}
	if strings.Contains(err.Error(), "wrong") {
		t.Fatalf("error leaked the secret: %v", err)
	}
}
