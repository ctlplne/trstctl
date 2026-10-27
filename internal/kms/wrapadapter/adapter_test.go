// SPDX-License-Identifier: BUSL-1.1

package wrapadapter

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"hash/crc32"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// dataKey stands in for the signer's 32-byte data key; its bytes all differ,
// so a double's reversible transform never reproduces it.
var dataKey = func() []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	return key
}()

func writeFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeConfig(t *testing.T, cfg map[string]any) string {
	t.Helper()
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return writeFile(t, t.TempDir(), "kms-wrap.json", string(raw))
}

// invoke runs the adapter as the signer does and returns stdout, stderr and the
// exit code.
func invoke(t *testing.T, configPath string, input []byte, args ...string) ([]byte, string, int) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	getenv := func(name string) string {
		if name == ConfigEnv {
			return configPath
		}
		return ""
	}
	code := Run(context.Background(), args, getenv, bytes.NewReader(input), &stdout, &stderr)
	return stdout.Bytes(), stderr.String(), code
}

func reversed(in []byte) []byte {
	out := slices.Clone(in)
	slices.Reverse(out)
	return out
}

// awsDouble answers TrentService.Encrypt and Decrypt as the KMS JSON API does,
// checking the signature header, the key and the encryption context.
type awsDouble struct {
	mu       sync.Mutex
	targets  []string
	contexts []map[string]string
	disabled bool
}

func (d *awsDouble) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	target := r.Header.Get("X-Amz-Target")
	var in struct {
		KeyId             string
		Plaintext         []byte
		CiphertextBlob    []byte
		EncryptionContext map[string]string
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
		http.Error(w, `{"__type":"ValidationException"}`, http.StatusBadRequest)
		return
	}
	d.mu.Lock()
	d.targets = append(d.targets, target)
	d.contexts = append(d.contexts, in.EncryptionContext)
	disabled := d.disabled
	d.mu.Unlock()
	const key = "arn:aws:kms:us-east-1:111122223333:key/0b1c2d3e-aaaa-bbbb-cccc-000000000001"
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	if disabled {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"__type":"DisabledException","message":"key is disabled"}`))
		return
	}
	if in.KeyId != key {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"__type":"IncorrectKeyException"}`))
		return
	}
	switch target {
	case "TrentService.Encrypt":
		_ = json.NewEncoder(w).Encode(map[string]any{"CiphertextBlob": append([]byte("aws:"), reversed(in.Plaintext)...), "KeyId": key})
	case "TrentService.Decrypt":
		if in.EncryptionContext["trstctl:purpose"] != Purpose || !bytes.HasPrefix(in.CiphertextBlob, []byte("aws:")) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"__type":"InvalidCiphertextException"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"Plaintext": reversed(in.CiphertextBlob[4:]), "KeyId": key})
	default:
		w.WriteHeader(http.StatusBadRequest)
	}
}

func awsConfigFor(t *testing.T, endpoint string) string {
	t.Helper()
	dir := t.TempDir()
	return writeConfig(t, map[string]any{"aws": map[string]any{
		"endpoint": endpoint, "allow_insecure_loopback": true, "access_key_id": "AKIAEXAMPLE",
		"secret_access_key_file": writeFile(t, dir, "aws-key", "example-secret\n"),
	}})
}

// A200: the adapter wraps a data key with KMS Encrypt under the referenced key
// and the signer key store's encryption context, and unwraps it with Decrypt
// naming the same key; the region comes from the key ARN.
func TestAWSWrapsAndUnwrapsThroughKMS(t *testing.T) {
	double := &awsDouble{}
	server := httptest.NewServer(double)
	defer server.Close()
	config := awsConfigFor(t, server.URL)
	const keyRef = "arn:aws:kms:us-east-1:111122223333:key/0b1c2d3e-aaaa-bbbb-cccc-000000000001"

	wrapped, stderr, code := invoke(t, config, dataKey, "wrap", "awskms", keyRef)
	if code != ExitOK || !bytes.HasPrefix(wrapped, []byte("TKW1A")) {
		t.Fatalf("wrap = %d %q (%s)", code, wrapped, stderr)
	}
	if bytes.Contains(wrapped, dataKey) {
		t.Fatal("the wrapped output carries the data key")
	}
	plain, stderr, code := invoke(t, config, wrapped, "unwrap", "awskms", keyRef)
	if code != ExitOK || !bytes.Equal(plain, dataKey) {
		t.Fatalf("unwrap = %d (%s)", code, stderr)
	}
	double.mu.Lock()
	targets, contexts := slices.Clone(double.targets), slices.Clone(double.contexts)
	double.mu.Unlock()
	if !slices.Equal(targets, []string{"TrentService.Encrypt", "TrentService.Decrypt"}) {
		t.Fatalf("KMS calls = %v", targets)
	}
	for _, c := range contexts {
		if c["trstctl:purpose"] != Purpose {
			t.Fatalf("encryption context = %v", c)
		}
	}

	// Another key reference is refused by KMS; a disabled key fails closed.
	if _, _, code := invoke(t, config, wrapped, "unwrap", "awskms", "arn:aws:kms:us-east-1:111122223333:key/other"); code != ExitFailed {
		t.Fatalf("unwrap under another key = %d, want %d", code, ExitFailed)
	}
	double.mu.Lock()
	double.disabled = true
	double.mu.Unlock()
	if out, stderr, code := invoke(t, config, wrapped, "unwrap", "awskms", keyRef); code != ExitFailed || len(out) != 0 || strings.Contains(stderr, string(dataKey)) {
		t.Fatalf("unwrap under a disabled key = %d %q (%s)", code, out, stderr)
	}
}

// gcpDouble answers Cloud KMS encrypt and decrypt, enforcing the request
// checksums the way the service does.
type gcpDouble struct {
	mu        sync.Mutex
	paths     []string
	badCRC    bool
	otherName bool
}

func (d *gcpDouble) set(change func()) {
	d.mu.Lock()
	defer d.mu.Unlock()
	change()
}

func crc(b []byte) string {
	return strconv.FormatUint(uint64(crc32.Checksum(b, crc32.MakeTable(crc32.Castagnoli))), 10)
}

func (d *gcpDouble) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	const key = "projects/p/locations/global/keyRings/r/cryptoKeys/signer"
	d.mu.Lock()
	d.paths = append(d.paths, r.URL.Path)
	badCRC, otherName := d.badCRC, d.otherName
	d.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer gcp-access-token" {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	var in map[string]string
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	aad, _ := base64.StdEncoding.DecodeString(in["additionalAuthenticatedData"])
	if string(aad) != Purpose || in["additionalAuthenticatedDataCrc32c"] != crc(aad) {
		http.Error(w, "aad", http.StatusBadRequest)
		return
	}
	switch r.URL.Path {
	case "/v1/" + key + ":encrypt":
		plain, _ := base64.StdEncoding.DecodeString(in["plaintext"])
		if in["plaintextCrc32c"] != crc(plain) {
			http.Error(w, "checksum mismatch", http.StatusBadRequest)
			return
		}
		ct := append([]byte("gcp:"), reversed(plain)...)
		name := key + "/cryptoKeyVersions/3"
		if otherName {
			name = "projects/p/locations/global/keyRings/r/cryptoKeys/other/cryptoKeyVersions/1"
		}
		sum := crc(ct)
		if badCRC {
			sum = "1"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"name": name, "ciphertext": ct, "ciphertextCrc32c": sum,
			"verifiedPlaintextCrc32c": true, "verifiedAdditionalAuthenticatedDataCrc32c": true,
		})
	case "/v1/" + key + ":decrypt":
		ct, _ := base64.StdEncoding.DecodeString(in["ciphertext"])
		if in["ciphertextCrc32c"] != crc(ct) || !bytes.HasPrefix(ct, []byte("gcp:")) {
			http.Error(w, "ciphertext", http.StatusBadRequest)
			return
		}
		plain := reversed(ct[4:])
		_ = json.NewEncoder(w).Encode(map[string]any{"plaintext": plain, "plaintextCrc32c": crc(plain), "usedPrimary": true})
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

// A200: Cloud KMS encrypt and decrypt carry CRC32C checksums both ways and the
// key store's associated data; decrypt names the CryptoKey, not a version, and
// a response for another key or with a bad checksum is refused.
func TestGCPWrapsAndUnwrapsThroughCloudKMS(t *testing.T) {
	double := &gcpDouble{}
	server := httptest.NewServer(double)
	defer server.Close()
	config := writeConfig(t, map[string]any{"gcp": map[string]any{
		"endpoint": server.URL + "/v1", "allow_insecure_loopback": true,
		"bearer_token_file": writeFile(t, t.TempDir(), "token", "gcp-access-token\n"),
	}})
	const keyRef = "projects/p/locations/global/keyRings/r/cryptoKeys/signer"
	wrapped, stderr, code := invoke(t, config, dataKey, "wrap", "gcpkms", keyRef)
	if code != ExitOK || !bytes.HasPrefix(wrapped, []byte("TKW1G")) {
		t.Fatalf("wrap = %d (%s)", code, stderr)
	}
	plain, stderr, code := invoke(t, config, wrapped, "unwrap", "gcpkms", keyRef)
	if code != ExitOK || !bytes.Equal(plain, dataKey) {
		t.Fatalf("unwrap = %d (%s)", code, stderr)
	}
	double.mu.Lock()
	paths := slices.Clone(double.paths)
	double.mu.Unlock()
	if !slices.Equal(paths, []string{"/v1/" + keyRef + ":encrypt", "/v1/" + keyRef + ":decrypt"}) {
		t.Fatalf("Cloud KMS calls = %v", paths)
	}
	if _, _, code := invoke(t, config, dataKey, "wrap", "gcpkms", keyRef+"/cryptoKeyVersions/3"); code != ExitFailed {
		t.Fatalf("a version as the key reference = %d, want refused", code)
	}
	double.set(func() { double.badCRC = true })
	if _, _, code := invoke(t, config, dataKey, "wrap", "gcpkms", keyRef); code != ExitFailed {
		t.Fatalf("a ciphertext failing its checksum = %d, want refused", code)
	}
	double.set(func() { double.badCRC, double.otherName = false, true })
	if _, _, code := invoke(t, config, dataKey, "wrap", "gcpkms", keyRef); code != ExitFailed {
		t.Fatalf("an answer for another key = %d, want refused", code)
	}
}

// azureDouble answers Key Vault's key read, wrapkey and unwrapkey.
type azureDouble struct {
	mu      sync.Mutex
	calls   []string
	current string
}

func (d *azureDouble) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	d.calls = append(d.calls, r.Method+" "+r.URL.Path+"?"+r.URL.RawQuery)
	current := d.current
	d.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer azure-access-token" || r.URL.Query().Get("api-version") != "7.4" {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	vault := "http://" + r.Host
	if r.Method == http.MethodGet && r.URL.Path == "/keys/signer" {
		_ = json.NewEncoder(w).Encode(map[string]any{"key": map[string]any{"kid": vault + "/keys/signer/" + current, "kty": "RSA", "key_ops": []string{"wrapKey", "unwrapKey"}}})
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) != 4 || parts[0] != "keys" || parts[1] != "signer" {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	var in struct{ Alg, Value string }
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Alg != "RSA-OAEP-256" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	value, err := base64.RawURLEncoding.DecodeString(in.Value)
	if err != nil {
		http.Error(w, "value", http.StatusBadRequest)
		return
	}
	version := parts[2]
	switch parts[3] {
	case "wrapkey":
		out := append([]byte("az:"+version+":"), reversed(value)...)
		_ = json.NewEncoder(w).Encode(map[string]string{"kid": vault + "/keys/signer/" + version, "value": base64.RawURLEncoding.EncodeToString(out)})
	case "unwrapkey":
		prefix := []byte("az:" + version + ":")
		if !bytes.HasPrefix(value, prefix) {
			http.Error(w, "wrong version", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"kid": vault + "/keys/signer/" + version, "value": base64.RawURLEncoding.EncodeToString(reversed(value[len(prefix):]))})
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

// A200: Key Vault wrapkey names a key version (the docs require it). Without
// one in the key reference the current version is read first, and the frame
// records the version that wrapped, so after the key rotates to a new version
// the older data key still unwraps under its own.
func TestAzureWrapsUnderTheCurrentVersionAndUnwrapsUnderTheRecordedOne(t *testing.T) {
	double := &azureDouble{current: "v1"}
	server := httptest.NewServer(double)
	defer server.Close()
	config := writeConfig(t, map[string]any{"azure": map[string]any{
		"allow_insecure_loopback": true,
		"bearer_token_file":       writeFile(t, t.TempDir(), "token", "azure-access-token\n"),
	}})
	keyRef := server.URL + "/keys/signer"
	wrapped, stderr, code := invoke(t, config, dataKey, "wrap", "azurekv", keyRef)
	if code != ExitOK || !bytes.HasPrefix(wrapped, []byte("TKW1Z")) || !bytes.Contains(wrapped, []byte("RSA-OAEP-256 v1")) {
		t.Fatalf("wrap = %d %q (%s)", code, wrapped, stderr)
	}
	double.mu.Lock()
	double.current = "v2"
	double.mu.Unlock()
	plain, stderr, code := invoke(t, config, wrapped, "unwrap", "azurekv", keyRef)
	if code != ExitOK || !bytes.Equal(plain, dataKey) {
		t.Fatalf("unwrap after rotation = %d (%s)", code, stderr)
	}
	want := []string{"GET /keys/signer?api-version=7.4", "POST /keys/signer/v1/wrapkey?api-version=7.4", "POST /keys/signer/v1/unwrapkey?api-version=7.4"}
	double.mu.Lock()
	calls := slices.Clone(double.calls)
	double.mu.Unlock()
	if !slices.Equal(calls, want) {
		t.Fatalf("Key Vault calls = %v, want %v", calls, want)
	}
	if _, _, code := invoke(t, config, wrapped, "unwrap", "azurekv", server.URL+"/keys/other"); code != ExitFailed {
		t.Fatalf("unwrap under another key = %d, want refused", code)
	}
}

// A200: the frame names the provider kind; another provider refuses it before
// any call, and input that is not a frame is refused.
func TestUnwrapRefusesAnotherProvidersFrameAndForeignInput(t *testing.T) {
	gcp := writeConfig(t, map[string]any{"gcp": map[string]any{
		"endpoint": "http://127.0.0.1:9/v1", "allow_insecure_loopback": true,
		"bearer_token_file": writeFile(t, t.TempDir(), "token", "gcp-access-token\n"),
	}})
	awsFrame, err := frame(codeAWS, nil, []byte("aws:ciphertext"))
	if err != nil {
		t.Fatal(err)
	}
	if _, stderr, code := invoke(t, gcp, awsFrame, "unwrap", "gcpkms", "projects/p/locations/global/keyRings/r/cryptoKeys/signer"); code != ExitFailed || !strings.Contains(stderr, "not from gcpkms") {
		t.Fatalf("unwrap of an AWS frame under GCP = %d (%s)", code, stderr)
	}
	if _, stderr, code := invoke(t, gcp, []byte("kmswrap:legacy"), "unwrap", "gcpkms", "projects/p/locations/global/keyRings/r/cryptoKeys/signer"); code != ExitFailed || !strings.Contains(stderr, "not a data key this adapter wrapped") {
		t.Fatalf("unwrap of foreign input = %d (%s)", code, stderr)
	}
	if _, _, _, err := unframe([]byte("TKW1A\x00\x05abc")); err == nil {
		t.Fatal("a truncated frame was accepted")
	}
}

// A200: malformed invocations and configurations exit 2 with a reason; an
// inline credential is an unknown field and is refused; the PKCS#11 provider
// says it needs the cgo build when this build has none.
func TestUsageAndConfigurationErrors(t *testing.T) {
	aws := awsConfigFor(t, "http://127.0.0.1:9")
	inline := writeConfig(t, map[string]any{"aws": map[string]any{"access_key_id": "AKIAEXAMPLE", "secret_access_key": "inline"}})
	for _, c := range []struct {
		name   string
		config string
		args   []string
		want   string
	}{
		{"no operation", aws, []string{"awskms", "arn:aws:kms:us-east-1:1:key/k"}, "usage"},
		{"bad operation", aws, []string{"seal", "awskms", "arn:aws:kms:us-east-1:1:key/k"}, "neither wrap nor unwrap"},
		{"unknown provider", aws, []string{"wrap", "vault", "k"}, "unsupported provider"},
		{"unknown flag", aws, []string{"--verbose", "wrap", "awskms", "k"}, "unknown flag"},
		{"no region", aws, []string{"wrap", "awskms", "alias/signer"}, "region is required"},
		{"inline credential", inline, []string{"wrap", "awskms", "arn:aws:kms:us-east-1:1:key/k"}, "unknown field"},
		{"no configuration", "", []string{"wrap", "awskms", "arn:aws:kms:us-east-1:1:key/k"}, ConfigEnv},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, stderr, code := invoke(t, c.config, dataKey, c.args...)
			if code != ExitUsage || !strings.Contains(stderr, c.want) {
				t.Fatalf("exit %d, stderr %q; want %d mentioning %q", code, stderr, ExitUsage, c.want)
			}
		})
	}
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"--config", aws, "wrap", "awskms", "arn:aws:kms:us-east-1:1:key/k"}, nil, io.LimitReader(bytes.NewReader(nil), 0), &stdout, &stderr)
	if code != ExitUsage || !strings.Contains(stderr.String(), "stdin must carry") {
		t.Fatalf("empty stdin = %d %q", code, stderr.String())
	}
}
