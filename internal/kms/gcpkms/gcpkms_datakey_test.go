// SPDX-License-Identifier: BUSL-1.1

package gcpkms_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"hash/crc32"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"

	"trstctl.com/trstctl/internal/kms/gcpkms"
)

func castagnoliSum(b []byte) string {
	return strconv.FormatUint(uint64(crc32.Checksum(b, crc32.MakeTable(crc32.Castagnoli))), 10)
}

// A200: encrypt sends the plaintext and associated data with their CRC32C, and
// a response the service did not verify is refused; decrypt checks the
// plaintext's CRC32C before returning it.
func TestEncryptDataKeyChecksBothWays(t *testing.T) {
	const key = "projects/p/locations/l/keyRings/r/cryptoKeys/k"
	var verified atomic.Bool
	verified.Store(true)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in map[string]string
		_ = json.NewDecoder(r.Body).Decode(&in)
		switch r.URL.Path {
		case "/v1/" + key + ":encrypt":
			plain, _ := base64.StdEncoding.DecodeString(in["plaintext"])
			if in["plaintextCrc32c"] != castagnoliSum(plain) || in["additionalAuthenticatedDataCrc32c"] == "" {
				http.Error(w, "checksum", http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"name": key + "/cryptoKeyVersions/1", "ciphertext": []byte("ct"), "ciphertextCrc32c": castagnoliSum([]byte("ct")),
				"verifiedPlaintextCrc32c": verified.Load(), "verifiedAdditionalAuthenticatedDataCrc32c": verified.Load(),
			})
		case "/v1/" + key + ":decrypt":
			_ = json.NewEncoder(w).Encode(map[string]any{"plaintext": []byte("data-key"), "plaintextCrc32c": castagnoliSum([]byte("tampered"))})
		}
	}))
	defer srv.Close()
	b := gcpkms.New("", gcpkms.Credentials{BearerToken: []byte(testToken)}, gcpkms.WithEndpoint(srv.URL+"/v1"), gcpkms.WithHTTPClient(srv.Client()))
	defer b.Destroy()
	ctx := context.Background()
	ct, err := b.EncryptDataKey(ctx, key, []byte("data-key"), []byte("aad"))
	if err != nil || !bytes.Equal(ct, []byte("ct")) {
		t.Fatalf("encrypt = %q, %v", ct, err)
	}
	if _, err := b.DecryptDataKey(ctx, key, ct, []byte("aad")); err == nil {
		t.Fatal("a plaintext failing its checksum was returned")
	}
	verified.Store(false)
	if _, err := b.EncryptDataKey(ctx, key, []byte("data-key"), []byte("aad")); err == nil {
		t.Fatal("an encrypt the service did not verify was accepted")
	}
	if _, err := b.EncryptDataKey(ctx, key+"/cryptoKeyVersions/1", []byte("data-key"), nil); err == nil {
		t.Fatal("a key version was accepted where the CryptoKey is required")
	}
}
