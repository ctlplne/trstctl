// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/secret"
)

// CR-231: require both the role's user and an exact, live slot fingerprint.
// This read-only SQL API fixture rejects every mutation before doing anything.
func TestSnowflakeStaticRotationRequiresAnOwnedLiveSlot(t *testing.T) {
	admin, _ := snowflakeTestKey(t)
	defer secret.Wipe(admin)
	liveFingerprint := SnowflakeKeyFingerprint([]byte("fixture-public-key"))
	var reads, writes atomic.Int32
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Statement string }
		if json.NewDecoder(r.Body).Decode(&req) == nil && strings.HasPrefix(req.Statement, "DESC USER ") {
			reads.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"data": [][]string{{"RSA_PUBLIC_KEY_FP", liveFingerprint}}})
			return
		}
		writes.Add(1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer api.Close()
	provider, err := NewSnowflakeBackend(SnowflakeConfig{
		Endpoint: api.URL, Account: "lab-account", AdminUser: "fixture_admin", AdminPrivateKey: admin,
		RoleBindings: map[string]string{"reporting": "user FIXTURE_REPORTING", "batch": "user FIXTURE_BATCH"},
		MaxLifetime:  time.Hour, AllowInsecureLoopback: true, HTTPClient: api.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()
	for _, tc := range []struct {
		name, reference string
		wantReads       int32
	}{
		{"other-role", "FIXTURE_BATCH/1/" + liveFingerprint, 0},
		{"stale-slot", "FIXTURE_REPORTING/1/" + SnowflakeKeyFingerprint([]byte("previous-fixture-key")), 1},
		{"empty-slot", "FIXTURE_REPORTING/2/" + liveFingerprint, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reads.Store(0)
			writes.Store(0)
			_, material, err := provider.CreateCredential(t.Context(), GenerateRequest{Role: "reporting", Static: true, Predecessor: tc.reference})
			defer secret.Wipe(material)
			if err == nil || reads.Load() != tc.wantReads || writes.Load() != 0 {
				t.Fatalf("invalid predecessor rejection: error=%t reads=%d want=%d writes=%d want=0", err != nil, reads.Load(), tc.wantReads, writes.Load())
			}
		})
	}
	t.Run("lease-revoke-has-no-static-role", func(t *testing.T) {
		reads.Store(0)
		writes.Store(0)
		err := provider.Revoke(t.Context(), "FIXTURE_REPORTING/1/"+liveFingerprint)
		if err == nil || reads.Load() != 0 || writes.Load() != 0 {
			t.Fatalf("role-free revoke: error=%t reads=%d writes=%d, want refusal before provider calls", err != nil, reads.Load(), writes.Load())
		}
	})
}
