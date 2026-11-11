// SPDX-License-Identifier: LicenseRef-trstctl-EE

package signerwiring

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const a169l1Audience = "//iam.googleapis.com/projects/123456/locations/global/workloadIdentityPools/trstctl/providers/k8s"

// gcpSTSStub is GCP Security Token Service and IAM Credentials on loopback:
// it exchanges a projected OIDC token for the pool provider's audience and
// narrows the federated token to a service account's.
func gcpSTSStub(t *testing.T) (*httptest.Server, *[]string) {
	t.Helper()
	var mu sync.Mutex
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/v1/token":
			_ = r.ParseForm()
			mu.Lock()
			calls = append(calls, "sts "+r.PostForm.Get("audience")+" "+r.PostForm.Get("subject_token"))
			mu.Unlock()
			if r.PostForm.Get("audience") != a169l1Audience {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = io.WriteString(w, `{"error":"invalid_target"}`)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "federated-" + r.PostForm.Get("subject_token"), "token_type": "Bearer", "expires_in": 3600})
		case strings.HasSuffix(r.URL.Path, ":generateAccessToken"):
			mu.Lock()
			calls = append(calls, "impersonate "+r.URL.Path+" "+strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"accessToken": "kms-signer-token", // #nosec G101 -- a stand-in fixture value, not a credential (CWE-798)
				"expireTime": time.Now().UTC().Add(time.Hour).Format(time.RFC3339)})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

// A169-L1: the child signer builds the GCP managed-key provider from a
// workload identity with no static bearer token, its token source exchanges
// the projected token at STS (and impersonates the service account when one is
// named), and a configuration that sets both credentials is refused.
func TestGCPManagedKeyProviderRunsOnWorkloadIdentityA169L1(t *testing.T) {
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "gcp-identity-token")
	bearerFile := filepath.Join(dir, "bearer")
	for path, value := range map[string]string{tokenFile: "projected-oidc", bearerFile: "static-token"} {
		if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write := func(extra string) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "provider.json")
		body := `{"enabled":true,"provider":"gcp-kms","gcp":{"parent":"projects/p/locations/l/keyRings/r",` + extra +
			`"workload_identity":{"audience":"` + a169l1Audience + `","subject_token_file":"` + tokenFile + `"}}}`
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	if option, err := ProviderOption(write(""), t.TempDir()); err != nil || option == nil {
		t.Fatalf("workload identity provider: option=%v err=%v", option != nil, err)
	}
	if _, err := ProviderOption(write(`"bearer_token_file":"`+bearerFile+`",`), t.TempDir()); err == nil || !strings.Contains(err.Error(), "set one, not both") {
		t.Fatalf("both credentials = %v; want them refused", err)
	}

	stub, calls := gcpSTSStub(t)
	ctx := context.Background()
	creds, wipe, err := gcpCredentials(gcpConfig{Parent: "projects/p/locations/l/keyRings/r", AllowInsecureLoopback: true,
		WorkloadIdentity: &gcpWorkloadIdentity{Audience: a169l1Audience, SubjectTokenFile: tokenFile, STSEndpoint: stub.URL + "/v1/token"}})
	if err != nil || creds.TokenSource == nil || len(creds.BearerToken) != 0 {
		t.Fatalf("gcp credentials = %+v %v; want a token source and no static token", creds, err)
	}
	wipe()
	token, done, err := creds.TokenSource.Token(ctx)
	if err != nil || string(token) != "federated-projected-oidc" {
		t.Fatalf("federated token = %q %v (%v)", token, err, *calls)
	}
	done()

	impersonating, wipe, err := gcpCredentials(gcpConfig{Parent: "projects/p/locations/l/keyRings/r", AllowInsecureLoopback: true,
		WorkloadIdentity: &gcpWorkloadIdentity{Audience: a169l1Audience, SubjectTokenFile: tokenFile, STSEndpoint: stub.URL + "/v1/token",
			ServiceAccount:        "kms-signer@acme.iam.gserviceaccount.com",
			ImpersonationEndpoint: stub.URL + "/v1/projects/-/serviceAccounts/kms-signer@acme.iam.gserviceaccount.com:generateAccessToken"}})
	if err != nil {
		t.Fatal(err)
	}
	wipe()
	token, done, err = impersonating.TokenSource.Token(ctx)
	if err != nil || string(token) != "kms-signer-token" {
		t.Fatalf("impersonated token = %q %v (%v)", token, err, *calls)
	}
	done()
	if last := (*calls)[len(*calls)-1]; !strings.HasSuffix(last, " federated-projected-oidc") || !strings.Contains(last, "kms-signer@acme.iam.gserviceaccount.com:generateAccessToken") {
		t.Fatalf("impersonation call = %q; want it authorized by the federated token", last)
	}
}
