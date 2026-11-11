// SPDX-License-Identifier: BUSL-1.1

package cloudauth

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// gcpSTSStandIn is GCP Security Token Service and IAM Credentials for one
// workload identity pool provider: the token endpoint accepts an RFC 8693
// exchange of a JWT for an access token and answers with one that names the
// subject token it was given; generateAccessToken narrows a federated token
// to the service account's.
type gcpSTSStandIn struct {
	srv           *httptest.Server
	mu            sync.Mutex
	exchanges     []url.Values
	impersonation []string
	expiresIn     int
}

const a169l1Audience = "//iam.googleapis.com/projects/123456/locations/global/workloadIdentityPools/trstctl/providers/k8s"

func newGCPSTSStandIn(t *testing.T, expiresIn int) *gcpSTSStandIn {
	t.Helper()
	g := &gcpSTSStandIn{expiresIn: expiresIn}
	g.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/token":
			_ = r.ParseForm()
			g.mu.Lock()
			g.exchanges = append(g.exchanges, r.PostForm)
			g.mu.Unlock()
			if r.PostForm.Get("grant_type") != "urn:ietf:params:oauth:grant-type:token-exchange" ||
				r.PostForm.Get("subject_token_type") != "urn:ietf:params:oauth:token-type:jwt" ||
				r.PostForm.Get("audience") != a169l1Audience || r.PostForm.Get("subject_token") == "" {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = io.WriteString(w, `{"error":"invalid_request"}`)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "federated-for-" + r.PostForm.Get("subject_token"), // #nosec G101 -- a stand-in fixture value, not a credential (CWE-798)
				"issued_token_type": "urn:ietf:params:oauth:token-type:access_token", "token_type": "Bearer", "expires_in": g.expiresIn})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, ":generateAccessToken"):
			auth := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			g.mu.Lock()
			g.impersonation = append(g.impersonation, r.URL.Path+" "+auth)
			g.mu.Unlock()
			if !strings.HasPrefix(auth, "federated-for-") {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = io.WriteString(w, `{"error":{"code":401}}`)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"accessToken": "sa-token-from-" + auth,
				"expireTime": time.Now().UTC().Add(time.Duration(g.expiresIn) * time.Second).Format(time.RFC3339)})
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"error":"not_found"}`)
		}
	}))
	t.Cleanup(g.srv.Close)
	return g
}

func (g *gcpSTSStandIn) count() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.exchanges)
}

// A169-L1: the GCP token source exchanges the projected OIDC token at STS for
// the pool provider's audience, reuses the access token until shortly before
// it expires, re-reads the file at the next exchange so a rotated projection
// is used, and, with a service account, narrows the federated token to that
// account's through generateAccessToken.
func TestGCPWorkloadIdentityTokenSourceExchangesAndRefreshesA169L1(t *testing.T) {
	sts := newGCPSTSStandIn(t, 3600)
	tokenFile := filepath.Join(t.TempDir(), "gcp-identity-token")
	if err := os.WriteFile(tokenFile, []byte("projected-oidc-1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := NewGCPWorkloadIdentityTokenSource(GCPWorkloadIdentityTokenSourceConfig{Audience: a169l1Audience,
		SubjectTokenFile: tokenFile, STSEndpoint: sts.srv.URL + "/v1/token", Doer: sts.srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(source.Close)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		token, wipe, err := source.Token(ctx)
		if err != nil || string(token) != "federated-for-projected-oidc-1" {
			t.Fatalf("token %d = %q %v", i, token, err)
		}
		wipe()
	}
	if sts.count() != 1 {
		t.Fatalf("exchanges = %d, want one cached token for three requests", sts.count())
	}
	if form := sts.exchanges[0]; form.Get("requested_token_type") != "urn:ietf:params:oauth:token-type:access_token" ||
		form.Get("scope") != "https://www.googleapis.com/auth/cloud-platform" {
		t.Fatalf("exchange form = %v", form)
	}

	// With a service account the federated token is narrowed to the account's.
	impersonating, err := NewGCPWorkloadIdentityTokenSource(GCPWorkloadIdentityTokenSourceConfig{Audience: a169l1Audience,
		SubjectTokenFile: tokenFile, STSEndpoint: sts.srv.URL + "/v1/token", ServiceAccount: "kms-signer@acme.iam.gserviceaccount.com",
		ImpersonationEndpoint: sts.srv.URL + "/v1/projects/-/serviceAccounts/kms-signer@acme.iam.gserviceaccount.com:generateAccessToken",
		Doer:                  sts.srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(impersonating.Close)
	token, wipe, err := impersonating.Token(ctx)
	if err != nil || string(token) != "sa-token-from-federated-for-projected-oidc-1" || len(sts.impersonation) != 1 {
		t.Fatalf("impersonated token = %q %v (%v)", token, err, sts.impersonation)
	}
	wipe()

	// A token inside the refresh window is replaced, from the rotated file.
	short := newGCPSTSStandIn(t, 3)
	refreshing, err := NewGCPWorkloadIdentityTokenSource(GCPWorkloadIdentityTokenSourceConfig{Audience: a169l1Audience,
		SubjectTokenFile: tokenFile, STSEndpoint: short.srv.URL + "/v1/token", Doer: short.srv.Client(), RefreshBefore: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(refreshing.Close)
	if _, wipe, err := refreshing.Token(ctx); err != nil {
		t.Fatal(err)
	} else {
		wipe()
	}
	if err := os.WriteFile(tokenFile, []byte("projected-oidc-2"), 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2100 * time.Millisecond) // past expiry minus the refresh window
	token, wipe, err = refreshing.Token(ctx)
	if err != nil || string(token) != "federated-for-projected-oidc-2" || short.count() != 2 {
		t.Fatalf("refreshed token = %q %v after %d exchanges", token, err, short.count())
	}
	wipe()
}

func TestGCPWorkloadIdentityTokenSourceRefusesBadConfigurationA169L1(t *testing.T) {
	sts := newGCPSTSStandIn(t, 3600)
	for name, cfg := range map[string]GCPWorkloadIdentityTokenSourceConfig{
		"no audience":                 {SubjectTokenFile: "/x", Doer: sts.srv.Client()},
		"no token file":               {Audience: a169l1Audience, Doer: sts.srv.Client()},
		"no client":                   {Audience: a169l1Audience, SubjectTokenFile: "/x"},
		"bad sts":                     {Audience: a169l1Audience, SubjectTokenFile: "/x", STSEndpoint: "ftp://sts", Doer: sts.srv.Client()},
		"impersonation without an sa": {Audience: a169l1Audience, SubjectTokenFile: "/x", ImpersonationEndpoint: "https://iam/x", Doer: sts.srv.Client()},
		"an sa that is not an email":  {Audience: a169l1Audience, SubjectTokenFile: "/x", ServiceAccount: "kms-signer", Doer: sts.srv.Client()},
	} {
		if _, err := NewGCPWorkloadIdentityTokenSource(cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if got := GCPImpersonationEndpoint("kms-signer@acme.iam.gserviceaccount.com"); got !=
		"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/kms-signer@acme.iam.gserviceaccount.com:generateAccessToken" {
		t.Fatalf("impersonation endpoint = %q", got)
	}
	missing, err := NewGCPWorkloadIdentityTokenSource(GCPWorkloadIdentityTokenSourceConfig{Audience: a169l1Audience,
		SubjectTokenFile: filepath.Join(t.TempDir(), "absent"), STSEndpoint: sts.srv.URL + "/v1/token", Doer: sts.srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	if _, wipe, err := missing.Token(context.Background()); err == nil {
		wipe()
		t.Fatal("a missing subject token file produced a token")
	}
	if sts.count() != 0 {
		t.Fatalf("an exchange was attempted without a subject token (%d)", sts.count())
	}
}
