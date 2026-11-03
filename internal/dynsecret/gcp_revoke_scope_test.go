// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A240: a gcp-iam reference becomes a request path, so revocation deletes
// only a key of the bound service account.
func TestGCPIAMRevokeDeletesOnlyKeysOfTheBoundAccountA240(t *testing.T) {
	var deleted []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			deleted = append(deleted, r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	b, err := NewGCPIAMBackend(GCPIAMConfig{Endpoint: srv.URL, HTTPClient: srv.Client(), Project: "p", ServiceAccountEmail: "app@p.iam.gserviceaccount.com", BearerToken: []byte("t")})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	for _, refused := range []string{
		"projects/p/serviceAccounts/other@p.iam.gserviceaccount.com/keys/abc",
		"projects/q/serviceAccounts/app@p.iam.gserviceaccount.com/keys/abc",
		"projects/p/serviceAccounts/app@p.iam.gserviceaccount.com/keys/../../x",
		"projects/p/serviceAccounts/app@p.iam.gserviceaccount.com",
		"organizations/1/roles/admin",
	} {
		if err := b.Revoke(context.Background(), refused); err == nil {
			t.Errorf("revoked %q", refused)
		}
	}
	if err := b.Revoke(context.Background(), "projects/p/serviceAccounts/app@p.iam.gserviceaccount.com/keys/0123abc"); err != nil {
		t.Fatal(err)
	}
	if strings.Join(deleted, ",") != "/v1/projects/p/serviceAccounts/app@p.iam.gserviceaccount.com/keys/0123abc" {
		t.Fatalf("deleted %v", deleted)
	}
}
