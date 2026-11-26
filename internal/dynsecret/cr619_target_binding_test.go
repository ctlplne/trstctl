// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCR619DatadogRevokeRefusesAnotherSite(t *testing.T) {
	old := &fakeDatadog{keys: map[string]datadogFakeKey{}}
	newTarget := &fakeDatadog{keys: map[string]datadogFakeKey{}}
	oldServer, newServer := httptest.NewServer(old), httptest.NewServer(newTarget)
	t.Cleanup(oldServer.Close)
	t.Cleanup(newServer.Close)
	open := func(srv *httptest.Server) *DatadogBackend {
		t.Helper()
		b, err := NewDatadogBackend(DatadogConfig{
			Endpoint: srv.URL, APIKey: []byte("admin-api-key"), ApplicationKey: []byte("admin-app-key"),
			RoleBindings: map[string]string{"ingest": "api_key"}, AllowInsecureLoopback: true, HTTPClient: srv.Client(),
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(b.Close)
		return b
	}
	ref, _, err := open(oldServer).CreateCredential(t.Context(), GenerateRequest{
		Role: "ingest", LeaseID: "lease-cr619-datadog", PrincipalSuffix: testPrincipalSuffix("lease-cr619-datadog"),
	})
	if err != nil || len(old.keys) != 1 {
		t.Fatalf("issue at old site: %v, keys=%d", err, len(old.keys))
	}
	if err := open(newServer).Revoke(t.Context(), ref); err == nil {
		t.Fatal("repointed Datadog site reported revoked while old site holds the live key")
	}
	if len(old.keys) != 1 || len(newTarget.keys) != 0 {
		t.Fatalf("wrong-target revoke changed keys: old=%d new=%d", len(old.keys), len(newTarget.keys))
	}
}

type cr619CloudflareVendor struct{ keys map[string]string }

func (v *cr619CloudflareVendor) mint(_ context.Context, _ hostedAPI, _, name string) (string, []byte, error) {
	const id = "0123456789abcdef0123456789abcdef"
	v.keys[id] = name
	return id, []byte(`{"api_token":"fixture"}`), nil
}
func (v *cr619CloudflareVendor) named(_ context.Context, _ hostedAPI, _, name string) ([]string, error) {
	for id, candidate := range v.keys {
		if candidate == name {
			return []string{id}, nil
		}
	}
	return nil, nil
}
func (v *cr619CloudflareVendor) nameOf(_ context.Context, _ hostedAPI, _, id string) (string, bool, error) {
	name, ok := v.keys[id]
	return name, ok, nil
}
func (v *cr619CloudflareVendor) remove(_ context.Context, _ hostedAPI, _, id string) error {
	delete(v.keys, id)
	return nil
}
func (v *cr619CloudflareVendor) verify(context.Context, hostedAPI, []byte) error {
	return ErrNoSelfProof
}

func TestCR619CloudflareUserTokenRevokeRefusesAnotherUser(t *testing.T) {
	const binding = "template 0123456789abcdef0123456789abcdef"
	open := func(key string, vendor *cr619CloudflareVendor) *HostedKeyBackend {
		t.Helper()
		b, err := NewHostedKeyBackend("cloudflare", HostedKeyConfig{
			Endpoint: "https://api.cloudflare.com", AdminKey: []byte(key),
			RoleBindings: map[string]string{"deploy": binding}, HTTPClient: http.DefaultClient,
		})
		if err != nil {
			t.Fatal(err)
		}
		b.vendor = vendor
		t.Cleanup(b.Close)
		return b
	}
	old := &cr619CloudflareVendor{keys: map[string]string{}}
	newTarget := &cr619CloudflareVendor{keys: map[string]string{}}
	ref, _, err := open("owner-a-token", old).CreateCredential(t.Context(), GenerateRequest{
		Role: "deploy", LeaseID: "lease-cr619-cloudflare", PrincipalSuffix: testPrincipalSuffix("lease-cr619-cloudflare"),
	})
	if err != nil || len(old.keys) != 1 {
		t.Fatalf("issue under original Cloudflare user: %v, keys=%d", err, len(old.keys))
	}
	if err := open("owner-b-token", newTarget).Revoke(t.Context(), ref); err == nil {
		t.Fatal("another Cloudflare user's token reported revoked while original user holds the live key")
	}
	if len(old.keys) != 1 || len(newTarget.keys) != 0 {
		t.Fatalf("wrong-user revoke changed keys: old=%d new=%d", len(old.keys), len(newTarget.keys))
	}
}
