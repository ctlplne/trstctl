// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// fakeVendor keeps keys by binding and ID, the way every hosted key API does.
type fakeVendor struct {
	keys    map[string]map[string]string // binding -> id -> name
	serial  int
	mintErr error
	removed []string
}

func (f *fakeVendor) mint(_ context.Context, _ hostedAPI, binding, name string) (string, []byte, error) {
	if f.mintErr != nil {
		return "", nil, f.mintErr
	}
	f.serial++
	id := fmt.Sprintf("key-%d", f.serial)
	if f.keys[binding] == nil {
		f.keys[binding] = map[string]string{}
	}
	f.keys[binding][id] = name
	return id, []byte(`{"api_key":"value-` + id + `"}`), nil
}

func (f *fakeVendor) named(_ context.Context, _ hostedAPI, binding, name string) ([]string, error) {
	var ids []string
	for id, candidate := range f.keys[binding] {
		if candidate == name {
			ids = append(ids, id)
		}
	}
	return ids, nil
}

func (f *fakeVendor) nameOf(_ context.Context, _ hostedAPI, binding, id string) (string, bool, error) {
	name, ok := f.keys[binding][id]
	return name, ok, nil
}

func (f *fakeVendor) remove(_ context.Context, _ hostedAPI, binding, id string) error {
	f.removed = append(f.removed, binding+"/"+id)
	delete(f.keys[binding], id)
	return nil
}

func (f *fakeVendor) verify(context.Context, hostedAPI, []byte) error { return ErrNoSelfProof }

func fakeHostedBackend(t *testing.T) (*HostedKeyBackend, *fakeVendor) {
	t.Helper()
	b, err := NewHostedKeyBackend("openrouter", HostedKeyConfig{
		Endpoint: "https://openrouter.example/api/v1", AdminKey: []byte("management"),
		RoleBindings: map[string]string{"inference": "limit 25", "batch": "unlimited"}, HTTPClient: http.DefaultClient,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	vendor := &fakeVendor{keys: map[string]map[string]string{}}
	b.vendor = vendor
	return b, vendor
}

// A240: a lease's key is named for the lease, so a retry after an uncertain
// mint first deletes the earlier attempt's key: one key per lease, not two.
func TestHostedKeyRetryReplacesTheEarlierAttemptsKeyA240(t *testing.T) {
	b, vendor := fakeHostedBackend(t)
	req := GenerateRequest{Role: "inference", LeaseID: "lease-1"}
	first, _, err := b.CreateCredential(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	second, credential, err := b.CreateCredential(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if first == second || !strings.HasPrefix(second, "limit-25/") || len(vendor.keys["limit-25"]) != 1 || vendor.removed[0] != first {
		t.Fatalf("first=%s second=%s keys=%v removed=%v", first, second, vendor.keys, vendor.removed)
	}
	if !strings.Contains(string(credential), "value-key-2") {
		t.Fatalf("credential = %s", credential)
	}
}

// Revocation deletes only keys this provider issued, under a bound target;
// a key already gone counts as revoked.
func TestHostedKeyRevokeDeletesOnlyIssuedKeysA240(t *testing.T) {
	b, vendor := fakeHostedBackend(t)
	ref, _, err := b.CreateCredential(context.Background(), GenerateRequest{Role: "batch", LeaseID: "lease-2"})
	if err != nil {
		t.Fatal(err)
	}
	vendor.keys["unlimited"]["foreign"] = "production-key"
	vendor.keys["other"] = map[string]string{"key-9": "trstctl-batch-0123456789"}
	for _, refused := range []string{"unlimited/foreign", "other/key-9", "unlimited", "/key-1", "unlimited/../key-1", "unlimited/key 1"} {
		if err := b.Revoke(context.Background(), refused); err == nil {
			t.Errorf("revoked %q", refused)
		}
	}
	if err := b.Revoke(context.Background(), ref); err != nil {
		t.Fatal(err)
	}
	if err := b.Revoke(context.Background(), ref); err != nil {
		t.Fatalf("a key already gone: %v", err)
	}
	if _, live := vendor.keys["unlimited"]["foreign"]; !live || len(vendor.removed) != 1 {
		t.Fatalf("removed=%v", vendor.removed)
	}
}

func TestHostedKeyBackendRefusesUnusableConfigurationA240(t *testing.T) {
	good := HostedKeyConfig{Endpoint: "https://api.example", AdminKey: []byte("k"), RoleBindings: map[string]string{"r": "abcdefghijklmnopqrst"}, HTTPClient: http.DefaultClient}
	for name, mutate := range map[string]func(*HostedKeyConfig){
		"no admin key":           func(c *HostedKeyConfig) { c.AdminKey = nil },
		"no bindings":            func(c *HostedKeyConfig) { c.RoleBindings = nil },
		"a bad binding":          func(c *HostedKeyConfig) { c.RoleBindings = map[string]string{"r": "not-a-project"} },
		"plain HTTP":             func(c *HostedKeyConfig) { c.Endpoint = "http://api.example" },
		"no client":              func(c *HostedKeyConfig) { c.HTTPClient = nil },
		"a digit-leading prefix": func(c *HostedKeyConfig) { c.UsernamePrefix = "9ci" },
	} {
		cfg := good
		mutate(&cfg)
		if b, err := NewHostedKeyBackend("supabase", cfg); err == nil {
			b.Close()
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := NewHostedKeyBackend("stripe", good); err == nil {
		t.Error("an unknown provider was accepted")
	}
	b, err := NewHostedKeyBackend("supabase", good)
	if err != nil {
		t.Fatal(err)
	}
	b.Close()
}

// A vendor's unusable key ID is refused and its credential wiped, so nothing
// unrevocable is handed out.
func TestHostedKeyRefusesAnUnusableVendorIDA240(t *testing.T) {
	b, _ := fakeHostedBackend(t)
	b.vendor = &badIDVendor{fakeVendor{keys: map[string]map[string]string{}}}
	if _, _, err := b.CreateCredential(context.Background(), GenerateRequest{Role: "batch"}); err == nil {
		t.Fatal("an ID with a slash was accepted")
	}
	b.vendor = &fakeVendor{keys: map[string]map[string]string{}, mintErr: errors.New("HTTP 500")}
	if _, _, err := b.CreateCredential(context.Background(), GenerateRequest{Role: "batch"}); err == nil {
		t.Fatal("a failed mint returned a credential")
	}
}

type badIDVendor struct{ fakeVendor }

func (v *badIDVendor) mint(ctx context.Context, api hostedAPI, binding, name string) (string, []byte, error) {
	_, credential, err := v.fakeVendor.mint(ctx, api, binding, name)
	return "a/b", credential, err
}

func TestCredentialFieldReadsOneSecretA240(t *testing.T) {
	key, err := credentialField("openrouter", []byte(`{"api_key":"sk-or-1","key_hash":"h"}`), "api_key")
	if err != nil || string(key) != "sk-or-1" {
		t.Fatalf("key=%q err=%v", key, err)
	}
	for _, bad := range []string{`{"key_hash":"h"}`, `{"api_key":""}`, `not json`} {
		if _, err := credentialField("openrouter", []byte(bad), "api_key"); err == nil {
			t.Errorf("%s: accepted", bad)
		}
	}
}
