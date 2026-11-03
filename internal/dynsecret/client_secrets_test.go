// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

type fakeClientSecrets struct {
	secrets map[string]map[string]bool // binding -> ids
	serial  int
	removed []string
}

func (f *fakeClientSecrets) add(_ context.Context, _ hostedAPI, binding string) (string, []byte, error) {
	f.serial++
	id := "s" + strings.Repeat("x", f.serial)
	if f.secrets[binding] == nil {
		f.secrets[binding] = map[string]bool{}
	}
	f.secrets[binding][id] = true
	return id, []byte(`{"client_secret":"v"}`), nil
}

func (f *fakeClientSecrets) present(_ context.Context, _ hostedAPI, binding, id string) (bool, error) {
	return f.secrets[binding][id], nil
}

func (f *fakeClientSecrets) remove(_ context.Context, _ hostedAPI, binding, id string) error {
	f.removed = append(f.removed, binding+"/"+id)
	delete(f.secrets[binding], id)
	return nil
}

func (f *fakeClientSecrets) verify(context.Context, hostedAPI, []byte) error { return nil }

// A240: a client secret rotator issues no leases, adds secrets only for a
// static rotation, and removes only secrets of a bound client.
func TestClientSecretRotatorKeepsToItsBoundClientsA240(t *testing.T) {
	b, err := NewClientSecretBackend("okta", ClientSecretConfig{Endpoint: "https://acme.okta.example", AdminKey: []byte("ssws"),
		RoleBindings: map[string]string{"portal": "0oa1b2c3d4e5f6g7h8i9"}, HTTPClient: http.DefaultClient})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	vendor := &fakeClientSecrets{secrets: map[string]map[string]bool{"0oa1b2c3d4e5f6g7h8i9": {"original": true}, "0oaother000000000000": {"theirs": true}}}
	b.vendor = vendor
	if _, _, err := b.CreateCredential(context.Background(), GenerateRequest{Role: "portal"}); err == nil || !strings.Contains(err.Error(), "issues no leases") {
		t.Fatalf("a lease: %v", err)
	}
	ref, _, err := b.CreateCredential(context.Background(), GenerateRequest{Role: "portal", Static: true, LeaseID: "cmd-1"})
	if err != nil || !strings.HasPrefix(ref, "0oa1b2c3d4e5f6g7h8i9/") {
		t.Fatalf("a rotation: %q %v", ref, err)
	}
	for _, refused := range []string{"0oaother000000000000/theirs", "original", "/original", "0oa1b2c3d4e5f6g7h8i9/a b"} {
		if err := b.Revoke(context.Background(), refused); err == nil {
			t.Errorf("revoked %q", refused)
		}
	}
	if err := b.Revoke(context.Background(), "0oa1b2c3d4e5f6g7h8i9/original"); err != nil {
		t.Fatal(err)
	}
	if err := b.Revoke(context.Background(), "0oa1b2c3d4e5f6g7h8i9/original"); err != nil {
		t.Fatalf("a secret already gone: %v", err)
	}
	if strings.Join(vendor.removed, ",") != "0oa1b2c3d4e5f6g7h8i9/original" || !vendor.secrets["0oaother000000000000"]["theirs"] {
		t.Fatalf("removed %v", vendor.removed)
	}
}

func TestClientSecretRotatorRefusesUnusableConfigurationA240(t *testing.T) {
	good := ClientSecretConfig{Endpoint: "https://accounts.example", AdminKey: []byte("k"), AdminClientID: "admin",
		RoleBindings: map[string]string{"etl": "a1b2c3d4-0000-4000-8000-0123456789ab 4471"}, HTTPClient: http.DefaultClient}
	for name, mutate := range map[string]func(*ClientSecretConfig){
		"no admin key":  func(c *ClientSecretConfig) { c.AdminKey = nil },
		"no bindings":   func(c *ClientSecretConfig) { c.RoleBindings = nil },
		"a bad binding": func(c *ClientSecretConfig) { c.RoleBindings = map[string]string{"etl": "4471"} },
		"plain HTTP":    func(c *ClientSecretConfig) { c.Endpoint = "http://accounts.example" },
	} {
		cfg := good
		mutate(&cfg)
		if b, err := NewClientSecretBackend("databricks", cfg); err == nil {
			b.Close()
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := NewClientSecretBackend("stripe", good); err == nil {
		t.Error("an unknown rotator was accepted")
	}
}
