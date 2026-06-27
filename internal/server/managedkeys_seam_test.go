package server

import (
	"context"
	"net/http"
	"testing"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
)

type fakeManagedKeyService struct{}

func (fakeManagedKeyService) Generate(_ context.Context, _ string, alg crypto.Algorithm, _ string) (api.ManagedKey, error) {
	return api.ManagedKey{KeyID: "fake-managed-key-1", Algorithm: alg, Version: 1, State: "active"}, nil
}
func (fakeManagedKeyService) Rotate(context.Context, string, string, string, string) (api.ManagedKey, error) {
	return api.ManagedKey{}, nil
}
func (fakeManagedKeyService) Revoke(context.Context, string, string, string, string) (api.ManagedKey, error) {
	return api.ManagedKey{}, nil
}
func (fakeManagedKeyService) Zeroize(context.Context, string, string, string, string) (api.ManagedKey, error) {
	return api.ManagedKey{}, nil
}

func TestManagedKeysServedThroughEditionFactory(t *testing.T) {
	var sawSpine bool
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.ManagedKeyFactory = func(md ManagedKeyServiceDeps) (api.ManagedKeyService, error) {
			if md.Log == nil || md.Idempotency == nil {
				t.Fatal("managed-key factory did not receive event log and idempotency spine")
			}
			sawSpine = true
			return fakeManagedKeyService{}, nil
		}
	})
	if !sawSpine {
		t.Fatal("managed-key edition factory was not invoked")
	}
	token := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "cloud-kms-operator", []string{
		string(authz.KeysRead), string(authz.KeysWrite),
	})
	code, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/managed-keys", token, "managed-key-seam-generate", map[string]string{
		"algorithm": string(crypto.RSA2048),
	})
	if code != http.StatusCreated {
		t.Fatalf("managed-key generate via factory = %d, want 201; body=%s", code, body)
	}
}
