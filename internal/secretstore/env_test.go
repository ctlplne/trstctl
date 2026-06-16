package secretstore

import (
	"context"
	"reflect"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
)

func envFixture(t *testing.T) (*EnvResolver, *Store, *Store) {
	t.Helper()
	kek, _ := crypto.NewKEK()
	base, _ := New(Config{TenantID: "t1", KEK: kek})
	prod, _ := New(Config{TenantID: "t1", KEK: kek})
	r := NewEnvResolver("t1", base, nil)
	r.AddEnvironment("prod", prod)
	return r, base, prod
}

func TestEnvironmentOverrideAndInheritance(t *testing.T) {
	r, base, prod := envFixture(t)
	ctx := context.Background()
	_, _ = base.Put(ctx, "p", []byte("base-val"), "")
	_, _ = prod.Put(ctx, "p", []byte("prod-val"), "")

	if v, _ := r.Resolve(ctx, "prod", "p"); string(v) != "prod-val" {
		t.Errorf("prod override = %q, want prod-val", v)
	}
	if v, _ := r.Resolve(ctx, "", "p"); string(v) != "base-val" {
		t.Errorf("base = %q, want base-val", v)
	}
	// An environment with no override inherits from base.
	if v, _ := r.Resolve(ctx, "dev", "p"); string(v) != "base-val" {
		t.Errorf("dev (no override) = %q, want base-val (inheritance)", v)
	}
}

func TestSecretReferenceTransitive(t *testing.T) {
	r, base, _ := envFixture(t)
	ctx := context.Background()
	_, _ = base.Put(ctx, "db_url", []byte("postgres://db"), "")
	_, _ = base.Put(ctx, "app_db", []byte("${ref:db_url}"), "")
	_, _ = base.Put(ctx, "alias", []byte("${ref:app_db}"), "") // transitive
	v, err := r.Resolve(ctx, "", "alias")
	if err != nil {
		t.Fatal(err)
	}
	if string(v) != "postgres://db" {
		t.Errorf("transitive reference = %q, want postgres://db", v)
	}
}

func TestDotEnvRoundTrip(t *testing.T) {
	m := map[string]string{"API_KEY": "abc123", "DB_HOST": "localhost", "DEBUG": "true"}
	out := ParseDotEnv(RenderDotEnv(m))
	if !reflect.DeepEqual(m, out) {
		t.Errorf(".env round-trip lost data: %v != %v", out, m)
	}
}
