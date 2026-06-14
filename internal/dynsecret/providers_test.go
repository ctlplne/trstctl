package dynsecret

import (
	"context"
	"fmt"
	"sync"
	"testing"
)

// memBackend is an in-memory dynamic-secret backend double: it issues a scoped
// credential with a backend-shaped ref prefix and revokes idempotently.
type memBackend struct {
	prefix string
	mu     sync.Mutex
	n      int
	live   map[string]bool
}

func newMemBackend(prefix string) *memBackend {
	return &memBackend{prefix: prefix, live: map[string]bool{}}
}

func (m *memBackend) Create(_ context.Context, role string) (string, []byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.n++
	ref := fmt.Sprintf("%s%d", m.prefix, m.n)
	m.live[ref] = true
	return ref, []byte("secret-for-" + ref + "-" + role), nil
}

func (m *memBackend) Revoke(_ context.Context, ref string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.live, ref) // idempotent: deleting a missing key is safe
	return nil
}

func TestAllSevenProvidersConform(t *testing.T) {
	providers := []*BackendProvider{
		NewPostgresProvider(newMemBackend("pg_user_")),
		NewMySQLProvider(newMemBackend("mysql_user_")),
		NewMongoProvider(newMemBackend("mongo_user_")),
		NewAWSSTSProvider(newMemBackend("AKIA")),
		NewGCPIAMProvider(newMemBackend("sa-")),
		NewAzureSPProvider(newMemBackend("sp-")),
		NewRedisSSHProvider(newMemBackend("ssh-")),
	}
	if len(providers) != 7 {
		t.Fatalf("expected 7 providers (S17.2–S17.8), have %d", len(providers))
	}
	names := map[string]bool{}
	for _, p := range providers {
		if err := Conform(p); err != nil {
			t.Errorf("%s failed conformance: %v", p.Name(), err)
		}
		if names[p.Name()] {
			t.Errorf("duplicate provider name %q", p.Name())
		}
		names[p.Name()] = true
	}
}
