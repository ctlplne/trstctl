package kmip

import (
	"context"
	"testing"

	"trstctl.com/trstctl/internal/auditsink"
)

// certAuth authenticates client certs whose bytes contain "good".
type certAuth struct{}

func (certAuth) Authenticate(cert []byte) (string, bool) {
	if len(cert) > 0 && string(cert) == "good-client" {
		return "client-a", true
	}
	return "", false
}

func TestKMIPLifecycleAuthenticated(t *testing.T) {
	ctx := context.Background()
	rec := &auditsink.Recorder{}
	s := New("t1", certAuth{}, rec)
	good := []byte("good-client")

	id, err := s.Create(ctx, good, "AES")
	if err != nil {
		t.Fatal(err)
	}
	key, err := s.Get(ctx, good, id)
	if err != nil || len(key) != 32 {
		t.Fatalf("get = %d bytes (err %v), want 32", len(key), err)
	}
	ids, _ := s.Locate(ctx, good, "AES")
	if len(ids) != 1 {
		t.Errorf("locate = %v, want 1", ids)
	}
	v, err := s.ReKey(ctx, good, id)
	if err != nil || v != 2 {
		t.Fatalf("rekey = v%d (err %v)", v, err)
	}
	if err := s.Revoke(ctx, good, id); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, good, id); err == nil {
		t.Error("got a revoked object")
	}
	if err := s.Destroy(ctx, good, id); err != nil {
		t.Fatal(err)
	}
}

func TestKMIPUnauthenticatedRefused(t *testing.T) {
	ctx := context.Background()
	rec := &auditsink.Recorder{}
	s := New("t1", certAuth{}, rec)
	bad := []byte("anonymous")
	if _, err := s.Create(ctx, bad, "AES"); err == nil {
		t.Error("Create allowed without client-cert auth")
	}
	if _, err := s.Get(ctx, bad, "kmip-1"); err == nil {
		t.Error("Get allowed without client-cert auth")
	}
	if rec.Count("kmip.unauthenticated") < 2 {
		t.Error("unauthenticated attempts not audited")
	}
}
