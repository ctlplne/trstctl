package breakglass

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/auth"
	"trstctl.com/trstctl/internal/crypto"
)

func TestAdminServiceAuthenticatesAndLocksOut(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	sessions := auth.NewSessionIssuer([]byte("breakglass-session-secret-012345"), time.Hour)
	audit := &auditsink.Recorder{}
	svc := NewAdminService(AdminConfig{
		Enabled: true, TenantID: "tenant-admin", Sessions: sessions,
		Params:      crypto.Argon2idParams{MemoryKiB: 1024, Iterations: 1, Parallelism: 1, SaltLen: 16, KeyLen: 32},
		MaxFailures: 2, Lockout: time.Minute, Now: func() time.Time { return now }, Audit: audit,
	})
	if err := svc.SetPassword("admin-1", []byte("correct horse battery staple")); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	token, err := svc.Authenticate(context.Background(), "admin-1", []byte("correct horse battery staple"), "203.0.113.10", "browser")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	sess, err := sessions.Verify(token)
	if err != nil {
		t.Fatalf("session verify: %v", err)
	}
	if sess.Subject != "admin-1" || sess.TenantID != "tenant-admin" {
		t.Fatalf("session = %+v", sess)
	}
	if _, err := svc.Authenticate(context.Background(), "admin-1", []byte("wrong"), "203.0.113.10", "browser"); !errors.Is(err, ErrAdminInvalidCredentials) {
		t.Fatalf("first wrong err = %v, want invalid credentials", err)
	}
	if _, err := svc.Authenticate(context.Background(), "admin-1", []byte("wrong"), "203.0.113.10", "browser"); !errors.Is(err, ErrAdminLocked) {
		t.Fatalf("second wrong err = %v, want lockout", err)
	}
	if _, err := svc.Authenticate(context.Background(), "admin-1", []byte("correct horse battery staple"), "203.0.113.10", "browser"); !errors.Is(err, ErrAdminLocked) {
		t.Fatalf("locked correct-password err = %v, want lockout", err)
	}
	if audit.Count("breakglass.admin_login") != 4 {
		t.Fatalf("audit count = %d, want 4", audit.Count("breakglass.admin_login"))
	}
	for _, rec := range audit.Records() {
		if rec.TenantID != "tenant-admin" {
			t.Fatalf("audit tenant = %q, want tenant-admin", rec.TenantID)
		}
		if strings.Contains(string(rec.Data), "correct horse battery staple") || strings.Contains(string(rec.Data), "wrong") {
			t.Fatalf("audit payload leaked password material: %s", string(rec.Data))
		}
	}
}

func TestAdminServiceDisabled(t *testing.T) {
	svc := NewAdminService(AdminConfig{})
	if _, err := svc.Authenticate(context.Background(), "admin-1", []byte("anything"), "", ""); !errors.Is(err, ErrAdminDisabled) {
		t.Fatalf("disabled Authenticate err = %v, want ErrAdminDisabled", err)
	}
}
