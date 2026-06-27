package auth_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/auth"
)

func TestServerSideSessionRevocationRejectsNextVerify(t *testing.T) {
	issuer := auth.NewSessionIssuer([]byte("0123456789abcdef0123456789abcdef"), time.Hour)
	token, err := issuer.Issue("user-1", "tenant-1", "u@example.test", []string{"viewer"})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if strings.Contains(token, "user-1") || strings.Contains(token, "tenant-1") {
		t.Fatalf("session cookie leaked claims: %q", token)
	}
	sess, err := issuer.Verify(token)
	if err != nil {
		t.Fatalf("Verify before revoke: %v", err)
	}
	if sess.ID == "" || sess.Subject != "user-1" || sess.TenantID != "tenant-1" {
		t.Fatalf("session = %+v", sess)
	}
	if err := issuer.Revoke(sess.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, err := issuer.Verify(token); !errors.Is(err, auth.ErrSessionRevoked) {
		t.Fatalf("Verify after revoke err = %v, want ErrSessionRevoked", err)
	}
}

func TestServerSideSessionExpiry(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	issuer := auth.NewSessionIssuerWithStore(
		[]byte("0123456789abcdef0123456789abcdef"),
		time.Hour,
		time.Minute,
		auth.NewMemorySessionStore(),
	)
	issuer.Now = func() time.Time { return now }
	idleToken, err := issuer.Issue("idle-user", "tenant-1", "", nil)
	if err != nil {
		t.Fatalf("Issue idle: %v", err)
	}
	now = now.Add(30 * time.Second)
	if _, err := issuer.Verify(idleToken); err != nil {
		t.Fatalf("Verify inside idle window: %v", err)
	}
	now = now.Add(2 * time.Minute)
	if _, err := issuer.Verify(idleToken); !errors.Is(err, auth.ErrSessionExpired) {
		t.Fatalf("Verify after idle expiry err = %v, want ErrSessionExpired", err)
	}

	now = time.Unix(1_700_010_000, 0)
	absoluteToken, err := issuer.Issue("absolute-user", "tenant-1", "", nil)
	if err != nil {
		t.Fatalf("Issue absolute: %v", err)
	}
	now = now.Add(time.Hour + time.Second)
	if _, err := issuer.Verify(absoluteToken); !errors.Is(err, auth.ErrSessionExpired) {
		t.Fatalf("Verify after absolute expiry err = %v, want ErrSessionExpired", err)
	}
}
