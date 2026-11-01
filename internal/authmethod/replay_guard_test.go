// SPDX-License-Identifier: BUSL-1.1

package authmethod

import (
	"context"
	"errors"
	"testing"
	"time"
)

type memoryReplayGuard struct {
	seen  map[string]time.Time
	calls int
}

func (g *memoryReplayGuard) FirstUse(_ context.Context, method, key string, expires time.Time) (bool, error) {
	g.calls++
	if _, used := g.seen[method+"|"+key]; used {
		return false, nil
	}
	g.seen[method+"|"+key] = expires
	return true, nil
}

// M4 prerequisite: an oidc or jwt machine credential with a durable guard is
// single-use. The use is recorded only after every other check passes, so a
// token refused for another reason never uses up a valid token's one use; a
// token without jti is keyed by its own bytes.
func TestJWTMethodsRecordSingleUseLastM4(t *testing.T) {
	f := newOIDCFixture(t)
	guard := &memoryReplayGuard{seen: map[string]time.Time{}}
	oidc := f.method()
	oidc.Guard = guard
	claims := map[string]any{
		"iss": "https://issuer.example", "aud": "trstctl", "sub": "ci-deployer",
		"exp": f.now.Add(10 * time.Minute).Unix(), "jti": "run-1",
	}
	tok := f.sign(t, claims)
	if _, _, err := oidc.Authenticate(context.Background(), tok); err != nil {
		t.Fatalf("first use: %v", err)
	}
	if _, _, err := oidc.Authenticate(context.Background(), tok); !errors.Is(err, ErrCredentialReplayed) {
		t.Fatalf("replay = %v, want ErrCredentialReplayed", err)
	}
	// The same jti from another token of the same issuer is the same credential.
	claims["sub"] = "someone-else"
	if _, _, err := oidc.Authenticate(context.Background(), f.sign(t, claims)); !errors.Is(err, ErrCredentialReplayed) {
		t.Fatalf("same issuer and jti = %v, want refused", err)
	}

	// A token for the wrong audience fails before the guard and records nothing.
	calls := guard.calls
	wrongAud := f.sign(t, map[string]any{
		"iss": "https://issuer.example", "aud": "elsewhere", "sub": "ci-deployer",
		"exp": f.now.Add(10 * time.Minute).Unix(), "jti": "run-2",
	})
	if _, _, err := oidc.Authenticate(context.Background(), wrongAud); err == nil || guard.calls != calls {
		t.Fatalf("a refused token reached the single-use record: err=%v calls=%d→%d", err, calls, guard.calls)
	}

	// No jti: the token itself is the key.
	jwt := JWTMethod{JWKS: f.jwks, Issuer: "https://issuer.example", Audience: "trstctl", Now: func() time.Time { return f.now }, Guard: guard}
	noJTI := f.sign(t, map[string]any{"iss": "https://issuer.example", "aud": "trstctl", "sub": "batch", "exp": f.now.Add(time.Minute).Unix()})
	if _, _, err := jwt.Authenticate(context.Background(), noJTI); err != nil {
		t.Fatalf("first use without jti: %v", err)
	}
	if _, _, err := jwt.Authenticate(context.Background(), noJTI); !errors.Is(err, ErrCredentialReplayed) {
		t.Fatalf("replay without jti = %v", err)
	}
}
