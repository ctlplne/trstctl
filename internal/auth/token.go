package auth

import (
	"encoding/base64"
	"encoding/hex"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// TokenPrefix marks trstctl API tokens.
const TokenPrefix = "trst_"

// APIToken is a stored API token's record — its identity, scopes, and expiry. The
// secret itself is never stored; only its hash is (see GenerateAPIToken).
type APIToken struct {
	ID        string
	TenantID  string
	Subject   string
	Scopes    []string
	ExpiresAt time.Time
}

// GenerateAPIToken creates a new opaque API token. The raw token is returned as
// an owned byte buffer to show once at the edge; callers must wipe it after use.
// Only the hash is stored for later lookup.
func GenerateAPIToken() (raw []byte, hash string, err error) {
	seed, err := crypto.RandomBytes(32)
	if err != nil {
		return nil, "", err
	}
	defer secret.Wipe(seed)

	raw = make([]byte, len(TokenPrefix)+base64.RawURLEncoding.EncodedLen(len(seed)))
	copy(raw, TokenPrefix)
	base64.RawURLEncoding.Encode(raw[len(TokenPrefix):], seed)
	hash, err = HashAPIToken(raw)
	if err != nil {
		secret.Wipe(raw)
		return nil, "", err
	}
	return raw, hash, nil
}

// HashAPIToken returns the deterministic lookup hash of a raw token (SHA-256
// hex), computed through the crypto boundary.
func HashAPIToken(raw []byte) (string, error) {
	sum, err := crypto.Digest(crypto.SHA256, raw)
	if err != nil {
		return "", err
	}
	defer secret.Wipe(sum)
	return hex.EncodeToString(sum), nil
}

// Principal builds the RBAC principal for the token: its scopes become the
// permissions of a token-scoped role, granted tenant-wide within the token's
// tenant. The API's RBAC guard then enforces those scopes per request.
func (t APIToken) Principal() authz.Principal {
	perms := make([]authz.Permission, 0, len(t.Scopes))
	for _, s := range t.Scopes {
		perms = append(perms, authz.Permission(s))
	}
	role := authz.Role{Name: "api-token", Permissions: perms}
	return authz.Principal{
		TenantID: t.TenantID,
		Subject:  t.Subject,
		Grants:   []authz.Grant{{Role: role, Scope: authz.Scope{TenantID: t.TenantID}}},
	}
}
