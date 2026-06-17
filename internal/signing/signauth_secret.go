package signing

import (
	"bytes"
	"fmt"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/crypto/secretfile"
)

const defaultSignAuthorizerBytes = 32

// LoadOrCreateAuthorizer loads the signer content-authorization secret from path,
// creating a random one when the file does not exist. The returned authorizer is
// backed by locked memory inside internal/crypto; the transient file bytes are
// wiped before this function returns (AN-8).
func LoadOrCreateAuthorizer(path string) (*crypto.SignAuthorizer, error) {
	if path == "" {
		return nil, fmt.Errorf("signing: sign authorizer secret path is required")
	}
	raw, err := secretfile.LoadOrCreate(path, func() ([]byte, error) {
		return crypto.RandomBytes(defaultSignAuthorizerBytes)
	})
	if err != nil {
		return nil, fmt.Errorf("load sign authorizer secret: %w", err)
	}
	defer secret.Wipe(raw)
	material := bytes.TrimSpace(raw)
	authz, err := crypto.NewSignAuthorizer(material)
	if err != nil {
		return nil, fmt.Errorf("load sign authorizer: %w", err)
	}
	return authz, nil
}
