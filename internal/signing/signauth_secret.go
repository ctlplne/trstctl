package signing

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
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
	raw, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("read sign authorizer secret: %w", err)
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, fmt.Errorf("create sign authorizer directory: %w", err)
		}
		raw, err = crypto.RandomBytes(defaultSignAuthorizerBytes)
		if err != nil {
			return nil, fmt.Errorf("generate sign authorizer secret: %w", err)
		}
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			secret.Wipe(raw)
			return nil, fmt.Errorf("write sign authorizer secret: %w", err)
		}
	}
	defer secret.Wipe(raw)
	material := bytes.TrimSpace(raw)
	authz, err := crypto.NewSignAuthorizer(material)
	if err != nil {
		return nil, fmt.Errorf("load sign authorizer: %w", err)
	}
	return authz, nil
}
