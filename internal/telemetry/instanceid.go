package telemetry

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"certctl.io/certctl/internal/crypto"
)

// LoadOrCreateInstanceID returns a stable, anonymized instance identifier,
// generating a random one on first use and persisting it at path. The ID is
// random 128-bit data — never derived from the host, network, or any credential
// — so it carries no PII; the receiver counts distinct IDs to estimate active
// deployments, and nothing more.
func LoadOrCreateInstanceID(path string) (string, error) {
	if b, err := os.ReadFile(path); err == nil {
		if id := strings.TrimSpace(string(b)); id != "" {
			return id, nil
		}
	}
	id, err := newInstanceID()
	if err != nil {
		return "", err
	}
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return "", fmt.Errorf("telemetry: create id dir: %w", err)
		}
	}
	if err := os.WriteFile(path, []byte(id+"\n"), 0o600); err != nil {
		return "", fmt.Errorf("telemetry: persist instance id: %w", err)
	}
	return id, nil
}

// newInstanceID returns a fresh random anonymized identifier. Randomness comes
// through the internal/crypto boundary (AN-3).
func newInstanceID() (string, error) {
	b, err := crypto.RandomBytes(16)
	if err != nil {
		return "", fmt.Errorf("telemetry: generate instance id: %w", err)
	}
	return hex.EncodeToString(b), nil
}
