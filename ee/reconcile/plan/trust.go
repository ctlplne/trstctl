// SPDX-License-Identifier: LicenseRef-trstctl-EE

package plan

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"trstctl.com/trstctl/internal/crypto"
)

const TrustBundleFile = "xrec-plan-trust.json"

var ErrInvalidTrustBundle = errors.New("xrec plan: invalid trust bundle")

type TrustBundle struct {
	PlanKeys []TrustedKey `json:"plan_keys"`
}

type TrustedKey struct {
	KeyID        string           `json:"key_id"`
	Algorithm    crypto.Algorithm `json:"algorithm"`
	PublicKeyDER []byte           `json:"public_key_der"`
}

func LoadTrustedPlanKeys(dir string) (map[string]crypto.PublicKey, error) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(filepath.Join(dir, TrustBundleFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("xrec plan: read trust bundle: %w", err)
	}
	var bundle TrustBundle
	if err := json.Unmarshal(raw, &bundle); err != nil {
		return nil, fmt.Errorf("%w: decode: %v", ErrInvalidTrustBundle, err)
	}
	return PlanKeyMap(bundle)
}

func WriteTrustBundle(dir string, bundle TrustBundle) error {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return fmt.Errorf("%w: directory required", ErrInvalidTrustBundle)
	}
	if _, err := PlanKeyMap(bundle); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("xrec plan: create trust dir: %w", err)
	}
	raw, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return fmt.Errorf("xrec plan: encode trust bundle: %w", err)
	}
	raw = append(raw, '\n')
	if err := os.WriteFile(filepath.Join(dir, TrustBundleFile), raw, 0o600); err != nil {
		return fmt.Errorf("xrec plan: write trust bundle: %w", err)
	}
	return nil
}

func PlanKeyMap(bundle TrustBundle) (map[string]crypto.PublicKey, error) {
	out := map[string]crypto.PublicKey{}
	for _, key := range bundle.PlanKeys {
		keyID := strings.TrimSpace(key.KeyID)
		if keyID == "" || key.Algorithm == "" || len(key.PublicKeyDER) == 0 {
			return nil, ErrInvalidTrustBundle
		}
		if _, exists := out[keyID]; exists {
			return nil, fmt.Errorf("%w: duplicate key id %q", ErrInvalidTrustBundle, keyID)
		}
		out[keyID] = crypto.PublicKey{Algorithm: key.Algorithm, DER: append([]byte(nil), key.PublicKeyDER...)}
	}
	return out, nil
}
