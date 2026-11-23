// SPDX-License-Identifier: BUSL-1.1

package signerwiring

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"trstctl.com/trstctl/internal/crypto"
)

// BreakGlassAuthorityFile is the file name, inside the signer custody
// directory, that carries the offline break-glass authority's PUBLIC key in
// PEM. It follows the same operator-provisions-trust-material pattern as the
// XREC plan trust bundle: nothing on the control plane can write it, and an
// absent file simply leaves break-glass unconfigured.
const BreakGlassAuthorityFile = "pcas-breakglass-authority.pem"

// DualControlAuthorityFile is the signer-only, operator-provisioned public
// approval authority. It must be mounted read-only to the signer and must not
// be writable or replaceable by a control-plane peer.
const DualControlAuthorityFile = "pcas-dual-control-authority.pem"

// LoadBreakGlassAuthority reads the break-glass authority public key from the
// signer custody directory. It returns nil (no error) when the directory is
// unset or the file is absent — the ordinary case, in which class downgrades
// stay refused unconditionally. A present-but-unparseable file is an error:
// half-configured break-glass must fail startup loudly rather than degrade
// into "downgrades always refused" that an operator believes is configured.
func LoadBreakGlassAuthority(dir string) ([]byte, error) {
	return loadSignerAuthority(dir, BreakGlassAuthorityFile, "break-glass")
}

// LoadDualControlAuthority resolves the signer's approval trust floor. An
// absent file leaves successor minting disabled by NewProductionMinter; a
// malformed file fails startup so an operator sees the configuration error.
func LoadDualControlAuthority(dir string) ([]byte, error) {
	return loadSignerAuthority(dir, DualControlAuthorityFile, "dual-control")
}

func loadSignerAuthority(dir, file, label string) ([]byte, error) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return nil, nil
	}
	// Through a directory handle: break-glass authority is the material that
	// permits an epoch downgrade, so a symlink in dir must not redirect it.
	root, err := os.OpenRoot(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("pcas signer: open %s authority dir: %w", label, err)
	}
	defer func() { _ = root.Close() }()
	raw, err := root.ReadFile(file)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("pcas %s: read authority key: %w", label, err)
	}
	pubDER, err := crypto.ParseEd25519PublicKeyPEM(raw)
	if err != nil {
		return nil, fmt.Errorf("pcas %s: parse authority key: %w", label, err)
	}
	return pubDER, nil
}
