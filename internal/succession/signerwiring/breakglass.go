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

// LoadBreakGlassAuthority reads the break-glass authority public key from the
// signer custody directory. It returns nil (no error) when the directory is
// unset or the file is absent — the ordinary case, in which class downgrades
// stay refused unconditionally. A present-but-unparseable file is an error:
// half-configured break-glass must fail startup loudly rather than degrade
// into "downgrades always refused" that an operator believes is configured.
func LoadBreakGlassAuthority(dir string) ([]byte, error) {
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
		return nil, fmt.Errorf("pcas signer: open break-glass dir: %w", err)
	}
	defer func() { _ = root.Close() }()
	raw, err := root.ReadFile(BreakGlassAuthorityFile)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("pcas break-glass: read authority key: %w", err)
	}
	pubDER, err := crypto.ParseEd25519PublicKeyPEM(raw)
	if err != nil {
		return nil, fmt.Errorf("pcas break-glass: parse authority key: %w", err)
	}
	return pubDER, nil
}
