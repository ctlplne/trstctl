// SPDX-License-Identifier: BUSL-1.1

package audit

import (
	"errors"

	"trstctl.com/trstctl/internal/crypto/jose"
)

// ErrUnsupportedArtifact refuses a signing request for any other artifact.
var ErrUnsupportedArtifact = errors.New("audit: the service signs only anchor log heads through this path")

// SignArtifact signs an anchor log head (A148) with the audit export key, under
// its own artifact domain so it can never be read as an export bundle.
func (s *Service) SignArtifact(kind string, payload []byte) (string, error) {
	if s.signer == nil {
		return "", ErrMissingSigner
	}
	if kind != jose.ArtifactAuditAnchorLog {
		return "", ErrUnsupportedArtifact
	}
	return s.signer.SignArtifact(kind, payload)
}
