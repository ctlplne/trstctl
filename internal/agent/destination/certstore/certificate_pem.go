// SPDX-License-Identifier: BUSL-1.1

package certstore

import (
	"encoding/pem"
	"errors"
)

// Require nonempty public certificate bytes before passing their first-byte
// address to an operating-system API. The OS still validates the DER structure.
func certificateDER(certPEM []byte) ([]byte, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" || len(block.Bytes) == 0 {
		return nil, errors.New("certstore: expected a nonempty PEM certificate block")
	}
	return block.Bytes, nil
}
