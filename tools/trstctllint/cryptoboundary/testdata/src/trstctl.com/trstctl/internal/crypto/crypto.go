// SPDX-License-Identifier: BUSL-1.1

package crypto

// This package IS the AN-3 boundary, so importing crypto/* here is allowed and
// must not be flagged.
import (
	_ "crypto/ecdsa"
	_ "crypto/x509"
)
