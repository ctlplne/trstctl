// SPDX-License-Identifier: MPL-2.0

package store

// store is outside internal/crypto, so any crypto/* import must be flagged.
import _ "crypto/x509" // want "not allowed outside internal/crypto"
