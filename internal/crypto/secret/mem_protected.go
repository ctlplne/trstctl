// SPDX-License-Identifier: BUSL-1.1
package secret

import "errors"

// ErrProtectedMemory means the platform could not guarantee off-heap,
// non-swappable plaintext and core-dump exclusion for rewrap verification.
var ErrProtectedMemory = errors.New("secret: protected memory unavailable")
