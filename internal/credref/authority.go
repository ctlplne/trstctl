// SPDX-License-Identifier: BUSL-1.1

package credref

import "errors"

// ErrReadAuthorityRevoked means a stored reference can no longer be redeemed
// under the principal that configured its destination.
var ErrReadAuthorityRevoked = errors.New("stored credential reference needs reauthorization")
