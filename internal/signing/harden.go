// SPDX-License-Identifier: BUSL-1.1

package signing

import "errors"

// ErrUnsupportedHardening means this platform cannot provide the signer's
// required process hardening, UDS peer-UID binding, and locked secret memory.
// cmd/trstctl-signer fails closed on this error unless the operator passes the
// explicit local-development non-Linux override.
var ErrUnsupportedHardening = errors.New("signer hardening unsupported on this platform")
