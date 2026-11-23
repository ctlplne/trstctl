// SPDX-License-Identifier: BUSL-1.1

package eventprotect

import "errors"

// ErrTenantAdmissionInUse means another writer holds this tenant's event
// protection fence. A caller may wait before entering its mutation callback;
// it must not replay a callback after an ambiguous publication failure.
var ErrTenantAdmissionInUse = errors.New("tenant event protection is in use")
