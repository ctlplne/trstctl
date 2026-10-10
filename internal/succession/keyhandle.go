// SPDX-License-Identifier: BUSL-1.1

package succession

import (
	"fmt"

	"trstctl.com/trstctl/internal/crypto"
)

// KeyHandle is the legacy unscoped signer handle used by older direct minter
// fixtures. New production requests must use TenantKeyHandle so two tenants
// cannot claim the same signer key by choosing the same identity string.
func KeyHandle(identityID string, epoch uint64) string {
	return fmt.Sprintf("pcas:%s:%d", identityID, epoch)
}

// TenantIdentityKey is the isolated signer's stable custody namespace. Hashing
// the length-delimited pair avoids collisions from user-chosen identity IDs and
// keeps raw tenant/identity names out of signer filenames and floor keys. Both
// the epoch floor and key handles use this namespace; PostgreSQL RLS alone
// cannot isolate state held inside the separate signer process.
func TenantIdentityKey(tenantID, identityID string) string {
	bound := fmt.Sprintf("trstctl/pcas/tenant-identity/v2:%d:%s:%d:%s", len(tenantID), tenantID, len(identityID), identityID)
	return fmt.Sprintf("pcas:v2:%x", crypto.SHA256Sum([]byte(bound)))
}

// TenantKeyHandle identifies one tenant's in-signer key at an epoch. New
// operator-registered identities use this handle; KeyHandle remains available
// for already provisioned legacy test fixtures and their migration path.
func TenantKeyHandle(tenantID, identityID string, epoch uint64) string {
	return fmt.Sprintf("%s:%d", TenantIdentityKey(tenantID, identityID), epoch)
}
