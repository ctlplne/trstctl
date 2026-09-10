// SPDX-License-Identifier: MPL-2.0

package store

// This exact application-owned routine checks current tenant scope before
// taking relation/advisory locks. It reads only pg_locks, never tenant rows.
// Recognition must not extend to an arbitrary SELECT that includes its name.
const (
	certificateMetadataLock   = "SELECT lock_certificate_metadata_order($1::uuid)"
	certificateLockPrefix     = "SELECT fake_lock_certificate_metadata_order($1::uuid)"                                            // want "does not filter on tenant_id"
	certificateLockSuffix     = "SELECT lock_certificate_metadata_order_unchecked($1::uuid)"                                       // want "does not filter on tenant_id"
	certificateLockExtra      = "SELECT lock_certificate_metadata_order($1::uuid), load_secret_without_tenant($2)"                 // want "does not filter on tenant_id"
	certificateLockSecond     = "SELECT lock_certificate_metadata_order($1::uuid); SELECT load_secret_without_tenant($2)"          // want "does not filter on tenant_id"
	certificateLockFrom       = "SELECT lock_certificate_metadata_order($1::uuid) FROM secrets WHERE id=$2"                        // want "does not filter on tenant_id"
	certificateLockJoin       = "SELECT lock_certificate_metadata_order($1::uuid) FROM secrets s JOIN owners o ON o.id=s.owner_id" // want "does not filter on tenant_id"
	certificateLockExpression = "SELECT lock_certificate_metadata_order(load_tenant_without_scope())"                              // want "does not filter on tenant_id"
)
