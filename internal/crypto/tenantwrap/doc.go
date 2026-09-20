// SPDX-License-Identifier: BUSL-1.1

// Package tenantwrap binds a tenant's domain key-encryption key (KEK) to an
// operator-provisioned local wrapper key.
//
// The wrapper file must already exist and pass secretfile's custody checks.
// This package never creates that file, never falls back to the deployment KEK,
// and has no remote or network path. A returned *seal.LocalKEK owns locked,
// non-dumpable memory; its caller must call Destroy when the operation ends.
package tenantwrap
