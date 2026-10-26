// SPDX-License-Identifier: BUSL-1.1

// Package tenantwrap binds a tenant's domain key-encryption key (KEK) to an
// operator-provisioned wrapper key: a local wrapper file, or a key held outside
// the process, such as an AES key on an HSM the isolated signer reaches over
// PKCS#11 (ExternalWrapper, A123).
//
// The wrapper file must already exist and pass secretfile's custody checks.
// This package never creates that file or an external key, never falls back to
// the deployment KEK, and has no remote or network path of its own. A returned
// *seal.LocalKEK owns locked, non-dumpable memory; its caller must call Destroy
// when the operation ends.
package tenantwrap
