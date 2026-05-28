// Package ssh implements the SSH issuance server: signing short-lived host and
// user certificates with principals, validity, and extensions, and maintaining
// the key revocation list (KRL).
//
// The SSH CA is chainless and is another implementation behind the
// internal/crypto boundary (AN-3), not a parallel crypto stack. Implementation
// begins in sprint S8.10; this file reserves the package.
package ssh
