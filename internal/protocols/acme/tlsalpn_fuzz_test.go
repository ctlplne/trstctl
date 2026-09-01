// SPDX-License-Identifier: MPL-2.0

package acme_test

// FuzzTLSALPN01Validate (S8b.5) hardens the tls-alpn-01 validator against hostile
// handshake results: no prober output may crash it, and it must fail closed — returning
// nil only when the negotiated ALPN is acme-tls/1 AND the presented acmeIdentifier
// equals SHA-256(keyAuthorization).
