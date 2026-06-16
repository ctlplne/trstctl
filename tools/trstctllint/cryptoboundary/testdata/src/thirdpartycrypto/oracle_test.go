package thirdpartycrypto

// A differential/conformance test may drive a reference implementation (here the
// upstream ACME client) as a known-good oracle. That is a test concern, not a
// handler/service pulling crypto outside the boundary, so a _test.go import of
// third-party crypto is allowed (no diagnostic). The stdlib crypto/* ban still
// applies to every file; only the third-party rule is test-exempt.
import _ "golang.org/x/crypto/acme"
