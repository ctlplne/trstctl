package thirdpartycrypto

// thirdpartycrypto is outside internal/crypto. A production (non-test) file may
// not import third-party cryptography (golang.org/x/crypto, circl) — it must go
// through the internal/crypto boundary (AN-3, CRYPTO-002).
import _ "golang.org/x/crypto/acme" // want "third-party cryptography and is not allowed outside internal/crypto"
