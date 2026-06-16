package software

// A subpackage of internal/crypto (a backend implementation) is also inside the
// boundary, so crypto/* imports here are allowed.
import _ "crypto/rsa"
