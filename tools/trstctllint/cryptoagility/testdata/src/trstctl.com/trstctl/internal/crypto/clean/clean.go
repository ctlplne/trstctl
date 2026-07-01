package clean

// A fixed protocol allowlist is not a runtime provider registry. This mirrors
// the production TLS AEAD allowlist shape and must stay allowed.
var aeadCipherSuites = []uint16{0x1301, 0x1302}

var aeadSet = map[uint16]struct{}{
	0x1301: {},
	0x1302: {},
}

type Backend interface {
	Name() string
}
