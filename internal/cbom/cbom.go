// Package cbom is trstctl's cryptographic discovery and observability layer
// (F52): it inventories cryptographic *usage* across an environment — TLS
// endpoints, host crypto configuration, and certificate keys — and classifies
// each observation by strength, post-quantum exposure, and policy compliance,
// producing a Cryptographic Bill of Materials (CBOM).
//
// This is posture across assets trstctl does not necessarily issue, distinct
// from the cert/SSH discovery in F2/F3/F42. Classification is pure data — it
// imports no crypto/*; the scanners read observations through the crypto
// boundary (certinfo, tlsprobe) and hand this layer crypto-free facts.
package cbom

// AssetKind classifies what kind of cryptographic asset a finding describes.
type AssetKind string

const (
	// AssetTLSEndpoint is a negotiated TLS protocol version on a network endpoint.
	AssetTLSEndpoint AssetKind = "tls-endpoint"
	// AssetCertKey is the public key of a certificate observed in use.
	AssetCertKey AssetKind = "certificate-key"
	// AssetHostConfig is a protocol or cipher declared in host crypto config.
	AssetHostConfig AssetKind = "host-config"
)

// Finding is one observed cryptographic usage. Exactly one of the crypto facts
// — Protocol, Cipher, or Algorithm — drives its classification.
type Finding struct {
	Kind      AssetKind      `json:"kind"`
	Location  string         `json:"location"`            // host:port or file path
	Algorithm string         `json:"algorithm,omitempty"` // RSA, ECDSA, Ed25519, ML-DSA, ...
	KeyBits   int            `json:"key_bits,omitempty"`
	Protocol  string         `json:"protocol,omitempty"` // TLSv1.0, TLSv1.2, ...
	Cipher    string         `json:"cipher,omitempty"`   // cipher suite name
	Library   string         `json:"library,omitempty"`
	Class     Classification `json:"classification"`
}

// Classified returns a copy of the finding with its classification filled in
// from the policy.
func (f Finding) Classified(p Policy) Finding {
	f.Class = Classify(f, p)
	return f
}
