// SPDX-License-Identifier: BUSL-1.1

// Package cbom is trstctl's cryptographic discovery and observability layer
// (F52): it inventories cryptographic *usage* across an environment — TLS
// endpoints, host crypto configuration, and certificate keys — and classifies
// each observation by strength, quantum exposure, and policy compliance,
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
	// AssetCryptoLibrary is a TLS library, Go program or Java installation
	// a host agent inventoried, rated by whether it can negotiate the
	// X25519MLKEM768 hybrid (X2-L5R).
	AssetCryptoLibrary AssetKind = "crypto-library"
	// AssetKeystoreKey is a key held in a keystore a host agent
	// inventoried, by its type and size (X2-L5R).
	AssetKeystoreKey AssetKind = "keystore-key"
	// AssetKeyFile is a private key file a host agent inventoried, by its
	// type and size (X2-L5R).
	AssetKeyFile AssetKind = "key-file"
)

// The answers a crypto-library asset's PQHybrid carries: whether the
// library can negotiate X25519MLKEM768 (X2-L5R).
const (
	PQHybridYes     = "yes"
	PQHybridNo      = "no"
	PQHybridUnknown = "unknown"
)

// Finding is one observed cryptographic usage. Exactly one of the crypto facts
// — Protocol, Cipher, or Algorithm — drives its classification.
type Finding struct {
	CertificateFingerprint string         `json:"certificate_fingerprint,omitempty"`
	Kind                   AssetKind      `json:"kind"`
	Location               string         `json:"location"`            // host:port or file path
	Algorithm              string         `json:"algorithm,omitempty"` // RSA, ECDSA, Ed25519, ...
	KeyBits                int            `json:"key_bits,omitempty"`
	Protocol               string         `json:"protocol,omitempty"` // TLSv1.0, TLSv1.2, ...
	Cipher                 string         `json:"cipher,omitempty"`   // cipher suite name
	Library                string         `json:"library,omitempty"`
	Class                  Classification `json:"classification"`
	// KeyWeakReasons and KeyDistrust are filled by a source while it holds the
	// certificate (Part 4); Classify turns them into a weak, out-of-policy
	// rating whose reasons say why. They are inputs only: the classification
	// carries them, so they are not serialized.
	KeyWeakReasons []string `json:"-"`
	KeyDistrust    string   `json:"-"`
	// Certificate is an imported certificate component's own facts (X6-L6):
	// the import takes a fingerprinted one into the certificate inventory.
	// It never reaches the CBOM row, which records the asset's crypto only.
	Certificate *ImportedCertificate `json:"-"`
	// ConfigSource is ConfigSourceDefault for a host-config fact the product
	// reaches only through its built-in default, with nothing in the file
	// saying so (X2-L7); empty for a stated configuration and every other
	// source.
	ConfigSource string `json:"config_source,omitempty"`
	// ProductVersion names the installed package whose default it is, as the
	// host's package database records it ("haproxy 2.8.5-1ubuntu3"); for a
	// crypto-library asset, the library and its version ("openssl 3.5.9",
	// X2-L5R).
	ProductVersion string `json:"product_version,omitempty"`
	// PQHybrid and PQBasis are a crypto-library asset's answer and its
	// reason, inputs to its classification only (X2-L5R).
	PQHybrid string `json:"-"`
	PQBasis  string `json:"-"`
}

// ConfigSourceDefault marks a fact a product reaches only through its
// built-in default (X2-L7).
const ConfigSourceDefault = "default"

// Classified returns a copy of the finding with its classification filled in
// from the policy.
func (f Finding) Classified(p Policy) Finding {
	f.Class = Classify(f, p)
	return f
}
