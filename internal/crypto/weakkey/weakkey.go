// SPDX-License-Identifier: BUSL-1.1

// Package weakkey decides whether a public key must be treated as weak
// whatever its algorithm and size, the way the badkeys project
// (https://badkeys.info, MIT licence) does: an elliptic-curve key whose private
// scalar is small (the eMudhra intermediates of October 2026), and an RSA key
// with a small prime factor, two close primes (Fermat), the ROCA structure
// (CVE-2017-15361), an entry on an operator-supplied blocklist such as
// Debian's 2008 OpenSSL list, an exponent no RSA key can have, or a prime it
// shares with another key in the same inventory (batch GCD). Nothing here is
// copied from badkeys; the checks are re-derived from their published
// definitions, and no third-party key list ships with trstctl (Debian's
// openssl-blacklist is GPL-3, so it is read from a file the operator supplies).
//
// Inputs are DER bytes, so callers outside the internal/crypto boundary (AN-3)
// never touch crypto/* types; results are plain findings.
package weakkey

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1" // #nosec G505 -- the Debian blocklist format is defined over SHA-1 of the modulus text; not used for security (CWE-328)
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"sync/atomic"
)

// Check names, stable for API consumers and finding records.
const (
	CheckECSmallScalar   = "ec_small_scalar"
	CheckRSASmallFactor  = "rsa_small_factor"
	CheckRSAClosePrimes  = "rsa_close_primes"
	CheckRSAROCA         = "rsa_roca"
	CheckRSABlocklist    = "rsa_blocklist"
	CheckRSAExponent     = "rsa_public_exponent"
	CheckRSASharedFactor = "rsa_shared_factor"
	CheckKeySize         = "key_size"
	CheckKeyAlgorithm    = "key_algorithm"
	CheckSignatureHash   = "signature_hash"
)

// Floors below which a key is rated weak whatever else is true of it (the
// CBOM default policy's floors).
const (
	MinimumRSABits = 2048
	MinimumECBits  = 256
)

// Finding is one reason a public key must be treated as weak.
type Finding struct {
	Check  string `json:"check"`
	Reason string `json:"reason"`
}

// Reasons joins findings into one operator sentence list.
func Reasons(findings []Finding) string {
	parts := make([]string, 0, len(findings))
	for _, f := range findings {
		parts = append(parts, f.Reason)
	}
	return strings.Join(parts, "; ")
}

// Blocklist is an operator-supplied list of known-compromised RSA keys in the
// format of Debian's openssl-blacklist (openssl-vulnkey): one entry per line,
// the last 20 hex digits of SHA-1("Modulus=" + uppercase hex modulus + "\n"),
// "#" comments allowed.
type Blocklist struct {
	Name    string
	entries map[string]bool
}

// Len reports how many entries the list holds.
func (b Blocklist) Len() int { return len(b.entries) }

// LoadOpenSSLBlocklist reads one list. A line that is neither a comment nor a
// 20-hex-digit entry is an error: a malformed list must not silently check
// nothing.
func LoadOpenSSLBlocklist(name string, data []byte) (Blocklist, error) {
	b := Blocklist{Name: name, entries: map[string]bool{}}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 4096), 1<<20)
	line := 0
	for sc.Scan() {
		line++
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		if len(text) != 20 {
			return Blocklist{}, fmt.Errorf("weakkey: %s line %d: want 20 hex digits", name, line)
		}
		if _, err := hex.DecodeString(text); err != nil {
			return Blocklist{}, fmt.Errorf("weakkey: %s line %d: want 20 hex digits", name, line)
		}
		b.entries[strings.ToLower(text)] = true
	}
	if err := sc.Err(); err != nil {
		return Blocklist{}, fmt.Errorf("weakkey: %s: %w", name, err)
	}
	if len(b.entries) == 0 {
		return Blocklist{}, fmt.Errorf("weakkey: %s holds no entries", name)
	}
	return b, nil
}

// openSSLBlocklistEntry is the openssl-vulnkey fingerprint of a modulus.
func openSSLBlocklistEntry(n *big.Int) string {
	sum := sha1.Sum([]byte("Modulus=" + strings.ToUpper(n.Text(16)) + "\n")) // #nosec G401 -- Debian blocklist entry format, not a security use of SHA-1 (CWE-328)
	return hex.EncodeToString(sum[:])[20:]
}

// Checker runs every check; the zero value checks without a blocklist. It
// remembers the structural verdict per public key (the EC search costs a few
// milliseconds), so rating the same key again is free.
type Checker struct {
	lists []Blocklist

	mu    sync.Mutex
	seen  map[[32]byte][]Finding
	order [][32]byte
}

// verdictCacheSize bounds the per-key memory: about 70 bytes a key.
const verdictCacheSize = 1 << 16

func (c *Checker) structural(spki []byte, pub any) []Finding {
	key := sha256.Sum256(spki)
	c.mu.Lock()
	if f, ok := c.seen[key]; ok {
		c.mu.Unlock()
		return append([]Finding(nil), f...)
	}
	c.mu.Unlock()
	f := c.checkPublic(pub)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.seen == nil {
		c.seen = make(map[[32]byte][]Finding)
	}
	if _, ok := c.seen[key]; !ok {
		if len(c.order) >= verdictCacheSize {
			delete(c.seen, c.order[0])
			c.order = c.order[1:]
		}
		c.seen[key] = append([]Finding(nil), f...)
		c.order = append(c.order, key)
	}
	return f
}

// NewChecker returns a checker with the given operator blocklists.
func NewChecker(lists ...Blocklist) *Checker {
	return &Checker{lists: append([]Blocklist(nil), lists...)}
}

var (
	defaultChecker atomic.Pointer[Checker]
	zeroChecker    = &Checker{}
)

// Default is the process-wide checker: no blocklist until SetDefault installs
// the operator's lists at startup.
func Default() *Checker {
	if c := defaultChecker.Load(); c != nil {
		return c
	}
	return zeroChecker
}

// SetDefault installs the process-wide checker (the operator's blocklists).
func SetDefault(c *Checker) {
	if c != nil {
		defaultChecker.Store(c)
	}
}

// Blocklists names the installed lists and their sizes, for startup logs.
func (c *Checker) Blocklists() map[string]int {
	out := make(map[string]int, len(c.lists))
	for _, l := range c.lists {
		out[l.Name] = l.Len()
	}
	return out
}

// CheckSPKI checks a DER SubjectPublicKeyInfo.
func (c *Checker) CheckSPKI(der []byte) ([]Finding, error) {
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("weakkey: public key does not parse: %w", err)
	}
	return c.structural(der, pub), nil
}

// CheckCertificate checks the subject public key of a DER certificate.
func (c *Checker) CheckCertificate(der []byte) ([]Finding, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("weakkey: certificate does not parse: %w", err)
	}
	return c.structural(cert.RawSubjectPublicKeyInfo, cert.PublicKey), nil
}

// RateCertificate is the full verdict on a DER certificate: its key size and
// algorithm against the floors, a broken signature hash, and every structural
// check of its public key.
func (c *Checker) RateCertificate(der []byte) ([]Finding, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("weakkey: certificate does not parse: %w", err)
	}
	var out []Finding
	switch k := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		if bits := k.N.BitLen(); bits < MinimumRSABits {
			out = append(out, Finding{Check: CheckKeySize, Reason: fmt.Sprintf("RSA-%d is below the %d-bit minimum", bits, MinimumRSABits)})
		}
	case *ecdsa.PublicKey:
		if k.Curve != nil && k.Curve.Params().BitSize < MinimumECBits {
			out = append(out, Finding{Check: CheckKeySize, Reason: fmt.Sprintf("%s is below the %d-bit curve minimum", k.Curve.Params().Name, MinimumECBits)})
		}
	}
	if cert.PublicKeyAlgorithm == x509.DSA {
		out = append(out, Finding{Check: CheckKeyAlgorithm, Reason: "DSA keys are no longer accepted for certificates"})
	}
	switch cert.SignatureAlgorithm {
	case x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		out = append(out, Finding{Check: CheckSignatureHash, Reason: fmt.Sprintf("signed with %s, a broken hash", cert.SignatureAlgorithm)})
	}
	return append(out, c.structural(cert.RawSubjectPublicKeyInfo, cert.PublicKey)...), nil
}

// RateKeyAlgorithmName rates a recorded key-algorithm name when no key bytes
// are at hand (an imported inventory row): "RSA-1024" and "DSA" are weak,
// "ECDSA", "Ed25519" and "ML-DSA-65" are not, and a name that names a broken
// hash ("SHA1", "MD5") is.
func RateKeyAlgorithmName(name string) []Finding {
	tokens := strings.FieldsFunc(strings.ToUpper(strings.TrimSpace(name)), func(r rune) bool {
		return (r < 'A' || r > 'Z') && (r < '0' || r > '9')
	})
	if len(tokens) == 0 {
		return nil
	}
	var out []Finding
	switch tokens[0] {
	case "RSA":
		for _, t := range tokens[1:] {
			var bits int
			if _, err := fmt.Sscanf(t, "%d", &bits); err == nil && fmt.Sprint(bits) == t && bits > 0 && bits < MinimumRSABits {
				out = append(out, Finding{Check: CheckKeySize, Reason: fmt.Sprintf("RSA-%d is below the %d-bit minimum", bits, MinimumRSABits)})
				break
			}
		}
	case "DSA":
		out = append(out, Finding{Check: CheckKeyAlgorithm, Reason: "DSA keys are no longer accepted for certificates"})
	}
	joined := strings.Join(tokens, "") // "sha1WithRSAEncryption", "ECDSA-SHA1", "SHA-1"
	for _, h := range []string{"MD2", "MD5", "SHA1"} {
		if strings.Contains(joined, h) {
			out = append(out, Finding{Check: CheckSignatureHash, Reason: fmt.Sprintf("the recorded algorithm %q names %s, a broken hash", name, h)})
			break
		}
	}
	return out
}

// CheckPEM checks every certificate or public key in a PEM bundle and returns
// the findings per block, in order (nil for a block with none).
func (c *Checker) CheckPEM(data []byte) ([][]Finding, error) {
	var out [][]Finding
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		var (
			findings []Finding
			err      error
		)
		switch block.Type {
		case "CERTIFICATE":
			findings, err = c.CheckCertificate(block.Bytes)
		case "PUBLIC KEY":
			findings, err = c.CheckSPKI(block.Bytes)
		default:
			continue
		}
		if err != nil {
			return nil, err
		}
		out = append(out, findings)
	}
	if len(out) == 0 {
		return nil, errors.New("weakkey: no certificate or public key in the PEM input")
	}
	return out, nil
}

// CheckPublicKey checks a parsed public key; for callers inside the crypto
// boundary (the signer's ceremony checks).
func (c *Checker) CheckPublicKey(pub any) []Finding { return c.checkPublic(pub) }

func (c *Checker) checkPublic(pub any) []Finding {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return c.checkRSA(k.N, k.E)
	case *ecdsa.PublicKey:
		if k.Curve == nil {
			return nil
		}
		enc, err := k.Bytes() // 0x04 || X || Y
		size := (k.Params().BitSize + 7) / 8
		if err != nil || len(enc) != 1+2*size || enc[0] != 4 {
			return nil
		}
		return checkEC(k.Params(), new(big.Int).SetBytes(enc[1:1+size]), new(big.Int).SetBytes(enc[1+size:]))
	default:
		// Ed25519, ML-DSA and the rest: no structural weakness to test here.
		return nil
	}
}

func (c *Checker) checkRSA(n *big.Int, e int) []Finding {
	var findings []Finding
	switch {
	case e < 3:
		findings = append(findings, Finding{Check: CheckRSAExponent, Reason: fmt.Sprintf("RSA public exponent %d provides no security", e)})
	case e%2 == 0:
		findings = append(findings, Finding{Check: CheckRSAExponent, Reason: fmt.Sprintf("RSA public exponent %d is even, which no valid RSA key has", e)})
	}
	if p := smallFactor(n); p != 0 {
		findings = append(findings, Finding{Check: CheckRSASmallFactor, Reason: fmt.Sprintf("the RSA modulus is divisible by %d", p)})
	} else if gap := fermatGap(n); gap != nil {
		findings = append(findings, Finding{Check: CheckRSAClosePrimes, Reason: fmt.Sprintf("the RSA primes differ by only %d bits, so Fermat's method factors the modulus", gap.BitLen())})
	}
	if rocaFingerprint(n) {
		findings = append(findings, Finding{Check: CheckRSAROCA, Reason: "the RSA modulus has the ROCA structure (CVE-2017-15361, Infineon RSALib), so it can be factored"})
	}
	if len(c.lists) > 0 {
		entry := openSSLBlocklistEntry(n)
		for _, l := range c.lists {
			if l.entries[entry] {
				findings = append(findings, Finding{Check: CheckRSABlocklist, Reason: fmt.Sprintf("the RSA key is on the blocklist %s", l.Name)})
				break
			}
		}
	}
	return findings
}

// smallPrimeWords groups the primes below 2^16 into products that fit 64 bits,
// so a modulus needs one big division per word, not per prime.
var smallPrimeWords = func() []primeWord {
	const limit = 1 << 16
	sieve := make([]bool, limit)
	var words []primeWord
	cur := primeWord{product: 1}
	for i := 2; i < limit; i++ {
		if sieve[i] {
			continue
		}
		for j := i * i; j < limit; j += i {
			sieve[j] = true
		}
		p := uint64(i) // #nosec G115 -- the sieve index is below 2^16, so it fits a uint64 (CWE-190)
		if cur.product > ^uint64(0)/p {
			words = append(words, cur)
			cur = primeWord{product: 1}
		}
		cur.product *= p
		cur.primes = append(cur.primes, p)
	}
	if len(cur.primes) > 0 {
		words = append(words, cur)
	}
	return words
}()

type primeWord struct {
	product uint64
	primes  []uint64
}

// smallFactor returns the smallest prime below 2^16 dividing n, or 0.
func smallFactor(n *big.Int) uint64 {
	w := new(big.Int)
	r := new(big.Int)
	for _, word := range smallPrimeWords {
		w.SetUint64(word.product)
		r.Mod(n, w)
		rem := r.Uint64()
		for _, p := range word.primes {
			if rem%p == 0 && n.Cmp(new(big.Int).SetUint64(p)) != 0 {
				return p
			}
		}
	}
	return 0
}

// fermatRounds bounds the search: primes this close are found in the first
// round or two; a hundred rounds covers what badkeys tests.
const fermatRounds = 100

// fermatGap returns |p − q| when Fermat's method factors n within the bound.
func fermatGap(n *big.Int) *big.Int {
	if n.Sign() <= 0 || n.Bit(0) == 0 {
		return nil
	}
	a := new(big.Int).Sqrt(n)
	if new(big.Int).Mul(a, a).Cmp(n) < 0 {
		a.Add(a, big.NewInt(1))
	}
	b2 := new(big.Int).Sub(new(big.Int).Mul(a, a), n)
	two := big.NewInt(2)
	for i := 0; i < fermatRounds; i++ {
		if isSquare(b2) {
			b := new(big.Int).Sqrt(b2)
			// p = a − b > 1 means a real factorisation (n = p·q).
			if new(big.Int).Sub(a, b).Cmp(big.NewInt(1)) > 0 {
				return new(big.Int).Mul(b, two)
			}
		}
		// (a+1)² − n = b2 + 2a + 1
		b2.Add(b2, new(big.Int).Add(new(big.Int).Mul(a, two), big.NewInt(1)))
		a.Add(a, big.NewInt(1))
	}
	return nil
}

var squareMod64 = func() [64]bool {
	var t [64]bool
	for i := 0; i < 64; i++ {
		t[(i*i)%64] = true
	}
	return t
}()

func isSquare(x *big.Int) bool {
	if x.Sign() < 0 {
		return false
	}
	if x.Sign() == 0 {
		return true
	}
	if !squareMod64[x.Bits()[0]&63] {
		return false
	}
	s := new(big.Int).Sqrt(x)
	return new(big.Int).Mul(s, s).Cmp(x) == 0
}
