// SPDX-License-Identifier: BUSL-1.1

package weakkey

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"
)

// ecdhCurve maps a curve to crypto/ecdh, the independent oracle for k·G.
func ecdhCurve(t *testing.T, name string) ecdh.Curve {
	t.Helper()
	switch name {
	case "P-256":
		return ecdh.P256()
	case "P-384":
		return ecdh.P384()
	case "P-521":
		return ecdh.P521()
	}
	t.Fatalf("no ecdh curve for %s", name)
	return nil
}

// pointFor returns k·G through crypto/ecdh (k in [1, n−1]).
func pointFor(t *testing.T, c *ecCurve, k *big.Int) (x, y *big.Int) {
	t.Helper()
	size := (c.params.BitSize + 7) / 8
	priv, err := ecdhCurve(t, c.name).NewPrivateKey(k.FillBytes(make([]byte, size)))
	if err != nil {
		t.Fatalf("ecdh private key for k=%s: %v", k, err)
	}
	pub := priv.PublicKey().Bytes() // 0x04 || X || Y
	return new(big.Int).SetBytes(pub[1 : 1+size]), new(big.Int).SetBytes(pub[1+size:])
}

func ecKey(t *testing.T, curveName string, k *big.Int) *ecdsa.PublicKey {
	t.Helper()
	for _, c := range ecCurves {
		if c.name == curveName {
			size := (c.params.BitSize + 7) / 8
			x, y := pointFor(t, c, k)
			enc := append([]byte{4}, append(x.FillBytes(make([]byte, size)), y.FillBytes(make([]byte, size))...)...)
			pub, err := ecdsa.ParseUncompressedPublicKey(curveByName(curveName), enc)
			if err != nil {
				t.Fatalf("%s k=%s: %v", curveName, k, err)
			}
			return pub
		}
	}
	t.Fatalf("unknown curve %s", curveName)
	return nil
}

func curveByName(name string) elliptic.Curve {
	switch name {
	case "P-256":
		return elliptic.P256()
	case "P-384":
		return elliptic.P384()
	case "P-521":
		return elliptic.P521()
	}
	return elliptic.P224()
}

// The table arithmetic is checked against crypto/ecdh on every supported curve
// for small, edge and random scalars.
func TestScalarBaseMultMatchesCryptoECDH(t *testing.T) {
	for _, c := range ecCurves {
		if c.name == "P-224" {
			continue // crypto/ecdh has no P-224; its arithmetic is the same code
		}
		scalars := []*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3), big.NewInt(4), big.NewInt(babySteps), big.NewInt(ecSmallScalarBound), new(big.Int).Sub(c.params.N, big.NewInt(1))}
		for i := 0; i < 4; i++ {
			k, err := rand.Int(rand.Reader, new(big.Int).Sub(c.params.N, big.NewInt(1)))
			if err != nil {
				t.Fatal(err)
			}
			scalars = append(scalars, k.Add(k, big.NewInt(1)))
		}
		for _, k := range scalars {
			wantX, wantY := pointFor(t, c, k)
			gotX, gotY, ok := c.scalarBaseMult(k)
			if !ok || gotX.Cmp(wantX) != 0 || gotY.Cmp(wantY) != 0 {
				t.Fatalf("%s: %s·G differs from crypto/ecdh", c.name, k)
			}
		}
	}
}

// Part 4 Done-when: a P-384 key whose private scalar is 4, and one whose
// scalar is n − 4, are flagged; so is every small scalar up to the bound, on
// every curve; ordinary keys pass.
func TestSmallPrivateScalarsAreFlagged(t *testing.T) {
	checker := NewChecker()
	p384 := ecCurves[2]
	cases := []struct {
		curve  string
		k      *big.Int
		expect string
	}{
		{"P-384", big.NewInt(4), "its private key is 4,"},
		{"P-384", new(big.Int).Sub(p384.params.N, big.NewInt(4)), "its private key is n − 4,"},
		{"P-384", big.NewInt(237), "its private key is 237,"},
		{"P-256", big.NewInt(1), "its private key is 1,"},
		{"P-256", big.NewInt(babySteps), "its private key is 65536,"},
		{"P-521", big.NewInt(65537), "its private key is 65537,"},
		{"P-384", big.NewInt(1<<24 - 1), "its private key is 16777215,"},
		{"P-256", new(big.Int).Sub(ecCurves[1].params.N, big.NewInt(ecSmallScalarBound)), "its private key is n − 16842752,"},
	}
	for _, tc := range cases {
		findings := checker.CheckPublicKey(ecKey(t, tc.curve, tc.k))
		if len(findings) != 1 || findings[0].Check != CheckECSmallScalar || !strings.Contains(findings[0].Reason, tc.expect) {
			t.Fatalf("%s k=%s: findings %+v, want %q", tc.curve, tc.k, findings, tc.expect)
		}
	}
	// Just past the bound, and ordinary random keys: nothing.
	if f := checker.CheckPublicKey(ecKey(t, "P-256", big.NewInt(ecSmallScalarBound+1))); len(f) != 0 {
		t.Fatalf("k past the bound flagged: %+v", f)
	}
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if f := checker.CheckPublicKey(&key.PublicKey); len(f) != 0 {
			t.Fatalf("a random %s key was flagged: %+v", curve.Params().Name, f)
		}
	}
}

// The real EM OV TLS CA - G3C intermediate (crt.sh id 18286207177, under
// emSign Root TLS CA - G3) is caught from its certificate bytes alone.
func TestEMudhraIntermediateIsFlaggedFromItsCertificate(t *testing.T) {
	data, err := os.ReadFile("testdata/em-ov-tls-ca-g3c.pem")
	if err != nil {
		t.Fatal(err)
	}
	per, err := NewChecker().CheckPEM(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(per) != 1 || len(per[0]) != 1 || per[0][0].Check != CheckECSmallScalar || !strings.Contains(per[0][0].Reason, "P-384") {
		t.Fatalf("EM OV TLS CA - G3C: %+v", per)
	}
	t.Logf("EM OV TLS CA - G3C: %s", per[0][0].Reason)
}

func rsaSPKI(t *testing.T, n *big.Int, e int) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&rsa.PublicKey{N: n, E: e})
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func prime(t *testing.T, bits int) *big.Int {
	t.Helper()
	p, err := rand.Prime(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func nextPrime(from *big.Int) *big.Int {
	p := new(big.Int).Set(from)
	if p.Bit(0) == 0 {
		p.Add(p, big.NewInt(1))
	}
	for !p.ProbablyPrime(20) {
		p.Add(p, big.NewInt(2))
	}
	return p
}

func onlyCheck(t *testing.T, findings []Finding, check string) Finding {
	t.Helper()
	for _, f := range findings {
		if f.Check == check {
			return f
		}
	}
	t.Fatalf("no %s finding in %+v", check, findings)
	return Finding{}
}

func TestRSAWeaknessesAreFlaggedAndStrongKeysPass(t *testing.T) {
	checker := NewChecker()
	// An ordinary key passes.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if f, err := checker.CheckSPKI(rsaSPKI(t, key.N, key.E)); err != nil || len(f) != 0 {
		t.Fatalf("an ordinary RSA-2048 key: %+v %v", f, err)
	}
	// A small prime factor.
	small := new(big.Int).Mul(big.NewInt(65521), prime(t, 1000))
	f, err := checker.CheckSPKI(rsaSPKI(t, small, 65537))
	if err != nil || !strings.Contains(onlyCheck(t, f, CheckRSASmallFactor).Reason, "divisible by 65521") {
		t.Fatalf("small factor: %+v %v", f, err)
	}
	// Close primes: Fermat factors them at once.
	p := prime(t, 1024)
	q := nextPrime(new(big.Int).Add(p, big.NewInt(1<<20)))
	close := new(big.Int).Mul(p, q)
	f, err = checker.CheckSPKI(rsaSPKI(t, close, 65537))
	if err != nil {
		t.Fatal(err)
	}
	onlyCheck(t, f, CheckRSAClosePrimes)
	// Exponents no RSA key can have.
	for _, e := range []int{1, 2, 4, 65536} {
		got := checker.CheckPublicKey(&rsa.PublicKey{N: key.N, E: e})
		onlyCheck(t, got, CheckRSAExponent)
	}
}

// A ROCA-structured modulus (each prime k·M + 65537^a mod M, M the primorial
// of the primes up to 167, as Infineon's RSALib built them) is flagged; random
// moduli are not.
func TestROCAStructuredModulusIsFlagged(t *testing.T) {
	m := big.NewInt(2)
	for _, p := range rocaPrimes {
		m.Mul(m, new(big.Int).SetUint64(p))
	}
	rocaPrime := func(a int64) *big.Int {
		c := new(big.Int).Exp(big.NewInt(65537), big.NewInt(a), m)
		for {
			k, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 512-uint(m.BitLen())))
			if err != nil {
				t.Fatal(err)
			}
			p := new(big.Int).Add(new(big.Int).Mul(k, m), c)
			if p.BitLen() >= 500 && p.ProbablyPrime(20) {
				return p
			}
		}
	}
	n := new(big.Int).Mul(rocaPrime(123), rocaPrime(4567))
	if !rocaFingerprint(n) {
		t.Fatal("a ROCA-structured modulus was not fingerprinted")
	}
	f, err := NewChecker().CheckSPKI(rsaSPKI(t, n, 65537))
	if err != nil {
		t.Fatal(err)
	}
	onlyCheck(t, f, CheckRSAROCA)
	for i := 0; i < 20; i++ {
		if rocaFingerprint(new(big.Int).Mul(prime(t, 512), prime(t, 512))) {
			t.Fatal("a random modulus was fingerprinted as ROCA")
		}
	}
}

// Debian's 2008 OpenSSL keys are checked against a list the operator supplies
// in openssl-vulnkey's format (trstctl ships no GPL-3 list). The entry for a
// modulus is checked against an independent computation: the last 20 hex
// digits of `printf 'Modulus=%s\n' <HEX> | shasum` for this fixed modulus.
func TestDebianStyleBlocklistFlagsAListedKey(t *testing.T) {
	n, _ := new(big.Int).SetString("C3A5F1E9B7D2804613579BDF02468ACE13579BDF02468ACE13579BDF02468ACE13579BDF02468ACE13579BDF02468ACE13579BDF02468ACE13579BDF02468AD1", 16)
	if got := openSSLBlocklistEntry(n); got != "df05151c30f384ccc09d" {
		t.Fatalf("openssl-vulnkey entry = %s", got)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	list, err := LoadOpenSSLBlocklist("blacklist.RSA-2048", []byte("# Debian openssl-blacklist format\n0000117ed71b2acc12ae\n"+openSSLBlocklistEntry(key.N)+"\n"))
	if err != nil {
		t.Fatal(err)
	}
	f, err := NewChecker(list).CheckSPKI(rsaSPKI(t, key.N, key.E))
	if err != nil || !strings.Contains(onlyCheck(t, f, CheckRSABlocklist).Reason, "blacklist.RSA-2048") {
		t.Fatalf("listed key: %+v %v", f, err)
	}
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if f, _ := NewChecker(list).CheckSPKI(rsaSPKI(t, other.N, other.E)); len(f) != 0 {
		t.Fatalf("an unlisted key was flagged: %+v", f)
	}
	for _, bad := range []string{"", "# only a comment\n", "zz00117ed71b2acc12ae\n", "0000117ed71b2acc12\n"} {
		if _, err := LoadOpenSSLBlocklist("bad", []byte(bad)); err == nil {
			t.Fatalf("malformed list %q loaded", bad)
		}
	}
}

// Part 4 Done-when: two moduli sharing a prime are found by batch GCD; the
// same key reused by two certificates is not a shared factor; an unrelated
// key is not flagged.
func TestSharedFactorsFindModuliSharingAPrime(t *testing.T) {
	p, q1, q2, r1, r2 := prime(t, 512), prime(t, 512), prime(t, 512), prime(t, 512), prime(t, 512)
	n1 := new(big.Int).Mul(p, q1)
	n2 := new(big.Int).Mul(p, q2)
	n3 := new(big.Int).Mul(r1, r2)
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecDER, err := x509.MarshalPKIXPublicKey(&ec.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	keys := [][]byte{rsaSPKI(t, n1, 65537), rsaSPKI(t, n3, 65537), ecDER, rsaSPKI(t, n2, 65537), rsaSPKI(t, n1, 65537), []byte("junk")}
	rep, err := SharedFactors(context.Background(), keys)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Keys != 6 || rep.RSA != 4 || rep.Distinct != 3 || rep.Skipped != 2 {
		t.Fatalf("report counts = %+v", rep)
	}
	got := map[int][]int{}
	for _, s := range rep.Shared {
		got[s.Index] = s.Partners
	}
	if len(got) != 3 || len(got[0]) != 1 || got[0][0] != 3 || len(got[4]) != 1 || got[4][0] != 3 || len(got[3]) != 2 {
		t.Fatalf("shared = %+v, want keys 0 and 4 (n1, reused) partnered with 3 (n2), and 3 with both", rep.Shared)
	}
	if _, flagged := got[1]; flagged {
		t.Fatal("an unrelated modulus was flagged")
	}
	// A certificate works as input too.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := SharedFactors(ctx, keys); err == nil {
		t.Fatal("a cancelled run returned no error")
	}
}

func TestCheckCertificateAndPEMPaths(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	weak := ecKey(t, "P-256", big.NewInt(7))
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"weak.example.test"}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, weak, key)
	if err != nil {
		t.Fatal(err)
	}
	f, err := NewChecker().CheckCertificate(der)
	if err != nil || len(f) != 1 {
		t.Fatalf("certificate with k=7: %+v %v", f, err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	bundle := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki})...)
	per, err := NewChecker().CheckPEM(bundle)
	if err != nil || len(per) != 2 || len(per[0]) != 1 || len(per[1]) != 0 {
		t.Fatalf("PEM bundle: %+v %v", per, err)
	}
	if _, err := NewChecker().CheckCertificate([]byte("not a certificate")); err == nil {
		t.Fatal("garbage parsed as a certificate")
	}
	if _, err := NewChecker().CheckPEM([]byte("no pem")); err == nil {
		t.Fatal("empty PEM input checked without error")
	}
}

func BenchmarkSmallScalarSearchP384(b *testing.B) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	checker := NewChecker()
	checker.CheckPublicKey(&key.PublicKey) // build the table once
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		checker.CheckPublicKey(&key.PublicKey)
	}
}

// The rating behind the rogue-certificate "weak_key_algorithm" finding: an
// ECDSA certificate is not weak by default, an RSA-1024 certificate is, and
// so are DSA and broken signature hashes; a recorded name is rated the same.
func TestRateCertificateAndRecordedNames(t *testing.T) {
	issuer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certFor := func(pub any, sig x509.SignatureAlgorithm, signer any) []byte {
		t.Helper()
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), SignatureAlgorithm: sig}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, signer)
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	ecLeaf, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if f, err := NewChecker().RateCertificate(certFor(&ecLeaf.PublicKey, x509.ECDSAWithSHA256, issuer)); err != nil || len(f) != 0 {
		t.Fatalf("an ordinary ECDSA certificate: %+v %v", f, err)
	}
	rsa1024, err := rsa.GenerateKey(rand.Reader, 1024) // #nosec G403 -- a deliberately weak RSA-1024 key, to prove it is rated weak (CWE-326)
	if err != nil {
		t.Fatal(err)
	}
	f, err := NewChecker().RateCertificate(certFor(&rsa1024.PublicKey, x509.ECDSAWithSHA256, issuer))
	if err != nil || !strings.Contains(onlyCheck(t, f, CheckKeySize).Reason, "RSA-1024 is below the 2048-bit minimum") {
		t.Fatalf("RSA-1024 certificate: %+v %v", f, err)
	}
	rsaIssuer, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f, err = NewChecker().RateCertificate(certFor(&ecLeaf.PublicKey, x509.SHA1WithRSA, rsaIssuer))
	if err != nil {
		t.Logf("this Go refuses to sign with SHA-1 (%v); the hash rule is covered by name below", err)
	} else {
		onlyCheck(t, f, CheckSignatureHash)
	}
	for name, weak := range map[string]bool{"RSA-1024": true, "rsa_512": true, "RSA-2048": false, "RSA": false, "ECDSA": false, "ECDSA-P256": false, "Ed25519": false, "ML-DSA-65": false, "DSA": true, "sha1WithRSAEncryption": true, "ECDSA-SHA1": true, "SHA-1": true, "SHA256-RSA": false, "": false} {
		if got := len(RateKeyAlgorithmName(name)) > 0; got != weak {
			t.Fatalf("RateKeyAlgorithmName(%q) weak = %v, want %v", name, got, weak)
		}
	}
}

// The structural verdict is remembered per public key, bounded, and a copy is
// returned so a caller cannot change what the next caller sees.
func TestCheckerRemembersVerdictsPerKey(t *testing.T) {
	c := NewChecker()
	weak := ecKey(t, "P-256", big.NewInt(9))
	spki, err := x509.MarshalPKIXPublicKey(weak)
	if err != nil {
		t.Fatal(err)
	}
	first, err := c.CheckSPKI(spki)
	if err != nil || len(first) != 1 {
		t.Fatalf("first = %+v %v", first, err)
	}
	first[0].Reason = "tampered"
	second, _ := c.CheckSPKI(spki)
	if len(second) != 1 || second[0].Reason == "tampered" || len(c.seen) != 1 {
		t.Fatalf("second = %+v, cache %d", second, len(c.seen))
	}
	first2, second2 := Default(), Default()
	if first2 != second2 {
		t.Fatal("Default returns a fresh checker each call, so nothing is remembered")
	}
}

// Batch-11 close repair: the small-scalar check built a curve's baby-step table
// on first use, which put seconds (under the race detector) on the first SVID a
// process issued. WarmECTables builds every curve's table up front, and the
// check then finds a small scalar from the warmed table.
func TestWarmECTablesBuildsEveryCurveTable(t *testing.T) {
	WarmECTables()
	for _, c := range ecCurves {
		if len(c.baby) == 0 || c.mx == nil || c.my == nil {
			t.Fatalf("%s: table not built by WarmECTables", c.name)
		}
	}
	WarmECTables() // a second call is free and safe
	p256 := curveFor(ecCurves[1].params)
	x, y := pointFor(t, p256, big.NewInt(77))
	if s := p256.smallScalar(x, y); s != 77 {
		t.Fatalf("small scalar from the warmed P-256 table = %d, want 77", s)
	}
}
