package cbom_test

import (
	"testing"

	"trstctl.com/trstctl/internal/cbom"
)

func TestClassifyKey(t *testing.T) {
	p := cbom.DefaultPolicy()
	cases := []struct {
		algo            string
		bits            int
		wantStrength    cbom.Strength
		wantQuantum     bool
		wantOutOfPolicy bool
	}{
		{"RSA", 1024, cbom.StrengthWeak, true, true},        // undersized + quantum-vulnerable
		{"RSA", 2048, cbom.StrengthAcceptable, true, false}, // ok size, still quantum-vulnerable
		{"RSA", 4096, cbom.StrengthAcceptable, true, false},
		{"ECDSA", 256, cbom.StrengthAcceptable, true, false},
		{"ECDSA", 192, cbom.StrengthWeak, true, true},
		{"Ed25519", 256, cbom.StrengthAcceptable, true, false},
		{"DSA", 1024, cbom.StrengthWeak, true, true}, // deprecated
		{"ML-DSA", 0, cbom.StrengthStrong, false, false},
		{"ML-KEM", 0, cbom.StrengthStrong, false, false},
	}
	for _, c := range cases {
		got := cbom.ClassifyKey(c.algo, c.bits, p)
		if got.Strength != c.wantStrength {
			t.Errorf("ClassifyKey(%s,%d).Strength = %q, want %q", c.algo, c.bits, got.Strength, c.wantStrength)
		}
		if got.QuantumVulnerable != c.wantQuantum {
			t.Errorf("ClassifyKey(%s,%d).QuantumVulnerable = %v, want %v", c.algo, c.bits, got.QuantumVulnerable, c.wantQuantum)
		}
		if got.OutOfPolicy != c.wantOutOfPolicy {
			t.Errorf("ClassifyKey(%s,%d).OutOfPolicy = %v, want %v", c.algo, c.bits, got.OutOfPolicy, c.wantOutOfPolicy)
		}
		if got.Strength == cbom.StrengthWeak && len(got.Reasons) == 0 {
			t.Errorf("ClassifyKey(%s,%d) weak but gave no reason", c.algo, c.bits)
		}
	}
}

func TestClassifyProtocol(t *testing.T) {
	p := cbom.DefaultPolicy()
	cases := []struct {
		version         string
		wantStrength    cbom.Strength
		wantOutOfPolicy bool
	}{
		{"SSLv3", cbom.StrengthWeak, true},
		{"TLSv1.0", cbom.StrengthWeak, true},
		{"TLSv1.1", cbom.StrengthWeak, true},
		{"TLSv1.2", cbom.StrengthAcceptable, false},
		{"TLSv1.3", cbom.StrengthStrong, false},
	}
	for _, c := range cases {
		got := cbom.ClassifyProtocol(c.version, p)
		if got.Strength != c.wantStrength || got.OutOfPolicy != c.wantOutOfPolicy {
			t.Errorf("ClassifyProtocol(%s) = %+v, want strength %q outOfPolicy %v", c.version, got, c.wantStrength, c.wantOutOfPolicy)
		}
		if got.QuantumVulnerable {
			t.Errorf("ClassifyProtocol(%s) marked quantum-vulnerable (not applicable)", c.version)
		}
	}
}

func TestClassifyCipher(t *testing.T) {
	p := cbom.DefaultPolicy()
	weak := []string{"TLS_RSA_WITH_3DES_EDE_CBC_SHA", "TLS_RSA_WITH_RC4_128_SHA", "TLS_RSA_WITH_NULL_SHA"}
	for _, name := range weak {
		got := cbom.ClassifyCipher(name, p)
		if got.Strength != cbom.StrengthWeak || !got.OutOfPolicy {
			t.Errorf("ClassifyCipher(%s) = %+v, want weak + out-of-policy", name, got)
		}
	}
	ok := cbom.ClassifyCipher("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", p)
	if ok.Strength == cbom.StrengthWeak || ok.OutOfPolicy {
		t.Errorf("ClassifyCipher(AES-GCM) = %+v, want not weak", ok)
	}
}

func TestTLSVersionName(t *testing.T) {
	cases := map[uint16]string{
		0x0301: "TLSv1.0",
		0x0302: "TLSv1.1",
		0x0303: "TLSv1.2",
		0x0304: "TLSv1.3",
	}
	for v, want := range cases {
		if got := cbom.TLSVersionName(v); got != want {
			t.Errorf("TLSVersionName(0x%04x) = %q, want %q", v, got, want)
		}
	}
}

// Classify dispatches on which crypto fact a finding carries.
func TestClassifyDispatch(t *testing.T) {
	p := cbom.DefaultPolicy()
	key := cbom.Classify(cbom.Finding{Kind: cbom.AssetCertKey, Algorithm: "RSA", KeyBits: 1024}, p)
	if key.Strength != cbom.StrengthWeak || !key.QuantumVulnerable {
		t.Errorf("key finding = %+v", key)
	}
	proto := cbom.Classify(cbom.Finding{Kind: cbom.AssetTLSEndpoint, Protocol: "TLSv1.0"}, p)
	if proto.Strength != cbom.StrengthWeak || !proto.OutOfPolicy {
		t.Errorf("protocol finding = %+v", proto)
	}
	cipher := cbom.Classify(cbom.Finding{Kind: cbom.AssetHostConfig, Cipher: "TLS_RSA_WITH_3DES_EDE_CBC_SHA"}, p)
	if cipher.Strength != cbom.StrengthWeak {
		t.Errorf("cipher finding = %+v", cipher)
	}
}
