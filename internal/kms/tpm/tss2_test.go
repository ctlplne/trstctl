// SPDX-License-Identifier: BUSL-1.1

package tpm

import (
	"bytes"
	"encoding/asn1"
	"encoding/pem"
	"strings"
	"testing"
)

// TestTSS2PrivateKeyRoundTripsAndRefusesWhatIsNotAHostKeyTPMO1: a host key file
// is a loadable TSS2 key with an empty authorization under a persistent parent;
// its areas come back exactly; another block type, another key type, a key
// with an authorization, a non-persistent parent, a TPM2B whose size lies, and
// trailing bytes are refused.
func TestTSS2PrivateKeyRoundTripsAndRefusesWhatIsNotAHostKeyTPMO1(t *testing.T) {
	public, private := []byte("tpmt-public-area"), []byte("tpm-wrapped-private-area")
	file, err := EncodeTSS2PrivateKey(HostSRKHandle, public, private)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(file, []byte("-----BEGIN TSS2 PRIVATE KEY-----")) || bytes.Contains(file, []byte("BEGIN PRIVATE KEY")) {
		t.Fatalf("file is not a TSS2 key PEM:\n%s", file)
	}
	parent, gotPublic, gotPrivate, err := DecodeTSS2PrivateKey(file)
	if err != nil || parent != HostSRKHandle || !bytes.Equal(gotPublic, public) || !bytes.Equal(gotPrivate, private) {
		t.Fatalf("round trip: parent 0x%x public %q private %q err %v", parent, gotPublic, gotPrivate, err)
	}
	block, _ := pem.Decode(file)
	reencode := func(mutate func(*tss2Key)) []byte {
		var key tss2Key
		if _, err := asn1.Unmarshal(block.Bytes, &key); err != nil {
			t.Fatal(err)
		}
		mutate(&key)
		der, err := asn1.Marshal(key)
		if err != nil {
			t.Fatal(err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: TSS2PEMType, Bytes: der})
	}
	for name, tc := range map[string]struct {
		file []byte
		want string
	}{
		"another PEM type":     {pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: block.Bytes}), "not one TSS2"},
		"an importable key":    {reencode(func(k *tss2Key) { k.Type = asn1.ObjectIdentifier{2, 23, 133, 10, 1, 4} }), "loadable TSS2 key"},
		"a key with auth":      {reencode(func(k *tss2Key) { k.EmptyAuth = false }), "empty authorization"},
		"a transient parent":   {reencode(func(k *tss2Key) { k.Parent = 0x80000001 }), "not a persistent handle"},
		"a lying public size":  {reencode(func(k *tss2Key) { k.Public[1]++ }), "public area"},
		"a lying private size": {reencode(func(k *tss2Key) { k.Private = k.Private[:len(k.Private)-1] }), "private area"},
		"trailing PEM":         {append(append([]byte(nil), file...), file...), "not one TSS2"},
	} {
		if _, _, _, err := DecodeTSS2PrivateKey(tc.file); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
	if _, err := EncodeTSS2PrivateKey(HostSRKHandle, nil, private); err == nil {
		t.Fatal("a key without its public area encoded")
	}
}
