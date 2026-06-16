package cmp_test

import (
	"bytes"
	"encoding/asn1"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
)

// TestCMPHeaderCarriesRequiredFields is the INTEROP-006 conformance guard: a built
// PKIMessage's PKIHeader must carry the fields stock CMP servers (EJBCA/OpenSSL)
// expect — messageTime [0], senderKID [2], and generalInfo [8] — not just the
// minimal pvno/sender/recipient/transactionID the previous encoder emitted.
//
// This parses the header structurally with the stdlib ASN.1 decoder using EXPLICIT
// context tags, asserting each field decodes. It FAILS on the pre-fix encoder,
// which omitted [0]/[2]/[8] entirely.
func TestCMPHeaderCarriesRequiredFields(t *testing.T) {
	clientCert, clientKey, csrDER := newClient(t)
	txid, _ := crypto.RandomBytes(16)
	nonce, _ := crypto.RandomBytes(16)
	reqDER, err := crypto.BuildCMPRequest(csrDER, clientCert, clientKey, txid, nonce)
	if err != nil {
		t.Fatalf("BuildCMPRequest: %v", err)
	}

	// PKIMessage ::= SEQUENCE { header PKIHeader, body, protection [0], extraCerts [1] }.
	// Decode the outer SEQUENCE, then walk the PKIHeader's top-level elements and
	// collect the context-specific [n] tags present. The PKIHeader optional fields
	// are all context-tagged, so a missing field simply does not appear.
	var msg struct {
		Header asn1.RawValue
		Rest   asn1.RawValue `asn1:"optional"`
	}
	if _, err := asn1.Unmarshal(reqDER, &msg); err != nil {
		t.Fatalf("parse PKIMessage: %v", err)
	}
	tags := contextTagsIn(t, msg.Header.Bytes)
	// messageTime [0], senderKID [2] and generalInfo [8] are the fields the previous
	// encoder omitted. protectionAlg [1] is the existing protection-alg field. These
	// tags are unambiguous in the PKIHeader (sender/recipient/transactionID share
	// [4], so [4] is not a meaningful presence assertion).
	for _, want := range []int{0, 1, 2, 8} {
		if !tags[want] {
			t.Errorf("PKIHeader missing context tag [%d]; present tags=%v (INTEROP-006 fields not added)", want, sortedKeys(tags))
		}
	}
}

// contextTagsIn walks a DER SEQUENCE body and returns the set of context-specific
// tag numbers present at the top level (the optional [n] PKIHeader fields).
func contextTagsIn(t *testing.T, body []byte) map[int]bool {
	t.Helper()
	tags := map[int]bool{}
	rest := body
	for len(rest) > 0 {
		var rv asn1.RawValue
		next, err := asn1.Unmarshal(rest, &rv)
		if err != nil {
			// Universal fields (pvno INTEGER, sender/recipient [n] GeneralName) decode
			// fine; stop on any trailing parse issue rather than failing.
			break
		}
		if rv.Class == asn1.ClassContextSpecific {
			tags[rv.Tag] = true
		}
		rest = next
	}
	return tags
}

func sortedKeys(m map[int]bool) []int {
	var ks []int
	for k := range m {
		ks = append(ks, k)
	}
	for i := 0; i < len(ks); i++ {
		for j := i + 1; j < len(ks); j++ {
			if ks[j] < ks[i] {
				ks[i], ks[j] = ks[j], ks[i]
			}
		}
	}
	return ks
}

// TestCMPMessageParsesWithOpenSSL is the INTEROP-006 non-circular external check:
// the built PKIMessage is handed to `openssl asn1parse`, an independent ASN.1
// decoder (NOT our own cmp.go structs), which must parse the full structure
// without error and show the GeneralizedTime (messageTime) we now emit. The
// previous round-trip test built and parsed with the SAME structs, proving only
// self-consistency; this proves the DER is well-formed to an outside parser.
func TestCMPMessageParsesWithOpenSSL(t *testing.T) {
	ossl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not on PATH; the CMP ASN.1 conformance check runs on the CI backstop")
	}
	clientCert, clientKey, csrDER := newClient(t)
	txid, _ := crypto.RandomBytes(16)
	nonce, _ := crypto.RandomBytes(16)
	reqDER, err := crypto.BuildCMPRequest(csrDER, clientCert, clientKey, txid, nonce)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	in := filepath.Join(dir, "msg.der")
	if err := os.WriteFile(in, reqDER, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(ossl, "asn1parse", "-inform", "DER", "-in", in).CombinedOutput()
	if err != nil {
		t.Fatalf("openssl asn1parse rejected our PKIMessage (malformed DER): %v\n%s", err, out)
	}
	// messageTime is a GeneralizedTime; openssl prints the type name when it decodes
	// the [0] EXPLICIT GeneralizedTime field. Its presence confirms the field is on
	// the wire and well-formed.
	if !bytes.Contains(out, []byte("GENERALIZEDTIME")) {
		t.Errorf("openssl did not find a GeneralizedTime (messageTime) in the PKIHeader:\n%s", out)
	}
}
