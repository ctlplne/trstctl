// SPDX-License-Identifier: BUSL-1.1

package k8s

import (
	"encoding/pem"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/crypto/mtls"
)

// TB-O1: a trust bundle holds only certificates that parse. The check read
// each PEM block's type and never its DER, so a truncated or garbled
// certificate reached ConfigMaps, Secrets and CSI volumes (only the API
// server's own ClusterTrustBundle validation refused it).
func TestTrustBundleRefusesACertificateThatDoesNotParseTBO1(t *testing.T) {
	ca, err := mtls.NewCA("tb-o1 CA")
	if err != nil {
		t.Fatal(err)
	}
	good := string(ca.BundlePEM())
	if err := validateTrustBundlePEM(good); err != nil {
		t.Fatalf("a valid bundle was refused: %v", err)
	}
	block, _ := pem.Decode([]byte(good))
	if block == nil {
		t.Fatal("fixture bundle has no PEM block")
	}
	truncated := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes[:len(block.Bytes)/2]}))
	garbled := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not a certificate at all")}))
	for name, bundle := range map[string]string{
		"truncated":            truncated,
		"garbled":              garbled,
		"valid then truncated": good + truncated,
	} {
		err := validateTrustBundlePEM(bundle)
		if err == nil || !strings.Contains(err.Error(), "does not parse") {
			t.Errorf("%s: %v, want a refusal naming the certificate that does not parse", name, err)
		}
	}
}
