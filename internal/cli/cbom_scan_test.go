// SPDX-License-Identifier: BUSL-1.1

package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// X6: scan-image runs the scanner the operator names with the arguments after
// --, keeps its CBOM only when it is one trstctl can import, and writes it;
// scan-source writes the repository's crypto uses as a CBOM.
func TestCBOMScanImageAndSourceWriteImportableCBOMs(t *testing.T) {
	dir := t.TempDir()
	scanner := filepath.Join(dir, "stand-in-scanner")
	script := "#!/bin/sh\n[ \"$1\" = dir ] || exit 3\ncat <<BOM\n" +
		`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"serialNumber":"urn:uuid:0a1b2c3d-4e5f-4a6b-8c7d-8e9f0a1b2c3d",` +
		`"components":[{"type":"cryptographic-asset","bom-ref":"cert:app","name":"CN=app","cryptoProperties":{"assetType":"certificate"},` +
		`"evidence":{"occurrences":[{"location":"` + "$2" + `/etc/ssl/certs/app.pem"}]}}]}` + "\nBOM\n"
	if err := os.WriteFile(scanner, []byte(script), 0o700); err != nil { // #nosec G306 -- the stand-in scanner must be executable (CWE-276)
		t.Fatal(err)
	}
	out := filepath.Join(dir, "image.cdx.json")
	var stdout, stderr bytes.Buffer
	if code := runCBOMScanImage(context.Background(), []string{"--scanner", scanner, "--out", out, "--", "dir", "/rootfs"}, &stdout, &stderr); code != 0 {
		t.Fatalf("scan-image exit %d: %s", code, stderr.String())
	}
	written, err := os.ReadFile(out) // #nosec G304 -- the test's own temp file (CWE-22)
	if err != nil || !bytes.Contains(written, []byte("/rootfs/etc/ssl/certs/app.pem")) || !strings.Contains(stderr.String(), "1 crypto findings") {
		t.Fatalf("scan-image wrote %s (stderr %s): %v", written, stderr.String(), err)
	}
	stderr.Reset()
	if code := runCBOMScanImage(context.Background(), []string{"--scanner", scanner, "--", "image", "x"}, &stdout, &stderr); code == 0 {
		t.Fatal("a failing scanner was accepted")
	}
	notCBOM := filepath.Join(dir, "not-a-cbom")
	if err := os.WriteFile(notCBOM, []byte("#!/bin/sh\necho '{\"bomFormat\":\"SPDX\"}'\n"), 0o700); err != nil { // #nosec G306 -- executable stand-in (CWE-276)
		t.Fatal(err)
	}
	if code := runCBOMScanImage(context.Background(), []string{"--scanner", notCBOM, "--", "dir", "x"}, &stdout, &stderr); code == 0 {
		t.Fatal("a scanner output that is not a CBOM was accepted")
	}

	repo := filepath.Join(dir, "repo")
	if err := os.MkdirAll(repo, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "keys.py"), []byte("from cryptography.hazmat.primitives.asymmetric import ec\nshared = k.exchange(ec.ECDH(), peer)\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	if code := runCBOMScanSource(context.Background(), []string{repo}, &stdout, &stderr); code != 0 || !bytes.Contains(stdout.Bytes(), []byte(`"location":"keys.py"`)) {
		t.Fatalf("scan-source exit %d: %s %s", code, stdout.String(), stderr.String())
	}
}
