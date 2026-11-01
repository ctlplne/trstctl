// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/cli"
	"trstctl.com/trstctl/internal/config"
)

// X6 against the real cbomkit-theia (owner decision 2026-11-01, outside input
// a): `trstctl-cli cbom scan-image` runs cbomkit-theia — built from its
// verified release tag — over a container image archive; `trstctl-cli cbom
// import` sends the CBOM it wrote to the running product with the image as
// its source; the image's crypto reaches the inventory under that source and
// coverage observes container-image crypto. Run by
// runners/x6-cbomkit-lab-proof.sh; skipped otherwise.
func TestCBOMScanImageWithCbomkitTheiaX6(t *testing.T) {
	scanner, archive, ref := os.Getenv("TRSTCTL_X6_LAB_SCANNER"), os.Getenv("TRSTCTL_X6_LAB_IMAGE_ARCHIVE"), os.Getenv("TRSTCTL_X6_LAB_IMAGE_REF")
	if scanner == "" || archive == "" || ref == "" {
		t.Skip("run runners/x6-cbomkit-lab-proof.sh (cbomkit-theia built from its release tag and an image archive)")
	}
	h := newOperatingServedHarness(t, config.Protocols{})
	writer := seedScopedToken(t, h.store, h.tenant, "discovery:write", "discovery:read", "risk:read")
	reader := seedScopedToken(t, h.store, h.tenant, "discovery:read", "risk:read")
	// cbomkit-theia writes its configuration under $HOME on first run.
	t.Setenv("HOME", t.TempDir())
	out := filepath.Join(t.TempDir(), "image.cdx.json")
	var stdout, stderr bytes.Buffer
	if code := cli.Run(context.Background(), []string{"cbom", "scan-image", "--scanner", scanner, "--out", out, "--", "image", "docker-archive:" + archive},
		cli.Env{}, strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("cbom scan-image with cbomkit-theia: exit %d\n%s", code, stderr.String())
	}
	t.Logf("scan-image: %s", strings.TrimSpace(lastLine(stderr.String())))
	stdout.Reset()
	stderr.Reset()
	if code := cli.Run(context.Background(), []string{"cbom", "import", "--source", "image:" + ref, "-f", out},
		cli.Env{Server: h.ts.URL, Token: writer, Tenant: h.tenant, IdempotencyKey: "x6-cbomkit-import", HTTPClient: h.ts.Client()},
		strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("cbom import: exit %d\n%s%s", code, stdout.String(), stderr.String())
	}
	var imported struct {
		Findings int      `json:"findings"`
		AssetIDs []string `json:"asset_ids"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &imported); err != nil || imported.Findings == 0 {
		t.Fatalf("the cbomkit-theia CBOM imported nothing: %v\n%s", err, stdout.String())
	}
	t.Logf("imported %d findings from cbomkit-theia", imported.Findings)

	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/cbom/assets", reader, nil)
	if status != http.StatusOK || !strings.Contains(string(body), `"image:`+ref+`:`) {
		t.Fatalf("the image's crypto is not in the inventory under its source: HTTP %d %.600s", status, body)
	}
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/discovery/coverage", reader, nil)
	var cov struct {
		Classes []struct {
			Class  string `json:"class"`
			Status string `json:"status"`
		} `json:"classes"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &cov) != nil {
		t.Fatalf("coverage: HTTP %d %s", status, body)
	}
	for _, c := range cov.Classes {
		if c.Class == "container-image-crypto" && c.Status == "OBSERVED" {
			return
		}
	}
	t.Fatalf("coverage does not observe container-image crypto: %s", body)
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return lines[len(lines)-1]
}
