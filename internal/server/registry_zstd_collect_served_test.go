// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
)

// N6-L2: an image whose layer is compressed with zstd (OCI tar+zstd), pushed
// to a stock registry over the distribution API, is collected as a gzip image
// is: the secret in its zstd layer is found, and the finding names the image.
func TestServedNativeLeakScanReadsZstdImageLayersN6L2(t *testing.T) {
	if testing.Short() {
		t.Skip("container acceptance test")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skipf("docker is required: %v", err)
	}
	if out, err := exec.Command("docker", "image", "inspect", "registry:2").CombinedOutput(); err != nil { // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
		t.Skipf("the registry:2 image is not present locally: %v\n%s", err, out)
	}
	_, address := a201Container(t, "5000", "registry:2")
	registry := "http://" + address
	a201Await(t, "the registry", func() bool {
		resp, err := http.Get(registry + "/v2/")
		if err != nil {
			return false
		}
		_ = resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	})

	// One zstd layer holding the secret, pushed as an OCI image.
	var plain bytes.Buffer
	tw := tar.NewWriter(&plain)
	for name, body := range map[string]string{"app/.env": "DB_PASSWORD=LEAK-N6L2-zstd-layer\n", "app/README": "nothing here\n"} {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	enc, err := zstd.NewWriter(nil, zstd.WithEncoderConcurrency(1))
	if err != nil {
		t.Fatal(err)
	}
	layer := enc.EncodeAll(plain.Bytes(), nil)
	_ = enc.Close()
	imageConfig := []byte(`{"architecture":"amd64","os":"linux","config":{},"rootfs":{"type":"layers","diff_ids":[]}}`)
	configDigest, layerDigest := n6UploadBlob(t, registry, "team/zstd-app", imageConfig), n6UploadBlob(t, registry, "team/zstd-app", layer)
	manifest, _ := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
		"config": map[string]any{"mediaType": "application/vnd.oci.image.config.v1+json", "digest": configDigest, "size": len(imageConfig)},
		"layers": []map[string]any{{"mediaType": "application/vnd.oci.image.layer.v1.tar+zstd", "digest": layerDigest, "size": len(layer)}}})
	put, _ := http.NewRequest(http.MethodPut, registry+"/v2/team/zstd-app/manifests/v1", bytes.NewReader(manifest))
	put.Header.Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
	resp, err := http.DefaultClient.Do(put)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("push manifest: HTTP %d", resp.StatusCode)
	}
	imageDigest := "sha256:" + crypto.SHA256Hex(manifest)

	h := newOperatingServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil),
		func(d *Deps) { d.SecretScanner = &a174MarkerScanner{marker: "LEAK-N6L2"} })
	tok := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write", "discovery:read", string(authz.PrivateEgress))
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/scans/third-party/container_registry/ingest", tok, "n6l2-zstd-app",
		map[string]any{"source": "team-zstd-app", "event": "n6l2", "collect": map[string]any{"base_url": registry, "repository": "team/zstd-app",
			"reference": "v1", "allow_private_endpoint": true, "private_egress_cidrs": []string{"127.0.0.1/32"}}})
	var receipt struct {
		RunID string `json:"run_id"`
	}
	if status != http.StatusAccepted || json.Unmarshal(body, &receipt) != nil || receipt.RunID == "" {
		t.Fatalf("ingest: HTTP %d %s", status, body)
	}
	var runStatus, runError string
	deadline := time.Now().Add(30 * time.Second)
	for {
		h.srv.dispatchOnce(context.Background())
		_ = h.store.SystemPool().QueryRow(t.Context(), `SELECT status, coalesce(error, '') FROM discovery_runs WHERE tenant_id = $1 AND id = $2`,
			h.tenant, receipt.RunID).Scan(&runStatus, &runError)
		if runStatus == "succeeded" || runStatus == "failed" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the collection did not finish: %s", runStatus)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if runStatus != "succeeded" {
		t.Fatalf("the collection = %s %q", runStatus, runError)
	}

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/discovery/findings?run_id="+receipt.RunID, tok, nil)
	var list struct {
		Items []struct {
			Metadata map[string]any `json:"metadata"`
		} `json:"items"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &list) != nil {
		t.Fatalf("findings: HTTP %d %s", status, body)
	}
	if strings.Contains(string(body), "LEAK-N6L2") {
		t.Fatalf("the findings carry collected content: %s", body)
	}
	if len(list.Items) != 1 {
		t.Fatalf("findings = %s; want the one in the zstd layer", body)
	}
	object, _ := list.Items[0].Metadata["provider_object"].(map[string]any)
	if object["repository"] != "team/zstd-app" || object["digest"] != imageDigest || list.Items[0].Metadata["collection_truncated"] != false {
		t.Fatalf("the finding = %+v; want image %s", list.Items[0].Metadata, imageDigest)
	}
	if h.logContains(t, "LEAK-N6L2") {
		t.Fatal("collected content reached the event log")
	}
	t.Logf("N6L2_ZSTD_LAYER_OK image=%s layer=%s", imageDigest, layerDigest)
}
