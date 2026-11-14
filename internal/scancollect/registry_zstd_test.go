// SPDX-License-Identifier: BUSL-1.1

package scancollect

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"

	"trstctl.com/trstctl/internal/crypto"
)

// zstdTar is a tar of files, compressed with zstd.
func zstdTar(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var plain bytes.Buffer
	tw := tar.NewWriter(&plain)
	for name, body := range files {
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
	defer func() { _ = enc.Close() }()
	return enc.EncodeAll(plain.Bytes(), nil)
}

// zstdImage serves one single-platform image whose layers are OCI tar+zstd
// blobs, anonymously, over the distribution API; blobs can be swapped after.
func zstdImage(t *testing.T, layers ...[]byte) (Request, string, map[string][]byte) {
	t.Helper()
	img := &testImage{blobs: map[string][]byte{}, manifests: map[string][]byte{}, tags: map[string]string{}}
	config := img.addBlob([]byte(`{"architecture":"amd64","os":"linux","config":{}}`))
	descs := make([]map[string]any, 0, len(layers))
	for _, layer := range layers {
		descs = append(descs, map[string]any{"mediaType": "application/vnd.oci.image.layer.v1.tar+zstd", "digest": img.addBlob(layer), "size": len(layer)})
	}
	top := img.addManifest(map[string]any{"schemaVersion": 2, "mediaType": mediaOCIManifest,
		"config": map[string]any{"mediaType": "application/vnd.oci.image.config.v1+json", "digest": config, "size": len(img.blobs[config])},
		"layers": descs})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ref := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
		switch {
		case r.URL.Path == "/v2/team/app/manifests/v1" || r.URL.Path == "/v2/team/app/manifests/"+top:
			w.Header().Set("Content-Type", mediaOCIManifest)
			_, _ = w.Write(img.manifests[top])
		case strings.HasPrefix(r.URL.Path, "/v2/team/app/blobs/") && img.blobs[ref] != nil:
			_, _ = w.Write(img.blobs[ref])
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return Request{Provider: ProviderContainerRegistry, BaseURL: srv.URL, Repository: "team/app", Reference: "v1", Doer: srv.Client()}, top, img.blobs
}

// N6-L2: a zstd layer's regular files are collected as a gzip layer's are,
// its digest checked while it streams. A frame asking for a decoding window
// over the bound, or a layer expanding past the limit, refuses the
// collection rather than leaving it to be retried.
func TestCollectRegistryReadsZstdLayersN6L2(t *testing.T) {
	layer := zstdTar(t, map[string]string{"app/.env": "DB_PASSWORD=zstd-file-value", "app/README": "nothing here"})
	req, top, blobs := zstdImage(t, layer)
	dir := t.TempDir()
	res, err := Collect(context.Background(), dir, req)
	if err != nil || res.Items != 2 || res.Truncated || res.Object["digest"] != top {
		t.Fatalf("collect = %+v %v; want the config and the zstd layer", res, err)
	}
	short := strings.TrimPrefix(top, "sha256:")[:12]
	if env := readFile(t, dir, "image-"+short+"/"+short+"/layer-0/app/.env"); env != "DB_PASSWORD=zstd-file-value" {
		t.Fatalf("the zstd layer's file = %q", env)
	}

	// Other bytes under the layer's digest fail the collection.
	blobs["sha256:"+crypto.SHA256Hex(layer)] = zstdTar(t, map[string]string{"app/.env": "DB_PASSWORD=swapped"})
	if _, err := Collect(context.Background(), t.TempDir(), req); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "does not match its digest") {
		t.Fatalf("a swapped zstd layer = %v", err)
	}

	// A frame header asking for a 256 MiB window (window descriptor 0x90), then
	// an empty last block.
	wide := []byte{0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x90, 0x01, 0x00, 0x00}
	req, _, _ = zstdImage(t, wide)
	if _, err := Collect(context.Background(), t.TempDir(), req); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "window") {
		t.Fatalf("a zstd frame over the window bound = %v", err)
	}

	// A layer expanding past the limit (lowered here) is refused.
	saved := maxLayerExpanded
	maxLayerExpanded = 4096
	t.Cleanup(func() { maxLayerExpanded = saved })
	req, _, _ = zstdImage(t, zstdTar(t, map[string]string{"app/big.bin": strings.Repeat("0", 64<<10)}))
	if _, err := Collect(context.Background(), t.TempDir(), req); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "expands past 4096 bytes") {
		t.Fatalf("a layer expanding past the limit = %v", err)
	}
}
