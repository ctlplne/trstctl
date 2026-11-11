// SPDX-License-Identifier: BUSL-1.1

package scanannotate_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/scanannotate"
)

// A174-L2 against a stock registry (the CNCF Distribution registry:2 image,
// which has no OCI referrers API), run with TRSTCTL_A174L2_REGISTRY set to
// its loopback URL (storage delete enabled). The annotator stores the
// referrer, lists it in the referrers tag schema's index the registry then
// serves, and resolving deletes it and takes it out of the index.
func TestStockRegistryKeepsTheReferrersTagSchemaA174L2(t *testing.T) {
	base := strings.TrimRight(os.Getenv("TRSTCTL_A174L2_REGISTRY"), "/")
	if base == "" {
		t.Skip("set TRSTCTL_A174L2_REGISTRY to a stock registry:2 URL to run")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	client := &http.Client{Timeout: 20 * time.Second}
	send := func(method, path, contentType string, body []byte) *http.Response {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, method, base+path, bytes.NewReader(body)) // #nosec G704 -- the loopback stock registry the operator names in TRSTCTL_A174L2_REGISTRY for this env-gated test (CWE-918)
		if err != nil {
			t.Fatal(err)
		}
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		req.Header.Set("Accept", "application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json")
		resp, err := client.Do(req) // #nosec G704 -- the loopback stock registry the operator names in TRSTCTL_A174L2_REGISTRY for this env-gated test (CWE-918)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	// The subject: a minimal OCI image whose config is the empty blob.
	repo := "a174l2/subject-" + crypto.SHA256Hex([]byte(time.Now().String()))[:8]
	empty := []byte("{}")
	emptyDigest := "sha256:" + crypto.SHA256Hex(empty)
	upload := send(http.MethodPost, "/v2/"+repo+"/blobs/uploads/", "", nil)
	location := upload.Header.Get("Location")
	_ = upload.Body.Close()
	if upload.StatusCode != http.StatusAccepted || location == "" {
		t.Fatalf("start upload = %d", upload.StatusCode)
	}
	if !strings.HasPrefix(location, "http") {
		location = base + location
	}
	sep := "?"
	if strings.Contains(location, "?") {
		sep = "&"
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPut, location+sep+"digest="+emptyDigest, bytes.NewReader(empty)) // #nosec G704 -- the loopback stock registry the operator names in TRSTCTL_A174L2_REGISTRY for this env-gated test (CWE-918)
	req.Header.Set("Content-Type", "application/octet-stream")
	put, err := client.Do(req) // #nosec G704 -- the loopback stock registry the operator names in TRSTCTL_A174L2_REGISTRY for this env-gated test (CWE-918)
	if err != nil || put.StatusCode != http.StatusCreated {
		t.Fatalf("upload the empty blob = %v %v", put, err)
	}
	_ = put.Body.Close()
	subject, _ := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
		"config": map[string]any{"mediaType": "application/vnd.oci.empty.v1+json", "digest": emptyDigest, "size": 2},
		"layers": []any{map[string]any{"mediaType": "application/vnd.oci.empty.v1+json", "digest": emptyDigest, "size": 2}}})
	subjectDigest := "sha256:" + crypto.SHA256Hex(subject)
	if resp := send(http.MethodPut, "/v2/"+repo+"/manifests/"+subjectDigest, "application/vnd.oci.image.manifest.v1+json", subject); resp.StatusCode != http.StatusCreated {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("push the subject = %d %s", resp.StatusCode, raw)
	}

	a, closeFn, err := scanannotate.New(scanannotate.Connection{Provider: "registry", BaseURL: base, Token: []byte("lab-registry-has-no-auth"), Doer: client})
	if err != nil {
		t.Fatal(err)
	}
	defer closeFn()
	annotation := scanannotate.Annotation{FindingID: "f1740000-0000-4000-8000-0000000000a3", Rule: "github-pat", DetectedAt: "2026-11-11T00:00:00Z",
		Object: scanannotate.Object{Repository: repo, Digest: subjectDigest}}
	made, err := a.Annotate(ctx, annotation)
	if err != nil || made.Status != scanannotate.Confirmed || !strings.Contains(made.Detail, "referrers tag") {
		t.Fatalf("annotate on the stock registry = %+v %v", made, err)
	}
	tag := strings.Replace(subjectDigest, ":", "-", 1)
	index := func() []string {
		t.Helper()
		resp := send(http.MethodGet, "/v2/"+repo+"/manifests/"+tag, "", nil)
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("read the referrers index = %d", resp.StatusCode)
		}
		var out struct {
			Manifests []struct {
				Digest string `json:"digest"`
			} `json:"manifests"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatal(err)
		}
		digests := []string{}
		for _, m := range out.Manifests {
			digests = append(digests, m.Digest)
		}
		return digests
	}
	if got := index(); len(got) != 1 || got[0] != made.ProviderRef {
		t.Fatalf("referrers index on the stock registry = %v; want %s", got, made.ProviderRef)
	}
	resolved, err := a.(scanannotate.Resolver).Resolve(ctx, annotation, made.ProviderRef)
	if err != nil || resolved.Status != scanannotate.Resolved || len(index()) != 0 {
		t.Fatalf("resolve on the stock registry = %+v %v, index %v", resolved, err, index())
	}
}
