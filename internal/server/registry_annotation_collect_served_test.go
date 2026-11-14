// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
)

// N6-L3: an annotation on a collected image names only its connection; the
// image it annotates is the one the collection read. A collection from a
// stock registry with an automatic annotation connection to that registry
// finds the secret, and the annotation lands as an OCI referrer on the
// collected image (listed through the referrers tag schema, since a stock
// registry:2 has no referrers API); the finding's annotation is confirmed.
// An annotation on a collected scan that names the image is refused.
func TestServedCollectedImageIsAnnotatedFromItsCollectionN6L3(t *testing.T) {
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
	imageDigest := n6PushImage(t, registry, "team/annotated", "v1", map[string]string{"app/.env": "DB_PASSWORD=LEAK-N6L3-layer\n"}, "LANG=C.UTF-8")

	t.Setenv("TRSTCTL_N6L3_REGISTRY", "n6l3-registry-token")
	h := newOperatingServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil),
		allowOutboundEnvCredentialRefs("env:TRSTCTL_N6L3_REGISTRY"),
		func(d *Deps) { d.SecretScanner = &a174MarkerScanner{marker: "LEAK-N6L3"} })
	// Its own tenant: another test's queued outbox work on the shared tenant
	// must not hold this one's annotation back.
	tenant := uuid.NewSHA1(uuid.NameSpaceOID, []byte("n6l3-collected-annotation-tenant")).String()
	registerServedTenantID(t, h, tenant, "N6-L3 collected annotation tenant")
	tok := seedScopedToken(t, h.store, tenant, "secrets:read", "secrets:write", "discovery:read", "connectors:write", string(authz.PrivateEgress))
	private := []string{"127.0.0.1/32"}
	collect := map[string]any{"base_url": registry, "repository": "team/annotated", "reference": "v1", "allow_private_endpoint": true, "private_egress_cidrs": private}
	annotation := func(extra map[string]any) map[string]any {
		out := map[string]any{"base_url": registry, "token_ref": "env:TRSTCTL_N6L3_REGISTRY", "auto": true, "allow_private_endpoint": true, "private_egress_cidrs": private} // #nosec G101 -- an env: reference to a test-only token, no credential value (CWE-798)
		for k, v := range extra {
			out[k] = v
		}
		return out
	}

	// Naming the image in a collected scan's annotation is refused: the
	// collection says which image it read.
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/scans/third-party/container_registry/ingest", tok, "n6l3-named",
		map[string]any{"source": "team-annotated-named", "event": "n6l3", "collect": collect,
			"annotation": annotation(map[string]any{"repository": "team/annotated", "digest": imageDigest})})
	if status != http.StatusBadRequest || !strings.Contains(string(body), "names only its connection") {
		t.Fatalf("an annotation naming the collected image = HTTP %d %s", status, body)
	}

	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/scans/third-party/container_registry/ingest", tok, "n6l3-annotated",
		map[string]any{"source": "team-annotated", "event": "n6l3", "collect": collect, "annotation": annotation(nil)})
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
			tenant, receipt.RunID).Scan(&runStatus, &runError)
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
	// The automatic annotation is queued with the finding; dispatch until the
	// registry has it (its delivery may be retried).
	type finding struct {
		ID       string         `json:"id"`
		Metadata map[string]any `json:"metadata"`
	}
	var f finding
	annotateState := func() map[string]any {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/discovery/findings?run_id="+receipt.RunID, tok, nil)
		var list struct {
			Items []finding `json:"items"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &list) != nil || len(list.Items) != 1 {
			t.Fatalf("findings: HTTP %d %s", status, body)
		}
		f = list.Items[0]
		actions, _ := f.Metadata["provider_actions"].(map[string]any)
		state, _ := actions["annotate"].(map[string]any)
		return state
	}
	state := annotateState()
	for deadline := time.Now().Add(30 * time.Second); state["status"] != "confirmed" && time.Now().Before(deadline); state = annotateState() {
		h.srv.dispatchOnce(context.Background())
		time.Sleep(100 * time.Millisecond)
	}
	object, _ := f.Metadata["provider_object"].(map[string]any)
	if object["repository"] != "team/annotated" || object["digest"] != imageDigest {
		t.Fatalf("the finding's object = %+v; want the collected image %s", object, imageDigest)
	}
	referrer, _ := state["provider_ref"].(string)
	if state["status"] != "confirmed" || !strings.HasPrefix(referrer, "sha256:") {
		t.Fatalf("the finding's annotation = %+v", state)
	}

	// The registry holds the referrer on the collected image, listed in the
	// referrers tag for that image.
	get := func(path, accept string, out any) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, registry+path, nil)
		req.Header.Set("Accept", accept)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK || json.NewDecoder(resp.Body).Decode(out) != nil {
			t.Fatalf("GET %s: HTTP %d", path, resp.StatusCode)
		}
	}
	var index struct {
		Manifests []struct {
			Digest       string            `json:"digest"`
			ArtifactType string            `json:"artifactType"`
			Annotations  map[string]string `json:"annotations"`
		} `json:"manifests"`
	}
	get("/v2/team/annotated/manifests/"+strings.Replace(imageDigest, ":", "-", 1), "application/vnd.oci.image.index.v1+json", &index)
	if len(index.Manifests) != 1 || index.Manifests[0].Digest != referrer || index.Manifests[0].Annotations["dev.trstctl.finding.id"] != f.ID {
		t.Fatalf("the referrers tag lists %+v; want referrer %s for finding %s", index.Manifests, referrer, f.ID)
	}
	var stored struct {
		ArtifactType string `json:"artifactType"`
		Subject      struct {
			Digest string `json:"digest"`
		} `json:"subject"`
	}
	get("/v2/team/annotated/manifests/"+referrer, "application/vnd.oci.image.manifest.v1+json", &stored)
	if stored.Subject.Digest != imageDigest || stored.ArtifactType != "application/vnd.trstctl.secret-finding.v1+json" {
		t.Fatalf("the referrer = %+v; want a finding on %s", stored, imageDigest)
	}
	if h.logContains(t, "LEAK-N6L3") || h.logContains(t, "n6l3-registry-token") {
		t.Fatal("collected content or the annotation token reached the event log")
	}
	t.Logf("N6L3_COLLECTED_ANNOTATION_OK image=%s referrer=%s", imageDigest, referrer)
}
