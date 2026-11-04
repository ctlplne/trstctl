// SPDX-License-Identifier: BUSL-1.1

package scancollect

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

func readFile(t *testing.T, dir, rel string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel))) // #nosec G304 -- the test's own temp directory (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// N6: Slack history is collected as Slack exports it — a folder per channel,
// a JSON array per day — so the scanner and the locator read it unchanged.
func TestCollectSlackWritesTheExportLayoutN6(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/conversations.history" || r.Header.Get("Authorization") != "Bearer xoxb-test-token" {
			_, _ = fmt.Fprint(w, `{"ok":false,"error":"invalid_auth"}`)
			return
		}
		switch r.URL.Query().Get("channel") + "|" + r.URL.Query().Get("cursor") {
		case "C0OPS|":
			_, _ = fmt.Fprint(w, `{"ok":true,"messages":[{"ts":"1762246800.000100","text":"deploying"},{"ts":"1762250400.000200","text":"key AKIAFAKE00000000EXAM"}],"has_more":true,"response_metadata":{"next_cursor":"p2"}}`)
		case "C0OPS|p2":
			_, _ = fmt.Fprint(w, `{"ok":true,"messages":[{"ts":"1762160400.000300","text":"older"}],"has_more":false}`)
		case "C0DEV|":
			_, _ = fmt.Fprint(w, `{"ok":true,"messages":[{"ts":"1762246900.000400","thread_ts":"1762246800.000100","text":"reply"}],"has_more":false}`)
		default:
			_, _ = fmt.Fprint(w, `{"ok":false,"error":"channel_not_found"}`)
		}
	}))
	defer srv.Close()
	dir := t.TempDir()
	res, err := Collect(context.Background(), dir, Request{Provider: ProviderSlack, BaseURL: srv.URL, Token: []byte("xoxb-test-token"),
		Channels: []string{"C0OPS", "C0DEV"}, Doer: srv.Client()})
	if err != nil || res.Items != 4 || res.Truncated {
		t.Fatalf("collect = %+v %v", res, err)
	}
	day := readFile(t, dir, "C0OPS/2025-11-04.json")
	if !strings.Contains(day, `"text": "key AKIAFAKE00000000EXAM"`) || !strings.Contains(day, `"channel_id": "C0OPS"`) {
		t.Fatalf("day file = %s", day)
	}
	if older := readFile(t, dir, "C0OPS/2025-11-03.json"); !strings.Contains(older, "older") {
		t.Fatalf("second page = %s", older)
	}
	if channels := readFile(t, dir, "channels.json"); !strings.Contains(channels, `"id": "C0DEV"`) {
		t.Fatalf("channels.json = %s", channels)
	}
	// A refused channel, a malformed ID and bad credentials refuse the collection.
	for name, req := range map[string]Request{
		"missing channel": {Channels: []string{"C0GONE"}, Token: []byte("xoxb-test-token")},
		"malformed":       {Channels: []string{"general"}, Token: []byte("xoxb-test-token")},
		"bad token":       {Channels: []string{"C0OPS"}, Token: []byte("xoxb-other")},
	} {
		req.Provider, req.BaseURL, req.Doer = ProviderSlack, srv.URL, srv.Client()
		if _, err := Collect(context.Background(), t.TempDir(), req); !errors.Is(err, ErrRefused) {
			t.Fatalf("%s = %v, want a refusal", name, err)
		}
	}
	// The item limit stops the collection and says so.
	if res, err := Collect(context.Background(), t.TempDir(), Request{Provider: ProviderSlack, BaseURL: srv.URL,
		Token: []byte("xoxb-test-token"), Channels: []string{"C0OPS"}, MaxItems: 1, Doer: srv.Client()}); err != nil || res.Items != 1 || !res.Truncated {
		t.Fatalf("limited collect = %+v %v", res, err)
	}
}

// N6: Jira issues are collected as Jira exports them, an issues array.
func TestCollectJiraWritesTheExportLayoutN6(t *testing.T) {
	var queries []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rest/api/2/search" || r.Header.Get("Authorization") != "Basic "+"b3BzQGV4YW1wbGUudGVzdDpqaXJhLXRva2Vu" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		queries = append(queries, r.URL.Query().Get("jql"))
		if r.URL.Query().Get("startAt") == "0" {
			_, _ = fmt.Fprint(w, `{"total":3,"issues":[{"key":"OPS-1","fields":{"summary":"rotate","description":"password=hunter2hunter2"}},{"key":"not a key","fields":{}}]}`)
			return
		}
		_, _ = fmt.Fprint(w, `{"total":3,"issues":[{"key":"OPS-2","fields":{"summary":"done","comment":{"comments":[{"id":"10","body":"token here"}]}}}]}`)
	}))
	defer srv.Close()
	dir := t.TempDir()
	since := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	res, err := Collect(context.Background(), dir, Request{Provider: ProviderJira, BaseURL: srv.URL, Username: "ops@example.test",
		Token: []byte("jira-token"), JQL: "project = OPS", Since: since, Doer: srv.Client()})
	if err != nil || res.Items != 2 {
		t.Fatalf("collect = %+v %v", res, err)
	}
	if len(queries) != 2 || queries[0] != `(project = OPS) AND updated >= "2026-11-01 00:00"` {
		t.Fatalf("queries = %q", queries)
	}
	var export struct {
		Issues []struct {
			Key string `json:"key"`
		} `json:"issues"`
	}
	if err := json.Unmarshal([]byte(readFile(t, dir, "issues.json")), &export); err != nil || len(export.Issues) != 2 || export.Issues[1].Key != "OPS-2" {
		t.Fatalf("issues.json = %+v %v", export, err)
	}
	if _, err := Collect(context.Background(), t.TempDir(), Request{Provider: ProviderJira, BaseURL: srv.URL, Token: []byte("x"), JQL: "project = OPS", Doer: srv.Client()}); !errors.Is(err, ErrRefused) {
		t.Fatalf("bad credentials = %v", err)
	}
}

type testImage struct {
	blobs     map[string][]byte
	manifests map[string][]byte
	tags      map[string]string
}

func (img *testImage) addBlob(data []byte) string {
	digest := "sha256:" + crypto.SHA256Hex(data)
	img.blobs[digest] = data
	return digest
}

func (img *testImage) addManifest(m any) string {
	data, _ := json.Marshal(m)
	digest := "sha256:" + crypto.SHA256Hex(data)
	img.manifests[digest] = data
	return digest
}

func gzipTar(t *testing.T, files map[string]string, extra ...*tar.Header) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	for _, h := range extra {
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// N6: an image is collected from its registry through the token service's
// challenge — every platform of an index, each platform's config and the
// regular files of its layers, digests checked — under the image's digest.
func TestCollectRegistryReadsEveryPlatformThroughTheTokenServiceN6(t *testing.T) {
	img := &testImage{blobs: map[string][]byte{}, manifests: map[string][]byte{}, tags: map[string]string{}}
	platform := func(env, file string) string {
		config := img.addBlob([]byte(`{"architecture":"amd64","os":"linux","config":{"Env":["` + env + `"]},"history":[{"created_by":"RUN echo"}]}`))
		layer := gzipTar(t, map[string]string{"app/.env": file, "../escape.txt": "outside?", "etc/.wh.removed": "x"},
			&tar.Header{Name: "app/link", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"})
		layerDigest := img.addBlob(layer)
		return img.addManifest(map[string]any{"schemaVersion": 2, "mediaType": mediaOCIManifest,
			"config": map[string]any{"mediaType": "application/vnd.oci.image.config.v1+json", "digest": config, "size": len(img.blobs[config])},
			"layers": []map[string]any{{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": layerDigest, "size": len(layer)}}})
	}
	amd := platform("API_KEY=amd64-env-value", "DB_PASSWORD=amd64-file-value")
	arm := platform("API_KEY=arm64-env-value", "DB_PASSWORD=arm64-file-value")
	index := img.addManifest(map[string]any{"schemaVersion": 2, "mediaType": mediaOCIIndex, "manifests": []map[string]any{
		{"mediaType": mediaOCIManifest, "digest": amd, "size": len(img.manifests[amd]), "platform": map[string]string{"os": "linux", "architecture": "amd64"}},
		{"mediaType": mediaOCIManifest, "digest": arm, "size": len(img.manifests[arm]), "platform": map[string]string{"os": "linux", "architecture": "arm64"}},
	}})
	img.tags["v1"] = index
	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			user, pass, ok := r.BasicAuth()
			if !ok || user != "robot" || pass != "registry-pass" || r.URL.Query().Get("scope") != "repository:team/app:pull" {
				http.Error(w, "denied", http.StatusUnauthorized)
				return
			}
			_, _ = fmt.Fprint(w, `{"token":"issued-pull-token"}`)
			return
		}
		if r.Header.Get("Authorization") != "Bearer issued-pull-token" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="`+srvURL+`/token",service="test-registry",scope="repository:team/app:pull"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		ref := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
		switch {
		case strings.HasPrefix(r.URL.Path, "/v2/team/app/manifests/"):
			if d, ok := img.tags[ref]; ok {
				ref = d
			}
			data, ok := img.manifests[ref]
			if !ok {
				http.NotFound(w, r)
				return
			}
			var probe struct {
				MediaType string `json:"mediaType"`
			}
			_ = json.Unmarshal(data, &probe)
			w.Header().Set("Content-Type", probe.MediaType)
			_, _ = w.Write(data)
		case strings.HasPrefix(r.URL.Path, "/v2/team/app/blobs/"):
			data, ok := img.blobs[ref]
			if !ok {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write(data)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	srvURL = srv.URL
	dir := t.TempDir()
	req := Request{Provider: ProviderContainerRegistry, BaseURL: srv.URL, Username: "robot", Token: []byte("registry-pass"),
		Repository: "team/app", Reference: "v1", Doer: srv.Client()}
	res, err := Collect(context.Background(), dir, req)
	if err != nil || res.Items != 4 || res.Object["digest"] != index || res.Object["repository"] != "team/app" {
		t.Fatalf("collect = %+v %v", res, err)
	}
	root := "image-" + strings.TrimPrefix(index, "sha256:")[:12]
	for platformDigest, want := range map[string]string{amd: "amd64", arm: "arm64"} {
		sub := root + "/" + strings.TrimPrefix(platformDigest, "sha256:")[:12]
		if config := readFile(t, dir, sub+"/config.json"); !strings.Contains(config, "API_KEY="+want+"-env-value") {
			t.Fatalf("%s config = %s", want, config)
		}
		if env := readFile(t, dir, sub+"/layer-0/app/.env"); env != "DB_PASSWORD="+want+"-file-value" {
			t.Fatalf("%s layer file = %q", want, env)
		}
		if got := readFile(t, dir, sub+"/layer-0/escape.txt"); got != "outside?" {
			t.Fatalf("a dot-dot entry was not kept inside the layer folder: %q", got)
		}
		for _, absent := range []string{sub + "/layer-0/etc/.wh.removed", sub + "/layer-0/app/link"} {
			if _, err := os.Lstat(filepath.Join(dir, filepath.FromSlash(absent))); err == nil {
				t.Fatalf("%s was written", absent)
			}
		}
	}
	// A blob that does not match its digest fails the collection.
	for d := range img.blobs {
		if strings.Contains(string(img.blobs[d]), "amd64-env-value") {
			img.blobs[d] = []byte(strings.Replace(string(img.blobs[d]), "amd64", "AMD64", 1))
		}
	}
	if _, err := Collect(context.Background(), t.TempDir(), req); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "does not match its digest") {
		t.Fatalf("a tampered config = %v", err)
	}
	// Wrong credentials at the token service refuse; so does a malformed reference.
	bad := req
	bad.Token = []byte("wrong")
	if _, err := Collect(context.Background(), t.TempDir(), bad); !errors.Is(err, ErrRefused) {
		t.Fatalf("wrong credentials = %v", err)
	}
	bad = req
	bad.Reference = "v1/../x"
	if _, err := Collect(context.Background(), t.TempDir(), bad); !errors.Is(err, ErrRefused) {
		t.Fatalf("a malformed reference = %v", err)
	}
}

func TestCollectionStaysInsideItsDirectoryAndBudgetN6(t *testing.T) {
	w := &writer{dir: t.TempDir(), budget: 10}
	for _, rel := range []string{"../x", "/etc/x", ".."} {
		if _, err := w.write(rel, []byte("a")); err == nil {
			t.Fatalf("%q was written", rel)
		}
	}
	if ok, err := w.write("a.txt", []byte("0123456789")); !ok || err != nil {
		t.Fatalf("within budget = %v %v", ok, err)
	}
	if ok, err := w.write("b.txt", []byte("x")); ok || err != nil || !w.full {
		t.Fatalf("past budget = %v %v full=%v", ok, err, w.full)
	}
}

// N6 part 2: CI logs are collected per run (GitHub Actions, the run's log
// archive) or per job (GitLab, the job's trace) into folders that name the
// repository and commit, so each finding's run or job is its object.
func TestCollectCILogsFromGitHubAndGitLabN6(t *testing.T) {
	const sha = "0123456789abcdef0123456789abcdef01234567"
	var archive bytes.Buffer
	zw := zip.NewWriter(&archive)
	f, _ := zw.Create("build/1_Set up job.txt")
	_, _ = f.Write([]byte("export TOKEN=ci-leak-value\n"))
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/repos/acme/app/actions/runs" && r.Header.Get("Authorization") == "Bearer gh-token":
			_, _ = fmt.Fprintf(w, `{"workflow_runs":[{"id":101,"head_sha":"%s"},{"id":102,"head_sha":"not-a-sha"}]}`, sha)
		case r.URL.Path == "/repos/acme/app/actions/runs/101/logs" && r.Header.Get("Authorization") == "Bearer gh-token":
			http.Redirect(w, r, "/storage/logs-101.zip", http.StatusFound)
		case r.URL.Path == "/storage/logs-101.zip":
			_, _ = w.Write(archive.Bytes())
		case r.URL.EscapedPath() == "/api/v4/projects/group%2Fapp/jobs" && r.Header.Get("PRIVATE-TOKEN") == "gl-token":
			_, _ = fmt.Fprintf(w, `[{"id":7,"created_at":"2026-11-04T08:00:00.000Z","commit":{"id":"%s"}}]`, sha)
		case r.URL.EscapedPath() == "/api/v4/projects/group%2Fapp/jobs/7/trace" && r.Header.Get("PRIVATE-TOKEN") == "gl-token":
			_, _ = fmt.Fprint(w, "$ deploy\nexport TOKEN=gl-leak-value\n")
		default:
			http.Error(w, "unauthorized", http.StatusUnauthorized)
		}
	}))
	defer srv.Close()
	dir := t.TempDir()
	res, err := Collect(context.Background(), dir, Request{Provider: ProviderCICDLog, BaseURL: srv.URL, Token: []byte("gh-token"),
		System: SystemGitHub, Repo: "acme/app", Doer: srv.Client()})
	if err != nil || res.Items != 1 {
		t.Fatalf("GitHub collect = %+v %v", res, err)
	}
	file := "ci/github/acme__app/" + sha + "/101/build__1_Set_up_job.txt"
	if got := readFile(t, dir, file); !strings.Contains(got, "ci-leak-value") {
		t.Fatalf("GitHub log = %q", got)
	}
	if o, ok := ObjectForPath(file); !ok || o["system"] != "github" || o["repo"] != "acme/app" || o["commit_sha"] != sha || o["run_id"] != "101" {
		t.Fatalf("GitHub object = %v %v", o, ok)
	}
	dir = t.TempDir()
	res, err = Collect(context.Background(), dir, Request{Provider: ProviderCICDLog, BaseURL: srv.URL, Token: []byte("gl-token"),
		System: SystemGitLab, Repo: "group/app", Doer: srv.Client()})
	if err != nil || res.Items != 1 {
		t.Fatalf("GitLab collect = %+v %v", res, err)
	}
	file = "ci/gitlab/group__app/" + sha + "/7/job.log"
	if got := readFile(t, dir, file); !strings.Contains(got, "gl-leak-value") {
		t.Fatalf("GitLab trace = %q", got)
	}
	if o, ok := ObjectForPath(file); !ok || o["system"] != "gitlab" || o["repo"] != "group/app" || o["job_id"] != "7" {
		t.Fatalf("GitLab object = %v %v", o, ok)
	}
	for name, req := range map[string]Request{
		"bad token":  {System: SystemGitHub, Repo: "acme/app", Token: []byte("x")},
		"bad repo":   {System: SystemGitHub, Repo: "acme", Token: []byte("gh-token")},
		"bad system": {System: "jenkins", Repo: "acme/app", Token: []byte("gh-token")},
	} {
		req.Provider, req.BaseURL, req.Doer = ProviderCICDLog, srv.URL, srv.Client()
		if _, err := Collect(context.Background(), t.TempDir(), req); !errors.Is(err, ErrRefused) {
			t.Fatalf("%s = %v, want a refusal", name, err)
		}
	}
	if _, ok := ObjectForPath("image-abc/def/layer-0/app/.env"); ok {
		t.Fatal("a registry path read as a CI object")
	}
}
