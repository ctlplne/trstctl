// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/tools/sdkpack/registry"
)

// The round trip every installed SDK runs against the served control plane:
// an unauthenticated read is refused 401; then create a secret (the front
// turns the first attempt away with 503 and Retry-After: 1), read it, rotate
// it and read the new version, issue a PKI certificate and revoke it, and
// delete the secret.
const (
	sdkSmokeGo = `package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"trstctl.com/sdk/go/trstctl"
)

func fail(step string, err error) {
	fmt.Fprintf(os.Stderr, "go smoke: %s: %v\n", step, err)
	os.Exit(1)
}

func main() {
	ctx := context.Background()
	base, token, tenant := os.Getenv("TRSTCTL_SERVER"), os.Getenv("TRSTCTL_TOKEN"), os.Getenv("TRSTCTL_TENANT")
	anon := trstctl.New(base, "", trstctl.WithTenant(tenant), trstctl.WithRetry(trstctl.RetryPolicy{MaxAttempts: 1}))
	var problem *trstctl.Problem
	if _, err := anon.GetSecret(ctx, "sdk/go/password"); !errors.As(err, &problem) || problem.HTTPStatus != 401 {
		fail("unauthenticated read", fmt.Errorf("want a 401 problem, got %v", err))
	}
	c := trstctl.New(base, token, trstctl.WithTenant(tenant),
		trstctl.WithRetry(trstctl.RetryPolicy{MaxAttempts: 3, BaseDelay: 50 * time.Millisecond, MaxDelay: 5 * time.Second}))
	const name = "sdk/go/password"
	if m, err := c.CreateSecret(ctx, name, []byte("v1")); err != nil || m.Version != 1 {
		fail("create", fmt.Errorf("%+v %v", m, err))
	}
	if v, err := c.GetSecret(ctx, name); err != nil || string(v.Value) != "v1" {
		fail("read", err)
	}
	if m, err := c.RotateSecret(ctx, name, []byte("v2")); err != nil || m.Version != 2 {
		fail("rotate", fmt.Errorf("%+v %v", m, err))
	}
	if v, err := c.GetSecret(ctx, name); err != nil || string(v.Value) != "v2" || v.Version != 2 {
		fail("read the rotated version", err)
	}
	pki, err := c.IssuePKISecret(ctx, "go-sdk.install.test", 5*time.Minute)
	if err != nil || pki.CertificateID == "" {
		fail("issue", err)
	}
	if res, err := c.RevokeCertificates(ctx, []string{pki.CertificateID}, "superseded"); err != nil || res.TotalRevoked != 1 {
		fail("revoke", fmt.Errorf("%+v %v", res, err))
	}
	if err := c.DeleteSecret(ctx, name); err != nil {
		fail("delete", err)
	}
	fmt.Println("smoke ok")
}
`
	sdkSmokeNode = `import { TrstctlClient } from "@trstctl/sdk";

const { TRSTCTL_SERVER: baseUrl, TRSTCTL_TOKEN: token, TRSTCTL_TENANT: tenant } = process.env;
const fail = (step, detail) => { console.error("npm smoke: " + step + ": " + detail); process.exit(1); };
try {
  await new TrstctlClient({ baseUrl, tenant, retry: { maxAttempts: 1 } }).getSecret("sdk/npm/password");
  fail("unauthenticated read", "it was answered");
} catch (e) {
  if (e.httpStatus !== 401) fail("unauthenticated read", "want 401, got " + e);
}
const c = new TrstctlClient({ baseUrl, token, tenant, retry: { maxAttempts: 3, baseDelayMs: 50, maxDelayMs: 5000 } });
const name = "sdk/npm/password";
if ((await c.createSecret(name, "v1")).version !== 1) fail("create", "not version 1");
if ((await c.getSecret(name)).value !== "v1") fail("read", "not v1");
if ((await c.rotateSecret(name, "v2")).version !== 2) fail("rotate", "not version 2");
const read = await c.getSecret(name);
if (read.value !== "v2" || read.version !== 2) fail("read the rotated version", JSON.stringify(read));
const pki = await c.issuePkiSecret("npm-sdk.install.test", 300);
if (!pki.certificate_id) fail("issue", JSON.stringify(pki));
const revoked = await c.revokeCertificates([pki.certificate_id], "superseded");
if (revoked.total_revoked !== 1) fail("revoke", JSON.stringify(revoked));
await c.deleteSecret(name);
console.log("smoke ok");
`
	sdkSmokePython = `import os
import sys

from trstctl_sdk import ProblemError, TrstctlClient


def fail(step, detail):
    print("pypi smoke: %s: %s" % (step, detail), file=sys.stderr)
    sys.exit(1)


try:
    TrstctlClient(base_url=os.environ["TRSTCTL_SERVER"], tenant=os.environ["TRSTCTL_TENANT"], retry={"max_attempts": 1}).get_secret("sdk/pypi/password")
    fail("unauthenticated read", "it was answered")
except ProblemError as exc:
    if exc.http_status != 401:
        fail("unauthenticated read", "want 401, got %s" % exc)
c = TrstctlClient.from_env(retry={"max_attempts": 3, "base_delay_seconds": 0.05, "max_delay_seconds": 5})
name = "sdk/pypi/password"
if c.create_secret(name, "v1")["version"] != 1:
    fail("create", "not version 1")
if c.get_secret(name)["value"] != "v1":
    fail("read", "not v1")
if c.rotate_secret(name, "v2")["version"] != 2:
    fail("rotate", "not version 2")
read = c.get_secret(name)
if read["value"] != "v2" or read["version"] != 2:
    fail("read the rotated version", read)
pki = c.issue_pki_secret("pypi-sdk.install.test", ttl_seconds=300)
if not pki.get("certificate_id"):
    fail("issue", pki)
revoked = c.revoke_certificates([pki["certificate_id"]], "superseded")
if revoked["total_revoked"] != 1:
    fail("revoke", revoked)
c.delete_secret(name)
print("smoke ok")
`
	sdkSmokeJava = `import com.trstctl.sdk.PkiSecret;
import com.trstctl.sdk.ProblemException;
import com.trstctl.sdk.TrstctlClient;
import java.util.List;
import java.util.Map;

public final class Smoke {
  static void fail(String step, Object detail) {
    System.err.println("maven smoke: " + step + ": " + detail);
    System.exit(1);
  }

  public static void main(String[] args) throws Exception {
    String base = System.getenv("TRSTCTL_SERVER");
    String tenant = System.getenv("TRSTCTL_TENANT");
    try {
      TrstctlClient.builder().baseUrl(base).tenant(tenant).maxAttempts(1).build().getSecret("sdk/maven/password");
      fail("unauthenticated read", "it was answered");
    } catch (ProblemException exc) {
      if (exc.httpStatus() != 401) fail("unauthenticated read", exc);
    }
    TrstctlClient c = TrstctlClient.builder().baseUrl(base).token(System.getenv("TRSTCTL_TOKEN")).tenant(tenant).maxAttempts(3).build();
    String name = "sdk/maven/password";
    if (c.createSecret(name, "v1", null).version() != 1) fail("create", "not version 1");
    if (!"v1".equals(c.getSecret(name).value())) fail("read", "not v1");
    if (c.rotateSecret(name, "v2", null).version() != 2) fail("rotate", "not version 2");
    if (!"v2".equals(c.getSecret(name).value())) fail("read the rotated version", "not v2");
    PkiSecret pki = c.issuePkiSecret("maven-sdk.install.test", 300, null);
    if (pki.certificateId().isEmpty()) fail("issue", "no certificate ID");
    Map<String, Object> revoked = c.revokeCertificates(List.of(pki.certificateId()), "superseded", null);
    if (((Number) revoked.get("total_revoked")).intValue() != 1) fail("revoke", revoked);
    c.deleteSecret(name, null);
    System.out.println("smoke ok");
  }
}
`
)

// sdkFront fronts the control plane for the installed SDKs: the first
// secret create from each SDK (told apart by its User-Agent) is turned away
// with 503 and Retry-After: 1, and every create attempt's key and time are
// kept.
type sdkFront struct {
	next       http.Handler
	mu         sync.Mutex
	turnedAway map[string]bool
	attempts   map[string][]sdkAttempt
}

type sdkAttempt struct {
	key string
	at  time.Time
}

func (f *sdkFront) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost && r.URL.Path == "/api/v1/secrets/store" {
		family := strings.SplitN(r.Header.Get("User-Agent"), "/", 2)[0]
		f.mu.Lock()
		f.attempts[family] = append(f.attempts[family], sdkAttempt{key: r.Header.Get("Idempotency-Key"), at: time.Now()})
		first := !f.turnedAway[family]
		f.turnedAway[family] = true
		f.mu.Unlock()
		if first {
			w.Header().Set("Content-Type", "application/problem+json")
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, `{"title":"Service Unavailable","status":503,"detail":"the install test's front turns the first create away"}`)
			return
		}
	}
	f.next.ServeHTTP(w, r)
}

// A250: the four SDKs, built as packages and served from a local registry,
// install in clean environments by exact version, upgrade to the next one,
// and run auth, read, rotate and revoke against a served control plane on
// both; each retried mutation keeps its Idempotency-Key and waits out
// Retry-After. It builds and
// installs with the real toolchains, so it runs when
// TRSTCTL_SDK_REGISTRY_INSTALL=1 (make sdk-install-check, and its CI job);
// the Maven package needs a JDK, required when TRSTCTL_REQUIRE_JAVA_SDK=1.
func TestServedSDKsInstallFromALocalRegistryA250(t *testing.T) {
	if os.Getenv("TRSTCTL_SDK_REGISTRY_INSTALL") != "1" {
		t.Skip("set TRSTCTL_SDK_REGISTRY_INSTALL=1 (make sdk-install-check) to build the SDK packages and install them from a local registry")
	}
	if runtime.GOOS == "windows" {
		t.Skip("the package script is POSIX shell")
	}
	_, thisFile, _, _ := runtime.Caller(0)
	repo := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))
	// Two versions in one registry: each SDK installs the first by exact
	// version, then upgrades to the second, and runs the round trip on both.
	const version, upgrade = "0.1.0", "0.1.1"
	dir := filepath.Join(t.TempDir(), "registry")
	for _, v := range []string{version, upgrade} {
		build := exec.CommandContext(t.Context(), "bash", filepath.Join(repo, "scripts", "release", "sdk-packages.sh"), v, dir) // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
		build.Dir = repo
		if out, err := build.CombinedOutput(); err != nil {
			t.Fatalf("sdk-packages.sh %s: %v\n%s", v, err, out)
		}
	}
	manifest, err := registry.ReadManifest(dir)
	if err != nil {
		t.Fatal(err)
	}
	built := func(t *testing.T, ecosystem, v string) registry.Package {
		t.Helper()
		p, ok := manifest.Find(ecosystem, v)
		if !ok {
			t.Fatalf("the manifest has no %s %s", ecosystem, v)
		}
		return p
	}
	var servedMu sync.Mutex
	served := map[string]int{}
	reg := httptest.NewServer(&registry.Handler{Dir: dir, Seen: func(s registry.Served) {
		servedMu.Lock()
		defer servedMu.Unlock()
		if s.Status == http.StatusOK {
			served[s.Path]++
		}
	}})
	t.Cleanup(reg.Close)

	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil))
	registerServedTenant(t, h, "A250 SDK install tenant")
	token := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write", "identities:write", "certs:issue", "certs:read")
	front := &sdkFront{next: h.srv.Handler(), turnedAway: map[string]bool{}, attempts: map[string][]sdkAttempt{}}
	cp := httptest.NewServer(front)
	t.Cleanup(cp.Close)

	work := t.TempDir()
	clean := func(extra ...string) []string {
		env := []string{"PATH=" + os.Getenv("PATH"), "HOME=" + filepath.Join(work, "home"), "TMPDIR=" + os.TempDir(),
			"TRSTCTL_SERVER=" + cp.URL, "TRSTCTL_TOKEN=" + token, "TRSTCTL_TENANT=" + h.tenant}
		return append(env, extra...)
	}
	runIn := func(t *testing.T, dir string, env []string, name string, args ...string) string {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, name, args...) // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
		cmd.Dir, cmd.Env = dir, env
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
		}
		return string(out)
	}
	mkdir := func(t *testing.T, name string) string {
		t.Helper()
		d := filepath.Join(work, name)
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
		return d
	}
	write := func(t *testing.T, p, body string) {
		t.Helper()
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// The registry served exactly the file the manifest names.
	servedManifestFile := func(t *testing.T, ecosystem, urlPath string) {
		t.Helper()
		servedMu.Lock()
		defer servedMu.Unlock()
		if served[urlPath] == 0 {
			t.Fatalf("%s: the registry never served %s (served %v)", ecosystem, urlPath, served)
		}
	}

	t.Run("go", func(t *testing.T) {
		d := mkdir(t, "go")
		gocache := strings.TrimSpace(runIn(t, d, append(clean(), "GOTOOLCHAIN=local"), "go", "env", "GOCACHE"))
		env := clean("GOPATH="+filepath.Join(work, "gopath"), "GOMODCACHE="+filepath.Join(work, "gomodcache"), "GOCACHE="+gocache,
			"GOPROXY="+reg.URL+"/go", "GOPRIVATE=trstctl.com/*,github.com/ctlplne/*", "GONOPROXY=none",
			"GOFLAGS=-mod=mod -modcacherw", "GOTOOLCHAIN=local")
		runIn(t, d, env, "go", "mod", "init", "example.com/smoke")
		write(t, filepath.Join(d, "main.go"), sdkSmokeGo)
		for _, v := range []string{version, upgrade} {
			runIn(t, d, env, "go", "get", "trstctl.com/sdk/go@v"+v)
			if got := strings.TrimSpace(runIn(t, d, env, "go", "list", "-m", "-f", "{{.Version}}", "trstctl.com/sdk/go")); got != "v"+v {
				t.Fatalf("installed trstctl.com/sdk/go %s, want v%s", got, v)
			}
			zip, err := os.ReadFile(filepath.Join(work, "gomodcache", "cache", "download", "trstctl.com", "sdk", "go", "@v", "v"+v+".zip")) // #nosec G304 -- the test reads what it downloaded under its own temp dir (CWE-22)
			if err != nil || crypto.SHA256Hex(zip) != built(t, "go", v).SHA256 {
				t.Fatalf("the downloaded v%s module zip is not the manifest's (%v)", v, err)
			}
			servedManifestFile(t, "go", "/"+built(t, "go", v).File)
			if out := runIn(t, d, env, "go", "run", "."); !strings.Contains(out, "smoke ok") {
				t.Fatalf("go smoke on v%s: %s", v, out)
			}
		}
	})

	t.Run("npm", func(t *testing.T) {
		d := mkdir(t, "npm")
		write(t, filepath.Join(d, "package.json"), `{"name":"smoke","version":"1.0.0","type":"module","private":true}`)
		write(t, filepath.Join(d, "smoke.mjs"), sdkSmokeNode)
		env := clean("NPM_CONFIG_USERCONFIG="+filepath.Join(work, "npmrc"), "NPM_CONFIG_CACHE="+filepath.Join(work, "npmcache"))
		for _, v := range []string{version, upgrade} {
			runIn(t, d, env, "npm", "install", "--no-audit", "--no-fund", "--registry", reg.URL+"/npm/", "@trstctl/sdk@"+v)
			installed, err := os.ReadFile(filepath.Join(d, "node_modules", "@trstctl", "sdk", "package.json")) // #nosec G304 -- the test reads what it installed under its own temp dir (CWE-22)
			if err != nil || !strings.Contains(string(installed), `"version": "`+v+`"`) {
				t.Fatalf("node_modules holds another @trstctl/sdk than %s (%v)", v, err)
			}
			lock, err := os.ReadFile(filepath.Join(d, "package-lock.json")) // #nosec G304 -- the test reads what it installed under its own temp dir (CWE-22)
			if err != nil || !strings.Contains(string(lock), "/npm/"+strings.TrimPrefix(built(t, "npm", v).File, "npm/")) {
				t.Fatalf("package-lock.json does not pin the registry's %s (%v):\n%s", v, err, lock)
			}
			servedManifestFile(t, "npm", "/"+built(t, "npm", v).File)
			if out := runIn(t, d, env, "node", "smoke.mjs"); !strings.Contains(out, "smoke ok") {
				t.Fatalf("npm smoke on %s: %s", v, out)
			}
		}
	})

	t.Run("pypi", func(t *testing.T) {
		d := mkdir(t, "pypi")
		env := clean("PIP_CONFIG_FILE="+os.DevNull, "PIP_DISABLE_PIP_VERSION_CHECK=1")
		runIn(t, d, env, "python3", "-m", "venv", filepath.Join(d, "venv"))
		python := filepath.Join(d, "venv", "bin", "python")
		write(t, filepath.Join(d, "smoke.py"), sdkSmokePython)
		for _, v := range []string{version, upgrade} {
			runIn(t, d, env, python, "-m", "pip", "install", "--upgrade", "--no-cache-dir", "--index-url", reg.URL+"/pypi/simple/", "trstctl-sdk=="+v)
			if got := strings.TrimSpace(runIn(t, d, env, python, "-c", "import importlib.metadata as m; print(m.version('trstctl-sdk'))")); got != v {
				t.Fatalf("installed trstctl-sdk %s, want %s", got, v)
			}
			servedManifestFile(t, "pypi", "/"+built(t, "pypi", v).File)
			if out := runIn(t, d, env, python, "smoke.py"); !strings.Contains(out, "smoke ok") {
				t.Fatalf("pypi smoke on %s: %s", v, out)
			}
		}
	})

	t.Run("maven", func(t *testing.T) {
		if _, ok := manifest.Find("maven", version); !ok {
			if os.Getenv("TRSTCTL_REQUIRE_JAVA_SDK") == "1" {
				t.Fatal("no Maven package was built")
			}
			t.Skip("no JDK here, so no Maven package was built")
		}
		d := mkdir(t, "maven")
		write(t, filepath.Join(d, "Smoke.java"), sdkSmokeJava)
		env := clean()
		fetch := func(urlPath string) []byte {
			resp, err := reg.Client().Get(reg.URL + urlPath)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()
			body, err := io.ReadAll(resp.Body)
			if err != nil || resp.StatusCode != http.StatusOK {
				t.Fatalf("GET %s = %d %v", urlPath, resp.StatusCode, err)
			}
			return body
		}
		for _, v := range []string{version, upgrade} {
			// The jar by its coordinates from the repository, checked against
			// the repository's own .sha256 and the manifest.
			pkg := built(t, "maven", v)
			data := fetch("/" + pkg.File)
			if sum := string(fetch("/" + pkg.File + ".sha256")); crypto.SHA256Hex(data) != sum || sum != pkg.SHA256 {
				t.Fatalf("the %s jar's digest %s, the repository's .sha256 %s and the manifest's %s disagree", v, crypto.SHA256Hex(data), sum, pkg.SHA256)
			}
			jar := filepath.Join(d, "trstctl-sdk-"+v+".jar")
			write(t, jar, string(data))
			runIn(t, d, env, "javac", "-cp", jar, "Smoke.java")
			if out := runIn(t, d, env, "java", "-cp", jar+string(os.PathListSeparator)+d, "Smoke"); !strings.Contains(out, "smoke ok") {
				t.Fatalf("maven smoke on %s: %s", v, out)
			}
		}
		if meta := string(fetch("/maven/com/trstctl/trstctl-sdk/maven-metadata.xml")); !strings.Contains(meta, "<release>"+upgrade+"</release>") {
			t.Fatalf("maven-metadata.xml does not name %s the release:\n%s", upgrade, meta)
		}
	})

	// Every SDK's turned-away create was retried after the server's
	// Retry-After, with the key it was first sent with.
	front.mu.Lock()
	defer front.mu.Unlock()
	// The first round trip's create was turned away and retried with its
	// key; the upgraded SDK's create, a new operation, has a key of its own.
	for family, attempts := range front.attempts {
		if len(attempts) != 3 || attempts[0].key == "" || attempts[0].key != attempts[1].key || attempts[1].at.Sub(attempts[0].at) < time.Second ||
			attempts[2].key == "" || attempts[2].key == attempts[0].key {
			t.Errorf("%s: create attempts %+v — want a retried pair with one Idempotency-Key at least a second apart, then the upgrade's own", family, attempts)
		}
	}
	for _, family := range []string{"trstctl-go-sdk", "trstctl-ts-sdk", "trstctl-python-sdk"} {
		if _, ok := front.attempts[family]; !ok {
			t.Errorf("%s never created its secret", family)
		}
	}
}
