// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
)

// TestJavaSDKAuthIssueAndSecretsRoundTripAgainstServedHandler is DIST-05's
// acceptance proof. It compiles and runs the published Java SDK against the same
// served handler cmd/trstctl wires: bearer auth, dynamic PKI issue, and secret
// create/read/rotate/delete all cross real REST routes.
func TestJavaSDKAuthIssueAndSecretsRoundTripAgainstServedHandler(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))
	javaSrc := filepath.Join(repoRoot, "clients", "sdk", "java", "src", "main", "java")
	clientSource := filepath.Join(javaSrc, "com", "trstctl", "sdk", "TrstctlClient.java")
	if _, err := os.Stat(clientSource); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			t.Fatalf("Java SDK client source missing at %s", clientSource)
		}
		t.Fatalf("stat Java SDK client source: %v", err)
	}
	javac := javaTool(t, "javac")
	java := javaTool(t, "java")

	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil))
	token := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")

	work := t.TempDir()
	classes := filepath.Join(work, "classes")
	if err := os.Mkdir(classes, 0o755); err != nil { // #nosec G301 -- fixture tree in a test tempdir; the mode is part of the fixture (CWE-276)
		t.Fatalf("make Java classes dir: %v", err)
	}
	roundTrip := filepath.Join(work, "RoundTrip.java")
	if err := os.WriteFile(roundTrip, []byte(javaRoundTripProgram()), 0o600); err != nil {
		t.Fatalf("write Java round-trip program: %v", err)
	}

	sources := []string{"-d", classes}
	sources = append(sources, javaSources(t, javaSrc)...)
	sources = append(sources, roundTrip)
	if out, err := exec.Command(javac, sources...).CombinedOutput(); err != nil { // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
		t.Fatalf("compile Java SDK served round-trip: %v\n%s", err, out)
	}

	cmd := exec.Command(java, "-cp", classes, "RoundTrip") // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
	cmd.Env = append(os.Environ(),
		"TRSTCTL_SERVER="+h.ts.URL,
		"TRSTCTL_TENANT="+h.tenant,
		"TRSTCTL_TOKEN="+token,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Java SDK served round-trip failed: %v\n%s", err, out)
	}
	var got struct {
		Serial  string `json:"serial"`
		Version int    `json:"version"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(out))), &got); err != nil {
		t.Fatalf("decode Java SDK round-trip output %q: %v", out, err)
	}
	if got.Serial == "" || got.Version != 2 {
		t.Fatalf("Java SDK round-trip output = %+v, want serial and version 2", got)
	}
	if !h.hasEvent(t, "pkisecret.issued") || !h.hasEvent(t, "secret.created") || !h.hasEvent(t, "secret.rotated") || !h.hasEvent(t, "secret.deleted") {
		t.Fatal("Java SDK did not drive the served issue + secrets event-sourced paths")
	}
}

func javaTool(t *testing.T, name string) string {
	t.Helper()
	path, err := exec.LookPath(name)
	if err != nil {
		t.Skipf("%s is required for the Java SDK acceptance test on this machine: %v", name, err)
	}
	if out, err := exec.Command(path, "-version").CombinedOutput(); err != nil { // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
		t.Skipf("%s is present but unusable on this machine: %v\n%s", name, err, out)
	}
	return path
}

func javaSources(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	if err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(path, ".java") {
			out = append(out, path)
		}
		return nil
	}); err != nil {
		t.Fatalf("walk Java SDK sources: %v", err)
	}
	if len(out) == 0 {
		t.Fatalf("no Java SDK sources found under %s", root)
	}
	return out
}

func javaRoundTripProgram() string {
	return `
import com.trstctl.sdk.ProblemException;
import com.trstctl.sdk.Secret;
import com.trstctl.sdk.PkiSecret;
import com.trstctl.sdk.TrstctlClient;

public final class RoundTrip {
  public static void main(String[] args) throws Exception {
    String base = System.getenv("TRSTCTL_SERVER");
    String tenant = System.getenv("TRSTCTL_TENANT");

    try {
      TrstctlClient.builder().baseUrl(base).tenant(tenant).maxAttempts(1).build().listSecrets();
      throw new AssertionError("unauthenticated listSecrets unexpectedly succeeded");
    } catch (ProblemException exc) {
      if (exc.httpStatus() != 401) {
        throw exc;
      }
    }

    TrstctlClient client = TrstctlClient.fromEnv().withMaxAttempts(1);
    PkiSecret issued = client.issuePkiSecret("java-sdk.served.test", 300, "java-sdk-issue");
    if (issued.serial().isEmpty() || !issued.certificate().contains("BEGIN CERTIFICATE") || !issued.privateKey().contains("BEGIN PRIVATE KEY")) {
      throw new AssertionError("bad issued certificate");
    }

    Secret created = client.createSecret("sdk/java/password", "initial-fixture-value", "java-sdk-secret-create");
    if (!"sdk/java/password".equals(created.name()) || created.version() != 1) {
      throw new AssertionError("bad created secret");
    }

    Secret read = client.getSecret("sdk/java/password");
    if (!"initial-fixture-value".equals(read.value()) || read.version() != 1) {
      throw new AssertionError("bad read secret");
    }

    Secret rotated = client.rotateSecret("sdk/java/password", "rotated-fixture-value", "java-sdk-secret-rotate");
    if (rotated.version() != 2) {
      throw new AssertionError("bad rotated version");
    }

    Secret read2 = client.getSecret("sdk/java/password");
    if (!"rotated-fixture-value".equals(read2.value()) || read2.version() != 2) {
      throw new AssertionError("bad rotated read");
    }

    client.deleteSecret("sdk/java/password", "java-sdk-secret-delete");
    System.out.println("{\"serial\":\"" + escape(issued.serial()) + "\",\"version\":" + read2.version() + "}");
  }

  private static String escape(String value) {
    return value.replace("\\", "\\\\").replace("\"", "\\\"");
  }
}
`
}
