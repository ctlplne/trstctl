package signing_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// These tests encode the S1.3 acceptance criteria for a design spike: the design
// doc is committed under docs/design/ and covers the required topics, the
// dependency budget is explicit, and the protocol is specified precisely enough
// to implement (the committed .proto stub).

func sourceDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Dir(file) // .../internal/signing
}

func readRepoFile(t *testing.T, rel string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(sourceDir(t), rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(data)
}

func TestDesignDocCoversRequiredSections(t *testing.T) {
	doc := readRepoFile(t, "../../docs/design/signing-service.md")
	for _, want := range []string{
		"Status:",                   // reviewed/accepted status
		"AN-4",                      // the architectural non-negotiable
		"AN-8",                      // memory safety
		"Threat model",              // threat model section
		"Process boundary",          // separate, sacred process
		"Protocol",                  // protocol section
		"gRPC",                      // transport
		"Unix domain socket",        // UDS
		"Memory-safety obligations", // AN-8 obligations
		"mlock",                     // locked memory
		"MADV_DONTDUMP",             // dump exclusion
		"Dependency budget",         // explicit dependency budget
		"Fuzzing plan",              // fuzzing plan
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("design doc is missing required content: %q", want)
		}
	}
}

func TestDependencyBudgetIsExplicit(t *testing.T) {
	doc := readRepoFile(t, "../../docs/design/signing-service.md")
	for _, want := range []string{
		"google.golang.org/grpc",     // allowed transport
		"google.golang.org/protobuf", // allowed messages
		"golang.org/x/sys",           // allowed syscalls
		"net/http",                   // named as forbidden (no HTTP server)
		"database/sql",               // named as forbidden (no SQL driver)
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("dependency budget is missing %q", want)
		}
	}
	if !strings.Contains(strings.ToLower(doc), "forbidden") {
		t.Error("dependency budget must explicitly list forbidden dependencies")
	}
}

// TestSignerDependencyClosure asserts AN-4 against the SHIPPED binary's actual
// dependency closure, not the design doc's wording (ARCH-006). It runs
// `go list -deps ./cmd/trstctl-signer` and requires that no SQL stack
// (database/sql, the pgx driver) and no message-bus client (NATS) is linked in.
//
// It does NOT assert net/http is absent: gRPC's HTTP/2 transport
// (golang.org/x/net/http2) transitively imports net/http, so the package is
// legitimately in the graph. What AN-4 forbids is standing up an HTTP *server* —
// asserted separately by TestSignerHasNoHTTPServerCall — not the package
// appearing transitively.
func TestSignerDependencyClosure(t *testing.T) {
	repoRoot := filepath.Join(sourceDir(t), "..", "..")
	cmd := exec.Command("go", "list", "-deps", "./cmd/trstctl-signer")
	cmd.Dir = repoRoot
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps ./cmd/trstctl-signer: %v\n%s", err, out)
	}
	deps := string(out)
	forbidden := []string{
		"database/sql",         // no SQL stdlib
		"github.com/jackc/pgx", // no Postgres driver
		"github.com/nats-io",   // no NATS / message bus
	}
	for _, f := range forbidden {
		for _, line := range strings.Split(deps, "\n") {
			if strings.TrimSpace(line) == f || strings.HasPrefix(strings.TrimSpace(line), f+"/") {
				t.Errorf("signer dependency closure must not contain %q (AN-4); found %q", f, strings.TrimSpace(line))
			}
		}
	}
}

// TestSignerHasNoHTTPServerCall asserts the signer source starts no HTTP server
// (AN-4): no http.Serve / http.ListenAndServe / (*http.Server).ListenAndServe.
// This is the precise property the design doc claims; checking the source (not
// the doc text) closes the ARCH-006 false-comfort gap.
func TestSignerHasNoHTTPServerCall(t *testing.T) {
	roots := []string{
		filepath.Join(sourceDir(t)), // internal/signing
		filepath.Join(sourceDir(t), "..", "..", "cmd", "trstctl-signer"),
	}
	needles := []string{
		"http.Serve(",
		"http.ListenAndServe(",
		"http.ListenAndServeTLS(",
		".ListenAndServe(",
		".ListenAndServeTLS(",
	}
	for _, root := range roots {
		err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			data, rerr := os.ReadFile(path)
			if rerr != nil {
				return rerr
			}
			src := string(data)
			for _, n := range needles {
				if strings.Contains(src, n) {
					t.Errorf("signer must start no HTTP server (AN-4): %s contains %q", path, n)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}
}

func TestProtocolStubIsImplementable(t *testing.T) {
	proto := readRepoFile(t, "proto/signer.proto")
	for _, want := range []string{
		"service SignerService",
		"rpc GenerateKey",
		"rpc GetPublicKey",
		"rpc Sign",
		"rpc DestroyKey",
		"rpc Health",
		"message SignRequest",
		"message SignResponse",
	} {
		if !strings.Contains(proto, want) {
			t.Errorf("protocol stub is missing %q", want)
		}
	}
}
