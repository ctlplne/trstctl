package signing_test

import (
	"os/exec"
	"strings"
	"testing"
)

// TestNoSQLDriverLinkedIntoSigner confirms the signer links no SQL packages
// (AN-4: the signer has no datastore).
func TestNoSQLDriverLinkedIntoSigner(t *testing.T) {
	cmd := exec.Command("go", "list", "-deps", "./cmd/trstctl-signer")
	cmd.Dir = repoRoot(t)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps: %v\n%s", err, out)
	}
	banned := map[string]bool{
		"database/sql":                   true,
		"database/sql/driver":            true,
		"github.com/lib/pq":              true,
		"github.com/jackc/pgx":           true,
		"github.com/jackc/pgx/v5":        true,
		"github.com/go-sql-driver/mysql": true,
	}
	for _, line := range strings.Split(string(out), "\n") {
		if banned[strings.TrimSpace(line)] {
			t.Errorf("signer links a SQL package: %s", strings.TrimSpace(line))
		}
	}
}

// TestNoHTTPServerLinkedIntoSigner confirms no net/http server entry points are
// linked into the signer binary (AN-4: no HTTP server). gRPC transitively
// imports net/http for client/types, but the server code is dead-code-eliminated
// because the signer never instantiates an HTTP server.
func TestNoHTTPServerLinkedIntoSigner(t *testing.T) {
	bin := buildSigner(t)
	cmd := exec.Command("go", "tool", "nm", bin)
	cmd.Dir = repoRoot(t)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go tool nm: %v\n%s", err, out)
	}
	syms := string(out)
	for _, sym := range []string{
		"net/http.(*Server).Serve",
		"net/http.(*Server).ListenAndServe",
		"net/http.ListenAndServe",
		"net/http.Serve",
	} {
		if strings.Contains(syms, sym) {
			t.Errorf("signer links an HTTP server symbol: %s", sym)
		}
	}
}
