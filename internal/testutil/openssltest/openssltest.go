package openssltest

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

type testingT interface {
	Helper()
	Fatalf(format string, args ...any)
	Skipf(format string, args ...any)
}

// RequireAny returns an openssl binary that can report its version.
func RequireAny(t testingT) string {
	t.Helper()
	return require(t, "", "openssl", func(path string) error {
		return commandOK(path, "version")
	})
}

// RequireCMP returns an openssl binary with the CMP subcommand.
func RequireCMP(t testingT) string {
	t.Helper()
	return require(t, "TRSTCTL_REQUIRE_OPENSSL_CMP", "openssl cmp", func(path string) error {
		return commandOK(path, "cmp", "-help")
	})
}

// RequireTSA returns an openssl binary with the RFC 3161 ts subcommand.
func RequireTSA(t testingT) string {
	t.Helper()
	return require(t, "TRSTCTL_REQUIRE_OPENSSL_TSA", "openssl ts", func(path string) error {
		return commandOK(path, "ts", "-help")
	})
}

// SupportsVerifyPartialChain reports whether openssl verify accepts -partial_chain.
func SupportsVerifyPartialChain(path string) bool {
	out, err := exec.Command(path, "verify", "-help").CombinedOutput()
	return err == nil && strings.Contains(string(out), "-partial_chain")
}

func require(t testingT, requireEnv, label string, probe func(string) error) string {
	t.Helper()
	var reasons []string
	for _, path := range candidates() {
		if err := probe(path); err == nil {
			return path
		} else {
			reasons = append(reasons, fmt.Sprintf("%s: %v", path, err))
		}
	}
	msg := fmt.Sprintf("%s is not available; tried %s", label, strings.Join(reasons, "; "))
	if requireEnv != "" && os.Getenv(requireEnv) == "1" {
		t.Fatalf("%s", msg)
	}
	t.Skipf("%s", msg)
	return ""
}

func candidates() []string {
	var raw []string
	if p := strings.TrimSpace(os.Getenv("TRSTCTL_OPENSSL")); p != "" {
		raw = append(raw, p)
	}
	if p, err := exec.LookPath("openssl"); err == nil {
		raw = append(raw, p)
	}
	raw = append(raw,
		"/opt/homebrew/opt/openssl@3/bin/openssl",
		"/usr/local/opt/openssl@3/bin/openssl",
		"/opt/homebrew/bin/openssl",
		"/usr/local/bin/openssl",
		"/usr/bin/openssl",
	)
	seen := make(map[string]bool, len(raw))
	out := make([]string, 0, len(raw))
	for _, p := range raw {
		p = strings.TrimSpace(p)
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		if st, err := os.Stat(p); err == nil && !st.IsDir() && st.Mode()&0o111 != 0 {
			out = append(out, p)
		}
	}
	return out
}

func commandOK(path string, args ...string) error {
	out, err := exec.Command(path, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", path, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	lower := strings.ToLower(string(out))
	if strings.Contains(lower, "invalid command") || strings.Contains(lower, "unknown command") {
		return fmt.Errorf("%s %s: unsupported command: %s", path, strings.Join(args, " "), strings.TrimSpace(string(out)))
	}
	return nil
}
