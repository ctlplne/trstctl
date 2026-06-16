// Package dist holds release-tooling helpers. Its job here is to publish the
// SHA-256 of release artifacts (for example, the signed Windows agent binary
// and its MSI) so downloaders can verify integrity.
package dist

import (
	"sort"
	"strings"

	"trstctl.com/trstctl/internal/crypto"
)

// Checksums returns a `sha256sum`-compatible manifest for files (a map of
// artifact name to contents): one line per artifact, "<hex>  <name>", sorted by
// name for deterministic output. The result verifies with `sha256sum -c`.
// SHA-256 is computed via the crypto boundary (AN-3).
func Checksums(files map[string][]byte) string {
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)

	var b strings.Builder
	for _, name := range names {
		b.WriteString(crypto.SHA256Hex(files[name]))
		b.WriteString("  ") // two spaces: the sha256sum binary-mode separator
		b.WriteString(name)
		b.WriteByte('\n')
	}
	return b.String()
}
