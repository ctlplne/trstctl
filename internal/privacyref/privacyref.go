// Package privacyref holds tenant-bound subject reference helpers shared by the
// privacy read-model code and the event-log storage erasure path.
package privacyref

import (
	"strings"

	"trstctl.com/trstctl/internal/crypto"
)

const erasedPrefix = "erased:"

// SubjectRef is the stable, tenant-bound identifier used when raw subject values
// must not be persisted. It is deterministic so projections and erasure selectors
// can correlate the same subject, but it is not the raw email/OIDC subject.
func SubjectRef(tenantID, subject string) string {
	return crypto.SHA256Hex([]byte(tenantID + "\x00" + subject))
}

// Placeholder is the non-PII string written back after subject erasure.
func Placeholder(ref string) string {
	if len(ref) > 12 {
		ref = ref[:12]
	}
	return erasedPrefix + ref
}

// IsPlaceholder reports whether s is an erasure placeholder.
func IsPlaceholder(s string) bool { return strings.HasPrefix(s, erasedPrefix) }
