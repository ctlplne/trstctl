// SPDX-License-Identifier: MPL-2.0

package discovery

import "github.com/google/uuid"

// findingNamespace owns the stable identity space for one observation inside one
// discovery run. It is fixed forever: changing it would make the same immutable
// source history project to different finding IDs after an upgrade.
var findingNamespace = uuid.MustParse("9fe04fa7-6572-58d1-8a64-c97b0d392842")

// FindingID derives the one payload identity for a tenant-local discovery
// observation. A retried at-least-once run therefore appends the same finding ID
// instead of minting a second UUID that collides only at PostgreSQL's natural-key
// constraint. The separators make the tuple unambiguous ("ab","c" cannot equal
// "a","bc"). Values are not normalized here: callers derive the ID from the
// exact validated strings they put in the immutable event.
func FindingID(tenantID, runID, kind, ref, fingerprint string) string {
	key := tenantID + "\x00" + runID + "\x00" + kind + "\x00" + ref + "\x00" + fingerprint
	return uuid.NewSHA1(findingNamespace, []byte(key)).String()
}
