// SPDX-License-Identifier: BUSL-1.1

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

// observationNamespace owns the stable identity space for one observed credential
// inside one discovery source, independent of the run that observed it. It is
// fixed forever for the same reason as findingNamespace.
var observationNamespace = uuid.MustParse("6c1f0d2e-5b7a-5c3d-9e48-2d8f1a7b4c90")

// FindingIdentity derives the one row identity for a credential observed by a
// source, so a later run of the same source that sees the same listener or
// secret refreshes the existing finding (last seen, seen count, latest run)
// instead of opening a duplicate. The run is deliberately absent from the key;
// the immutable event still records which run made each observation.
func FindingIdentity(tenantID, sourceID, kind, ref, fingerprint string) string {
	key := tenantID + "\x00" + sourceID + "\x00" + kind + "\x00" + ref + "\x00" + fingerprint
	return uuid.NewSHA1(observationNamespace, []byte(key)).String()
}
