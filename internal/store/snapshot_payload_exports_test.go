// SPDX-License-Identifier: MPL-2.0

package store

// SnapshotTablesForCaptureTest exposes a copy of the actual restore inventory
// only to the external integration tests. It is absent from production builds.
func SnapshotTablesForCaptureTest() []string {
	return append([]string(nil), snapshotTables...)
}
