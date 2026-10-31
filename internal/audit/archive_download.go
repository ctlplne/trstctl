// SPDX-License-Identifier: BUSL-1.1

package audit

// EventTypeArchiveDownloaded records that a tenant's archived segment was
// released to it (A234). It is appended before the bytes leave, so every
// download is in the audit log. It names the segment and the digest of the
// exact signed bytes; it carries no record content.
const (
	EventTypeArchiveDownloaded     = "audit.archive.downloaded"
	ArchiveDownloadedSchemaVersion = 1
)

// ArchiveDownloaded is the payload of EventTypeArchiveDownloaded.
type ArchiveDownloaded struct {
	SegmentID   string `json:"segment_id"`
	SHA256      string `json:"sha256"`
	FirstRecord int    `json:"first_record"`
	LastRecord  int    `json:"last_record"`
}
