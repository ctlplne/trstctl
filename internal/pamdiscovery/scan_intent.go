// SPDX-License-Identifier: BUSL-1.1
package pamdiscovery

import (
	"errors"
	"github.com/google/uuid"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const ScanDestination = "pam.discovery.scan"

// ScanIntent fixes the source revision and both event IDs before any provider I/O.
type ScanIntent struct {
	RunID             string    `json:"run_id"`
	CompletionEventID string    `json:"completion_event_id"`
	ProviderID        string    `json:"provider_id"`
	SourceSavedAt     time.Time `json:"source_saved_at"`
	RequestedBy       string    `json:"requested_by"`
	QueuedAt          time.Time `json:"queued_at"`
}

func (i ScanIntent) Validate() error {
	for _, id := range []string{i.RunID, i.CompletionEventID} {
		parsed, err := uuid.Parse(id)
		if err != nil || parsed.String() != id || parsed == uuid.Nil {
			return errors.New("PAM discovery: canonical source IDs required")
		}
	}
	if i.RunID == i.CompletionEventID || len(i.ProviderID) == 0 || len(i.ProviderID) > 255 || len(i.RequestedBy) == 0 || len(i.RequestedBy) > 1024 || !utf8.ValidString(i.ProviderID) || !utf8.ValidString(i.RequestedBy) || strings.TrimSpace(i.ProviderID) != i.ProviderID || i.SourceSavedAt.IsZero() || i.QueuedAt.IsZero() {
		return errors.New("PAM discovery: incomplete queued source binding")
	}
	for _, value := range []string{i.ProviderID, i.RequestedBy} {
		for _, c := range value {
			if unicode.IsControl(c) {
				return errors.New("PAM discovery: invalid public source metadata")
			}
		}
	}
	return nil
}
