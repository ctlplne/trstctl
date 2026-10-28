// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto"
)

// A219: with --edge-journal-upload, the agent sends its edge issuance journal
// (--edge-journal) over the agent channel when it connects, after a heartbeat
// that follows failed ones, and when the journal grows while connected, so
// issuances made while the host was offline reconcile without an operator
// posting the file. The journal itself still only grows and the CLI reconcile
// keeps working; <journal>.uploaded records how much of it the control plane
// has acknowledged, so the agent sends only what is new.

// edgeJournalUploadState is the acknowledged prefix of the journal.
type edgeJournalUploadState struct {
	Entries int `json:"entries"`
	// LastEntrySHA256 pins that prefix: a journal rewritten under the same
	// path is sent again from the start, and the control plane counts what it
	// already holds as already recorded.
	LastEntrySHA256 string `json:"last_entry_sha256"`
}

type edgeJournalSender interface {
	ReportEdgeJournal(ctx context.Context, req *transport.EdgeJournalRequest) (*transport.EdgeJournalResponse, error)
}

// edgeJournalUploader decides when to send. It is used from the agent's
// heartbeat loop only.
type edgeJournalUploader struct {
	path    string
	pending bool
	size    int64
	modTime time.Time
}

// afterHeartbeat sends the journal after a successful heartbeat when the agent
// just connected or reconnected, a previous upload failed, or the journal
// changed since the last upload.
func (u *edgeJournalUploader) afterHeartbeat(ctx context.Context, sender edgeJournalSender, reconnected bool) {
	if u == nil || u.path == "" {
		return
	}
	info, statErr := os.Stat(u.path)
	if errors.Is(statErr, os.ErrNotExist) {
		return
	}
	changed := statErr == nil && (info.Size() != u.size || !info.ModTime().Equal(u.modTime))
	if !reconnected && !u.pending && !changed {
		return
	}
	resp, err := uploadEdgeJournal(ctx, sender, u.path)
	if err != nil {
		u.pending = true
		fmt.Fprintln(os.Stderr, "trstctl-agent: edge journal upload failed; retrying after the next heartbeat:", err)
		return
	}
	u.pending = false
	if statErr == nil {
		u.size, u.modTime = info.Size(), info.ModTime()
	}
	if resp.Reconciled+resp.Already+resp.Violations+resp.Rejected > 0 {
		fmt.Printf("trstctl-agent: edge journal sent: %d reconciled, %d already recorded, %d outside the delegation's constraints, %d rejected\n",
			resp.Reconciled, resp.Already, resp.Violations, resp.Rejected)
	}
}

// uploadEdgeJournal sends the journal entries the control plane has not
// acknowledged, in parts of at most transport.EdgeJournalMaxCertificates, and
// records each acknowledged part before sending the next.
func uploadEdgeJournal(ctx context.Context, sender edgeJournalSender, path string) (transport.EdgeJournalResponse, error) {
	var total transport.EdgeJournalResponse
	raw, err := os.ReadFile(path) // #nosec G304 -- operator-configured journal path on the agent's own host (CWE-22)
	if errors.Is(err, os.ErrNotExist) {
		return total, nil
	}
	if err != nil {
		return total, err
	}
	var journal edgeJournal
	if err := json.Unmarshal(raw, &journal); err != nil {
		return total, fmt.Errorf("edge journal %s does not parse: %w", path, err)
	}
	entries := journal.CertificatesPEM
	start := 0
	if state, ok := readEdgeJournalUploadState(path + ".uploaded"); ok && state.Entries > 0 && state.Entries <= len(entries) &&
		state.LastEntrySHA256 == crypto.SHA256Hex([]byte(entries[state.Entries-1])) {
		start = state.Entries
	}
	for start < len(entries) {
		end := min(start+transport.EdgeJournalMaxCertificates, len(entries))
		part := make([]string, 0, end-start)
		for _, entry := range entries[start:end] {
			if len(entry) > transport.EdgeJournalMaxCertificateBytes {
				// No edge leaf is this large; sending it would refuse the whole
				// part, so it is counted here and left to the CLI path.
				total.Rejected++
				continue
			}
			part = append(part, entry)
		}
		if len(part) > 0 {
			resp, err := sender.ReportEdgeJournal(ctx, &transport.EdgeJournalRequest{CertificatesPEM: part})
			if err != nil {
				return total, err
			}
			total.Reconciled += resp.Reconciled
			total.Already += resp.Already
			total.Violations += resp.Violations
			total.Rejected += resp.Rejected
		}
		state, err := json.Marshal(edgeJournalUploadState{Entries: end, LastEntrySHA256: crypto.SHA256Hex([]byte(entries[end-1]))})
		if err != nil {
			return total, err
		}
		if err := writeEdgePrivateFile(path+".uploaded", state); err != nil {
			return total, fmt.Errorf("record edge journal upload: %w", err)
		}
		start = end
	}
	return total, nil
}

func readEdgeJournalUploadState(path string) (edgeJournalUploadState, bool) {
	raw, err := os.ReadFile(path) // #nosec G304 -- the agent's own upload record beside its journal (CWE-22)
	if err != nil {
		return edgeJournalUploadState{}, false
	}
	var state edgeJournalUploadState
	if err := json.Unmarshal(raw, &state); err != nil {
		return edgeJournalUploadState{}, false
	}
	return state, true
}

// edgeJournalUploadPath is the journal the agent sends, or empty when
// --edge-journal-upload is off.
func edgeJournalUploadPath(enabled bool, journal string) string {
	if !enabled {
		return ""
	}
	return journal
}
