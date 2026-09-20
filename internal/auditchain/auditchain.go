// SPDX-License-Identifier: BUSL-1.1

// Package auditchain contains the dependency-light audit hash-chain primitive.
// It deliberately imports no event log, SQL, HTTP, or signing-service dependencies
// so signer-side artifact code can bind an already-supplied audit head without
// pulling the full audit service into the AN-4 process.
package auditchain

import (
	"encoding/json"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/eventspec"
)

// Record is one audit entry in the tamper-evident chain.
type Record struct {
	Sequence       uint64           `json:"sequence"`
	StreamSequence uint64           `json:"-"`
	ID             string           `json:"id"`
	Type           string           `json:"type"`
	TenantID       string           `json:"tenant_id"`
	Time           time.Time        `json:"time"`
	Actor          *eventspec.Actor `json:"actor,omitempty"`
	Data           json.RawMessage  `json:"data,omitempty"`
	Hash           string           `json:"hash,omitempty"`
}

type recordCore struct {
	Sequence uint64           `json:"sequence"`
	ID       string           `json:"id"`
	Type     string           `json:"type"`
	TenantID string           `json:"tenant_id"`
	Time     string           `json:"time"`
	Actor    *eventspec.Actor `json:"actor,omitempty"`
	Data     json.RawMessage  `json:"data,omitempty"`
}

// Seal fills in each record's chain hash in order and returns the head.
func Seal(records []Record) string { return SealFrom("", records) }

// SealFrom is Seal seeded from a prior chain head.
func SealFrom(seed string, records []Record) string {
	prev := seed
	for i := range records {
		core := recordCore{
			Sequence: records[i].Sequence,
			ID:       records[i].ID,
			Type:     records[i].Type,
			TenantID: records[i].TenantID,
			Time:     records[i].Time.UTC().Format("2006-01-02T15:04:05.999999999Z07:00"),
			Actor:    records[i].Actor,
			Data:     records[i].Data,
		}
		canonical, err := json.Marshal(core)
		if err != nil {
			records[i].Hash = ""
			continue
		}
		records[i].Hash = crypto.SHA256Hex(append([]byte(prev), canonical...))
		prev = records[i].Hash
	}
	return prev
}
