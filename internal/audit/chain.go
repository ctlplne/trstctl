package audit

import (
	"encoding/json"
	"fmt"

	"trstctl.com/trstctl/internal/crypto"
)

// This file implements the tamper-evident hash chain over audit records (R2.1).
// Each record is linked to its predecessor: hash_i = SHA256(hash_{i-1} ||
// canonical(record_i without its hash)). Because every link folds in the prior
// hash, altering, dropping, inserting, or reordering any record changes that
// record's link and every link after it — so re-running VerifyChain detects it.
// The head is published in a signed evidence bundle (Bundle.ChainHead), which
// anchors a point in time: an export signed earlier won't match a log tampered
// later. SHA-256 routes through the crypto boundary (AN-3).

// recordCore is the canonical, hash-covered content of a record — everything
// except the chain hash itself, so a record's link can be recomputed
// independently of the (possibly tampered) stored hash.
type recordCore struct {
	Sequence uint64          `json:"sequence"`
	ID       string          `json:"id"`
	Type     string          `json:"type"`
	TenantID string          `json:"tenant_id"`
	Time     string          `json:"time"`
	Actor    *eventsActor    `json:"actor,omitempty"`
	Data     json.RawMessage `json:"data,omitempty"`
}

// eventsActor mirrors events.Actor for canonical marshaling without importing a
// pointer alias surprise; the JSON shape is identical so the link is stable
// across the search -> export -> verify round-trip.
type eventsActor struct {
	Subject string   `json:"subject"`
	Roles   []string `json:"roles,omitempty"`
}

// link computes the chain hash of r given the previous record's hash.
func link(prevHash string, r Record) (string, error) {
	core := recordCore{
		Sequence: r.Sequence, ID: r.ID, Type: r.Type, TenantID: r.TenantID,
		Time: r.Time.UTC().Format("2006-01-02T15:04:05.999999999Z07:00"), Data: r.Data,
	}
	if r.Actor != nil {
		core.Actor = &eventsActor{Subject: r.Actor.Subject, Roles: r.Actor.Roles}
	}
	canonical, err := json.Marshal(core)
	if err != nil {
		return "", err
	}
	return crypto.SHA256Hex(append([]byte(prevHash), canonical...)), nil
}

// Seal fills in each record's chain hash in order and returns the head (the last
// record's hash, or "" for an empty slice). It is what Search and Export use to
// produce a verifiable chain.
func Seal(records []Record) string { return SealFrom("", records) }

// SealFrom is Seal seeded from a prior chain head: it links the first record to
// seed instead of to genesis, so a slice that is the *continuation* of an
// already-archived prefix reproduces the exact hashes it had in the full chain.
// This is what makes retention pruning hash-stable (R4.4): after the prefix is
// archived behind a signed checkpoint, the surviving suffix is sealed from the
// checkpoint's boundary hash and verifies unchanged.
func SealFrom(seed string, records []Record) string {
	prev := seed
	for i := range records {
		h, err := link(prev, records[i])
		if err != nil {
			// json.Marshal of these fixed types does not fail in practice; leave the
			// hash empty so VerifyChain reports a mismatch rather than silently passing.
			records[i].Hash = ""
			continue
		}
		records[i].Hash = h
		prev = h
	}
	return prev
}

// chainHead returns the head hash for an already-sealed slice (the last record's
// hash), or "" when empty.
func chainHead(records []Record) string {
	if len(records) == 0 {
		return ""
	}
	return records[len(records)-1].Hash
}

// VerifyChain recomputes the chain over records and confirms each record's stored
// hash matches its recomputed link. It returns the verified head, or an error
// naming the first record whose hash does not match — i.e. evidence that a stored
// event was altered, dropped, inserted, or reordered.
func VerifyChain(records []Record) (string, error) { return VerifyChainFrom("", records) }

// VerifyChainFrom is VerifyChain seeded from a prior chain head: it verifies a
// continuation slice against the head it chains onto. A retention checkpoint's
// boundary hash is the seed, so the surviving suffix verifies across the prune
// (R4.4); an archived segment whose PrevHash is the previous segment's head
// verifies the two are contiguous.
func VerifyChainFrom(seed string, records []Record) (string, error) {
	prev := seed
	for i := range records {
		want, err := link(prev, records[i])
		if err != nil {
			return "", err
		}
		if records[i].Hash != want {
			return "", fmt.Errorf("audit: tamper detected — chain broken at record %d (sequence %d, type %q)", i, records[i].Sequence, records[i].Type)
		}
		prev = want
	}
	return prev, nil
}
