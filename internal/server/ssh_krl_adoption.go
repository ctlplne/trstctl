// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"unicode/utf8"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/agent/sshkrl"
	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/sshkeys"
	"trstctl.com/trstctl/internal/events"
)

// KRL adoption (A110). A host keeps its installed KRL until a replacement
// revokes everything it does and has a newer version. A restored or
// replacement control plane counts its own versions and knows nothing of its
// predecessor's revocations, so an operator carries the predecessor's list in:
// every revocation it holds is recorded here, scoped to any CA, and this
// control plane's KRL version moves past the predecessor's. Hosts then take
// the new list on their next poll.

const eventSSHKRLAdopted = "ssh.krl.adopted"

const (
	// maxSSHKRLAdoptionEntries bounds one adoption; each part is one event.
	maxSSHKRLAdoptionEntries = 100000
	// maxSSHKRLAdoptionPartBytes keeps each part's payload well under the
	// event log's message bound.
	maxSSHKRLAdoptionPartBytes = 256 << 10
	maxSSHKRLAdoptionPartItems = 1000
	// maxSSHKRLAdoptedVersion leaves headroom above an adopted version for this
	// control plane's own revocations, within a signed 64-bit integer.
	maxSSHKRLAdoptedVersion = 1 << 62
	maxSSHKRLKeyIDBytes     = 1024
	maxSSHKRLKeyBlobBytes   = 4096
)

var sshKRLAdoptionNamespace = uuid.MustParse("4f0f6f39-5c43-4b1c-9b0e-2b9d0d6b8a11")

// sshKRLAdoptedEvent is one part of an adopted predecessor list.
type sshKRLAdoptedEvent struct {
	AdoptionID         string           `json:"adoption_id"` // SHA-256 of the adopted list
	PredecessorVersion uint64           `json:"predecessor_version"`
	Part               int              `json:"part"`
	Parts              int              `json:"parts"`
	SerialRanges       []sshSerialRange `json:"serial_ranges,omitempty"`
	KeyIDs             []string         `json:"key_ids,omitempty"`
	Keys               []string         `json:"keys,omitempty"`       // base64 SSH wire-format public keys
	KeySHA1            []string         `json:"key_sha1,omitempty"`   // hex
	KeySHA256          []string         `json:"key_sha256,omitempty"` // hex
}

type sshSerialRange struct {
	Lo uint64 `json:"lo"`
	Hi uint64 `json:"hi"`
}

func (e sshKRLAdoptedEvent) entries() int {
	return len(e.SerialRanges) + len(e.KeyIDs) + len(e.Keys) + len(e.KeySHA1) + len(e.KeySHA256)
}

// AdoptSSHKRL carries a predecessor's binary KRL into this control plane's
// list. Adopting a list this one already carries, at a newer version, records
// nothing.
func (s *Server) AdoptSSHKRL(ctx context.Context, tenantID, idempotencyKey string, krl []byte) (api.SSHKRLAdoption, error) {
	sp, err := s.sshWorkflowProtocol(tenantID)
	if err != nil {
		return api.SSHKRLAdoption{}, err
	}
	if idempotencyKey == "" {
		return api.SSHKRLAdoption{}, fmt.Errorf("%w: idempotency key is required", api.ErrSSHWorkflowInvalid)
	}
	predecessor, err := sshkrl.ParseRevocations(krl)
	if err != nil {
		return api.SSHKRLAdoption{}, fmt.Errorf("%w: the request body is not an OpenSSH binary KRL this control plane can carry: %v", api.ErrSSHWorkflowInvalid, err)
	}
	if predecessor.Version >= maxSSHKRLAdoptedVersion {
		return api.SSHKRLAdoption{}, fmt.Errorf("%w: the predecessor KRL version %d leaves no room for a newer list", api.ErrSSHWorkflowInvalid, predecessor.Version)
	}
	carried := predecessor.Carried()
	parts, err := sshKRLAdoptionParts(crypto.SHA256Hex(krl), predecessor.Version, carried)
	if err != nil {
		return api.SSHKRLAdoption{}, err
	}
	out := api.SSHKRLAdoption{
		PredecessorSHA256: crypto.SHA256Hex(krl), PredecessorVersion: predecessor.Version,
		Carried: api.SSHKRLAdoptionCarried{
			SerialRanges: len(carried.Serials), KeyIDs: len(carried.KeyIDs), Keys: len(carried.Keys),
			KeyHashes: len(carried.SHA1) + len(carried.SHA256), BroadenedToAnyCA: carried.Broadened,
		},
	}
	if err := sp.syncRevocations(ctx, true); err != nil {
		return api.SSHKRLAdoption{}, fmt.Errorf("%w: the revocation list cannot be brought up to date: %v", api.ErrSSHWorkflowUnavailable, err)
	}
	served, err := sshkrl.ParseRevocations(sp.KRLBytes())
	if err != nil {
		return api.SSHKRLAdoption{}, fmt.Errorf("%w: read the served KRL: %v", api.ErrSSHWorkflowUnavailable, err)
	}
	if drop := served.Dropped(predecessor); drop.Empty() && served.Version > predecessor.Version {
		out.AlreadyCarried = true
	} else {
		for _, part := range parts {
			data, err := json.Marshal(part)
			if err != nil {
				return api.SSHKRLAdoption{}, err
			}
			id := uuid.NewSHA1(sshKRLAdoptionNamespace, fmt.Appendf(nil, "%s\x00%s\x00%d", tenantID, part.AdoptionID, part.Part)).String()
			if _, err := s.appendSSHKRLAdoptionPart(ctx, tenantID, id, data); err != nil {
				return api.SSHKRLAdoption{}, err
			}
		}
		out.Parts = len(parts)
		if err := sp.syncRevocations(ctx, true); err != nil {
			return api.SSHKRLAdoption{}, fmt.Errorf("%w: the adoption is recorded and will be listed once the event log is readable: %v", api.ErrSSHWorkflowUnavailable, err)
		}
	}
	status, err := s.SSHStatus(ctx, tenantID)
	if err != nil {
		return api.SSHKRLAdoption{}, err
	}
	out.KRL = status
	return out, nil
}

func (s *Server) appendSSHKRLAdoptionPart(ctx context.Context, tenantID, id string, data []byte) (events.Event, error) {
	if s == nil || s.log == nil {
		return events.Event{}, fmt.Errorf("%w: event log is unavailable", api.ErrSSHWorkflowUnavailable)
	}
	return s.log.Append(ctx, events.Event{ID: id, Type: eventSSHKRLAdopted, TenantID: tenantID, Data: data})
}

// sshKRLAdoptionParts validates what a list carries and splits it into event
// parts. Everything is checked before the first part is recorded: an adopted
// entry is permanent, and one OpenSSH cannot read would make every host refuse
// the whole list.
func sshKRLAdoptionParts(adoptionID string, version uint64, carried sshkrl.Carried) ([]sshKRLAdoptedEvent, error) {
	total := len(carried.Serials) + len(carried.KeyIDs) + len(carried.Keys) + len(carried.SHA1) + len(carried.SHA256)
	if total > maxSSHKRLAdoptionEntries {
		return nil, fmt.Errorf("%w: the predecessor KRL holds %d revocation entries; at most %d can be adopted at once", api.ErrSSHWorkflowInvalid, total, maxSSHKRLAdoptionEntries)
	}
	for _, id := range carried.KeyIDs {
		if len(id) > maxSSHKRLKeyIDBytes || !utf8.ValidString(id) {
			return nil, fmt.Errorf("%w: a predecessor key ID is longer than %d bytes or not UTF-8, so it cannot be carried exactly", api.ErrSSHWorkflowInvalid, maxSSHKRLKeyIDBytes)
		}
	}
	for _, blob := range carried.Keys {
		if len(blob) > maxSSHKRLKeyBlobBytes {
			return nil, fmt.Errorf("%w: a revoked key in the predecessor KRL is larger than %d bytes", api.ErrSSHWorkflowInvalid, maxSSHKRLKeyBlobBytes)
		}
		if _, err := sshkeys.ParseWireKey(blob); err != nil {
			return nil, fmt.Errorf("%w: the predecessor KRL revokes an entry that is not an SSH public key: %v", api.ErrSSHWorkflowInvalid, err)
		}
	}
	var parts []sshKRLAdoptedEvent
	current := sshKRLAdoptedEvent{AdoptionID: adoptionID, PredecessorVersion: version}
	size := 0
	add := func(n int, put func(*sshKRLAdoptedEvent)) {
		if current.entries() > 0 && (size+n > maxSSHKRLAdoptionPartBytes || current.entries() >= maxSSHKRLAdoptionPartItems) {
			parts = append(parts, current)
			current = sshKRLAdoptedEvent{AdoptionID: adoptionID, PredecessorVersion: version}
			size = 0
		}
		put(&current)
		size += n
	}
	for _, r := range carried.Serials {
		add(48, func(e *sshKRLAdoptedEvent) {
			e.SerialRanges = append(e.SerialRanges, sshSerialRange{Lo: r.Lo, Hi: r.Hi})
		})
	}
	for _, id := range carried.KeyIDs {
		encoded, _ := json.Marshal(id)
		add(len(encoded)+1, func(e *sshKRLAdoptedEvent) { e.KeyIDs = append(e.KeyIDs, id) })
	}
	for _, blob := range carried.Keys {
		encoded := base64.StdEncoding.EncodeToString(blob)
		add(len(encoded)+3, func(e *sshKRLAdoptedEvent) { e.Keys = append(e.Keys, encoded) })
	}
	for _, hash := range carried.SHA1 {
		add(43, func(e *sshKRLAdoptedEvent) { e.KeySHA1 = append(e.KeySHA1, hex.EncodeToString(hash)) })
	}
	for _, hash := range carried.SHA256 {
		add(67, func(e *sshKRLAdoptedEvent) { e.KeySHA256 = append(e.KeySHA256, hex.EncodeToString(hash)) })
	}
	// A list that revokes nothing still records one part, so its version moves
	// this control plane's list past the predecessor's.
	parts = append(parts, current)
	for i := range parts {
		parts[i].Part, parts[i].Parts = i+1, len(parts)
	}
	return parts, nil
}

// applySSHKRLAdoption applies one adopted part to the served list and moves
// its version past the predecessor's. Caller holds syncMu.
func (p *sshProtocol) applySSHKRLAdoption(event events.Event) error {
	var part sshKRLAdoptedEvent
	if err := json.Unmarshal(event.Data, &part); err != nil {
		return fmt.Errorf("decode %s event %d: %w", eventSSHKRLAdopted, event.Sequence, err)
	}
	ranges := make([][2]uint64, 0, len(part.SerialRanges))
	for _, r := range part.SerialRanges {
		if r.Lo == 0 || r.Lo > r.Hi {
			return fmt.Errorf("decode %s event %d: invalid serial range", eventSSHKRLAdopted, event.Sequence)
		}
		ranges = append(ranges, [2]uint64{r.Lo, r.Hi})
	}
	keys := make([][]byte, 0, len(part.Keys))
	for _, encoded := range part.Keys {
		blob, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil || len(blob) == 0 {
			return fmt.Errorf("decode %s event %d: invalid key", eventSSHKRLAdopted, event.Sequence)
		}
		keys = append(keys, blob)
	}
	hashes := func(values []string, size int) ([][]byte, error) {
		out := make([][]byte, 0, len(values))
		for _, value := range values {
			hash, err := hex.DecodeString(value)
			if err != nil || len(hash) != size {
				return nil, fmt.Errorf("decode %s event %d: invalid key hash", eventSSHKRLAdopted, event.Sequence)
			}
			out = append(out, hash)
		}
		return out, nil
	}
	sha1s, err := hashes(part.KeySHA1, 20)
	if err != nil {
		return err
	}
	sha256s, err := hashes(part.KeySHA256, 32)
	if err != nil {
		return err
	}
	p.krl.RevokeSerialRanges(ranges)
	for _, id := range part.KeyIDs {
		p.krl.RevokeKeyID(id)
	}
	for _, blob := range keys {
		p.krl.RevokeKey(blob)
	}
	for _, hash := range sha1s {
		p.krl.RevokeKeySHA1(hash)
	}
	for _, hash := range sha256s {
		p.krl.RevokeKeySHA256(hash)
	}
	if part.PredecessorVersion >= maxSSHKRLAdoptedVersion {
		return fmt.Errorf("decode %s event %d: predecessor version out of range", eventSSHKRLAdopted, event.Sequence)
	}
	if part.PredecessorVersion > p.krlVersion.Load() {
		p.krlVersion.Store(part.PredecessorVersion)
	}
	p.krlVersion.Add(1)
	return nil
}
