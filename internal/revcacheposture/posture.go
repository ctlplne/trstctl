// SPDX-License-Identifier: BUSL-1.1

// Package revcacheposture defines the signed, metadata-only statement a
// network relay uses to report LAN revocation-cache health.
package revcacheposture

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
)

const (
	ProtocolCRL  = "crl"
	ProtocolOCSP = "ocsp"

	StatusEmpty = "empty"
	StatusFresh = "fresh"
	StatusStale = "stale"
	StatusError = "error"

	MaxEntries = 256

	statementVersion = "trstctl-agent-revocation-cache-posture/v1\n"
)

// Entry is one issuer/protocol cache as observed by the relay. It deliberately
// contains no upstream URL, issuer bytes, request bytes, or cached response.
// Those values stay inside the segment; the control plane needs only enough
// evidence to distinguish fresh, stale, empty, and failed local service.
type Entry struct {
	CacheID             string `json:"cache_id"`
	Segment             string `json:"segment"`
	Protocol            string `json:"protocol"`
	IssuerFingerprint   string `json:"issuer_fingerprint"`
	LocalPath           string `json:"local_path"`
	Status              string `json:"status"`
	DetailCode          string `json:"detail_code,omitempty"`
	CachedResponses     int    `json:"cached_responses"`
	Fresh               bool   `json:"fresh"`
	SignatureVerified   bool   `json:"signature_verified"`
	ThisUpdateUnix      int64  `json:"this_update_unix,omitempty"`
	NextUpdateUnix      int64  `json:"next_update_unix,omitempty"`
	LastValidatedAtUnix int64  `json:"last_validated_at_unix,omitempty"`
	ServedRequests      int64  `json:"served_requests"`
	RefusedRequests     int64  `json:"refused_requests"`
}

// Report is carried on the certificate-authenticated heartbeat. Signature is
// produced by the same key behind that connection.
type Report struct {
	Entries      []Entry `json:"entries"`
	IssuedAtUnix int64   `json:"issued_at_unix"`
	Signature    []byte  `json:"signature"`
}

// Statement binds all cache rows to the tenant, relay, and observation time.
type Statement struct {
	TenantID        string
	AgentCommonName string
	Entries         []Entry
	IssuedAtUnix    int64
}

// Normalize validates the closed vocabulary, bounds every field, and returns
// one deterministic copy suitable for signing and replay comparison.
func Normalize(entries []Entry) ([]Entry, error) {
	if len(entries) > MaxEntries {
		return nil, fmt.Errorf("revocation cache posture has %d entries; maximum is %d", len(entries), MaxEntries)
	}
	out := append([]Entry(nil), entries...)
	seen := make(map[string]bool, len(out))
	for i := range out {
		row := &out[i]
		if !safeToken(row.CacheID, 128) || !safeToken(row.Segment, 128) {
			return nil, fmt.Errorf("revocation cache posture row %d has invalid cache or segment identity", i)
		}
		if row.Protocol != ProtocolCRL && row.Protocol != ProtocolOCSP {
			return nil, fmt.Errorf("revocation cache %q has unsupported protocol %q", row.CacheID, row.Protocol)
		}
		if !sha256Fingerprint(row.IssuerFingerprint) {
			return nil, fmt.Errorf("revocation cache %q has invalid issuer fingerprint", row.CacheID)
		}
		if !localPath(row.LocalPath) {
			return nil, fmt.Errorf("revocation cache %q has invalid local path", row.CacheID)
		}
		if row.Status != StatusEmpty && row.Status != StatusFresh && row.Status != StatusStale && row.Status != StatusError {
			return nil, fmt.Errorf("revocation cache %q has unsupported status %q", row.CacheID, row.Status)
		}
		if row.DetailCode != "" && !safeToken(row.DetailCode, 128) {
			return nil, fmt.Errorf("revocation cache %q has invalid detail code", row.CacheID)
		}
		if row.CachedResponses < 0 || row.ServedRequests < 0 || row.RefusedRequests < 0 ||
			row.ThisUpdateUnix < 0 || row.NextUpdateUnix < 0 || row.LastValidatedAtUnix < 0 {
			return nil, fmt.Errorf("revocation cache %q has a negative counter or timestamp", row.CacheID)
		}
		if row.Fresh != (row.Status == StatusFresh) {
			return nil, fmt.Errorf("revocation cache %q fresh flag disagrees with status", row.CacheID)
		}
		if row.Fresh && (!row.SignatureVerified || row.CachedResponses == 0 || row.NextUpdateUnix == 0 || row.LastValidatedAtUnix == 0) {
			return nil, fmt.Errorf("revocation cache %q claims fresh without validated cached evidence", row.CacheID)
		}
		key := row.Protocol + "\x00" + row.CacheID
		if seen[key] {
			return nil, fmt.Errorf("revocation cache posture duplicates %s cache %q", row.Protocol, row.CacheID)
		}
		seen[key] = true
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CacheID != out[j].CacheID {
			return out[i].CacheID < out[j].CacheID
		}
		return out[i].Protocol < out[j].Protocol
	})
	return out, nil
}

// Validate requires the caller to have transmitted the normalized order. The
// server does not silently rewrite signed meaning after verification.
func (s Statement) Validate() error {
	if !safeIdentity(s.TenantID) || !safeIdentity(s.AgentCommonName) || s.IssuedAtUnix <= 0 {
		return errors.New("revocation cache posture identity or issued-at is invalid")
	}
	normalized, err := Normalize(s.Entries)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(normalized, s.Entries) {
		return errors.New("revocation cache posture is not normalized")
	}
	return nil
}

// Canonical returns the only byte representation that may be signed.
func (s Statement) Canonical() ([]byte, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	body, err := json.Marshal(struct {
		TenantID        string  `json:"tenant_id"`
		AgentCommonName string  `json:"agent_common_name"`
		Entries         []Entry `json:"entries"`
		IssuedAtUnix    int64   `json:"issued_at_unix"`
	}{s.TenantID, s.AgentCommonName, s.Entries, s.IssuedAtUnix})
	if err != nil {
		return nil, err
	}
	return append([]byte(statementVersion), body...), nil
}

func safeIdentity(value string) bool {
	return value != "" && len(value) <= 256 && !strings.ContainsAny(value, "\r\n\x00")
}

func safeToken(value string, max int) bool {
	if value == "" || len(value) > max {
		return false
	}
	for i, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') ||
			(i > 0 && (r == '.' || r == '_' || r == '-')) {
			continue
		}
		return false
	}
	return true
}

func localPath(value string) bool {
	return strings.HasPrefix(value, "/") && len(value) <= 512 && !strings.HasPrefix(value, "//") &&
		!strings.ContainsAny(value, "?#\r\n\x00") && !strings.Contains(value, "..")
}

func sha256Fingerprint(value string) bool {
	raw, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return strings.HasPrefix(value, "sha256:") && value == strings.ToLower(value) && err == nil && len(raw) == 32
}
