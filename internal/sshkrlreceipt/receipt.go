// SPDX-License-Identifier: BUSL-1.1

// Package sshkrlreceipt defines the signed statement an enrolled host agent
// uses to report which OpenSSH KRL its sshd enforces (A109): the digest and
// version read back from the RevokedKeys file after each watcher attempt, and
// how that attempt ended.
package sshkrlreceipt

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Outcomes of one watcher attempt.
const (
	// OutcomeCurrent: the served list is the installed one.
	OutcomeCurrent = "current"
	// OutcomeInstalled: this attempt installed a newer served list.
	OutcomeInstalled = "installed"
	// OutcomeRefusedNotNewer: the served list does not advance the installed
	// version; the installed list stays.
	OutcomeRefusedNotNewer = "refused_not_newer"
	// OutcomeRefusedDropsRevocations: the served list would stop revoking
	// something the installed list revokes; the installed list stays.
	OutcomeRefusedDropsRevocations = "refused_drops_revocations"
	// OutcomeFetchFailed: the served list could not be fetched over the pinned
	// channel, or named another tenant.
	OutcomeFetchFailed = "fetch_failed"
	// OutcomeApplyFailed: the served list failed OpenSSH or host checks, or the
	// host rolled it back; the installed list stays.
	OutcomeApplyFailed = "apply_failed"

	statementVersion = "trstctl-agent-ssh-krl-receipt/v1\n"

	maxPollEverySeconds = 7 * 24 * 60 * 60
)

// Receipt is one host's account of its installed KRL. Installed* are read
// back from the RevokedKeys file sshd uses, not from the last download.
type Receipt struct {
	KRLTenantID      string `json:"krl_tenant_id"`
	InstalledVersion uint64 `json:"installed_version"`
	InstalledSHA256  string `json:"installed_sha256"`
	Outcome          string `json:"outcome"`
	FetchedVersion   uint64 `json:"fetched_version,omitempty"`
	FetchedSHA256    string `json:"fetched_sha256,omitempty"`
	DroppedSerials   uint64 `json:"dropped_serials,omitempty"`
	DroppedKeyIDs    int    `json:"dropped_key_ids,omitempty"`
	DroppedKeys      int    `json:"dropped_keys,omitempty"`
	DroppedKeyHashes int    `json:"dropped_key_hashes,omitempty"`
	CheckedAtUnix    int64  `json:"checked_at_unix"`
	InstalledAtUnix  int64  `json:"installed_at_unix,omitempty"`
	// PollEverySeconds is the watcher's interval, so a reader can tell a
	// watcher that stopped checking from one that checks rarely.
	PollEverySeconds int64 `json:"poll_every_seconds"`
}

// Report is carried on the certificate-authenticated heartbeat. Signature is
// produced by the same key behind that connection.
type Report struct {
	Receipt      Receipt `json:"receipt"`
	IssuedAtUnix int64   `json:"issued_at_unix"`
	Signature    []byte  `json:"signature"`
}

// Statement binds a receipt to the tenant, host agent, and report time.
type Statement struct {
	TenantID        string
	AgentCommonName string
	Receipt         Receipt
	IssuedAtUnix    int64
}

// Validate checks the closed vocabulary and that each outcome carries what it
// claims.
func (r Receipt) Validate() error {
	if !safeIdentity(r.KRLTenantID) {
		return errors.New("SSH KRL receipt names no valid tenant")
	}
	if !sha256Hex(r.InstalledSHA256) {
		return errors.New("SSH KRL receipt has no valid installed digest")
	}
	if r.CheckedAtUnix <= 0 || r.InstalledAtUnix < 0 {
		return errors.New("SSH KRL receipt has an invalid timestamp")
	}
	if r.PollEverySeconds <= 0 || r.PollEverySeconds > maxPollEverySeconds {
		return errors.New("SSH KRL receipt has an invalid poll interval")
	}
	if r.FetchedSHA256 != "" && !sha256Hex(r.FetchedSHA256) {
		return errors.New("SSH KRL receipt has an invalid fetched digest")
	}
	dropped := r.DroppedSerials != 0 || r.DroppedKeyIDs != 0 || r.DroppedKeys != 0 || r.DroppedKeyHashes != 0
	if r.DroppedKeyIDs < 0 || r.DroppedKeys < 0 || r.DroppedKeyHashes < 0 {
		return errors.New("SSH KRL receipt has a negative count")
	}
	switch r.Outcome {
	case OutcomeCurrent, OutcomeInstalled:
		if r.FetchedSHA256 != r.InstalledSHA256 || r.FetchedVersion != r.InstalledVersion || dropped {
			return fmt.Errorf("SSH KRL receipt outcome %q disagrees with its digests", r.Outcome)
		}
	case OutcomeRefusedDropsRevocations:
		if r.FetchedSHA256 == "" || !dropped {
			return errors.New("SSH KRL receipt refuses a list without naming what it drops")
		}
	case OutcomeRefusedNotNewer, OutcomeApplyFailed:
		if r.FetchedSHA256 == "" || dropped {
			return fmt.Errorf("SSH KRL receipt outcome %q is incomplete", r.Outcome)
		}
	case OutcomeFetchFailed:
		if r.FetchedSHA256 != "" || r.FetchedVersion != 0 || dropped {
			return errors.New("SSH KRL receipt reports a fetched list on a failed fetch")
		}
	default:
		return fmt.Errorf("SSH KRL receipt has unsupported outcome %q", r.Outcome)
	}
	return nil
}

// Validate checks the identity, issued-at, and receipt.
func (s Statement) Validate() error {
	if !safeIdentity(s.TenantID) || !safeIdentity(s.AgentCommonName) || s.IssuedAtUnix <= 0 {
		return errors.New("SSH KRL receipt identity or issued-at is invalid")
	}
	if s.Receipt.KRLTenantID != s.TenantID {
		return errors.New("SSH KRL receipt names another tenant's list")
	}
	return s.Receipt.Validate()
}

// Canonical returns the only byte representation that may be signed.
func (s Statement) Canonical() ([]byte, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	body, err := json.Marshal(struct {
		TenantID        string  `json:"tenant_id"`
		AgentCommonName string  `json:"agent_common_name"`
		Receipt         Receipt `json:"receipt"`
		IssuedAtUnix    int64   `json:"issued_at_unix"`
	}{s.TenantID, s.AgentCommonName, s.Receipt, s.IssuedAtUnix})
	if err != nil {
		return nil, err
	}
	return append([]byte(statementVersion), body...), nil
}

func sha256Hex(s string) bool {
	if len(s) != 64 || strings.ToLower(s) != s {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func safeIdentity(value string) bool {
	return value != "" && len(value) <= 256 && !strings.ContainsAny(value, "\r\n\x00")
}
