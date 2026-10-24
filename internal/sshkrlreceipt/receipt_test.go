// SPDX-License-Identifier: BUSL-1.1

package sshkrlreceipt

import (
	"bytes"
	"strings"
	"testing"
)

const digestA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const digestB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

func receipt(outcome string) Receipt {
	r := Receipt{KRLTenantID: "tenant-1", InstalledVersion: 7, InstalledSHA256: digestA, Outcome: outcome, CheckedAtUnix: 1700000000, PollEverySeconds: 30}
	switch outcome {
	case OutcomeCurrent, OutcomeInstalled:
		r.FetchedVersion, r.FetchedSHA256 = 7, digestA
	case OutcomeRefusedDropsRevocations:
		r.FetchedVersion, r.FetchedSHA256, r.DroppedSerials = 9, digestB, 2
	case OutcomeRefusedNotNewer, OutcomeApplyFailed:
		r.FetchedVersion, r.FetchedSHA256 = 3, digestB
	}
	return r
}

// Each outcome carries what it claims, and the statement binds the receipt to
// the agent's own tenant.
func TestReceiptValidatesEveryOutcome(t *testing.T) {
	for _, outcome := range []string{OutcomeCurrent, OutcomeInstalled, OutcomeRefusedNotNewer, OutcomeRefusedDropsRevocations, OutcomeFetchFailed, OutcomeApplyFailed} {
		statement := Statement{TenantID: "tenant-1", AgentCommonName: "edge-1", Receipt: receipt(outcome), IssuedAtUnix: 1700000001}
		canonical, err := statement.Canonical()
		if err != nil {
			t.Fatalf("%s: %v", outcome, err)
		}
		if !bytes.HasPrefix(canonical, []byte(statementVersion)) || !strings.Contains(string(canonical), `"outcome":"`+outcome+`"`) {
			t.Fatalf("%s: canonical = %s", outcome, canonical)
		}
	}
	bad := map[string]func(*Statement){
		"unknown outcome":       func(s *Statement) { s.Receipt.Outcome = "fine" },
		"another tenant's list": func(s *Statement) { s.Receipt.KRLTenantID = "tenant-2" },
		"current but differs":   func(s *Statement) { s.Receipt.FetchedSHA256 = digestB },
		"uppercase digest":      func(s *Statement) { s.Receipt.InstalledSHA256 = strings.ToUpper(digestA) },
		"short digest":          func(s *Statement) { s.Receipt.InstalledSHA256 = "abc" },
		"no check time":         func(s *Statement) { s.Receipt.CheckedAtUnix = 0 },
		"no poll interval":      func(s *Statement) { s.Receipt.PollEverySeconds = 0 },
		"no issued-at":          func(s *Statement) { s.IssuedAtUnix = 0 },
		"multi-line agent name": func(s *Statement) { s.AgentCommonName = "edge\n1" },
		"current with drops":    func(s *Statement) { s.Receipt.DroppedKeyIDs = 1 },
		"negative count":        func(s *Statement) { s.Receipt.DroppedKeys = -1 },
		"drops refusal without any": func(s *Statement) {
			s.Receipt.Outcome = OutcomeRefusedDropsRevocations
			s.Receipt.FetchedSHA256 = digestB
		},
		"fetch failure with a list": func(s *Statement) { s.Receipt.Outcome = OutcomeFetchFailed },
	}
	for name, mutate := range bad {
		statement := Statement{TenantID: "tenant-1", AgentCommonName: "edge-1", Receipt: receipt(OutcomeCurrent), IssuedAtUnix: 1700000001}
		mutate(&statement)
		if _, err := statement.Canonical(); err == nil {
			t.Errorf("%s: invalid receipt was canonicalized", name)
		}
	}
}
