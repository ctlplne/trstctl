// SPDX-License-Identifier: BUSL-1.1
package sshcollection

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestReportBindsEveryTargetAndRejectsInventedReadback(t *testing.T) {
	command := Config{Enabled: true, Segment: "owned", RelayAgentID: "11111111-1111-4111-8111-111111111111", Hosts: []Host{{Address: "example.test:22", Username: "reader", HostKeyFingerprint: "SHA256:" + strings.Repeat("A", 43), CredentialRef: "secret://ssh/reader"}}}.Resolve() // #nosec G101 -- public host pin, restricted account and vault-reference fixtures contain no credential value (CWE-798).
	command.ID = "22222222-2222-4222-8222-222222222222"
	command.SourceID = "33333333-3333-4333-8333-333333333333"
	digest, err := command.Digest()
	if err != nil {
		t.Fatal(err)
	}
	valid := Report{CommandDigest: digest, Results: []Observation{{Address: command.Hosts[0].Address, Status: "connection_or_auth_failed"}}}
	if err := valid.Validate(command); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*Report){func(r *Report) { r.CommandDigest = "invented" }, func(r *Report) { r.Results = nil }, func(r *Report) { r.Results[0].Address = "other.test:22" }, func(r *Report) { r.Results[0].Status = "observed" }, func(r *Report) { r.Results[0].Snapshot = &Snapshot{} }} {
		raw, _ := json.Marshal(valid)
		var bad Report
		_ = json.Unmarshal(raw, &bad)
		change(&bad)
		if err := bad.Validate(command); err == nil {
			t.Fatal("unbound target or invented success accepted")
		}
	}
}
func FuzzSSHCollectionContracts(f *testing.F) {
	f.Add([]byte(`{"enabled":false}`))
	f.Add([]byte(`{"version":1,"profile":"ssh-trust-read-v1"}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = DecodeConfig(raw)
		_, _ = DecodeCommand(raw)
		_, _ = DecodeSnapshot(raw)
		_, _ = DecodeReport(raw, Command{})
	})
}
