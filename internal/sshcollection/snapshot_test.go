// SPDX-License-Identifier: BUSL-1.1

package sshcollection

import (
	"encoding/json"
	"testing"
)

func TestSnapshotCannotAddPrivateReadsOrHideMissingCoverage(t *testing.T) {
	s := Snapshot{Version: 1, Profile: Profile, ConfigPath: "/etc/ssh/sshd_config", Settings: map[string][]string{"trustedusercakeys": {"/etc/ssh/ca.pub"}, "revokedkeys": {"none"}, "authorizedkeysfile": {"none"}, "authorizedprincipalsfile": {"none"}, "hostcertificate": {"none"}}, Files: []PublicFile{{Path: "/etc/ssh/ca.pub", Kind: "ca", State: "missing"}}}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeSnapshot(raw); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*Snapshot){"untyped-extra-file": func(s *Snapshot) {
		s.Files = append(s.Files, PublicFile{Path: "/private/undeclared", Kind: "", State: "read", Data: []byte("undeclared public bytes")})
	},
		"empty-setting":    func(s *Snapshot) { s.Settings["authorizedkeysfile"] = []string{""} },
		"conflicting-none": func(s *Snapshot) { s.Settings["hostcertificate"] = []string{"none", "/etc/ssh/host-cert.pub"} },
		"missing-setting":  func(s *Snapshot) { delete(s.Settings, "authorizedkeysfile") },
		"private-config":   func(s *Snapshot) { s.Settings = map[string][]string{"hostkey": {"/private/ssh_host_key"}} }, "extra-path": func(s *Snapshot) { s.Files[0].Path = "/private/key" }, "hidden-coverage": func(s *Snapshot) { s.Files = nil }, "private-bytes": func(s *Snapshot) { s.Files[0].State = "read"; s.Files[0].Data = []byte("-----BEGIN PRIVATE KEY-----") }, "unknown-state": func(s *Snapshot) { s.Files[0].State = "assumed_safe" }} {
		t.Run(name, func(t *testing.T) {
			var other Snapshot
			if err := json.Unmarshal(raw, &other); err != nil {
				t.Fatal(err)
			}
			change(&other)
			if err := other.Validate(); err == nil {
				t.Fatal("unsafe or incomplete public snapshot accepted")
			}
		})
	}
}
