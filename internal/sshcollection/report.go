// SPDX-License-Identifier: BUSL-1.1

package sshcollection

import (
	"encoding/json"
	"errors"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/discovery/segmentscan"
)

const MaxJobReportBytes = 1 << 20

// Observation records every requested target, including an explicit failed read.
// Raw private material and arbitrary error text have no field in this contract.
type Observation struct {
	Address  string    `json:"address"`
	Status   string    `json:"status"`
	Snapshot *Snapshot `json:"snapshot,omitempty"`
}
type Report struct {
	CommandDigest string        `json:"command_digest"`
	Results       []Observation `json:"results"`
}

func (c Command) ScopeIntent() segmentscan.Intent {
	out := segmentscan.Intent{Execution: c.Execution, Mode: segmentscan.ModeSSH, Segment: c.Segment, RequiredAgentID: c.RequiredAgentID, RequiredAgentRole: c.RequiredAgentRole, AllowRFC1918: c.AllowRFC1918, AllowLoopback: c.AllowLoopback}
	for _, h := range c.Hosts {
		out.Targets = append(out.Targets, h.Address)
	}
	return out
}
func DecodeReport(raw []byte, command Command) (Report, error) {
	var out Report
	if len(raw) > MaxJobReportBytes {
		return out, errors.New("SSH collection job report exceeds its bound")
	}
	if err := decodeBounded(raw, &out, MaxJobReportBytes); err != nil {
		return out, err
	}
	return out, out.Validate(command)
}
func (r Report) Validate(command Command) error {
	digest, err := command.Digest()
	if err != nil {
		return err
	}
	if r.CommandDigest != digest || len(r.Results) != len(command.Hosts) {
		return errors.New("SSH collection report does not cover its exact immutable command")
	}
	for i, result := range r.Results {
		if result.Address != command.Hosts[i].Address {
			return errors.New("SSH collection report target differs from its command")
		}
		switch result.Status {
		case "observed":
			if result.Snapshot == nil {
				return errors.New("SSH collection success requires public readback")
			}
			if err := result.Snapshot.Validate(); err != nil {
				return err
			}
		case "connection_or_auth_failed", "invalid_snapshot", "report_too_large", "cancelled":
			if result.Snapshot != nil {
				return errors.New("SSH collection failure cannot carry purported readback")
			}
		default:
			return errors.New("SSH collection report has an unknown outcome")
		}
	}
	return nil
}
func (r Report) EvidenceDigest() string {
	raw, _ := json.Marshal(r)
	return "sha256:" + crypto.SHA256Hex(raw)
}
