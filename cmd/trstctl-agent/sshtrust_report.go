// SPDX-License-Identifier: BUSL-1.1
package main

import (
	"trstctl.com/trstctl/internal/agent"
	"trstctl.com/trstctl/internal/agent/sshdiscovery"
)

type sshTrustCertificateReport = sshdiscovery.TrustCertificateReport

func sshTrustInventoryFindings(postures []sshdiscovery.SSHDTrust) ([]agent.InventoryFinding, error) {
	shared, err := sshdiscovery.InventoryFindings(postures)
	if err != nil {
		return nil, err
	}
	out := make([]agent.InventoryFinding, 0, len(shared))
	for _, finding := range shared {
		out = append(out, agent.InventoryFinding{Kind: finding.Kind, Ref: finding.Ref, Provenance: finding.Provenance, Fingerprint: finding.Fingerprint, RiskScore: finding.RiskScore, Metadata: finding.Metadata})
	}
	return out, nil
}
