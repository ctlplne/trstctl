// SPDX-License-Identifier: BUSL-1.1

package pqcruntime

import (
	"trstctl.com/trstctl/internal/editionseam"
	"trstctl.com/trstctl/internal/pqc"
)

// Runtime is the complete PQC issuance object graph attached by the one AN-9
// seam. Keeping the construction in one called function gives production and
// the wiring census the same closed inventory: licensed X.509 signing, hybrid
// CSR inspection, pure RFC 9881 parsing, and multi-key SPIFFE issuance.
type Runtime struct {
	LeafSigner         editionseam.LicensedLeafSigner
	PreparedLeafSigner editionseam.PreparedSubjectLeafSigner
	CSRInspector       editionseam.LicensedCSRInspector
	CSRParser          editionseam.LicensedCSRParser
	SPIFFESVIDFactory  editionseam.LicensedSPIFFESVIDFactory
}

func NewRuntime() Runtime {
	return Runtime{
		LeafSigner:         pqc.SignLicensedLeafFromCSRWithProfile,
		PreparedLeafSigner: pqc.SignPQCLeafFromCSRWithPreparation,
		CSRInspector:       pqc.InspectHybridCSR,
		CSRParser:          pqc.ParsePureMLDSACSR,
		SPIFFESVIDFactory:  NewSPIFFEHybridSVIDIssuer,
	}
}
