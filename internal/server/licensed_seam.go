// SPDX-License-Identifier: MPL-2.0

package server

import "trstctl.com/trstctl/internal/editionseam"

type LicensedLeafSigner = editionseam.LicensedLeafSigner
type LicensedCSRInspector = editionseam.LicensedCSRInspector
type LicensedCSRParser = editionseam.LicensedCSRParser
type LicensedSPIFFESVIDFactory = editionseam.LicensedSPIFFESVIDFactory
type LicensedAPIOptionsDeps = editionseam.LicensedAPIOptionsDeps
type LicensedAPIOptionsFactory = editionseam.LicensedAPIOptionsFactory
type LicensedOutboxHandler = editionseam.LicensedOutboxHandler
type LicensedOutboxTerminalFailureHandler = editionseam.LicensedOutboxTerminalFailureHandler
type LicensedOutboxDeps = editionseam.LicensedOutboxDeps
type LicensedOutboxFactory = editionseam.LicensedOutboxFactory
type SuccessionMinter = editionseam.SuccessionMinter
type IssuanceGate = editionseam.IssuanceGate
type KEMCustody = editionseam.KEMCustody
type ManagedKeyCustody = editionseam.ManagedKeyCustody
type GatedDestruction = editionseam.GatedDestruction
type ProtocolLeafIssuer = editionseam.ProtocolLeafIssuer
type AdmissionHook = editionseam.AdmissionHook
