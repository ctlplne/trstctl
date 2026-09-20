// SPDX-License-Identifier: BUSL-1.1

//go:build !windows

package relay

import (
	"context"

	"trstctl.com/trstctl/internal/discovery/adcs"
)

func observeCAAgentRestrictions(_ context.Context, _ adcs.EnrollmentService) adcs.EnrollmentAgentRestrictions {
	return adcs.EnrollmentAgentRestrictions{State: adcs.EvidenceUnobserved, Source: "requires_windows_relay"}
}
