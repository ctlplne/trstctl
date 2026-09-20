// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package relay

import (
	"bytes"
	"context"
	"os/exec"

	"trstctl.com/trstctl/internal/discovery/adcs"
)

const maxCertutilEvidenceBytes = 64 * 1024

type boundedCommandBuffer struct{ bytes.Buffer }

func (b *boundedCommandBuffer) Write(p []byte) (int, error) {
	original := len(p)
	remaining := maxCertutilEvidenceBytes - b.Len()
	if remaining > 0 {
		if len(p) > remaining {
			p = p[:remaining]
		}
		_, _ = b.Buffer.Write(p)
	}
	return original, nil
}

func observeCAAgentRestrictions(ctx context.Context, service adcs.EnrollmentService) adcs.EnrollmentAgentRestrictions {
	if service.DNSName == "" || service.Name == "" {
		return adcs.EnrollmentAgentRestrictions{State: adcs.EvidenceUnobserved, Source: "ca_identity_unobserved"}
	}
	cmd := exec.CommandContext(ctx, "certutil.exe", "-config", service.DNSName+"\\"+service.Name, "-getreg", "CA\\EnrollmentAgentRights")
	var output boundedCommandBuffer
	cmd.Stdout, cmd.Stderr = &output, &output
	err := cmd.Run()
	return parseCAAgentRestrictions(output.Bytes(), err == nil)
}
