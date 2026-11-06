// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package relay

import (
	"bytes"
	"context"
	"golang.org/x/sys/windows"
	"os/exec"
	"path/filepath"

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
	configuration, ok := nativeCAConfigurationArgument(service.DNSName, service.Name)
	if !ok {
		return adcs.EnrollmentAgentRestrictions{State: adcs.EvidenceUnobserved, Source: "ca_identity_unobserved"}
	}
	systemDirectory, err := windows.GetSystemDirectory()
	if err != nil {
		return adcs.EnrollmentAgentRestrictions{State: adcs.EvidenceUnobserved, Source: "native_tool_unavailable"}
	}
	// #nosec G204 -- CWE-78: the Windows SDK supplies System32, certutil.exe and command switches are fixed, and the bounded validated CA selector is one argv value; no shell or credentials are used.
	cmd := exec.CommandContext(ctx, filepath.Join(systemDirectory, "certutil.exe"), "-config", configuration, "-getreg", "CA\\EnrollmentAgentRights")
	var output boundedCommandBuffer
	cmd.Stdout, cmd.Stderr = &output, &output
	err = cmd.Run()
	return parseCAAgentRestrictions(output.Bytes(), err == nil)
}
