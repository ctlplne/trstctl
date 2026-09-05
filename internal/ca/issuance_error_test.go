// SPDX-License-Identifier: MPL-2.0

package ca

import (
	"errors"
	"strings"
	"testing"
)

func TestExternalIssueStageErrorClassifiesWithoutRenderingCause(t *testing.T) {
	const unsafe = "upstream-body-with-a-credential"
	err := safeExternalIssueError("external_ca_record_failed", "external CA certificate recording failed", errors.New(unsafe))
	if strings.Contains(err.Error(), unsafe) {
		t.Fatalf("safe stage error rendered its cause: %q", err)
	}
	classified := err.(interface{ SafeDeliveryClass() string })
	if got := classified.SafeDeliveryClass(); got != "external_ca_record_failed" {
		t.Fatalf("class = %q", got)
	}
}
