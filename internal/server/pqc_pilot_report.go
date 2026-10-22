// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"

	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/pqc/compatlab"
)

// pqcPilotReportSigner signs a finished pilot's compat-lab report through the
// signer process's readiness-report key and returns the signed report's JSON,
// which verifies offline against that key (M1).
func pqcPilotReportSigner(provider SignerProvider) orchestrator.PQCPilotReportSigner {
	return func(ctx context.Context, report compatlab.Report) (string, error) {
		client := provider.Client()
		if client == nil {
			return "", errors.New("server: the isolated signer is unavailable for the readiness report")
		}
		signed, err := compatlab.SignReport(ctx, client, report, "")
		if err != nil {
			return "", err
		}
		out, err := json.Marshal(signed)
		if err != nil {
			return "", err
		}
		return string(out), nil
	}
}
