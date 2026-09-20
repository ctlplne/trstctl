// SPDX-License-Identifier: BUSL-1.1

package wasm

import (
	"encoding/json"
	"fmt"

	vdecverify "trstctl.com/trstctl/internal/decommission/verify"
)

type Response struct {
	OK      bool               `json:"ok"`
	Verdict vdecverify.Verdict `json:"verdict,omitempty"`
	Error   string             `json:"error,omitempty"`
}

// VerifyJSON is the stored-instruction form of the verifier and practices
// VDEC-claim-24: a distributable medium carrying the verification instructions
// together with the destruction-record structure, evaluated with no control-plane
// network access.
func VerifyJSON(raw []byte) ([]byte, error) {
	var req vdecverify.Request
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, fmt.Errorf("vdec verify wasm: decode request: %w", err)
	}
	verdict, err := vdecverify.Verify(req)
	resp := Response{OK: err == nil, Verdict: verdict}
	if err != nil {
		resp.Error = err.Error()
	}
	out, encErr := json.Marshal(resp)
	if encErr != nil {
		return nil, fmt.Errorf("vdec verify wasm: encode response: %w", encErr)
	}
	return out, nil
}
