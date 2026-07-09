// SPDX-License-Identifier: LicenseRef-trstctl-EE

package wasm

import (
	"encoding/json"
	"fmt"

	vdecverify "trstctl.com/trstctl/ee/decommission/verify"
)

type Response struct {
	OK      bool               `json:"ok"`
	Verdict vdecverify.Verdict `json:"verdict,omitempty"`
	Error   string             `json:"error,omitempty"`
}

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
