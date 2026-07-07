// SPDX-License-Identifier: LicenseRef-trstctl-EE

//go:build js

// Command wasm builds a sample AGID credential and verifies it OFFLINE under
// js/wasm, printing the decision so TestRPVerify_WASMParity can assert the AGID-09
// relying-party verifier produces the SAME result on wasm as on native (claim 28 /
// INV-A7 WASM build parity). It exercises the verify path -- which holds no key and
// constructs no network client -- under GOOS=js GOARCH=wasm, confirming external
// relying parties (in a browser or an edge runtime) get identical offline decisions.
package main

import (
	"fmt"

	"trstctl.com/trstctl/ee/agentid/verify"
)

func main() {
	res, ok := verify.BuildAndVerifySample()
	if !ok {
		fmt.Println("PARITY build-error")
		return
	}
	// A single, stable line the native parity test compares byte-for-byte.
	fmt.Printf("PARITY accepted=%v class=%s op=%s tool=%s refusal=%q\n",
		res.Accepted, res.AuthClass, res.Operation, res.Tool, res.RefusalError)
}
