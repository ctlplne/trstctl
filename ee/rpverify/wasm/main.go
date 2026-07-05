// SPDX-License-Identifier: LicenseRef-trstctl-EE

//go:build js

// Command wasm verifies a freshly-built sample succession chain under js/wasm and
// prints the verdict, so TestRPVerify_WASMParity can assert the verifier produces
// the same result on wasm as on native (claim-13 portability / WASM build parity).
package main

import (
	"fmt"

	"trstctl.com/trstctl/ee/rpverify"
	"trstctl.com/trstctl/ee/succession"
	"trstctl.com/trstctl/internal/crypto"
)

func main() {
	sc, err := succession.BuildSampleChain(crypto.NewSoftwareBackend(), "spiffe://d", "spiffe://d/id", "t1")
	if err != nil {
		fmt.Printf("build error: %v\n", err)
		return
	}
	res, err := rpverify.Verify(
		rpverify.Input{TrustRootPubDER: sc.TrustRootPubDER, Genesis: sc.Genesis, Chain: sc.Records},
		nil,
		rpverify.Options{ExpectedTenant: "t1"},
	)
	fmt.Printf("epoch=%d ok=%v\n", res.Epoch, err == nil)
}
