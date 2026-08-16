//go:build windows

// SPDX-License-Identifier: MPL-2.0

package proof

import (
	"net/http"
	"testing"
)

const (
	processModeNative = "native"
	processModeBinfmt = "binfmt"
)

// ShippedProcess keeps the DOD proof package type-complete for Windows build and
// vet gates. The production-assembly proof itself is intentionally Linux-only:
// it audits Linux PIDs, capabilities, executable mappings, and socket ownership.
// Every executable entry point below fails closed if a Windows test tries to run
// the proof instead of merely compiling it.
type ShippedProcess struct {
	t *testing.T
}

type launchedResponse struct {
	id       string
	response *http.Response
	witness  launchedProcessReceipt
}

func BuildShippedProcess(t *testing.T, _ string, _ []byte) *ShippedProcess {
	t.Helper()
	t.Fatal("DOD-CENSUS: shipped-process proof requires the pinned Linux runtime runner")
	return &ShippedProcess{t: t}
}

func (p *ShippedProcess) CreateToken(_ string, _ []string, _ ...string) string {
	p.failWindows()
	return ""
}

func (p *ShippedProcess) Start(_ string, _ []string) {
	p.failWindows()
}

func (p *ShippedProcess) Do(_ *http.Request) *launchedResponse {
	p.failWindows()
	return nil
}

func (p *ShippedProcess) Logs() string {
	p.failWindows()
	return ""
}

func (p *ShippedProcess) Stop() {}

func (p *ShippedProcess) failWindows() {
	if p == nil || p.t == nil {
		panic("DOD-CENSUS: invalid Windows shipped-process proof")
	}
	p.t.Helper()
	p.t.Fatal("DOD-CENSUS: shipped-process proof requires the pinned Linux runtime runner")
}
