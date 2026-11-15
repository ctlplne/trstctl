// SPDX-License-Identifier: BUSL-1.1

package relay

import (
	"time"

	"trstctl.com/trstctl/internal/agent/k8s"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/kms/tpm"
	"trstctl.com/trstctl/internal/pluginhost"
)

// SetKubernetesClientForTest points the k8s_secret executor at a test API
// server instead of the pod's in-cluster service account. It returns the
// restore function.
func SetKubernetesClientForTest(f func() (*k8s.Client, error)) func() {
	previous := newKubernetesClient
	newKubernetesClient = f
	return func() { newKubernetesClient = previous }
}

// SetMDMTokenClockForTest gives the relay a fresh MDM token cache on the
// given clock (A156-L2) and returns the restore function and a counter of
// the tokens it keeps.
func SetMDMTokenClockForTest(now func() time.Time) (restore func(), kept func() int) {
	previous := mdmTokens
	mdmTokens = newMDMTokenCache(now)
	cache := mdmTokens
	return func() { mdmTokens = previous }, cache.len
}

// SetCertutilPagingForTest lowers one certutil read's byte bound and the
// request ids a paged read covers (A162-L1); it returns the restore
// function.
func SetCertutilPagingForTest(bound int64, pageRows int) func() {
	previousBound, previousRows := certutilOutputBound, certutilPageRows
	certutilOutputBound, certutilPageRows = bound, pageRows
	return func() { certutilOutputBound, certutilPageRows = previousBound, previousRows }
}

// PluginHTTPDoerForTest is the HTTP service a plugin call gives its module
// (A193), so a test can read exactly what the module would be handed.
func PluginHTTPDoerForTest(call PluginCall) pluginhost.HTTPDoer {
	return pluginHTTPDoer(call.Client, call.Intent, call.Material)
}

// SetHostKeyTPMForTest makes the host key TPM dev for every host profile, and
// its attestation attest (TPM-O1). Tests that use it do not run in parallel.
func SetHostKeyTPMForTest(dev tpm.HostKeyDevice, attest func(jobID int64, file, csrDER []byte) ([]byte, error)) func() {
	prevOpen, prevAttest := openHostKeyTPM, attestTPMHostKey
	openHostKeyTPM = func(connector.HostKeyTPMConfig) (*hostKeyTPM, error) { return &hostKeyTPM{device: dev}, nil }
	attestTPMHostKey = func(_ *hostKeyTPM, jobID int64, file, csrDER []byte) ([]byte, error) {
		return attest(jobID, file, csrDER)
	}
	return func() { openHostKeyTPM, attestTPMHostKey = prevOpen, prevAttest }
}
