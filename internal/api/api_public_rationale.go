// SPDX-License-Identifier: BUSL-1.1

package api

// publicRationaleForRoute is the reviewed reason each deliberately public
// (unauthenticated) route is public; the OpenAPI security metadata and the
// feature authorization manifest publish it.
func publicRationaleForRoute(r route) string {
	if r.perm != "" {
		return ""
	}
	switch r.opID {
	case "machineLogin":
		return "public credential exchange: the presented machine credential authenticates the workload and yields a tenant-scoped session."
	case "receiveSecretScanHook":
		return "public provider webhook: GitHub authenticates each delivery with an HMAC-SHA256 signature under the hook's own secret (X-Hub-Signature-256), checked before any work; the configured hook names its tenant."
	case "getOpenAPISpec":
		return specPublicRationale
	case "getBrand":
		return brandPublicRationale
	case "getEditions":
		return editionsPublicRationale
	default:
		return ""
	}
}
