// SPDX-License-Identifier: MPL-2.0

package api

import "trstctl.com/trstctl/internal/authz"

// codeSigningRoutes are the served code-signing endpoints.
//
// Extracted from the main route table to keep api.go inside the served-surface
// file-size budget. The grouping is by WORKFLOW rather than by convenience: a
// reader asking "what can this product do with code signing" gets one file, and
// the budget stops the central table growing without anybody deciding to let it.
func (a *API) codeSigningRoutes() []route {
	return []route{
		// Code-signing (CLM-06/F50): key-backed and keyless/Sigstore artifact signing
		// over the served path. Requests carry only a digest and key/identity
		// references; the authenticated principal is the signer identity. The service
		// queues transparency-log publication through outbox (AN-6), rather than
		// calling Rekor/Fulcio inline.
		// B-4: which identities signed, and did the transparency entry land.
		{method: "GET", path: "/api/v1/code-signing/identities", opID: "listCodeSigningIdentities", summary: "List signing operations with their transparency-log verification state", handler: a.listCodeSigningIdentities, resSchema: "CodeSigningIdentityList", successCode: "200", perm: authz.CertsRead},
		{method: "POST", path: "/api/v1/code-signing/preview", opID: "previewCodeArtifact", summary: "Review an exact managed-key signing plan without signing or publishing", handler: a.previewCodeArtifact, reqSchema: "CodeSigningRequest", resSchema: "CodeSigningPreview", successCode: "200", perm: authz.KeysWrite},
		{method: "POST", path: "/api/v1/code-signing/keyless/preview", opID: "previewCodeArtifactKeyless", summary: "Review an exact keyless signing plan without attesting, signing, or publishing", handler: a.previewCodeArtifactKeyless, reqSchema: "CodeSigningKeylessRequest", resSchema: "CodeSigningPreview", successCode: "200", perm: authz.KeysWrite},
		{method: "POST", path: "/api/v1/code-signing/sign", opID: "signCodeArtifact", summary: "Sign an artifact digest with a managed code-signing key", handler: a.signCodeArtifact, reqSchema: "CodeSigningRequest", resSchema: "CodeSigningSignature", successCode: "200", mutation: true, perm: authz.KeysWrite},
		{method: "POST", path: "/api/v1/code-signing/keyless", opID: "signCodeArtifactKeyless", summary: "Sign an artifact digest with a verified Sigstore/Fulcio identity", handler: a.signCodeArtifactKeyless, reqSchema: "CodeSigningKeylessRequest", resSchema: "CodeSigningSignature", successCode: "200", mutation: true, perm: authz.KeysWrite},
	}
}
