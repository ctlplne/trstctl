// SPDX-License-Identifier: BUSL-1.1

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
		// P9: the certificate chain that names a managed key, for stock signing
		// tools, and a certificate request the key signs inside the signer.
		{method: "GET", path: "/api/v1/code-signing/keys/{key_id}/certificate", opID: "getCodeSigningKeyCertificate", summary: "Read the certificate chain of a managed code-signing key: the one attached through the API, or else the one configured beside it", handler: a.getCodeSigningKeyCertificate, pathParams: []param{pathString("key_id", "Code-signing key id")}, resSchema: "CodeSigningKeyCertificate", successCode: "200", perm: authz.KeysRead},
		{method: "PUT", path: "/api/v1/code-signing/keys/{key_id}/certificate", opID: "attachCodeSigningKeyCertificate", summary: "Attach or rotate a managed code-signing key's certificate chain (leaf first), checked against the key; signing tools get it at once, without a restart", handler: a.attachCodeSigningKeyCertificate, pathParams: []param{pathString("key_id", "Code-signing key id")}, reqSchema: "CodeSigningKeyCertificateAttach", resSchema: "CodeSigningKeyCertificate", successCode: "200", mutation: true, perm: authz.KeysWrite},
		{method: "POST", path: "/api/v1/code-signing/keys/{key_id}/csr", opID: "createCodeSigningKeyCSR", summary: "Get a certificate request signed by a managed code-signing key inside the signer", handler: a.createCodeSigningKeyCSR, pathParams: []param{pathString("key_id", "Code-signing key id")}, reqSchema: "CodeSigningKeyCSRRequest", resSchema: "CodeSigningKeyCSR", successCode: "200", mutation: true, perm: authz.KeysWrite},
		{method: "POST", path: "/api/v1/code-signing/sign", opID: "signCodeArtifact", summary: "Sign an artifact digest with a managed code-signing key", handler: a.signCodeArtifact, reqSchema: "CodeSigningRequest", resSchema: "CodeSigningSignature", successCode: "200", mutation: true, perm: authz.KeysWrite},
		{method: "POST", path: "/api/v1/code-signing/keyless", opID: "signCodeArtifactKeyless", summary: "Sign an artifact digest with a verified Sigstore/Fulcio identity", handler: a.signCodeArtifactKeyless, reqSchema: "CodeSigningKeylessRequest", resSchema: "CodeSigningSignature", successCode: "200", mutation: true, perm: authz.KeysWrite},
	}
}
