// SPDX-License-Identifier: BUSL-1.1

package api

import "trstctl.com/trstctl/internal/authz"

// endpointContainmentRoutes are the emergency host actions on one enrolled
// target: stopping its listener, removing its installed material, and asking
// the host whether the stopped listener can come back.
func (a *API) endpointContainmentRoutes(idPath []param) []route {
	return []route{
		{method: "GET", path: "/api/v1/connectors/targets/{id}/contain/preview", opID: "previewEndpointContainment", summary: "Review an exact host target and compromised leaf before emergency containment", handler: a.previewEndpointContainment, pathParams: idPath, resSchema: "EndpointContainmentPreview", successCode: "200", perm: authz.ConnectorsWrite},
		{method: "POST", path: "/api/v1/connectors/targets/{id}/contain", opID: "containEndpoint", summary: "Queue exact-fingerprint containment on the enrolled host", handler: a.containEndpoint, pathParams: idPath, reqSchema: "EndpointContainmentRequest", resSchema: "ConnectorDelivery", successCode: "202", mutation: true, perm: authz.ConnectorsWrite},
		{method: "POST", path: "/api/v1/connectors/targets/{id}/recovery-check", opID: "requestEndpointRecoveryCheck", summary: "Ask a contained target's enrolled host whether its profile pins an action that brings the listener back and what the listener serves now", handler: a.requestEndpointRecoveryCheck, pathParams: idPath, reqSchema: "EndpointRecoveryCheckRequest", resSchema: "EndpointRecoveryCheck", successCode: "202", mutation: true, perm: authz.ConnectorsWrite},
		{method: "GET", path: "/api/v1/connectors/targets/{id}/recovery-check", opID: "getEndpointRecoveryCheck", summary: "Read the latest recovery check of a contained target and the host's signed answer", handler: a.getEndpointRecoveryCheck, pathParams: idPath, resSchema: "EndpointRecoveryCheck", successCode: "200", perm: authz.ConnectorsRead},
		{method: "GET", path: "/api/v1/connectors/targets/{id}/purge/preview", opID: "previewEndpointPurge", summary: "Review an exact host target and compromised leaf before removing its installed material", handler: a.previewEndpointPurge, pathParams: idPath, resSchema: "EndpointContainmentPreview", successCode: "200", perm: authz.ConnectorsWrite},
		{method: "POST", path: "/api/v1/connectors/targets/{id}/purge", opID: "purgeEndpoint", summary: "Queue exact-fingerprint removal of installed certificate and key material on the enrolled host", handler: a.purgeEndpoint, pathParams: idPath, reqSchema: "EndpointContainmentRequest", resSchema: "ConnectorDelivery", successCode: "202", mutation: true, perm: authz.ConnectorsWrite},
	}
}
