// SPDX-License-Identifier: BUSL-1.1

package api

import "trstctl.com/trstctl/internal/authz"

// acmeRoutes is the served ACME operator surface: the admin console
// (accounts, orders, deactivation; A52), the readiness plan, the external
// account binding credentials with their policy and rotation verbs
// (B4, A50/A53/A54), and the ARI posture. Split out of the core table by
// workflow so the served-file budget keeps api.go readable.
func (a *API) acmeRoutes(acmeEABKeyPath, acmeAccountPath, page []param) []route {
	return []route{
		{method: "GET", path: "/api/v1/acme/eab-credentials", opID: "listACMEEABCredentials", summary: "List served ACME external account binding credentials with their scope and usage", handler: a.listACMEEABCredentials, resSchema: "ACMEEABPosture", successCode: "200", perm: authz.IssuersRead},
		{method: "GET", path: "/api/v1/acme/accounts", opID: "listACMEAccounts", summary: "List the served ACME server's accounts with their status, binding credential and order counts", handler: a.listACMEAccounts, resSchema: "ACMEAccountList", successCode: "200", perm: authz.IssuersRead},
		{method: "GET", path: "/api/v1/acme/accounts/{id}/orders", opID: "listACMEAccountOrders", summary: "List one ACME account's orders with their authorizations, challenges and issued certificate record", handler: a.listACMEAccountOrders, pathParams: acmeAccountPath, resSchema: "ACMEOrderList", successCode: "200", perm: authz.IssuersRead},
		{method: "POST", path: "/api/v1/acme/accounts/{id}/deactivate", opID: "deactivateACMEAccount", summary: "Deactivate an ACME account: refuse new requests under its key and cancel its pending orders, leaving issued certificates untouched", handler: a.deactivateACMEAccount, pathParams: acmeAccountPath, resSchema: "ACMEAccount", successCode: "200", mutation: true, perm: authz.IssuersWrite},
		{method: "GET", path: "/api/v1/acme/operator-plan", opID: "getACMEOperatorPlan", summary: "Preview tenant-bound ACME readiness, the exact next action, and recovery steps without effects", handler: a.getACMEOperatorPlan, resSchema: "ACMEOperatorPlan", successCode: "200", perm: authz.IssuersRead},
		{method: "POST", path: "/api/v1/acme/eab-credentials/{kid}/disable", opID: "disableACMEEABCredential", summary: "Stop new ACME accounts and orders under an external account binding credential", handler: a.setACMEEABCredentialDisabled, pathParams: acmeEABKeyPath, resSchema: "ACMEEABCredential", successCode: "200", mutation: true, perm: authz.IssuersWrite},
		{method: "POST", path: "/api/v1/acme/eab-credentials/{kid}/enable", opID: "enableACMEEABCredential", summary: "Re-enable an operator-disabled ACME external account binding credential", handler: a.setACMEEABCredentialDisabled, pathParams: acmeEABKeyPath, resSchema: "ACMEEABCredential", successCode: "200", mutation: true, perm: authz.IssuersWrite},
		{method: "PUT", path: "/api/v1/acme/eab-credentials/{kid}/policy", opID: "updateACMEEABPolicy", summary: "Replace an ACME external account binding credential's identifier scope, order quota, validity window and pinned profile at runtime", handler: a.updateACMEEABPolicy, pathParams: acmeEABKeyPath, reqSchema: "ACMEEABPolicyUpdate", resSchema: "ACMEEABCredential", successCode: "200", mutation: true, perm: authz.IssuersWrite},
		{method: "POST", path: "/api/v1/acme/eab-credentials/{kid}/rotate", opID: "rotateACMEEABCredential", summary: "Register a successor ACME external account binding credential from a tenant secret-store reference, inheriting the predecessor's policy", handler: a.rotateACMEEABCredential, pathParams: acmeEABKeyPath, reqSchema: "ACMEEABRotationRequest", resSchema: "ACMEEABCredential", successCode: "201", mutation: true, perm: authz.IssuersWrite},
		{method: "GET", path: "/api/v1/acme/ari/posture", opID: "getACMEARIPosture", summary: "Get ACME Renewal Information publication and lifecycle-consumption posture", handler: a.getACMEARIPosture, query: page, resSchema: "ACMEARIPosture", successCode: "200", perm: authz.LifecycleRead},
	}
}
