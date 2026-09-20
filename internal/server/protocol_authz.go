// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/protocols/spiffe/workloadpb"
)

const ProtocolFeatureAuthzTestRef = "internal/server/protocol_authz_test.go"

// ProtocolAuthzEntry records the authorization contract for one non-/api/v1
// protocol surface. Permission means the protocol checks a trstctl permission at
// runtime. PublicRationale means the protocol is intentionally public because its
// own wire credential proves the caller or because the endpoint returns public
// trust material.
type ProtocolAuthzEntry struct {
	Protocol            string
	FeatureIDs          []string
	RoutePatterns       []string
	Permission          authz.Permission
	PublicRationale     string
	TenantMapping       string
	PrincipalMapping    string
	EnablementAuthority string
	DefaultDenyTest     string
}

// ProtocolAuthzManifest is the feature-to-authz manifest for the served enrollment,
// SSH, SPIFFE, ACME, and timestamping protocol surfaces.
func ProtocolAuthzManifest() []ProtocolAuthzEntry {
	return []ProtocolAuthzEntry{
		{
			Protocol:            "acme",
			FeatureIDs:          []string{"F5", "F46", "F69", "F70", "F71", "F72", "F73", "F74"},
			RoutePatterns:       protocolAuthzRoutePatterns("acme"),
			PublicRationale:     "ACME is a public CA protocol: the ACME account key, JWS nonce, challenge validation, and certificate possession checks authenticate the action rather than a trstctl bearer token.",
			TenantMapping:       "tenant is fixed by protocols.acme.tenant_id or the server default tenant before ACME state/log events are appended.",
			PrincipalMapping:    "principal is the ACME account key thumbprint plus validated identifier/challenge state; no human principal is accepted from request headers.",
			EnablementAuthority: "operator/admin configuration enables the mount; any future runtime toggle must require " + string(authz.CertsIssue) + ".",
			DefaultDenyTest:     "internal/server/protocols_served_test.go",
		},
		{
			Protocol:            "est",
			FeatureIDs:          []string{"F22"},
			RoutePatterns:       protocolAuthzRoutePatterns("est"),
			Permission:          authz.CertsRequest,
			TenantMapping:       "tenant is fixed by protocols.est.tenant_id and the bearer API token must belong to that same tenant.",
			PrincipalMapping:    "principal is the trstctl API token subject; the token must grant certs:request.",
			EnablementAuthority: "operator/admin configuration enables the mount; API tokens used for enrollment must carry " + string(authz.CertsRequest) + ".",
			DefaultDenyTest:     "internal/server/protocols_served_enroll_test.go",
		},
		{
			Protocol:            "scep",
			FeatureIDs:          []string{"F23", "F56"},
			RoutePatterns:       protocolAuthzRoutePatterns("scep"),
			PublicRationale:     "SCEP is a device bootstrap protocol: CMS request protection, transaction id idempotency, optional challenge password policy, profile checks, and the sealed RA transport key are the protocol credential boundary.",
			TenantMapping:       "tenant is fixed by protocols.scep.tenant_id or the server default tenant before the enroller records certificate events.",
			PrincipalMapping:    "principal is the SCEP client certificate/request transaction plus optional challenge-password decision; request headers are not trusted as identity.",
			EnablementAuthority: "operator/admin configuration enables the mount; any future runtime toggle must require " + string(authz.CertsRequest) + ".",
			DefaultDenyTest:     "internal/server/protocols_served_enroll_test.go",
		},
		{
			Protocol:            "cmp",
			FeatureIDs:          []string{"F55"},
			RoutePatterns:       protocolAuthzRoutePatterns("cmp"),
			PublicRationale:     "CMP is a PKI enrollment protocol: the protected PKIMessage, transaction id idempotency, profile checks, and sealed RA transport key are the protocol credential boundary.",
			TenantMapping:       "tenant is fixed by protocols.cmp.tenant_id or the server default tenant before the enroller records certificate events.",
			PrincipalMapping:    "principal is the CMP PKIMessage transaction and subject CSR; request headers are not trusted as identity.",
			EnablementAuthority: "operator/admin configuration enables the mount; any future runtime toggle must require " + string(authz.CertsRequest) + ".",
			DefaultDenyTest:     "internal/server/protocols_served_enroll_test.go",
		},
		{
			Protocol:      "ssh",
			FeatureIDs:    []string{"F43", "F45"},
			RoutePatterns: protocolAuthzRoutePatterns("ssh"),
			// GET /ssh/ca and GET /ssh/krl remain public: they are the trust
			// material a host must fetch before it can authenticate anything,
			// exactly like a CRL distribution point. The three MUTATING routes
			// require certs:issue. They were previously public on the rationale
			// that "principals are constrained by the served SSH profile" — that
			// was not true (ssh.Profile carries no principal allowlist and
			// issue() checks only non-empty + TTL), so an anonymous caller could
			// mint a `root` user certificate.
			Permission:          authz.CertsIssue,
			TenantMapping:       "tenant is fixed by protocols.ssh.tenant_id or the server default tenant when the signer-backed SSH CA is built; the bearer token must belong to that same tenant.",
			PrincipalMapping:    "principal is the trstctl API token subject, which must grant " + string(authz.CertsIssue) + "; the SSH subject public key, key id and principals are recorded in the certificate/KRL operation.",
			EnablementAuthority: "operator/admin configuration enables the mount; issuance and revocation require " + string(authz.CertsIssue) + ".",
			DefaultDenyTest:     "internal/server/protocols_served_spiffe_ssh_test.go",
		},
		{
			Protocol:            "tsa",
			FeatureIDs:          []string{"F51"},
			RoutePatterns:       protocolAuthzRoutePatterns("tsa"),
			PublicRationale:     "RFC 3161 timestamping is a public protocol: the request contains a hashed message imprint, not tenant data, and the signer-held TSA key only returns an auditable timestamp token.",
			TenantMapping:       "tenant is fixed by protocols.tsa.tenant_id or the server default tenant when the TSA authority is built.",
			PrincipalMapping:    "principal is the timestamp request nonce/message-imprint tuple; request headers are not trusted as identity.",
			EnablementAuthority: "operator/admin configuration enables the mount; any future runtime toggle must require " + string(authz.CertsIssue) + ".",
			DefaultDenyTest:     "internal/tsa/http_test.go",
		},
		{
			Protocol:            "spiffe",
			FeatureIDs:          []string{"F24", "F25", "F30"},
			RoutePatterns:       protocolAuthzRoutePatterns("spiffe"),
			PublicRationale:     "The SPIFFE Workload API is local UDS-only and requires workload.spiffe.io:true metadata; caller selectors, not bearer headers, decide which registered workload identity can receive an SVID.",
			TenantMapping:       "tenant is fixed by protocols.spiffe.tenant_id or the server default tenant in the Workload API server config.",
			PrincipalMapping:    "principal is the local UDS caller selector set matched against registration entries and the requested SPIFFE ID/audience.",
			EnablementAuthority: "operator/admin configuration enables the socket; any future runtime registration toggle must require " + string(authz.CertsIssue) + ".",
			DefaultDenyTest:     "internal/server/protocols_served_spiffe_ssh_test.go",
		},
	}
}

func protocolHTTPMountPatterns(protocol string) []string {
	switch protocol {
	case "acme":
		return []string{"/directory", "/acme/"}
	case "est":
		return []string{"/.well-known/est/"}
	case "scep":
		return []string{"/scep", "/scep/"}
	case "cmp":
		return []string{"/cmp"}
	case "ssh":
		return []string{"/ssh/"}
	case "tsa":
		return []string{"/tsa"}
	default:
		return nil
	}
}

// protocolHTTPNamespacePatterns returns every path shape owned by an HTTP machine
// protocol, including child paths that are not valid operations. The root mux
// reserves this larger set before the browser SPA fallback so a disabled or
// misspelled protocol URL can never become a successful console document.
func protocolHTTPNamespacePatterns(protocol string) []string {
	switch protocol {
	case "acme":
		return []string{"/directory", "/directory/", "/acme/"}
	case "est":
		return []string{"/.well-known/est/"}
	case "scep":
		return []string{"/scep", "/scep/"}
	case "cmp":
		return []string{"/cmp", "/cmp/"}
	case "ssh":
		return []string{"/ssh/"}
	case "tsa":
		return []string{"/tsa", "/tsa/"}
	default:
		return nil
	}
}

func protocolAuthzRoutePatterns(protocol string) []string {
	switch protocol {
	case "acme":
		return []string{
			"GET /directory",
			"GET /acme/renewal-info/{certid}",
			"GET /acme/new-nonce",
			"HEAD /acme/new-nonce",
			"POST /acme/new-account",
			"POST /acme/new-order",
			"POST /acme/authz/{id}",
			"POST /acme/chal/{id}",
			"POST /acme/order/{id}",
			"POST /acme/order/{id}/finalize",
			"POST /acme/cert/{id}",
			"POST /acme/key-change",
			"POST /acme/revoke-cert",
		}
	case "est":
		return []string{
			"GET /.well-known/est/cacerts",
			"GET /.well-known/est/csrattrs",
			"POST /.well-known/est/simpleenroll",
			"POST /.well-known/est/simplereenroll",
		}
	case "scep":
		return []string{
			"GET /scep?operation=GetCACaps",
			"GET /scep?operation=GetCACert",
			"GET /scep?operation=PKIOperation",
			"POST /scep?operation=PKIOperation",
			"GET /scep/pkiclient.exe?operation=GetCACaps",
			"GET /scep/pkiclient.exe?operation=GetCACert",
			"GET /scep/pkiclient.exe?operation=PKIOperation",
			"POST /scep/pkiclient.exe?operation=PKIOperation",
		}
	case "cmp":
		return []string{"POST /cmp"}
	case "ssh":
		return []string{
			"GET /ssh/ca",
			"POST /ssh/issue/user",
			"POST /ssh/issue/host",
			"GET /ssh/krl",
			"POST /ssh/revoke",
		}
	case "tsa":
		return []string{"POST /tsa"}
	case "spiffe":
		return []string{
			"gRPC UDS " + workloadpb.SpiffeWorkloadAPI_FetchX509SVID_FullMethodName,
			"gRPC UDS " + workloadpb.SpiffeWorkloadAPI_FetchX509Bundles_FullMethodName,
			"gRPC UDS " + workloadpb.SpiffeWorkloadAPI_FetchJWTSVID_FullMethodName,
			"gRPC UDS " + workloadpb.SpiffeWorkloadAPI_FetchJWTBundles_FullMethodName,
			"gRPC UDS " + workloadpb.SpiffeWorkloadAPI_ValidateJWTSVID_FullMethodName,
		}
	default:
		return nil
	}
}
