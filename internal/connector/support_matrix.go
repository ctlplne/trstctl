// SPDX-License-Identifier: MPL-2.0

package connector

import "sort"

// What each E1 connector family is actually known to work against (epic E3).
//
// The obvious shape for this surface is a firmware compatibility table — "F5
// BIG-IP 15.1–17.1 supported" — and that shape is the reason it is not what this
// is. A version range is a claim about hardware somebody ran, and this
// repository has run none. Publishing one would be marketing wearing the
// clothes of evidence, and an operator would reasonably plan a migration around
// it.
//
// What this repository can attest is narrower and true: which API or local
// execution contract each connector implements, which operations its tests
// exercise, and what is explicitly not covered. DeviceProven separately tells
// callers whether that test is a faithful management-API double. Keeping those
// facts separate prevents an ordinary connector unit test from being presented
// as appliance proof.
//
// The distinction matters most when it disappoints. An operator asking "will
// this work against our 16.1 boxes" deserves "we implement iControl REST and
// exercise these three calls against a double of it; nobody has run it against
// 16.1 hardware" rather than a version number that was typed rather than
// measured.

// SupportRow is one family's attested support surface.
type SupportRow struct {
	// Family is the connector name.
	Family string
	// APIContract names the management API this connector speaks, in the
	// vendor's own terms, so an operator can match it to their device's docs.
	APIContract string
	// ProvenOperations are the operations exercised against a faithful double
	// of that API in this repository's test suite. Read from the code that
	// exists, not from intent.
	ProvenOperations []string
	// KnownLimits are the things this family cannot do, stated plainly. A limit
	// here is a property of the device's API, not a backlog item — the
	// difference matters, because one is a constraint to design around and the
	// other is a wait.
	KnownLimits []string
	// HardwareTested is whether any physical or vendor-hosted device has been
	// run against this connector in CI.
	//
	// False for every family today, and it is a field rather than a footnote so
	// the surface cannot quietly imply otherwise. When a family gains a real
	// device in CI this flips and the docs page regenerates.
	HardwareTested bool
}

// supportMatrix is the attested surface, one row per accepted E1 family. The
// exact-denominator guard in support_matrix_test.go cross-checks this table
// against E1Families, so a family cannot vanish from the published matrix just
// because its relay migration has not been implemented.
var supportMatrix = []SupportRow{
	{
		Family:      "a10",
		APIContract: "A10 Thunder aXAPI v3",
		ProvenOperations: []string{
			"deploy: upload certificate and key, then bind to the client-SSL template",
			"rollback: re-bind the template to a previously installed certificate",
		},
		KnownLimits: []string{
			"partition-aware deploys are not modelled; the double serves a single partition",
		},
	},
	{
		Family:      "aws-acm",
		APIContract: "AWS Certificate Manager ImportCertificate (AWS JSON 1.1, SigV4)",
		ProvenOperations: []string{
			"deploy: import an externally issued certificate and key into a new or existing ACM ARN",
			"request contract: sign the exact AWS JSON 1.1 request with SigV4 through the connector sandbox",
		},
		KnownLimits: []string{
			"no rollback: the connector does not retain and re-import a predecessor ACM version",
			"no E1 relay migration: execution remains in the control plane with no relay constructor, " +
				"relay proof, or control-plane refusal",
		},
	},
	{
		Family:      "azure-keyvault",
		APIContract: "Azure Key Vault Certificates REST import API v7.4",
		ProvenOperations: []string{
			"deploy: import a PEM certificate and key as a new version of a named vault certificate",
			"authentication contract: acquire and wipe an Entra ID bearer token per operation",
		},
		KnownLimits: []string{
			"no rollback: the connector does not select and restore a predecessor certificate version",
			"no E1 relay migration: execution remains in the control plane with no relay constructor, " +
				"relay proof, or control-plane refusal",
		},
	},
	{
		Family:      "cisco",
		APIContract: "Cisco management certificate-import API (HTTP Basic, JSON)",
		ProvenOperations: []string{
			"deploy: import certificate and key under a named entry",
		},
		KnownLimits: []string{
			"no rollback: the API's only certificate call both uploads and installs, with no way " +
				"to address an already-installed object, so a re-bind is not expressible",
			"the device's own trustpoint lifecycle is not driven; the connector imports and stops",
		},
	},
	{
		Family:      "envoy",
		APIContract: "Envoy SDS management HTTP resource (v3 Secret payload)",
		ProvenOperations: []string{
			"deploy: read the current SDS secret and push the desired v3 Secret only when it differs",
			"compensation: re-push the previous SDS secret when an update fails after current-state read",
		},
		KnownLimits: []string{
			"the shipped target is a co-resident loopback SDS endpoint and executes on a host agent",
			"no E1 network-relay migration: there is no network-relay constructor, relay proof, or E1 refusal",
		},
	},
	{
		Family:      "f5",
		APIContract: "F5 BIG-IP iControl REST",
		ProvenOperations: []string{
			"deploy: upload, crypto-install, and bind to a Client SSL profile",
			"rollback: re-bind the profile to a previously installed crypto object",
			"readback: report the certificate the Client SSL profile is bound to",
			"HA-peer sync: deploy, rollback, and readback reach BOTH peers when a peer " +
				"endpoint is configured — a pair whose certificate stores do not replicate " +
				"is treated as one target, and a readback reports serving only when both " +
				"peers are bound to the deployed certificate",
		},
		KnownLimits: []string{
			"the HA peer shares the pair's synced admin credential; a pair with per-peer " +
				"credentials is not modelled",
			"partition (folder) routing is not modelled beyond the default",
		},
	},
	{
		Family:      "fortigate",
		APIContract: "FortiOS CMDB REST (vpn.certificate/local)",
		ProvenOperations: []string{
			"deploy: upsert the local-certificate object carrying certificate and key",
		},
		KnownLimits: []string{
			"no rollback: the local-certificate object holds the material rather than referencing " +
				"it, and the deploy replaces its contents in place, so no predecessor survives to " +
				"bind back to",
			"VDOM routing is not modelled; the double serves the root VDOM",
		},
	},
	{
		Family:      "gcp-certificate-manager",
		APIContract: "Google Cloud Certificate Manager certificates.patch REST API",
		ProvenOperations: []string{
			"deploy: patch a self-managed certificate and private key with updateMask=self_managed",
			"completion: poll the returned long-running operation until it succeeds or reaches a bounded failure",
		},
		KnownLimits: []string{
			"no rollback: the connector does not retain and restore a predecessor Certificate Manager resource",
			"no E1 relay migration: execution remains in the control plane with no relay constructor, " +
				"relay proof, or control-plane refusal",
		},
	},
	{
		Family:      "kemp",
		APIContract: "Kemp LoadMaster RESTful API",
		ProvenOperations: []string{
			"deploy: upload the certificate set and bind it to a virtual service",
			"rollback: re-bind the virtual service to a previously installed certificate",
		},
		KnownLimits: []string{
			"certificate-set naming collisions across virtual services are not modelled",
		},
	},
	{
		Family:      "mysql",
		APIContract: "host-local MySQL TLS files plus allowlisted mysqladmin reload",
		ProvenOperations: []string{
			"deploy: replace the configured certificate and key files and run the exact allowlisted reload",
			"rollback: restore the encrypted predecessor bundle on the exact host agent, reload, and reverify",
		},
		KnownLimits: []string{
			"the connector proof uses sandboxed filesystem/process operations, not a live MySQL server",
			"no E1 network-relay migration: execution is host-agent local with no network-relay constructor, " +
				"relay proof, or E1 refusal",
		},
	},
	{
		Family:      "netscaler",
		APIContract: "Citrix NetScaler NITRO REST",
		ProvenOperations: []string{
			"deploy: upload, create the certkey, and bind it to the SSL virtual server",
			"rollback: re-bind the virtual server to a previously created certkey",
		},
		KnownLimits: []string{
			"cluster and HA-pair propagation is not performed; one NSIP is addressed",
		},
	},
	{
		Family:      "paloalto",
		APIContract: "PAN-OS XML API (certificate import)",
		ProvenOperations: []string{
			"deploy: import the certificate and the private key as separate calls, in order",
		},
		KnownLimits: []string{
			"no rollback: import both uploads and installs, and the API exposes no call that " +
				"re-points an installed certificate, so a re-bind is not expressible",
			"no commit is issued; a candidate configuration is left for the operator's own commit " +
				"policy, which is deliberate — an automatic commit would push unrelated pending " +
				"changes somebody else staged",
		},
	},
	{
		Family:      "postgresql",
		APIContract: "host-local PostgreSQL TLS files plus allowlisted pg_ctl reload",
		ProvenOperations: []string{
			"deploy: replace the configured certificate and key files and run the exact allowlisted reload",
			"rollback: restore the encrypted predecessor bundle on the exact host agent, reload, and reverify",
		},
		KnownLimits: []string{
			"the connector proof uses sandboxed filesystem/process operations, not a live PostgreSQL server",
			"no E1 network-relay migration: execution is host-agent local with no network-relay constructor, " +
				"relay proof, or E1 refusal",
		},
	},
}

// SupportMatrix returns the attested support rows, ordered by family.
func SupportMatrix() []SupportRow {
	out := append([]SupportRow(nil), supportMatrix...)
	sort.Slice(out, func(i, j int) bool { return out[i].Family < out[j].Family })
	return out
}

// SupportRowFor returns one family's row.
func SupportRowFor(family string) (SupportRow, bool) {
	for _, row := range supportMatrix {
		if row.Family == family {
			return row, true
		}
	}
	return SupportRow{}, false
}
