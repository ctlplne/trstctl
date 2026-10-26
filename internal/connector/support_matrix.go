// SPDX-License-Identifier: BUSL-1.1

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
			"appliance key (key_generation=appliance): pki create makes an ECDSA P-256 key file and a CSR " +
				"file named for the renewal job, the signed certificate is uploaded and bound to the template " +
				"with that key, and a rollback re-binds a predecessor with its own key file, which is never read",
		},
		KnownLimits: []string{
			"partition-aware deploys are not modeled; the double serves a single partition",
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
			"no rollback: ACM re-imports in place under one certificate ARN and keeps no previous " +
				"version, so there is no installed predecessor to re-bind and no readback; restoring one " +
				"would mean re-uploading a key the control plane no longer holds",
			"E1 architecture exception: an enrolled network relay executes imports and the control " +
				"plane's egress-guarded client remains the executor where no relay is enrolled; " +
				"rollback and readback are not expressible, so the family keeps E1 open",
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
			"no rollback: Key Vault keeps every imported version but serves the newest to consumers " +
				"that read by name and exposes no call that makes an older version current; " +
				"re-pointing consumers at a version is outside this connector, and there is no readback " +
				"of what a consumer serves",
			"E1 architecture exception: an enrolled network relay executes imports and the control " +
				"plane's egress-guarded client remains the executor where no relay is enrolled; " +
				"rollback and readback are not expressible, so the family keeps E1 open",
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
			"relay deploy: a target declaring vantage network is driven by the network relay through the " +
				"same connector (targets with vantage network only)",
		},
		KnownLimits: []string{
			"the default target is a co-resident loopback SDS endpoint and executes on a host agent; a target " +
				"that declares vantage network is driven by a network relay against a remote SDS endpoint",
			"no rollback: SDS replaces the secret in place, so no predecessor object survives to re-bind",
			"no E1 network-relay migration as a family: the relay path exists only for targets that declare " +
				"it, and no family-wide refusal or readback exists",
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
			"appliance key (key_generation=appliance, single BIG-IP): the BIG-IP generates an ECDSA P-256 " +
				"key and CSR named for the renewal job, the signed certificate is installed and the Client SSL " +
				"profile bound to it with that key, and a rollback re-binds a predecessor with its own key",
		},
		KnownLimits: []string{
			"an HA pair keeps control-plane keys: each BIG-IP keeps its own crypto objects, so each peer " +
				"would generate a different key for one certificate",
			"the HA peer shares the pair's synced admin credential; a pair with per-peer " +
				"credentials is not modeled",
			"partition (folder) routing is not modeled beyond the default",
		},
	},
	{
		Family:      "fortigate",
		APIContract: "FortiOS CMDB REST (vpn.certificate/local, system/global, vpn.ssl/settings)",
		ProvenOperations: []string{
			"deploy: upsert the local-certificate object carrying certificate and key; with bind_to " +
				"(admin or ssl-vpn) the object is fingerprint-named and the admin-server-cert or " +
				"SSL-VPN servercert setting is pointed at it",
			"rollback: re-point the bound setting at a previously installed fingerprint-named " +
				"local certificate (targets with bind_to only)",
			"readback: report the local certificate the bound setting points at (targets with " +
				"bind_to only)",
		},
		KnownLimits: []string{
			"a target without bind_to deploys in place under the target name, so no predecessor " +
				"survives and its rollback is refused as not configured rather than reported done",
			"FortiOS caps a local-certificate name at 35 characters; a fingerprint-named deploy " +
				"needs a target name of 22 characters or fewer",
			"VDOM routing is not modeled; the double serves the root VDOM",
		},
	},
	{
		Family:      "gcp-certificate-manager",
		APIContract: "Google Cloud Certificate Manager certificates and certificateMapEntries REST API",
		ProvenOperations: []string{
			"deploy: patch a self-managed certificate and private key with updateMask=self_managed; with " +
				"certificate_map_entry the deploy instead creates a fingerprint-named certificate and points " +
				"the map entry at it, leaving the predecessor in the project",
			"rollback: re-point the certificate map entry at a previously created fingerprint-named " +
				"certificate, uploading nothing (targets with certificate_map_entry only); a predecessor the " +
				"project no longer holds fails rather than reporting success",
			"readback: report the certificate the map entry points at (targets with certificate_map_entry only)",
			"completion: poll the returned long-running operation until it succeeds or reaches a bounded failure",
		},
		KnownLimits: []string{
			"a target without certificate_map_entry patches the target-named certificate in place, so no " +
				"predecessor survives and its rollback is refused as not configured",
			"objects accumulate one certificate per deploy on a map-entry target and nothing prunes them",
			"E1 migrated: an enrolled network relay executes deploys, re-binds and readbacks and the " +
				"control plane refuses the deploy while a relay is enrolled; where none is enrolled the " +
				"control plane's egress-guarded client executes them, including the re-bind rollback",
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
			"certificate-set naming collisions across virtual services are not modeled",
		},
	},
	{
		Family:      "mysql",
		APIContract: "host-local MySQL TLS files plus a fixed mysql-tls-reload action for ALTER INSTANCE RELOAD TLS",
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
			"appliance key (key_generation=appliance): the NetScaler generates an ECDSA P-256 key file and a " +
				"CSR named for the renewal job, the certkey binds the signed certificate to that key, and a " +
				"rollback re-binds a predecessor with its own key file, which is never read",
		},
		KnownLimits: []string{
			"cluster and HA-pair propagation is not performed; one NSIP is addressed",
		},
	},
	{
		Family:      "paloalto",
		APIContract: "PAN-OS XML API (certificate import, config set, partial commit)",
		ProvenOperations: []string{
			"deploy: import the certificate and the private key as separate calls, in order; with " +
				"ssl_tls_profile the objects are fingerprint-named, the shared SSL/TLS service " +
				"profile is set to the new certificate and a partial commit scoped to commit_admin " +
				"pushes only that administrator's changes",
			"rollback: set the SSL/TLS service profile back to a previously imported " +
				"fingerprint-named certificate and partial-commit it (targets with ssl_tls_profile only)",
			"readback: report the certificate the SSL/TLS service profile is set to (targets with " +
				"ssl_tls_profile only)",
			"appliance key (key_generation=appliance, targets with ssl_tls_profile): the firewall generates an " +
				"ECDSA P-256 key and a CSR for an external authority in a certificate object named for the " +
				"renewal job, the signed certificate is imported into it and the profile set to it in a partial " +
				"commit; readback exports the bound certificate, never its key, and a rollback sets the profile " +
				"back to a predecessor's object after checking it holds that certificate",
		},
		KnownLimits: []string{
			"a target without ssl_tls_profile imports in place under the target name and issues no " +
				"commit, leaving the candidate configuration to the operator's own commit policy; " +
				"its rollback is refused as not configured rather than reported done",
			"the partial commit is scoped to commit_admin; other administrators' staged changes " +
				"are never pushed, and a profile outside the shared location is not modeled",
			"PAN-OS keeps no CSR once the certificate for it is imported, so an appliance-key renewal " +
				"reclaimed after that import stops and says so instead of requesting a second signature",
		},
	},
	{
		Family:      "postgresql",
		APIContract: "host-local PostgreSQL TLS files plus allowlisted pg_ctl reload",
		ProvenOperations: []string{
			"deploy: replace the configured certificate and key files and run the exact allowlisted reload",
			"live reload: a bundled PostgreSQL server started with ssl=on serves the renewed certificate " +
				"after the connector's pg_ctl reload, observed by a real SSLRequest handshake",
			"rollback: restore the encrypted predecessor bundle on the exact host agent, reload, and reverify",
		},
		KnownLimits: []string{
			"the live proof runs the pinned bundled PostgreSQL runtime inside the repository tests; no " +
				"external or customer PostgreSQL version was tested",
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
