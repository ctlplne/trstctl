// SPDX-License-Identifier: BUSL-1.1

package docs

import (
	"strings"
	"testing"
)

// The build list's doc fixes (2026-10-19, owner note 2026-11-10): where two
// statements in limitations.md disagreed, the code decides which is true, and
// these guards keep the statement the code contradicts from coming back while
// the code stands. Each guard anchors on the code it follows, so a change to
// that code fails here and sends the reader back to the doc.

// flatDoc reads a doc with every run of whitespace, line breaks and list
// indentation included, collapsed to one space, so a guarded phrase matches
// however the paragraph is wrapped.
func flatDoc(t *testing.T, rel string) string {
	t.Helper()
	return strings.Join(strings.Fields(read(t, rel)), " ")
}

func requireDocAnchor(t *testing.T, name, body string, needles ...string) {
	t.Helper()
	for _, needle := range needles {
		if !strings.Contains(body, needle) {
			t.Fatalf("%s no longer contains %q; revisit this doc guard and the limitations text it protects", name, needle)
		}
	}
}

// DF-1: the private CA hierarchy flows past root/intermediate/leaf issuance are
// served, so the bullet that lists them may not call them remaining; and a CA
// the served signer mints is ECDSA P-256 or an ML-DSA parameter set (an
// imported one may carry any key the platform verifies, ML-DSA included), so
// the doc may not say every minted CA stays P-256.
func TestLimitationsCAHierarchyFlowsAreServed(t *testing.T) {
	requireDocAnchor(t, "internal/api/routes_ca_hierarchy.go", read(t, "../internal/api/routes_ca_hierarchy.go"),
		`path: "/api/v1/ca/authorities/{id}/rotate"`,
		`path: "/api/v1/ca/authorities/{id}/rekey"`,
		`path: "/api/v1/ca/authorities/{id}/cross-sign"`,
		`path: "/api/v1/ca/authorities/{id}/offline-rekey"`,
		`path: "/api/v1/ca/authorities/{id}/offline-cross-signs"`,
		`path: "/api/v1/ca/offline-rekeys/{id}"`,
		`path: "/api/v1/ca/discovery"`,
	)
	requireDocAnchor(t, "internal/crypto/hierarchy_ca.go", read(t, "../internal/crypto/hierarchy_ca.go"),
		`case "ml-dsa-65":`,
		`"rsa-4096", "ml-dsa-44", "ml-dsa-65", "ml-dsa-87"}`,
	)
	limitations := flatDoc(t, "limitations.md")
	for _, stale := range []string{"Remaining private CA hierarchy operator flows", "CAs the served signer mints stay ECDSA P-256"} {
		if strings.Contains(limitations, stale) {
			t.Errorf("limitations.md still says %q, but the code serves it otherwise", stale)
		}
	}
	for _, want := range []string{
		"Private CA hierarchy operator flows beyond root/intermediate/leaf issuance are served",
		"Ed25519, RSA-2048/3072/4096 and ML-DSA-44/65/87",
		"A CA the served signer mints is ECDSA P-256, or ML-DSA-44/65/87",
	} {
		if !strings.Contains(limitations, want) {
			t.Errorf("limitations.md should state the served CA hierarchy flows and minted key algorithms (missing %q)", want)
		}
	}
}

// DF-2: the AD CS CA-database ingest is served (a relay's certutil rows, or a
// relay read the control plane queues, become per-CA disposition counts), so
// limitations.md may not say that nothing calls it. What stays true and must
// be said: the counts are not inventory rows, nothing collects on a schedule,
// and XREC has no AD CS source.
func TestLimitationsADCSDatabaseIngestIsServed(t *testing.T) {
	requireDocAnchor(t, "internal/api/routes_platform.go", read(t, "../internal/api/routes_platform.go"),
		`path: "/api/v1/adcs/ca-database/ingest"`,
		`path: "/api/v1/adcs/ca-database/collect"`,
	)
	limitations := flatDoc(t, "limitations.md")
	for _, stale := range []string{"NOTHING YET CALLS THE DATABASE INGESTION", "no scheduled or served ingest"} {
		if strings.Contains(limitations, stale) {
			t.Errorf("limitations.md still says %q, but the CA-database ingest and the relay read are served", stale)
		}
	}
	for _, want := range []string{
		"the ingest that runs it is served",
		"per-disposition counts per CA, not inventory rows",
		"XREC has no AD CS source",
	} {
		if !strings.Contains(limitations, want) {
			t.Errorf("limitations.md should say what the served CA-database ingest does and does not do (missing %q)", want)
		}
	}
}

// DF-3: a pure ML-DSA CSR is carried by CMP (58c0c54c4) and by SCEP when the
// client's CMS transport identity is RSA (55264a09d): both protocol mounts
// verify and inspect through the platform's PQC-aware seams, so the doc may
// not keep saying SCEP cannot by protocol. What SCEP cannot do is deliver its
// enveloped reply to a signature-only transport key.
func TestLimitationsPureMLDSAOverCMPAndSCEPAgree(t *testing.T) {
	mounts := read(t, "../internal/server/protocol_mounts.go")
	requireDocAnchor(t, "internal/server/protocol_mounts.go", mounts, "scepSrv := scep.New(scep.Config{", "issuer.verifyCSR", "issuer.inspectCSRInfo")
	requireDocAnchor(t, "internal/protocols/scep/mldsa_csr_test.go", read(t, "../internal/protocols/scep/mldsa_csr_test.go"), "ML-DSA")
	limitations := flatDoc(t, "limitations.md")
	for _, stale := range []string{"SCEP cannot by protocol", "SCEP and CMP still verify CSRs with the core parser"} {
		if strings.Contains(limitations, stale) {
			t.Errorf("limitations.md still says %q, but SCEP and CMP verify a pure ML-DSA CSR through the PQC-aware seam", stale)
		}
	}
	for _, want := range []string{
		"CMP consults the same PQC parser for its carried CSR",
		"and SCEP does too when the client's CMS transport identity is RSA",
		"a pure ML-DSA PKCS#10 enrolls when the client's CMS transport identity",
	} {
		if !strings.Contains(limitations, want) {
			t.Errorf("limitations.md should state how CMP and SCEP carry a pure ML-DSA CSR (missing %q)", want)
		}
	}
}

// DF-5: the gcp-iam and azure-entra lease providers had no proof status. Their
// proof is a contract test against stand-ins of the IAM keys API and Microsoft
// Graph (create, then delete; add a password, then remove it; a second revoke
// is a no-op), so the doc says that and that a live proof needs an account.
func TestLimitationsGCPAndEntraLeaseProvidersStateTheirProof(t *testing.T) {
	requireDocAnchor(t, "internal/dynsecret/providers_real_test.go", read(t, "../internal/dynsecret/providers_real_test.go"),
		`{"gcp-iam", gcpBackend`, `{"azure-entra", azureBackend`, "double revoke must be idempotent")
	requireDocAnchor(t, "internal/dynsecret/providers_real.go", read(t, "../internal/dynsecret/providers_real.go"),
		"/keys:upload", "/addPassword", "/removePassword")
	limitations := flatDoc(t, "limitations.md")
	for _, want := range []string{
		"The `gcp-iam` and `azure-entra` lease providers are contract-tested adapters",
		"A live proof needs a Google Cloud project or an Entra tenant",
	} {
		if !strings.Contains(limitations, want) {
			t.Errorf("limitations.md should state the gcp-iam and azure-entra lease providers' proof (missing %q)", want)
		}
	}
}

// DF-6: the DNS-01 preflight reads the challenge TXT record from live DNS
// through the control plane's resolver unless the caller supplies its own
// observation (labeled caller_supplied), so the doc may not say it only
// evaluates values the caller supplies. What stays true: neither the preflight
// nor the qualification run gates a challenge before the authority validates.
func TestLimitationsDNS01PreflightReadsLiveDNS(t *testing.T) {
	requireDocAnchor(t, "internal/api/acme_dns01.go", read(t, "../internal/api/acme_dns01.go"),
		`out.Source = "caller_supplied"`, `out.Source = "live_dns"`, "a.acmeTXTResolver.LookupTXT(")
	requireDocAnchor(t, "internal/server/server.go", read(t, "../internal/server/server.go"),
		"api.WithACMEDNS01TXTResolver(net.DefaultResolver)")
	limitations := flatDoc(t, "limitations.md")
	if stale := "evaluates TXT values the caller supplies rather than querying DNS itself"; strings.Contains(limitations, stale) {
		t.Errorf("limitations.md still says the preflight %q, but it reads live DNS unless the caller supplies values", stale)
	}
	for _, want := range []string{
		"propagation (read from live DNS unless the caller supplies its own observation",
		"reads the challenge TXT record from live DNS through the control plane's resolver",
		"neither gates a challenge before the authority validates",
	} {
		if !strings.Contains(limitations, want) {
			t.Errorf("limitations.md should describe the DNS-01 preflight the way it runs (missing %q)", want)
		}
	}
}

// DOC-O1: ClickHouse is an enforcing protocol for command rules (A262), whose
// rules name its operation classes and no A275 risk category; so the doc may
// not call ClickHouse rules unbuilt, and it says ClickHouse has no categories.
func TestLimitationsClickHouseRulesAreBuiltWithoutCategories(t *testing.T) {
	rules := read(t, "../internal/accessrules/rules.go")
	requireDocAnchor(t, "internal/accessrules/rules.go", rules,
		`r.Protocol != "clickhouse"`,
		"if protocol == \"clickhouse\" {\n\t\treturn slices.Clone(clickhouseOperationNames)\n\t}",
	)
	requireDocAnchor(t, "internal/server/pam_command_clickhouse_served_test.go", read(t, "../internal/server/pam_command_clickhouse_served_test.go"),
		"func TestServedClickHouseCommandRuleBlocksAndRecordsA262(",
		"func TestServedClickHouseCommandReviewWaitsAndCancelsA262(",
	)
	limitations := flatDoc(t, "limitations.md")
	if strings.Contains(limitations, "ClickHouse rules remain unbuilt") {
		t.Error("limitations.md still says ClickHouse rules remain unbuilt, but ClickHouse is an enforcing protocol with served proofs")
	}
	for _, want := range []string{
		"ClickHouse rules match the operation class of each statement sent over ClickHouse's HTTP interface",
		"`TestServedClickHouseCommandRuleBlocksAndRecordsA262`",
		"`TestServedClickHouseCommandReviewWaitsAndCancelsA262`",
		"Redis, MongoDB, ClickHouse and network devices have no categories",
	} {
		if !strings.Contains(limitations, want) {
			t.Errorf("limitations.md no longer says %q", want)
		}
	}
}

// DOC-O2: a target whose host renewals are refused as another job's, because
// a signed record from a rolled-back successor holds its slot, is freed by the
// stuck host renewal runbook. The guard anchors the runbook's record name,
// directory and symptom on the agent's code, and on the relay test that
// proves the removal frees the slot.
func TestStuckHostRenewalRunbookMatchesTheAgent(t *testing.T) {
	requireDocAnchor(t, "internal/agent/relay/host_renew_pending.go", read(t, "../internal/agent/relay/host_renew_pending.go"),
		`trstcrypto.SHA256Hex([]byte(s.tenantID + "\x00" + connectorName + "\x00" + targetID))`,
		`filepath.Join(s.root, name+".renew")`,
		`p.Fingerprint != "" || len(p.CertPEM) != 0`,
	)
	requireDocAnchor(t, "internal/agent/relay/hostrenew.go", read(t, "../internal/agent/relay/hostrenew.go"),
		"the encrypted pending host key belongs to another job or cannot be read",
	)
	requireDocAnchor(t, "cmd/trstctl-agent/main.go", read(t, "../cmd/trstctl-agent/main.go"),
		`filepath.Join(filepath.Dir(o.keyPath), "host-rollbacks")`,
		`"trstctl-agent: encrypted host rollback state enabled at %s\n"`,
	)
	requireDocAnchor(t, "internal/agent/relay/host_renew_manual_release_test.go", read(t, "../internal/agent/relay/host_renew_manual_release_test.go"),
		"func TestTheRunbooksManualReleaseFreesASignedPendingHostKeyDOCO2(",
	)
	runbook := flatDoc(t, "runbooks/stuck-host-renewal.md")
	for _, want := range []string{
		"the encrypted pending host key belongs to another job or cannot be read",
		`printf '%s\0%s\0%s' "$TENANT_ID" "$CONNECTOR" "$TARGET_ID" | sha256sum`,
		`"$HOST_ROLLBACK_DIR/$NAME.renew"`,
		"`host-rollbacks` beside the file its `--key` flag names",
		"trstctl-agent: encrypted host rollback state enabled at <directory>",
		"Remove only that one file.",
	} {
		if !strings.Contains(runbook, want) {
			t.Errorf("the stuck host renewal runbook no longer says %q", want)
		}
	}
	if !strings.Contains(read(t, "../mkdocs.yml"), "runbooks/stuck-host-renewal.md") {
		t.Error("mkdocs.yml does not list the stuck host renewal runbook")
	}
}
