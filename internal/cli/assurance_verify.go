// SPDX-License-Identifier: BUSL-1.1

package cli

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"trstctl.com/trstctl/internal/assurance"
	"trstctl.com/trstctl/internal/crypto/jose"
)

// certificates verify-assurance-record re-checks a saved credential assurance
// record (A179) on this machine against an audit JWK set the operator pinned
// separately. Nothing is sent anywhere.

func certificateVerifyAssuranceRecordUsage(w io.Writer) {
	_, _ = fmt.Fprintln(w, "Usage: trstctl certificates verify-assurance-record --record <file> --audit-jwks <file>")
	_, _ = fmt.Fprintln(w, "\nVerifies a saved 'certificates assurance-record' response offline: the signature over the record, under the")
	_, _ = fmt.Fprintln(w, "credential-assurance-record artifact domain, with keys from --audit-jwks (an audit JWK set you pinned")
	_, _ = fmt.Fprintln(w, "separately; the file's own public_jwks is never trusted), and that the record beside the signature is exactly")
	_, _ = fmt.Fprintln(w, "the signed record. Prints which stages were independently observed. Nothing is sent anywhere.")
	_, _ = fmt.Fprintln(w, "\nExample: trstctl certificates verify-assurance-record --record record.json --audit-jwks audit-jwks.json")
}

func runCertificateVerifyAssuranceRecord(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("certificates verify-assurance-record", flag.ContinueOnError)
	fs.SetOutput(stderr)
	recordFile := fs.String("record", "", "JSON from 'certificates assurance-record'")
	jwksFile := fs.String("audit-jwks", "", "the audit evidence public JWK set you pinned separately")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *recordFile == "" || *jwksFile == "" {
		_, _ = fmt.Fprintln(stderr, "error: --record and --audit-jwks are required")
		return 2
	}
	document, err := os.ReadFile(*recordFile) // #nosec G304 -- operator-named local file (CWE-22)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: read record: %v\n", err)
		return 1
	}
	jwksDoc, err := os.ReadFile(*jwksFile) // #nosec G304 -- operator-named local file (CWE-22)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: read audit JWK set: %v\n", err)
		return 1
	}
	keys, err := jose.ParseJWKSet(jwksDoc)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: parse audit JWK set: %v\n", err)
		return 1
	}
	verified, err := assurance.Verify(document, keys)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	r := verified.Record
	_, _ = fmt.Fprintf(stdout, "verified: assurance record for certificate %s (%s)\n", r.Credential.CertificateID, r.Credential.Fingerprint)
	_, _ = fmt.Fprintf(stdout, "  signed by key %s, record %s, generated %s\n", verified.KeyID, verified.RecordSHA256, r.GeneratedAt.UTC().Format("2006-01-02T15:04:05Z"))
	_, _ = fmt.Fprintf(stdout, "  independently observed: %s\n", stageList(r.IndependentlyObserved))
	_, _ = fmt.Fprintf(stdout, "  recorded by trstctl only: %s\n", stageList(r.RecordedOnly))
	_, _ = fmt.Fprintf(stdout, "  no evidence: %s\n", stageList(r.Absent))
	return 0
}

func stageList(stages []string) string {
	if len(stages) == 0 {
		return "none"
	}
	return strings.Join(stages, ", ")
}
