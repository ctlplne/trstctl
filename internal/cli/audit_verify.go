// SPDX-License-Identifier: BUSL-1.1

package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"trstctl.com/trstctl/internal/auditanchor"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/jose"
)

const auditVerifyTrustFileLimit = 1 << 20

func runAuditVerify(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("trstctl audit verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	artifactPath := fs.String("artifact", "-", "saved audit export path, or - for stdin")
	formatName := fs.String("format", string(auditanchor.FormatAuto), "artifact format: auto, jws, ndjson, csv, splunk-hec, or sentinel")
	auditJWKSPath := fs.String("audit-jwks", "", "separately pinned audit signing public JWK set (required for jws)")
	tsaRootPath := fs.String("tsa-root", "", "separately pinned TSA root certificate in PEM or DER form")
	maxAnchorDelay := fs.Duration("max-anchor-delay", 0, "optional maximum delay between the newest record and its authority timestamp")
	fs.Usage = func() { auditVerifyUsage(stderr) }
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if len(fs.Args()) != 0 {
		_, _ = fmt.Fprintln(stderr, "error: audit verify accepts flags only; pass the file with --artifact")
		return 2
	}
	if *maxAnchorDelay < 0 {
		_, _ = fmt.Fprintln(stderr, "error: --max-anchor-delay cannot be negative")
		return 2
	}
	if strings.TrimSpace(*tsaRootPath) == "" {
		_, _ = fmt.Fprintln(stderr, "error: --tsa-root is required; never trust a TSA root supplied only by the artifact")
		return 2
	}

	format := auditanchor.Format(strings.ToLower(strings.TrimSpace(*formatName)))
	if format != auditanchor.FormatAuto {
		parsed, err := auditanchor.ParseFormat(string(format))
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "error: %v\n", err)
			return 2
		}
		format = parsed
	}

	artifact, err := readAuditVerifyInput(*artifactPath, stdin, auditanchor.MaxArtifactBytes)
	if err != nil {
		return auditVerifyFailure(stderr, err)
	}
	tsaRootRaw, err := readAuditVerifyFile(*tsaRootPath, auditVerifyTrustFileLimit)
	if err != nil {
		return auditVerifyFailure(stderr, fmt.Errorf("read TSA root: %w", err))
	}
	tsaRootDER, err := crypto.NormalizeCertificateDER(tsaRootRaw)
	if err != nil {
		return auditVerifyFailure(stderr, fmt.Errorf("parse TSA root: %w", err))
	}
	var auditKeys *jose.JWKSet
	if strings.TrimSpace(*auditJWKSPath) != "" {
		doc, err := readAuditVerifyFile(*auditJWKSPath, auditVerifyTrustFileLimit)
		if err != nil {
			return auditVerifyFailure(stderr, fmt.Errorf("read audit JWK set: %w", err))
		}
		auditKeys, err = jose.ParseJWKSet(doc)
		if err != nil {
			return auditVerifyFailure(stderr, fmt.Errorf("parse audit JWK set: %w", err))
		}
	}

	result, err := auditanchor.VerifyArtifact(artifact, auditanchor.VerificationOptions{
		Format: format, AuditKeys: auditKeys, TSARootDER: tsaRootDER, MaxAnchorDelay: *maxAnchorDelay,
	})
	if err != nil {
		return auditVerifyFailure(stderr, err)
	}
	encoded, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return auditVerifyFailure(stderr, fmt.Errorf("encode verification receipt: %w", err))
	}
	_, _ = stdout.Write(encoded)
	_, _ = fmt.Fprintln(stdout)
	return 0
}

func readAuditVerifyInput(path string, stdin io.Reader, limit int) ([]byte, error) {
	if path == "-" {
		return readAuditVerifyBounded(stdin, limit)
	}
	return readAuditVerifyFile(path, limit)
}

func readAuditVerifyFile(path string, limit int) ([]byte, error) {
	f, err := os.Open(path) // #nosec G304 -- path is the explicit read-only local artifact selected by this CLI command (CWE-22).
	if err != nil {
		return nil, err
	}
	return readAuditVerifyReadCloser(f, limit)
}

func readAuditVerifyReadCloser(r io.ReadCloser, limit int) (raw []byte, err error) {
	defer func() {
		if closeErr := r.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close audit verification input: %w", closeErr))
		}
	}()
	return readAuditVerifyBounded(r, limit)
}

func readAuditVerifyBounded(r io.Reader, limit int) ([]byte, error) {
	if r == nil {
		return nil, fmt.Errorf("input reader is unavailable")
	}
	raw, err := io.ReadAll(io.LimitReader(r, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > limit {
		return nil, fmt.Errorf("input exceeds the %d-byte limit", limit)
	}
	return raw, nil
}

func auditVerifyFailure(stderr io.Writer, err error) int {
	_, _ = fmt.Fprintf(stderr, "error: audit verification failed: %v\n", err)
	return 1
}

func auditVerifyUsage(w io.Writer) {
	_, _ = fmt.Fprintln(w, "Usage: trstctl audit verify --artifact <file|-> --tsa-root <root.pem|root.der> [--audit-jwks <audit.jwks.json>] [--format auto|jws|ndjson|csv|splunk-hec|sentinel] [--max-anchor-delay 24h]")
	_, _ = fmt.Fprintln(w, "\nVerify a saved audit export completely offline. The TSA root may be PEM or DER. The audit JWK set and TSA root are external trust inputs; keys carried only by an artifact are never trusted.")
	_, _ = fmt.Fprintln(w, "\nExample: trstctl audit verify --artifact audit.jws.json --audit-jwks audit.jwks.json --tsa-root tsa-root.pem --max-anchor-delay 24h")
}
