// SPDX-License-Identifier: BUSL-1.1

package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"reflect"

	"trstctl.com/trstctl/internal/crypto/jose"
)

// cbom verify-cyclonedx re-checks a saved CycloneDX CBOM export on this
// machine (Q3): the signature over the BOM bytes with the audit evidence keys
// the operator pinned separately (the export's own public_jwks is never
// trusted), and that the export's bom is exactly what was signed. It can
// write the verified BOM for a scanner or an agency to ingest. Nothing is
// sent anywhere.

const cbomVerifyFileLimit = 64 << 20

func cbomVerifyCycloneDXUsage(w io.Writer) {
	_, _ = fmt.Fprintln(w, "Usage: trstctl cbom verify-cyclonedx --export <file> --audit-jwks <file> [--bom-out <file>]")
	_, _ = fmt.Fprintln(w, "\nVerifies a file saved from 'cbom export-cyclonedx' offline: the signature over the CycloneDX BOM with the")
	_, _ = fmt.Fprintln(w, "audit evidence keys in --audit-jwks (from 'audit verification-keys', pinned separately; the export's own")
	_, _ = fmt.Fprintln(w, "public_jwks is never trusted), and that the export's bom is the signed document. --bom-out writes the")
	_, _ = fmt.Fprintln(w, "verified BOM, exactly the signed bytes. Nothing is sent anywhere.")
	_, _ = fmt.Fprintln(w, "\nExample: trstctl cbom verify-cyclonedx --export cbom-export.json --audit-jwks audit.jwks.json --bom-out cbom.cdx.json")
}

func runCBOMVerifyCycloneDX(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("cbom verify-cyclonedx", flag.ContinueOnError)
	fs.SetOutput(stderr)
	exportFile := fs.String("export", "", "a file saved from 'cbom export-cyclonedx'")
	jwksFile := fs.String("audit-jwks", "", "the audit evidence public JWK set you pinned separately ('audit verification-keys')")
	bomOut := fs.String("bom-out", "", "write the verified CycloneDX BOM (the signed bytes) to this file")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *exportFile == "" || *jwksFile == "" || len(fs.Args()) != 0 {
		_, _ = fmt.Fprintln(stderr, "error: --export and --audit-jwks are required, and nothing else")
		return 2
	}
	bom, err := verifyCBOMCycloneDXExport(*exportFile, *jwksFile)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	var doc struct {
		SpecVersion  string            `json:"specVersion"`
		SerialNumber string            `json:"serialNumber"`
		Components   []json.RawMessage `json:"components"`
	}
	if err := json.Unmarshal(bom, &doc); err != nil {
		_, _ = fmt.Fprintf(stderr, "error: the signed BOM is not a CycloneDX document: %v\n", err)
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "verified: CycloneDX %s CBOM %s with %d components, signed by the pinned audit evidence key\n",
		doc.SpecVersion, doc.SerialNumber, len(doc.Components))
	if *bomOut != "" {
		if err := os.WriteFile(*bomOut, bom, 0o600); err != nil {
			_, _ = fmt.Fprintf(stderr, "error: write the BOM: %v\n", err)
			return 1
		}
		_, _ = fmt.Fprintf(stdout, "  verified BOM written to %s\n", *bomOut)
	}
	return 0
}

// verifyCBOMCycloneDXExport returns the exact signed BOM bytes of a saved
// export, after checking the signature with the pinned keys and that the
// export's own bom is the same document.
func verifyCBOMCycloneDXExport(exportPath, jwksPath string) ([]byte, error) {
	raw, err := readCBOMVerifyFile(exportPath)
	if err != nil {
		return nil, fmt.Errorf("read export: %w", err)
	}
	var export struct {
		BOM       json.RawMessage `json:"bom"`
		SignedBOM string          `json:"signed_bom"`
	}
	if err := json.Unmarshal(raw, &export); err != nil || export.SignedBOM == "" || len(export.BOM) == 0 {
		return nil, errors.New("the export has no bom and signed_bom; save the whole 'cbom export-cyclonedx' response")
	}
	jwks, err := readCBOMVerifyFile(jwksPath)
	if err != nil {
		return nil, fmt.Errorf("read audit JWK set: %w", err)
	}
	keys, err := jose.ParseJWKSet(jwks)
	if err != nil {
		return nil, fmt.Errorf("parse audit JWK set: %w", err)
	}
	signed, err := keys.VerifyArtifact(export.SignedBOM, jose.ArtifactCBOMCycloneDX)
	if err != nil {
		return nil, fmt.Errorf("the signature does not verify with the pinned keys: %w", err)
	}
	var signedDoc, exportDoc any
	if json.Unmarshal(signed, &signedDoc) != nil || json.Unmarshal(export.BOM, &exportDoc) != nil || !reflect.DeepEqual(signedDoc, exportDoc) {
		return nil, errors.New("the export's bom is not the document the signature covers")
	}
	return signed, nil
}

func readCBOMVerifyFile(path string) ([]byte, error) {
	f, err := os.Open(path) // #nosec G304 -- operator-named local file (CWE-22)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, cbomVerifyFileLimit+1))
	if err != nil {
		return nil, err
	}
	if len(data) > cbomVerifyFileLimit {
		return nil, errors.New("file exceeds 64 MiB")
	}
	return data, nil
}
