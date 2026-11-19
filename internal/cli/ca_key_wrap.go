// SPDX-License-Identifier: BUSL-1.1

package cli

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// ca authorities wrap-key seals an existing CA private key to the signer's
// one-time import key on the operator's machine (A128). The private key is
// read from a local PEM file and sent nowhere: the output is the request body
// 'ca authorities import-key' takes, carrying only the sealed key.

func caWrapKeyUsage(w io.Writer) {
	_, _ = fmt.Fprintln(w, "Usage: trstctl-cli ca authorities wrap-key --offer <file> --key <file> --request <file> --tenant-id <uuid> --signer-fingerprint <sha256> [--out <file>]")
	_, _ = fmt.Fprintln(w, "\nSeals a CA's existing private key to a key offer, on this machine. --offer is the JSON 'ca authorities key-offer'")
	_, _ = fmt.Fprintln(w, "printed; --key is the CA's PKCS#8 private key in PEM ('openssl pkcs8 -topk8 -nocrypt' converts other forms);")
	_, _ = fmt.Fprintln(w, "--request is the import request (ceremony_id, certificate_pem, spec and any parent_id the ceremony approved).")
	_, _ = fmt.Fprintln(w, "Obtain the signer fingerprint directly from the signer host over a separate trusted channel.")
	_, _ = fmt.Fprintln(w, "The key must be the one the certificate names. The output is the request with sealed_key_v2 added, for")
	_, _ = fmt.Fprintln(w, "'ca authorities import-key'. The private key itself is never sent.")
	_, _ = fmt.Fprintln(w, "\nExample: trstctl-cli ca authorities wrap-key --offer offer.json --key ca-key.pem --request import.json --tenant-id \"$tenant_id\" --signer-fingerprint \"$signer_fingerprint\" --out import-sealed.json")
}

func runCAWrapKey(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("ca authorities wrap-key", flag.ContinueOnError)
	fs.SetOutput(stderr)
	offerFile := fs.String("offer", "", "JSON from 'ca authorities key-offer'")
	keyFile := fs.String("key", "", "the CA's PKCS#8 private key, PEM")
	requestFile := fs.String("request", "", "the import request before sealing")
	tenantID := fs.String("tenant-id", "", "the tenant UUID from the reviewed ceremony")
	signerFingerprint := fs.String("signer-fingerprint", "", "the SHA-256 fingerprint obtained directly from the signer host")
	out := fs.String("out", "", "write the sealed import request here instead of stdout")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *offerFile == "" || *keyFile == "" || *requestFile == "" {
		_, _ = fmt.Fprintln(stderr, "error: --offer, --key and --request are required")
		return 2
	}
	if *signerFingerprint == "" || *tenantID == "" {
		_, _ = fmt.Fprintln(stderr, "error: --signer-fingerprint and --tenant-id are required")
		return 2
	}
	body, err := buildCAKeyImportRequest(*offerFile, *keyFile, *requestFile, *tenantID, *signerFingerprint)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	if *out != "" {
		if err := os.WriteFile(*out, body, 0o600); err != nil {
			_, _ = fmt.Fprintf(stderr, "error: %v\n", err)
			return 1
		}
		_, _ = fmt.Fprintf(stdout, "wrote %s\n", *out)
		return 0
	}
	_, _ = stdout.Write(body)
	return 0
}

func buildCAKeyImportRequest(offerFile, keyFile, requestFile, tenantID, signerFingerprint string) ([]byte, error) {
	raw, err := readCAImportFile(offerFile, 64<<10)
	if err != nil {
		return nil, fmt.Errorf("read offer: %w", err)
	}
	var offer struct {
		crypto.AuthenticatedKeyImportOffer
		CeremonyID string `json:"ceremony_id"`
	}
	if err := json.Unmarshal(raw, &offer); err != nil || offer.CeremonyID != offer.OperationID {
		return nil, errors.New("offer file must carry one key-offer ceremony and operation")
	}
	if offer.Suite != crypto.AuthenticatedKeyImportSuite {
		return nil, errors.New("the offer must use authenticated key import v2; obtain a new offer from the upgraded signer")
	}
	info, err := offer.Verify(signerFingerprint, time.Now())
	if err != nil {
		return nil, err
	}
	if offer.TenantID != tenantID {
		return nil, errors.New("the authenticated offer belongs to a different tenant")
	}
	rawRequest, err := readCAImportFile(requestFile, 2<<20)
	if err != nil {
		return nil, fmt.Errorf("read request: %w", err)
	}
	var request map[string]json.RawMessage
	if err := json.Unmarshal(rawRequest, &request); err != nil {
		return nil, fmt.Errorf("request file is not a JSON object: %w", err)
	}
	var ceremonyID string
	if err := json.Unmarshal(request["ceremony_id"], &ceremonyID); err != nil || ceremonyID != offer.CeremonyID {
		return nil, fmt.Errorf("the request's ceremony_id does not match the offer's ceremony %s", offer.CeremonyID)
	}
	for field := range request {
		if strings.EqualFold(field, "sealed_key") || strings.EqualFold(field, "sealed_key_v2") {
			return nil, errors.New("the wrapping request already carries a sealed key")
		}
	}
	var certificatePEM string
	if err := json.Unmarshal(request["certificate_pem"], &certificatePEM); err != nil {
		return nil, errors.New("the wrapping request requires the reviewed certificate chain")
	}
	certificate, _ := pem.Decode([]byte(certificatePEM))
	if certificate == nil || certificate.Type != "CERTIFICATE" {
		return nil, errors.New("the wrapping request requires a CA certificate as its first PEM block")
	}
	certificateSPKI, err := crypto.CertificateSubjectPublicKeyInfo(certificate.Bytes)
	if err != nil || !bytes.Equal(certificateSPKI, offer.ExpectedPublicKey) {
		return nil, errors.New("the wrapping request's CA certificate does not match the authenticated offer")
	}
	keyPEM, err := readCAImportFile(keyFile, 64<<10)
	if err != nil {
		return nil, fmt.Errorf("read private key: %w", err)
	}
	defer secret.Wipe(keyPEM)
	block, _ := pem.Decode(keyPEM)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("the private key file must be a PKCS#8 PEM (\"PRIVATE KEY\"); convert with 'openssl pkcs8 -topk8 -nocrypt'")
	}
	defer secret.Wipe(block.Bytes)
	locked, err := crypto.LockedKeyFromPKCS8(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	matches := bytes.Equal(locked.Public().DER, offer.ExpectedPublicKey)
	locked.Destroy()
	if !matches {
		return nil, errors.New("this private key is not the key in the certificate being imported")
	}
	sealed, err := crypto.SealKeyImport(offer.PublicKey, info, block.Bytes)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(sealed)
	if err != nil {
		return nil, err
	}
	request["sealed_key_v2"] = encoded
	return json.MarshalIndent(request, "", "  ")
}

func readCAImportFile(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path) // #nosec G304 -- operator-named local file (CWE-22)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		secret.Wipe(data)
		return nil, err
	}
	if int64(len(data)) > limit {
		secret.Wipe(data)
		return nil, errors.New("file exceeds the wrapping input limit")
	}
	return data, nil
}
