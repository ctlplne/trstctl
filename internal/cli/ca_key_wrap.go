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

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// ca authorities wrap-key seals an existing CA private key to the signer's
// one-time import key on the operator's machine (A128). The private key is
// read from a local PEM file and sent nowhere: the output is the request body
// 'ca authorities import-key' takes, carrying only the sealed key.

func caWrapKeyUsage(w io.Writer) {
	_, _ = fmt.Fprintln(w, "Usage: trstctl ca authorities wrap-key --offer <file> --key <file> --request <file> [--out <file>]")
	_, _ = fmt.Fprintln(w, "\nSeals a CA's existing private key to a key offer, on this machine. --offer is the JSON 'ca authorities key-offer'")
	_, _ = fmt.Fprintln(w, "printed; --key is the CA's PKCS#8 private key in PEM ('openssl pkcs8 -topk8 -nocrypt' converts other forms);")
	_, _ = fmt.Fprintln(w, "--request is the import request (ceremony_id, certificate_pem, spec and any parent_id the ceremony approved).")
	_, _ = fmt.Fprintln(w, "The key must be the one the certificate names. The output is the request with sealed_key added, for")
	_, _ = fmt.Fprintln(w, "'ca authorities import-key'. The private key itself is never sent.")
	_, _ = fmt.Fprintln(w, "\nExample: trstctl ca authorities wrap-key --offer offer.json --key ca-key.pem --request import.json --out import-sealed.json")
}

func runCAWrapKey(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("ca authorities wrap-key", flag.ContinueOnError)
	fs.SetOutput(stderr)
	offerFile := fs.String("offer", "", "JSON from 'ca authorities key-offer'")
	keyFile := fs.String("key", "", "the CA's PKCS#8 private key, PEM")
	requestFile := fs.String("request", "", "the import request without sealed_key")
	out := fs.String("out", "", "write the sealed import request here instead of stdout")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *offerFile == "" || *keyFile == "" || *requestFile == "" {
		_, _ = fmt.Fprintln(stderr, "error: --offer, --key and --request are required")
		return 2
	}
	body, err := buildCAKeyImportRequest(*offerFile, *keyFile, *requestFile)
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

func buildCAKeyImportRequest(offerFile, keyFile, requestFile string) ([]byte, error) {
	raw, err := os.ReadFile(offerFile) // #nosec G304 -- operator-named local file (CWE-22)
	if err != nil {
		return nil, fmt.Errorf("read offer: %w", err)
	}
	var offer struct {
		CeremonyID        string `json:"ceremony_id"`
		TenantID          string `json:"tenant_id"`
		OperationID       string `json:"operation_id"`
		Suite             string `json:"suite"`
		PublicKey         []byte `json:"public_key"`
		ExpectedPublicKey []byte `json:"expected_public_key"`
	}
	if err := json.Unmarshal(raw, &offer); err != nil || offer.CeremonyID == "" || offer.TenantID == "" ||
		offer.OperationID == "" || len(offer.PublicKey) == 0 || len(offer.ExpectedPublicKey) == 0 {
		return nil, errors.New("offer file must be the JSON printed by 'ca authorities key-offer'")
	}
	if offer.Suite != crypto.KeyImportSuite {
		return nil, fmt.Errorf("the offer uses suite %q; this trstctl seals %q", offer.Suite, crypto.KeyImportSuite)
	}
	rawRequest, err := os.ReadFile(requestFile) // #nosec G304 -- operator-named local file (CWE-22)
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
	if _, present := request["sealed_key"]; present {
		return nil, errors.New("the request already carries a sealed_key")
	}
	keyPEM, err := os.ReadFile(keyFile) // #nosec G304 -- operator-named local file (CWE-22)
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
	sealed, err := crypto.SealKeyImport(offer.PublicKey, crypto.KeyImportInfo(offer.TenantID, offer.OperationID, offer.ExpectedPublicKey), block.Bytes)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(sealed)
	if err != nil {
		return nil, err
	}
	request["sealed_key"] = encoded
	return json.MarshalIndent(request, "", "  ")
}
