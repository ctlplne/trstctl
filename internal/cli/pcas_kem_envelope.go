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

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/pqc"
	"trstctl.com/trstctl/internal/succession"
)

// pcas kem envelope builds a KEM-wrapped data-key envelope on the operator's
// machine: the data key is read from a file, encapsulated to the epoch's public
// key fetched with `pcas kem public-key`, and never sent anywhere. The output is
// the exact request body `pcas kem data-keys register` takes.

func pcasKEMEnvelopeUsage(w io.Writer) {
	_, _ = fmt.Fprintln(w, "Usage: trstctl pcas kem envelope --public-key <file> --dek-file <file> --target-ref <ref> [--stage <name>] [--out <file>]")
	_, _ = fmt.Fprintln(w, "\nBuilds a KEM-wrapped data-key envelope offline. --public-key is the JSON that 'pcas kem public-key' printed")
	_, _ = fmt.Fprintln(w, "(identity_id, epoch, kem_algorithm, public_key_der); --dek-file holds the raw data key (1 to 256 bytes).")
	_, _ = fmt.Fprintln(w, "The data key is encapsulated and sealed locally and never sent to the control plane; the printed JSON is")
	_, _ = fmt.Fprintln(w, "the request body for 'pcas kem data-keys register'.")
	_, _ = fmt.Fprintln(w, "\nExample: trstctl pcas kem envelope --public-key epoch2.json --dek-file backup.dek --target-ref backup:2026-10 --out register.json")
}

func runPCASKEMEnvelope(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("pcas kem envelope", flag.ContinueOnError)
	fs.SetOutput(stderr)
	publicKeyFile := fs.String("public-key", "", "JSON from 'pcas kem public-key'")
	dekFile := fs.String("dek-file", "", "file holding the raw data key (1 to 256 bytes)")
	targetRef := fs.String("target-ref", "", "operator's stable reference for the protected object")
	stage := fs.String("stage", "default", "re-wrap stage the envelope belongs to")
	out := fs.String("out", "", "write the register request here instead of stdout")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *publicKeyFile == "" || *dekFile == "" || strings.TrimSpace(*targetRef) == "" {
		_, _ = fmt.Fprintln(stderr, "error: --public-key, --dek-file and --target-ref are required")
		return 2
	}
	body, err := buildPCASKEMEnvelope(*publicKeyFile, *dekFile, strings.TrimSpace(*targetRef), strings.TrimSpace(*stage))
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

func buildPCASKEMEnvelope(publicKeyFile, dekFile, targetRef, stage string) ([]byte, error) {
	raw, err := os.ReadFile(publicKeyFile) // #nosec G304 -- operator-named local file (CWE-22)
	if err != nil {
		return nil, fmt.Errorf("read public key: %w", err)
	}
	var pub struct {
		IdentityID   string `json:"identity_id"`
		Epoch        uint64 `json:"epoch"`
		KEMAlgorithm string `json:"kem_algorithm"`
		PublicKeyDER []byte `json:"public_key_der"`
	}
	if err := json.Unmarshal(raw, &pub); err != nil || pub.IdentityID == "" || pub.Epoch == 0 || pub.KEMAlgorithm == "" || len(pub.PublicKeyDER) == 0 {
		return nil, errors.New("public key file must be the JSON printed by 'pcas kem public-key'")
	}
	dek, err := os.ReadFile(dekFile) // #nosec G304 -- operator-named local file (CWE-22)
	if err != nil {
		return nil, fmt.Errorf("read data key: %w", err)
	}
	defer secret.Wipe(dek)
	if len(dek) == 0 || len(dek) > crypto.MaxKEMDataKeyBytes {
		return nil, fmt.Errorf("data key must be 1 to %d bytes", crypto.MaxKEMDataKeyBytes)
	}
	ct, ss, err := pqc.Encapsulate(crypto.PublicKey{Algorithm: crypto.Algorithm(pub.KEMAlgorithm), DER: pub.PublicKeyDER})
	if err != nil {
		return nil, fmt.Errorf("encapsulate: %w", err)
	}
	defer secret.Wipe(ss)
	wrapped, err := crypto.KEMDataKeySeal(ss, dek, succession.KEMDataKeyAAD(pub.IdentityID, pub.Epoch, targetRef))
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(map[string]any{
		"identity_id": pub.IdentityID, "epoch": pub.Epoch, "target_ref": targetRef, "stage": stage,
		"kem_ciphertext": ct, "wrapped_dek": wrapped, "dek_sha256": crypto.SHA256Sum(dek),
	}, "", "  ")
}
