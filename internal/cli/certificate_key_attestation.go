// SPDX-License-Identifier: BUSL-1.1

package cli

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"trstctl.com/trstctl/internal/crypto/deviceattest"
)

// certificates verify-key-attestation re-checks a certificate's device-bound
// custody claim (A131) on this machine: the evidence 'certificates
// key-attestation' printed, against TPM roots the operator chooses. Nothing is
// sent anywhere.

func certificateVerifyKeyAttestationUsage(w io.Writer) {
	_, _ = fmt.Fprintln(w, "Usage: trstctl certificates verify-key-attestation --evidence <file> --roots <file> [--certificate <file>]")
	_, _ = fmt.Fprintln(w, "\nRe-checks a certificate's device-bound custody claim offline. --evidence is the JSON 'certificates")
	_, _ = fmt.Fprintln(w, "key-attestation' printed; --roots is a PEM bundle of the TPM attestation roots you trust; --certificate")
	_, _ = fmt.Fprintln(w, "checks a certificate file instead of the one the evidence carries. It verifies the TPM attestation under your")
	_, _ = fmt.Fprintln(w, "roots at the time it was first verified, that it and its binding name the certificate's key, and that the")
	_, _ = fmt.Fprintln(w, "TPM generated the key and will not release it. Nothing is sent anywhere.")
	_, _ = fmt.Fprintln(w, "\nExample: trstctl certificates verify-key-attestation --evidence evidence.json --roots tpm-roots.pem")
}

func runCertificateVerifyKeyAttestation(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("certificates verify-key-attestation", flag.ContinueOnError)
	fs.SetOutput(stderr)
	evidenceFile := fs.String("evidence", "", "JSON from 'certificates key-attestation'")
	rootsFile := fs.String("roots", "", "PEM bundle of the TPM attestation roots you trust")
	certificateFile := fs.String("certificate", "", "a certificate (PEM or DER) to check instead of the one in the evidence")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *evidenceFile == "" || *rootsFile == "" {
		_, _ = fmt.Fprintln(stderr, "error: --evidence and --roots are required")
		return 2
	}
	evidence, result, err := verifyKeyAttestationFiles(*evidenceFile, *rootsFile, *certificateFile)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "verified: certificate %s holds a device-bound key\n", evidence.Fingerprint)
	_, _ = fmt.Fprintf(stdout, "  the TPM generated it and will not release it (sensitiveDataOrigin, fixedTPM, fixedParent)\n")
	_, _ = fmt.Fprintf(stdout, "  attested by the TPM attestation key whose certificate is sha256:%s, verified %s\n",
		hex.EncodeToString(result.AttestationCertificateSHA256), evidence.VerifiedAt.UTC().Format(time.RFC3339))
	return 0
}

// keyAttestationEvidence is the part of the 'certificates key-attestation'
// response the verifier reads.
type keyAttestationEvidence struct {
	Fingerprint    string    `json:"fingerprint"`
	Format         string    `json:"format"`
	Credential     []byte    `json:"credential"`
	Binding        []byte    `json:"binding"`
	VerifiedAt     time.Time `json:"verified_at"`
	CertificatePEM string    `json:"certificate_pem"`
}

func verifyKeyAttestationFiles(evidenceFile, rootsFile, certificateFile string) (keyAttestationEvidence, deviceattest.TPMDeviceAttestationResult, error) {
	var evidence keyAttestationEvidence
	raw, err := os.ReadFile(evidenceFile) // #nosec G304 -- operator-named local file (CWE-22)
	if err != nil {
		return evidence, deviceattest.TPMDeviceAttestationResult{}, fmt.Errorf("read evidence: %w", err)
	}
	if err := json.Unmarshal(raw, &evidence); err != nil || len(evidence.Credential) == 0 || len(evidence.Binding) == 0 {
		return evidence, deviceattest.TPMDeviceAttestationResult{}, errors.New("the evidence file must be the JSON printed by 'certificates key-attestation'")
	}
	if evidence.Format != "tpm-webauthn" {
		return evidence, deviceattest.TPMDeviceAttestationResult{}, fmt.Errorf("evidence format %q is not one this trstctl verifies (tpm-webauthn)", evidence.Format)
	}
	roots, err := os.ReadFile(rootsFile) // #nosec G304 -- operator-named local file (CWE-22)
	if err != nil {
		return evidence, deviceattest.TPMDeviceAttestationResult{}, fmt.Errorf("read roots: %w", err)
	}
	certificate := []byte(evidence.CertificatePEM)
	if certificateFile != "" {
		if certificate, err = os.ReadFile(certificateFile); err != nil { // #nosec G304 -- operator-named local file (CWE-22)
			return evidence, deviceattest.TPMDeviceAttestationResult{}, fmt.Errorf("read certificate: %w", err)
		}
	}
	if len(certificate) == 0 {
		return evidence, deviceattest.TPMDeviceAttestationResult{}, errors.New("no certificate to check: the evidence carries none and --certificate is not set")
	}
	result, err := deviceattest.VerifyTPMCustodyEvidence(deviceattest.TPMCustodyEvidence{
		Credential: evidence.Credential, Binding: evidence.Binding, VerifiedAt: evidence.VerifiedAt,
	}, certificate, [][]byte{roots})
	return evidence, result, err
}
