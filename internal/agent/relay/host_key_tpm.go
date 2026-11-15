// SPDX-License-Identifier: BUSL-1.1

package relay

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/deviceattest"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/kms/tpm"
)

// HostKeyCustodyTPM is a renewal intent's key_custody when the profile
// requires the key to be created in the host's TPM and attested (TPM-O1).
const HostKeyCustodyTPM = "tpm"

// tpmHostKeyConnectors are the host connectors that install a TPM-held key:
// the service reads the TSS2 key file the TPM wraps the key in through OpenSSL
// 3's tpm2 provider. nginx is the one proven against the provider (TPM-O1). A
// connector that converts the key — into a keystore, a Windows store, a
// Kubernetes Secret — cannot take one, because the key never leaves the TPM.
var tpmHostKeyConnectors = []string{"nginx"}

// AttestedCSRSigner is the SignJobCSR call that carries the TPM's attestation
// of the CSR's key (TPM-O1). A channel without it cannot take a renewal whose
// profile requires a TPM-held key, and the agent says so before the TPM makes
// a key.
type AttestedCSRSigner interface {
	SignJobCSRWithKeyAttestation(ctx context.Context, jobID int64, attempt int, csrDER, keyAttestation []byte) (certPEM, chainPEM []byte, fingerprint string, err error)
}

// tpmHostKeyRefusal is why this agent cannot take a renewal whose key must be
// TPM-held, checked before any key exists; empty means it can.
func tpmHostKeyRefusal(ch Channel, profile connector.LocalOpsConfig, intent DeployIntent) string {
	switch {
	case intent.KeyCustody != HostKeyCustodyTPM:
		return "the renewal asks for key custody " + fmt.Sprintf("%q", intent.KeyCustody) + ", which this agent does not provide"
	case profile.HostKeyTPM == nil:
		return "the profile requires a TPM-held key and this host's profile names no host_key_tpm"
	case !slices.Contains(tpmHostKeyConnectors, intent.Connector):
		return "a TPM-held key is installed only for " + strings.Join(tpmHostKeyConnectors, ", ") + ", not " + intent.Connector
	case intent.PQCRunID != "" || (intent.SubjectKeyAlgorithm != "" && intent.SubjectKeyAlgorithm != string(crypto.ECDSAP256)):
		return "a TPM-held host key is ECDSA P-256"
	}
	if _, ok := ch.(AttestedCSRSigner); !ok {
		return "this agent build cannot send a TPM key attestation with its request"
	}
	return ""
}

// hostKeyTPM is this host's TPM opened for one renewal: the device, the
// attestation key that certifies host keys, its certificate chain and its
// authorization.
type hostKeyTPM struct {
	device   tpm.HostKeyDevice
	aik      crypto.EdgeCAKeyHandle
	aikChain []byte
	aikAuth  []byte
	closeDev func()
}

// Close wipes the attestation key's authorization and closes the device.
func (h *hostKeyTPM) Close() {
	if h == nil {
		return
	}
	secret.Wipe(h.aikAuth)
	if h.closeDev != nil {
		h.closeDev()
	}
}

// openHostKeyTPM opens the host profile's TPM. Tests replace it with a
// software TPM.
var openHostKeyTPM = openProductionHostKeyTPM

func openProductionHostKeyTPM(cfg connector.HostKeyTPMConfig) (*hostKeyTPM, error) {
	raw, err := os.ReadFile(cfg.AttestationKey) // #nosec G304 -- the operator's host profile names it (CWE-22)
	if err != nil {
		return nil, fmt.Errorf("relay: read the TPM attestation key handle: %w", err)
	}
	var aik crypto.EdgeCAKeyHandle
	if err := json.Unmarshal(raw, &aik); err != nil {
		return nil, fmt.Errorf("relay: decode the TPM attestation key handle: %w", err)
	}
	chain, err := os.ReadFile(cfg.AttestationCertChain) // #nosec G304 -- the operator's host profile names it (CWE-22)
	if err != nil {
		return nil, fmt.Errorf("relay: read the TPM attestation key's certificate chain: %w", err)
	}
	aikAuth, err := readTPMAuthFile(cfg.AttestationKeyAuthFile)
	if err != nil {
		return nil, fmt.Errorf("relay: read the TPM attestation key authorization: %w", err)
	}
	ownerAuth, err := readTPMAuthFile(cfg.OwnerAuthFile)
	if err != nil {
		secret.Wipe(aikAuth)
		return nil, fmt.Errorf("relay: read the TPM owner authorization: %w", err)
	}
	// OpenDevice keeps its own locked copy of the owner authorization.
	defer secret.Wipe(ownerAuth)
	dev, err := tpm.OpenDevice(tpm.DeviceConfig{Path: cfg.Path, OwnerAuth: ownerAuth})
	if err != nil {
		secret.Wipe(aikAuth)
		return nil, err
	}
	host, ok := dev.(tpm.HostKeyDevice)
	if !ok {
		_ = dev.Close()
		secret.Wipe(aikAuth)
		return nil, errors.New("relay: this TPM binding cannot make host keys")
	}
	return &hostKeyTPM{device: host, aik: aik, aikChain: chain, aikAuth: aikAuth, closeDev: func() { _ = dev.Close() }}, nil
}

// readTPMAuthFile reads an optional TPM authorization value, trimmed.
func readTPMAuthFile(path string) ([]byte, error) {
	if path == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path) // #nosec G304 -- the operator's host profile names it (CWE-22)
	if err != nil {
		return nil, err
	}
	defer secret.Wipe(raw)
	return append([]byte(nil), bytes.TrimSpace(raw)...), nil
}

// generateTPMHostRenewSubjectKey has the TPM create the renewal's key and
// sign its CSR. The key's private half exists only inside the TPM; what the
// agent keeps, retains for a reclaim and installs is the TSS2 key file, which
// only this TPM can load.
func generateTPMHostRenewSubjectKey(h *hostKeyTPM, intent DeployIntent) (*hostRenewSubjectKey, error) {
	tmpl, err := hostSubjectTemplate(intent)
	if err != nil {
		return nil, err
	}
	file, publicDER, err := h.device.CreateHostKey()
	if err != nil {
		return nil, err
	}
	csrDER, err := crypto.CreateHostSubjectCSR(tmpl, tpm.HostKeySigner(h.device, file, publicDER))
	if err != nil {
		secret.Wipe(file)
		return nil, err
	}
	return &hostRenewSubjectKey{
		CSRDER:     csrDER,
		privatePEM: func() ([]byte, error) { return append([]byte(nil), file...), nil },
		destroy:    func() { secret.Wipe(file) },
	}, nil
}

// attest has the TPM certify the key file's key under the attestation key,
// over the job's host-key binding, and returns the credential the control
// plane verifies (it is checked here first).
func (h *hostKeyTPM) attest(jobID int64, file, csrDER []byte) ([]byte, error) {
	return attestTPMHostKey(h, jobID, file, csrDER)
}

// attestTPMHostKey is the TPM's attestation; a test replaces it where no TPM
// can certify (the swtpm journey runs the real one).
var attestTPMHostKey = func(h *hostKeyTPM, jobID int64, file, csrDER []byte) ([]byte, error) {
	binding, err := deviceattest.HostKeyBinding(jobID, csrDER)
	if err != nil {
		return nil, err
	}
	publicDER, err := h.device.HostKeyPublicDER(file)
	if err != nil {
		return nil, err
	}
	return deviceattest.CreateHostKeyTPMCredential(binding, csrDER, publicDER, h.aik, h.aikChain,
		func(qualifyingData []byte) (crypto.EdgeTPMCertification, error) {
			return h.device.CertifyHostKey(file, h.aik.KeyID, qualifyingData, h.aikAuth)
		})
}
