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
	"trstctl.com/trstctl/internal/connector/nginx"
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
// 3's tpm2 provider, each proven against its stock Debian package. nginx
// (TPM-O1) runs one worker and is re-executed for each deploy (TPM-O1-L3);
// haproxy (TPM-O1-L2) runs one thread, and its reload re-executes its
// master; postfix with dovecot (TPM-O1-L2) starts OpenSSL in each daemon
// process. Not apache, postgresql or mysql: their threads or forked processes
// share the provider's one TPM context and fail concurrent handshakes, which
// the lab's TestSwtpmServicesSharingTheTPM2ProviderFailConcurrentHandshakes
// TPMO1L2 shows. A connector that converts the key — into a keystore, a
// Windows store, a Kubernetes Secret — cannot take one, because the key never
// leaves the TPM.
var tpmHostKeyConnectors = []string{"nginx", "haproxy", "postfix"}

// TPMHostKeyConnectors are the host connectors that install a TPM-held key;
// the control plane queues a TPM-held renewal only for these.
func TPMHostKeyConnectors() []string { return slices.Clone(tpmHostKeyConnectors) }

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
	case intent.Connector == "nginx" && !profileHasAction(profile, nginx.ReexecAction):
		// TPM-O1-L3: an in-place reload leaves OpenSSL's tpm2 provider failing
		// nginx's handshakes or serving the previous certificate.
		return "a TPM-held key on nginx needs the host profile's " + nginx.ReexecAction +
			" action, which re-executes nginx so a fresh master loads the key; an in-place reload does not serve it"
	}
	if intent.Connector == "haproxy" {
		if refusal := haproxyTPMRefusal(profile, intent); refusal != "" {
			return refusal
		}
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

// profileHasAction reports whether the host profile maps the logical action.
func profileHasAction(profile connector.LocalOpsConfig, logicalName string) bool {
	for _, action := range profile.Actions {
		if action.LogicalName == logicalName {
			return true
		}
	}
	return false
}

// haproxyTPMRefusal: haproxy's threads share the tpm2 provider's one TPM
// context and fail concurrent handshakes, so a TPM-held key needs the
// configuration's global section to set nbthread 1 (TPM-O1-L2). The agent
// reads config_path inside the host profile's allowed roots.
func haproxyTPMRefusal(profile connector.LocalOpsConfig, intent DeployIntent) string {
	var target HostTargetConfig
	if len(intent.TargetConfig) > 0 && json.Unmarshal(intent.TargetConfig, &target) != nil {
		return "the haproxy target configuration did not decode"
	}
	const unreadable = "a TPM-held key on haproxy needs its config_path readable inside the host profile's allowed roots, to check nbthread"
	if strings.TrimSpace(target.ConfigPath) == "" {
		return unreadable
	}
	ops, err := connector.NewLocalOps(profile)
	if err != nil {
		return "the host exec profile is not usable: " + err.Error()
	}
	reader, ok := ops.(connector.FileReader)
	if !ok {
		return unreadable
	}
	raw, err := reader.ReadFile(target.ConfigPath)
	if err != nil {
		return unreadable
	}
	if threads, set := haproxyGlobalNbthread(raw); !set || threads != "1" {
		return "a TPM-held key on haproxy needs nbthread 1 in its global section: haproxy's threads share the tpm2 provider's one TPM context and fail concurrent handshakes"
	}
	return ""
}

// haproxySections are the keywords that start an haproxy configuration
// section.
var haproxySections = map[string]bool{
	"global": true, "defaults": true, "frontend": true, "backend": true, "listen": true, "resolvers": true,
	"peers": true, "userlist": true, "program": true, "http-errors": true, "ring": true, "cache": true,
	"mailers": true, "log-forward": true, "crt-store": true, "traces": true,
}

// haproxyGlobalNbthread is the nbthread an haproxy configuration's global
// section sets, the last one if it sets several, as haproxy reads it.
func haproxyGlobalNbthread(cfg []byte) (string, bool) {
	inGlobal, value, set := false, "", false
	for _, line := range strings.Split(string(cfg), "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if haproxySections[fields[0]] {
			inGlobal = fields[0] == "global"
			continue
		}
		if inGlobal && fields[0] == "nbthread" && len(fields) >= 2 {
			value, set = fields[1], true
		}
	}
	return value, set
}
