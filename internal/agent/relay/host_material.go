// SPDX-License-Identifier: BUSL-1.1

package relay

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/kms/tpm"
)

// validateHostMaterial runs before any host connector writes or network calls.
// The job's bytes are data only after their certificate, key and advertised
// identity agree. The returned key must be destroyed after connector.Run.
func validateHostMaterial(profile connector.LocalOpsConfig, intent DeployIntent, material Material) ([]byte, *secret.Buffer, error) {
	leafRaw := material["credential.cert_pem"]
	if len(leafRaw) == 0 {
		return nil, nil, errors.New("relay: redeemed material carries no certificate")
	}
	leaf, err := certinfo.NormalizePublicCertificatePEM(leafRaw)
	if err != nil {
		return nil, nil, errors.New("relay: redeemed certificate must contain only X.509 PEM blocks")
	}
	info, err := certinfo.Inspect(leaf)
	if err != nil {
		return nil, nil, errors.New("relay: redeemed certificate does not parse")
	}
	if !sameHostRollbackFingerprint(info.SHA256Fingerprint, intent.Fingerprint) {
		return nil, nil, errors.New("relay: redeemed certificate does not match the job fingerprint")
	}
	serving := leaf
	if chainRaw := material["credential.chain_pem"]; len(chainRaw) != 0 {
		chain, err := certinfo.NormalizePublicCertificatePEM(chainRaw)
		if err != nil {
			return nil, nil, errors.New("relay: redeemed certificate chain is not X.509 PEM")
		}
		serving = append(serving, chain...)
	}
	keyRaw := material["credential.key_pem"]
	if len(keyRaw) == 0 {
		return nil, nil, errors.New("relay: redeemed material carries no private key")
	}
	var key *secret.Buffer
	var keySPKI string
	if intent.KeyCustody == HostKeyCustodyTPM {
		if !bytes.HasPrefix(bytes.TrimSpace(keyRaw), []byte("-----BEGIN "+"TSS2 PRIVATE KEY-----")) || len(keyRaw) > 128<<10 || profile.HostKeyTPM == nil {
			return nil, nil, errors.New("relay: expected a bounded TPM host key file and operator TPM profile")
		}
		parent, public, private, err := tpm.DecodeTSS2PrivateKey(keyRaw)
		if err != nil {
			return nil, nil, fmt.Errorf("relay: invalid TPM host key file: %w", err)
		}
		defer secret.Wipe(public)
		defer secret.Wipe(private)
		canonical, err := tpm.EncodeTSS2PrivateKey(parent, public, private)
		if err != nil {
			return nil, nil, err
		}
		defer secret.Wipe(canonical)
		key, err = secret.NewFrom(canonical)
		if err != nil {
			return nil, nil, err
		}
		hostTPM, err := openHostKeyTPM(*profile.HostKeyTPM)
		if err != nil {
			key.Destroy()
			return nil, nil, fmt.Errorf("relay: open host TPM to check key identity: %w", err)
		}
		defer hostTPM.Close()
		publicDER, err := hostTPM.device.HostKeyPublicDER(key.Bytes())
		if err != nil {
			key.Destroy()
			return nil, nil, fmt.Errorf("relay: inspect TPM host key: %w", err)
		}
		keySPKI = crypto.SHA256Hex(publicDER)
	} else {
		var keyInfo crypto.PrivateKeyInfo
		key, keyInfo, err = crypto.NormalizeDeploymentPrivateKeyPEM(keyRaw)
		if err != nil {
			return nil, nil, fmt.Errorf("relay: invalid deployment private key: %w", err)
		}
		keySPKI = keyInfo.FingerprintSHA256
	}
	if !strings.EqualFold(keySPKI, info.SPKISHA256) {
		key.Destroy()
		return nil, nil, errors.New("relay: private key does not match the redeemed certificate")
	}
	return serving, key, nil
}
