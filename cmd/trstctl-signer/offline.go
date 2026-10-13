// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"trstctl.com/trstctl/internal/breakglass/offline"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/fsatomic"
	"trstctl.com/trstctl/internal/signing"
)

const offlineFileLimit = 4 << 20

func runOfflineBreakglass(initPolicy string, caTTL time.Duration, issueRequest, issueApprovals,
	approveRequest, approveKey, approveCustodian, generateCustodian, custodianPrivateOut,
	custodianPublicOut, output, keystore, kekFile,
	kmsProvider, kmsKeyRef, kmsWrapCommand string, kmsTimeout time.Duration) error {
	modes := 0
	for _, value := range []string{initPolicy, issueRequest, approveRequest, generateCustodian} {
		if value != "" {
			modes++
		}
	}
	if modes != 1 {
		return errors.New("choose exactly one offline init, issue, approve or custodian-generation mode")
	}
	if generateCustodian != "" {
		if custodianPrivateOut == "" || custodianPublicOut == "" || keystore != "" || output != "" {
			return errors.New("custodian generation requires separate private/public output paths and no CA keystore")
		}
		priv, pub, err := crypto.GenerateEd25519KeyPEM()
		if err != nil {
			return err
		}
		defer secret.Wipe(priv)
		pubDER, err := crypto.ParseEd25519PublicKeyPEM(pub)
		if err != nil {
			return err
		}
		entry, err := json.MarshalIndent(offline.OfflineCustodian{ID: generateCustodian, PublicKeyDER: pubDER}, "", "  ")
		if err != nil {
			return err
		}
		if err := writeOfflineOutput(custodianPrivateOut, priv); err != nil {
			return err
		}
		return writeOfflineOutput(custodianPublicOut, entry)
	}
	if approveRequest != "" {
		if approveKey == "" || approveCustodian == "" || output == "" ||
			keystore != "" || issueApprovals != "" || initPolicy != "" {
			return errors.New("offline approval requires --offline-approve-key, --offline-approve-custodian and --offline-output, without a CA keystore")
		}
		var request offline.OfflineRequest
		if err := readOfflineJSON(approveRequest, &request); err != nil {
			return err
		}
		if request.ID == "" || request.ExpiresAt.Before(time.Now()) {
			return errors.New("offline request is empty or expired")
		}
		if _, err := offline.InspectEmergencyCSR(request.Subject, request.CSRDER); err != nil {
			return err
		}
		message, err := request.CanonicalBytes()
		if err != nil {
			return err
		}
		key, err := readPrivateFile(approveKey)
		if err != nil {
			return err
		}
		defer secret.Wipe(key)
		sig, err := crypto.SignEd25519(key, message)
		if err != nil {
			return err
		}
		encoded, err := json.MarshalIndent(offline.OfflineApproval{CustodianID: approveCustodian, Signature: sig}, "", "  ")
		if err != nil {
			return err
		}
		return writeOfflineOutput(output, encoded)
	}
	if keystore == "" {
		return errors.New("offline recovery signer requires its dedicated --keystore directory")
	}
	wrapper, cleanup, err := signerKeystoreWrapper(kekFile, kmsProvider, kmsKeyRef, kmsWrapCommand, kmsTimeout)
	if err != nil {
		return err
	}
	defer cleanup()
	vault, err := signing.NewOfflineBreakglassVault(keystore, wrapper)
	if err != nil {
		return err
	}
	if initPolicy != "" {
		if issueApprovals != "" || output != "" {
			return errors.New("offline initialization writes its kit into the dedicated keystore directory")
		}
		var policy offline.OfflinePolicy
		if err := readOfflineJSON(initPolicy, &policy); err != nil {
			return err
		}
		if _, err := vault.Provision(policy, caTTL); err != nil {
			return err
		}
		kitPath := filepath.Join(keystore, "offline-kit.json")
		kitBytes, err := os.ReadFile(kitPath) // #nosec G304 -- fixed public-kit path beneath the operator-selected offline vault (CWE-22)
		if err != nil {
			return err
		}
		fmt.Printf("kit=%s\nsha256=%s\n", kitPath, crypto.SHA256Hex(kitBytes))
		return nil
	}
	if issueApprovals == "" || output == "" {
		return errors.New("offline issuance requires --offline-issue-approvals and --offline-output")
	}
	var request offline.OfflineRequest
	if err := readOfflineJSON(issueRequest, &request); err != nil {
		return err
	}
	var approvals []offline.OfflineApproval
	if err := readOfflineJSON(issueApprovals, &approvals); err != nil {
		return err
	}
	bundle, replayed, err := vault.Issue(request, approvals)
	if err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return err
	}
	if err := writeOfflineOutput(output, encoded); err != nil {
		return err
	}
	if replayed {
		fmt.Fprintln(os.Stderr, "trstctl-signer: offline operation replayed from sealed journal")
	}
	return nil
}

func readOfflineJSON(path string, target any) error {
	f, err := os.Open(path) // #nosec G304 -- operator-selected local offline input file (CWE-22)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	decoder := json.NewDecoder(io.LimitReader(f, offlineFileLimit+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("offline JSON contains trailing data or exceeds its size limit")
	}
	return nil
}

func readPrivateFile(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("custodian private key must be a regular owner-only file")
	}
	if info.Size() > offlineFileLimit {
		return nil, errors.New("custodian private key exceeds size limit")
	}
	return os.ReadFile(path) // #nosec G304 -- operator-selected owner-only custodian key file (CWE-22)
}

func writeOfflineOutput(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- operator-selected create-new offline output file (CWE-22)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return fsatomic.SyncDirectory(filepath.Dir(path))
}

func runOfflinePrepare(kitPath, csrPath, requester, subject, reason string, ttl time.Duration, output string) error {
	if kitPath == "" || csrPath == "" || requester == "" || subject == "" || reason == "" || output == "" {
		return errors.New("offline preparation requires kit, CSR, requester, subject, reason and output")
	}
	var kit signing.OfflineBreakglassKit
	if err := readOfflineJSON(kitPath, &kit); err != nil {
		return err
	}
	if err := signing.VerifyOfflineBreakglassKit(kit); err != nil {
		return err
	}
	raw, err := os.ReadFile(csrPath) // #nosec G304 -- operator-selected public CSR input file (CWE-22)
	if err != nil {
		return err
	}
	csrDER, _, err := crypto.ParsePublicCSRPEM(raw)
	if err != nil {
		return err
	}
	if _, err := offline.InspectEmergencyCSR(subject, csrDER); err != nil {
		return err
	}
	if ttl <= 0 || ttl > time.Duration(kit.Policy.MaxTTLSeconds)*time.Second || ttl%time.Second != 0 {
		return errors.New("offline requested TTL must be a whole second within the installed policy")
	}
	random, err := crypto.RandomBytes(16)
	if err != nil {
		return err
	}
	req := offline.OfflineRequest{ID: hex.EncodeToString(random), TenantID: kit.Policy.TenantID,
		DeploymentID: kit.Policy.DeploymentID, Epoch: kit.Policy.Epoch, Requester: requester,
		CAKeySHA256: crypto.SHA256Hex(kit.PublicKeyDER),
		Subject:     subject, CSRDER: csrDER, Reason: reason, TTLSeconds: int64(ttl / time.Second),
		ExpiresAt: time.Now().UTC().Add(time.Hour)}
	encoded, err := json.MarshalIndent(req, "", "  ")
	if err != nil {
		return err
	}
	return writeOfflineOutput(output, encoded)
}
