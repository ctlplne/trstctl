// SPDX-License-Identifier: BUSL-1.1

package signing

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"trstctl.com/trstctl/internal/breakglass/offline"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/fsatomic"
)

const offlineBreakglassHandle = "offline-breakglass-authority"

// OfflineBreakglassKit contains only public, deployment-bound recovery trust.
// Its signed bytes are safe to copy to the control plane and each custodian.
type OfflineBreakglassKit struct {
	Version      int                   `json:"version"`
	Policy       offline.OfflinePolicy `json:"policy"`
	CACertDER    []byte                `json:"ca_cert_der"`
	PublicKeyDER []byte                `json:"public_key_der"`
	Signature    []byte                `json:"signature"`
}

func (k OfflineBreakglassKit) signedBytes() ([]byte, error) {
	return json.Marshal(struct {
		Domain       string                `json:"domain"`
		Version      int                   `json:"version"`
		Policy       offline.OfflinePolicy `json:"policy"`
		CACertDER    []byte                `json:"ca_cert_der"`
		PublicKeyDER []byte                `json:"public_key_der"`
	}{"trstctl.breakglass.offline.kit.v2", k.Version, k.Policy, k.CACertDER, k.PublicKeyDER})
}

// VerifyOfflineBreakglassKit checks the kit self-consistency. Recovery must
// additionally pin its public-key fingerprint before trusting this file.
func VerifyOfflineBreakglassKit(k OfflineBreakglassKit) error {
	if k.Version != 2 {
		return errors.New("signing: unsupported offline kit version")
	}
	if err := offline.ValidateOfflinePolicy(k.Policy); err != nil {
		return err
	}
	pub, err := crypto.PublicKeyDERFromCert(k.CACertDER)
	if err != nil {
		return err
	}
	if !bytes.Equal(pub, k.PublicKeyDER) {
		return errors.New("signing: offline kit key differs from CA certificate")
	}
	message, err := k.signedBytes()
	if err != nil {
		return err
	}
	return crypto.VerifyMessage(k.PublicKeyDER, message, k.Signature)
}

// OfflineBreakglassVault is used only by a one-shot trstctl-signer process when
// the control plane is unavailable. It has no generic Sign transport or SQL/NATS
// dependency. Its key remains sealed and marked offlineOnly in the key store.
type OfflineBreakglassVault struct{ store *KeyStore }

func NewOfflineBreakglassVault(dir string, wrapper seal.KeyWrapper) (*OfflineBreakglassVault, error) {
	if dir == "" || wrapper == nil {
		return nil, errors.New("signing: offline vault needs a state directory and key wrapper")
	}
	return &OfflineBreakglassVault{store: NewKeyStore(dir, wrapper)}, nil
}

func (v *OfflineBreakglassVault) kitPath() string {
	return filepath.Join(v.store.dir, "offline-kit.json")
}
func (v *OfflineBreakglassVault) journalPath(id string) string {
	return filepath.Join(v.store.dir, "offline-operations", crypto.SHA256Hex([]byte(id))+".sealed")
}

// Provision creates one sealed recovery CA and a signed public kit. Repeating
// setup after a committed kit fails; a partial first boot can be retried using
// the same sealed key without silently rotating the trust root.
func (v *OfflineBreakglassVault) Provision(policy offline.OfflinePolicy, caTTL time.Duration) (OfflineBreakglassKit, error) {
	if err := offline.ValidateOfflinePolicy(policy); err != nil {
		return OfflineBreakglassKit{}, err
	}
	if caTTL < time.Hour || caTTL > 10*365*24*time.Hour {
		return OfflineBreakglassKit{}, errors.New("signing: offline CA lifetime outside one hour to ten years")
	}
	if err := os.MkdirAll(v.store.dir, 0o700); err != nil {
		return OfflineBreakglassKit{}, err
	}
	unlock, err := lockOfflineVault(v.store.dir)
	if err != nil {
		return OfflineBreakglassKit{}, err
	}
	defer unlock()
	if _, err := os.Stat(v.kitPath()); err == nil {
		return OfflineBreakglassKit{}, errors.New("signing: offline kit already provisioned")
	} else if !errors.Is(err, os.ErrNotExist) {
		return OfflineBreakglassKit{}, err
	}
	held, err := v.store.LoadHandle(offlineBreakglassHandle)
	if err != nil {
		return OfflineBreakglassKit{}, err
	}
	if held == nil {
		key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
		if err != nil {
			return OfflineBreakglassKit{}, err
		}
		held = &heldKey{signer: key, constraints: keyConstraints{offlineOnly: true}}
		if err := v.store.Save(offlineBreakglassHandle, key, held.constraints); err != nil {
			key.Destroy()
			return OfflineBreakglassKit{}, err
		}
	}
	defer held.signer.Destroy()
	if !held.constraints.offlineOnly {
		return OfflineBreakglassKit{}, errors.New("signing: recovery handle lacks offline-only constraint")
	}
	caDER, err := crypto.SelfSignedCACert(held.signer, "trstctl offline break-glass CA", caTTL)
	if err != nil {
		return OfflineBreakglassKit{}, err
	}
	kit := OfflineBreakglassKit{Version: 2, Policy: policy, CACertDER: caDER, PublicKeyDER: held.signer.Public().DER}
	message, err := kit.signedBytes()
	if err != nil {
		return OfflineBreakglassKit{}, err
	}
	kit.Signature, err = crypto.SignMessage(held.signer, message)
	if err != nil {
		return OfflineBreakglassKit{}, err
	}
	encoded, err := json.MarshalIndent(kit, "", "  ")
	if err != nil {
		return OfflineBreakglassKit{}, err
	}
	if err := durableWriteNew(v.kitPath(), encoded); err != nil {
		return OfflineBreakglassKit{}, err
	}
	return kit, nil
}

func (v *OfflineBreakglassVault) LoadKit() (OfflineBreakglassKit, error) {
	raw, err := os.ReadFile(v.kitPath())
	if err != nil {
		return OfflineBreakglassKit{}, err
	}
	var kit OfflineBreakglassKit
	if err := json.Unmarshal(raw, &kit); err != nil {
		return OfflineBreakglassKit{}, err
	}
	if err := VerifyOfflineBreakglassKit(kit); err != nil {
		return OfflineBreakglassKit{}, err
	}
	return kit, nil
}

type offlineJournalRecord struct {
	Version     int             `json:"version"`
	OperationID string          `json:"operation_id"`
	RequestHash string          `json:"request_hash"`
	State       string          `json:"state"`
	Bundle      *offline.Bundle `json:"bundle,omitempty"`
}

// Issue verifies the exact m-of-n signed request inside the isolated signer,
// then journals the complete bundle before returning it. An exact retry after a
// crash returns the same bytes; the same ID with changed content is refused.
func (v *OfflineBreakglassVault) Issue(request offline.OfflineRequest, approvals []offline.OfflineApproval) (offline.Bundle, bool, error) {
	unlock, err := lockOfflineVault(v.store.dir)
	if err != nil {
		return offline.Bundle{}, false, err
	}
	defer unlock()
	kit, err := v.LoadKit()
	if err != nil {
		return offline.Bundle{}, false, err
	}
	if request.CAKeySHA256 != crypto.SHA256Hex(kit.PublicKeyDER) {
		return offline.Bundle{}, false, errors.New("signing: offline request was approved for another recovery CA")
	}
	intent, err := json.Marshal(struct {
		Request   offline.OfflineRequest    `json:"request"`
		Approvals []offline.OfflineApproval `json:"approvals"`
	}{request, approvals})
	if err != nil {
		return offline.Bundle{}, false, err
	}
	digest := crypto.SHA256Hex(intent)
	journalDir := filepath.Dir(v.journalPath(request.ID))
	if err := os.MkdirAll(journalDir, 0o700); err != nil {
		return offline.Bundle{}, false, err
	}
	prior, err := v.readOfflineJournal(request.ID)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return offline.Bundle{}, false, err
	}
	if err == nil {
		if prior.RequestHash != digest {
			return offline.Bundle{}, false, errors.New("signing: offline operation ID already binds another request")
		}
		if prior.State == "completed" && prior.Bundle != nil {
			if err := offline.VerifyDisconnected(*prior.Bundle, kit.Policy, kit.CACertDER, kit.PublicKeyDER); err != nil {
				return offline.Bundle{}, false, err
			}
			return *prior.Bundle, true, nil
		}
		if prior.State != "executing" {
			return offline.Bundle{}, false, errors.New("signing: invalid offline journal state")
		}
	}
	if err := offline.VerifyOfflineApprovals(kit.Policy, request, approvals, time.Now().UTC()); err != nil {
		return offline.Bundle{}, false, err
	}
	if errors.Is(err, os.ErrNotExist) {
		if err := v.writeOfflineJournal(offlineJournalRecord{Version: 1, OperationID: request.ID, RequestHash: digest, State: "executing"}, false); err != nil {
			return offline.Bundle{}, false, err
		}
	}
	held, err := v.store.LoadHandle(offlineBreakglassHandle)
	if err != nil {
		return offline.Bundle{}, false, err
	}
	if held == nil || !held.constraints.offlineOnly {
		return offline.Bundle{}, false, errors.New("signing: offline-only CA key unavailable")
	}
	defer held.signer.Destroy()
	if !bytes.Equal(held.signer.Public().DER, kit.PublicKeyDER) {
		return offline.Bundle{}, false, errors.New("signing: sealed recovery key differs from public kit")
	}
	bundle, err := offline.IssueDisconnected(kit.Policy, request, approvals,
		kit.CACertDER, held.signer, time.Now().UTC())
	if err != nil {
		return offline.Bundle{}, false, err
	}
	if err := offline.VerifyDisconnected(bundle, kit.Policy, kit.CACertDER, kit.PublicKeyDER); err != nil {
		return offline.Bundle{}, false, err
	}
	if err := v.writeOfflineJournal(offlineJournalRecord{Version: 1, OperationID: request.ID, RequestHash: digest, State: "completed", Bundle: &bundle}, true); err != nil {
		return offline.Bundle{}, false, err
	}
	return bundle, false, nil
}

func (v *OfflineBreakglassVault) readOfflineJournal(id string) (offlineJournalRecord, error) {
	sealed, err := os.ReadFile(v.journalPath(id))
	if err != nil {
		return offlineJournalRecord{}, err
	}
	plain, err := seal.Open(v.store.wrapper, sealed, []byte("trstctl:offline-breakglass-journal:v1\x00"+id))
	if err != nil {
		return offlineJournalRecord{}, err
	}
	defer secret.Wipe(plain)
	var record offlineJournalRecord
	if err := json.Unmarshal(plain, &record); err != nil {
		return offlineJournalRecord{}, err
	}
	if record.Version != 1 || record.OperationID != id {
		return offlineJournalRecord{}, errors.New("signing: offline journal identity mismatch")
	}
	return record, nil
}

func (v *OfflineBreakglassVault) writeOfflineJournal(record offlineJournalRecord, replace bool) error {
	encoded, err := json.Marshal(record)
	if err != nil {
		return err
	}
	defer secret.Wipe(encoded)
	sealed, err := seal.Seal(v.store.wrapper, encoded, []byte("trstctl:offline-breakglass-journal:v1\x00"+record.OperationID))
	if err != nil {
		return err
	}
	defer secret.Wipe(sealed)
	path := v.journalPath(record.OperationID)
	if !replace {
		return durableWriteNew(path, sealed)
	}
	return durableReplace(path, sealed)
}

func durableWriteNew(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- path is the signer-owned offline vault journal or kit (CWE-22)
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

func durableReplace(path string, data []byte) error {
	temp, err := os.CreateTemp(filepath.Dir(path), ".offline-result-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(temp.Name()) }()
	if err := temp.Chmod(0o600); err != nil {
		_ = temp.Close()
		return err
	}
	if _, err := temp.Write(data); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(temp.Name(), path); err != nil {
		return err
	}
	return fsatomic.SyncDirectory(filepath.Dir(path))
}
