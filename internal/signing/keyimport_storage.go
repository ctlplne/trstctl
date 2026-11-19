// SPDX-License-Identifier: BUSL-1.1

package signing

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
)

const (
	keyImportIdentityName = "key-import-offer-identity.sealed"
	keyImportIdentityAAD  = "trstctl.ca-key-import.identity.v2"
	keyImportOfferExt     = ".import-v2"
	custodyStageExt       = ".stage"
)

func (ks *KeyStore) readCustodyFile(name, aad string) ([]byte, error) {
	root, err := os.OpenRoot(ks.dir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	file, err := root.Open(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	raw, err := io.ReadAll(io.LimitReader(file, maxSealedImportKey+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxSealedImportKey {
		return nil, errors.New("signing: sealed key import state exceeds its size limit")
	}
	return seal.Open(ks.wrapper, raw, []byte(aad))
}

func (ks *KeyStore) loadKeyImportIdentity() (*crypto.LockedSigner, error) {
	plain, err := ks.readCustodyFile(keyImportIdentityName, keyImportIdentityAAD)
	if err != nil {
		return nil, err
	}
	defer secret.Wipe(plain)
	if err := syncDirectory(ks.dir); err != nil {
		return nil, err
	}
	return parseKeyImportIdentity(plain)
}

func parseKeyImportIdentity(plain []byte) (*crypto.LockedSigner, error) {
	if len(plain) == 0 {
		return nil, errors.New("signing: CA import offer identity has not been provisioned on the signer host")
	}
	return crypto.NewLockedSignerFromPKCS8(crypto.ECDSAP256, plain)
}

// KeyImportIdentityFingerprint reads the existing offer identity without
// initializing either the keystore or the signing key.
func (ks *KeyStore) KeyImportIdentityFingerprint() (string, error) {
	identity, err := ks.loadKeyImportIdentity()
	if err != nil {
		return "", err
	}
	defer identity.Destroy()
	return crypto.SHA256Hex(identity.Public().DER), nil
}

// InitializeKeyImportIdentity is a signer-host operation. The first sealed
// identity wins and an existing identity is never overwritten.
func (ks *KeyStore) InitializeKeyImportIdentity() (string, error) {
	unlock, err := ks.lockCustodyFile("key-import-identity.lock")
	if err != nil {
		return "", err
	}
	defer unlock()
	plain, err := ks.readCustodyFile(keyImportIdentityName, keyImportIdentityAAD)
	if err != nil {
		return "", err
	}
	defer secret.Wipe(plain)
	if plain == nil {
		der, err := crypto.GeneratePKCS8(crypto.ECDSAP256)
		if err != nil {
			return "", err
		}
		defer secret.Wipe(der)
		sealed, err := seal.Seal(ks.wrapper, der, []byte(keyImportIdentityAAD))
		if err != nil {
			return "", err
		}
		if err := ks.publishCustodyFile(keyImportIdentityName, keyImportIdentityName+custodyStageExt, sealed); err != nil {
			return "", err
		}
	} else if err := ks.retireCustodyNames(keyImportIdentityName + custodyStageExt); err != nil {
		return "", err
	}
	return ks.KeyImportIdentityFingerprint()
}

type keyImportPreparation struct {
	offer     crypto.AuthenticatedKeyImportOffer
	recipient *crypto.KeyImportKey
}

func keyImportPreparationName(handle string) string {
	return handle + keyImportOfferExt
}

func keyImportPreparationAAD(handle string) string {
	return "trstctl.ca-key-import.preparation.v2\x00" + handle
}

func (ks *KeyStore) loadKeyImportPreparation(handle string) (keyImportPreparation, error) {
	plain, err := ks.readCustodyFile(keyImportPreparationName(handle), keyImportPreparationAAD(handle))
	if err != nil || plain == nil {
		return keyImportPreparation{}, err
	}
	defer secret.Wipe(plain)
	return parseKeyImportPreparation(handle, plain)
}

func parseKeyImportPreparation(handle string, plain []byte) (keyImportPreparation, error) {
	if len(plain) <= crypto.KeyImportSeedSize {
		return keyImportPreparation{}, errors.New("signing: truncated CA import preparation")
	}
	var offer crypto.AuthenticatedKeyImportOffer
	if err := json.Unmarshal(plain[crypto.KeyImportSeedSize:], &offer); err != nil || offer.Handle != handle {
		return keyImportPreparation{}, errors.New("signing: invalid CA import preparation")
	}
	recipient, err := crypto.NewKeyImportKey(plain[:crypto.KeyImportSeedSize])
	if err != nil {
		return keyImportPreparation{}, err
	}
	if !bytes.Equal(recipient.Public(), offer.PublicKey) {
		recipient.Destroy()
		return keyImportPreparation{}, errors.New("signing: the prepared CA import recipient differs from the offer")
	}
	return keyImportPreparation{offer: offer, recipient: recipient}, nil
}

// validateImportPreparationForRewrap checks the historical signed object.
// Runtime import still checks the current identity and the real clock.
func validateImportPreparationForRewrap(handle string, plain []byte) error {
	prepared, err := parseKeyImportPreparation(handle, plain)
	if err != nil {
		return err
	}
	defer prepared.recipient.Destroy()
	offer := prepared.offer
	_, err = offer.Verify(crypto.SHA256Hex(offer.SignerPublicKey), time.Unix(offer.IssuedAt, 0))
	return err
}

func (ks *KeyStore) saveKeyImportPreparation(prepared keyImportPreparation) error {
	seed, err := prepared.recipient.Seed()
	if err != nil {
		return err
	}
	defer secret.Wipe(seed)
	wire, err := json.Marshal(prepared.offer)
	if err != nil {
		return err
	}
	plain := append(seed, wire...)
	defer secret.Wipe(plain)
	sealed, err := seal.Seal(ks.wrapper, plain, []byte(keyImportPreparationAAD(prepared.offer.Handle)))
	if err != nil {
		return err
	}
	name := keyImportPreparationName(prepared.offer.Handle)
	return ks.publishCustodyFile(name, name+custodyStageExt, sealed)
}

func (ks *KeyStore) retireKeyImportPreparation(handle string) error {
	name := keyImportPreparationName(handle)
	return ks.retireCustodyNames(name, name+custodyStageExt)
}
