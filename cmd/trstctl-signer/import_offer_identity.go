// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"errors"
	"fmt"
	"os"
	"time"

	"trstctl.com/trstctl/internal/crypto/kek"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/signing"
)

func runImportOfferIdentity(initialize bool, dir, kekFile, provider, keyRef, wrapCommand string, timeout time.Duration) (string, error) {
	if dir == "" {
		return "", errors.New("--keystore is required")
	}
	info, err := os.Stat(dir)
	if err != nil {
		return "", fmt.Errorf("open existing signer keystore: %w", err)
	}
	if !info.IsDir() {
		return "", errors.New("--keystore must name an existing directory")
	}
	var wrapper seal.KeyWrapper
	if provider != "" || keyRef != "" || wrapCommand != "" {
		if kekFile != "" {
			return "", errors.New("--kek and --kms-* are mutually exclusive for signer keystore custody")
		}
		wrapper, err = externalSignerKeystoreWrapper(provider, keyRef, wrapCommand, timeout)
		if err != nil {
			return "", err
		}
		if initialize {
			if err := probeKeystoreWrapper(wrapper); err != nil {
				return "", err
			}
		}
	} else {
		if kekFile == "" {
			return "", errors.New("--kek or --kms-provider/--kms-key-ref/--kms-wrap-command is required with --keystore")
		}
		local, err := kek.Load(kekFile)
		if err != nil {
			return "", err
		}
		defer local.Destroy()
		wrapper = local
	}
	store := signing.NewKeyStore(dir, wrapper)
	if initialize {
		return store.InitializeKeyImportIdentity()
	}
	return store.KeyImportIdentityFingerprint()
}
