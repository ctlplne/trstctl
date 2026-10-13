//go:build !darwin && !linux

// SPDX-License-Identifier: BUSL-1.1

package signing

import "errors"

func lockOfflineVault(string) (func(), error) {
	return nil, errors.New("signing: disconnected recovery requires a supported filesystem lock on Linux or macOS")
}
