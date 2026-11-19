//go:build !darwin && !linux

// SPDX-License-Identifier: BUSL-1.1

package signing

import (
	"errors"
	"os"
)

func tryLockSignerCustody(_ *os.File) error {
	return errors.New("signing: this platform cannot lock and durably publish CA hierarchy custody")
}
