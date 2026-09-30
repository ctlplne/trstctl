//go:build windows

// SPDX-License-Identifier: BUSL-1.1

package sshkrl

import (
	"errors"
	"os"
)

func lockTarget(string) (func(), error) {
	return nil, errors.New("sshkrl: atomic KRL update requires Unix filesystem locking; Windows is not yet supported")
}

func preserveOwner(string, os.FileInfo) error {
	return errors.New("sshkrl: preserving KRL ownership on Windows is not yet supported")
}
