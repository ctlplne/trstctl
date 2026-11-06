// SPDX-License-Identifier: BUSL-1.1
package ldapbind

import (
	"context"
	"errors"
	"trstctl.com/trstctl/internal/crypto/secret"
	"unicode/utf8"
)

// ValidateADRecoveryPassword validates the imported predecessor before any
// native side effect. Generated passwords keep their separate ASCII contract.
func ValidateADRecoveryPassword(password []byte) error {
	_, err := adRecoveryUTF16Units(password)
	return err
}

func adRecoveryUTF16Units(password []byte) (int, error) {
	if len(password) < 16 || len(password) > 1024 {
		return 0, errors.New("AD recovery password exceeds its bounds")
	}
	units := 0
	for len(password) > 0 {
		r, width := utf8.DecodeRune(password)
		if (r == utf8.RuneError && width == 1) || r == 0 {
			return 0, errors.New("AD recovery password must be valid UTF-8 without NUL")
		}
		password = password[width:]
		units++
		if r > 0xffff {
			units++
		}
	}
	return units, nil
}

// ResetADRecoveryPassword restores an imported UTF-8 credential using the
// quoted UTF-16LE unicodePwd representation required by MS-ADTS 3.1.1.3.1.5.1.
// It shares the verified LDAPS transport and administrative reset operation.
func ResetADRecoveryPassword(ctx context.Context, route PinnedTLS, adminDN string, adminPassword []byte, accountDN string, password []byte) error {
	packet, err := newADRecoveryPasswordPacket(accountDN, password)
	if err != nil {
		return err
	}
	defer packet.Destroy()
	return resetADPasswordPacket(ctx, route, adminDN, adminPassword, packet)
}

func newADRecoveryPasswordPacket(dn string, password []byte) (*secret.Buffer, error) {
	if len(dn) == 0 || len(dn) > 4096 {
		return nil, errors.New("AD recovery account exceeds its bounds")
	}
	units, err := adRecoveryUTF16Units(password)
	if err != nil {
		return nil, err
	}
	return newADPasswordPacketValue(dn, password, units)
}
