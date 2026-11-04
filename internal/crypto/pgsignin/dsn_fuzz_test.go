// SPDX-License-Identifier: BUSL-1.1

package pgsignin

import (
	"strconv"
	"testing"
)

// FuzzParseDSN feeds arbitrary bytes to the session DSN parser: it must never
// panic, and whatever it accepts names one TCP host and a valid port.
func FuzzParseDSN(f *testing.F) {
	for _, seed := range []string{
		"postgres://pam_ab12:p%40ss@db.internal:6432/orders?sslmode=verify-full",
		"postgresql://u:pw@[::1]/db",
		`host=10.0.0.5 port=5433 user=u password='a \'b\' c' dbname=d sslmode=disable`,
		"host=h password='open",
		"postgres://u:%zz@h/d",
		"",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, dsn []byte) {
		target, err := ParseDSN(dsn)
		if err != nil {
			return
		}
		defer target.Wipe()
		port, perr := strconv.Atoi(target.Port)
		if target.Host == "" || perr != nil || port < 1 || port > 65535 {
			t.Fatalf("accepted %q as host %q port %q", dsn, target.Host, target.Port)
		}
	})
}
