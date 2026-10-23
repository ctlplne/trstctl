// SPDX-License-Identifier: BUSL-1.1

package weakkey

import (
	"context"
	"os"
	"testing"
)

// The checks read untrusted bytes (discovered certificates, keys reported by
// agents, operator files); none may panic or hang on any input.
func FuzzCheckSPKI(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("0\x82\x01\"0\r\x06\t*\x86H\x86\xf7\r\x01\x01\x01\x05\x00"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = NewChecker().CheckSPKI(data)
	})
}

func FuzzCheckCertificate(f *testing.F) {
	f.Add([]byte{})
	if pem, err := os.ReadFile("testdata/em-ov-tls-ca-g3c.pem"); err == nil {
		f.Add(pem)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = NewChecker().CheckCertificate(data)
		_, _ = NewChecker().CheckPEM(data)
	})
}

func FuzzLoadOpenSSLBlocklist(f *testing.F) {
	f.Add([]byte("# comment\n0000117ed71b2acc12ae\n"))
	f.Add([]byte("zz\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = LoadOpenSSLBlocklist("fuzz", data)
	})
}

func FuzzSharedFactors(f *testing.F) {
	f.Add([]byte("a"), []byte("b"))
	f.Fuzz(func(t *testing.T, a, b []byte) {
		_, _ = SharedFactors(context.Background(), [][]byte{a, b})
	})
}
