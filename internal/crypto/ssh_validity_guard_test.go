// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"testing"
	"time"
)

// SignSSHCertificate is exported from the crypto boundary, so the validity
// window it stamps into the certificate has to be enforced here and not only by
// whichever caller happens to compute it. A zero-value time.Time has a negative
// Unix() (-62135596800); converted to uint64 for the OpenSSH wire format that
// would become 18446744011573954816 -- a certificate that never expires.
func TestSignSSHCertificateRejectsInvalidValidityWindow(t *testing.T) {
	ca, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer ca.Destroy()
	subj, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer subj.Destroy()
	subjPub, err := SSHPublicKeyFromSigner(subj)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()

	cases := []struct {
		name        string
		validAfter  time.Time
		validBefore time.Time
	}{
		{"zero window", time.Time{}, time.Time{}},
		{"inverted window", now.Add(time.Hour), now.Add(time.Minute)},
		{"pre epoch valid after", time.Unix(-1, 0), now.Add(time.Hour)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			certB, err := SignSSHCertificate(ca, SSHCertParams{
				SubjectPublicKey: subjPub,
				KeyID:            "alice",
				Principals:       []string{"alice"},
				CertType:         SSHUserCert,
				ValidAfter:       tc.validAfter,
				ValidBefore:      tc.validBefore,
			})
			if err == nil {
				t.Fatalf("SignSSHCertificate accepted %s and returned a certificate: %s", tc.name, certB)
			}
		})
	}
}
