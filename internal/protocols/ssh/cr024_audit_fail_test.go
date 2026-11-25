// SPDX-License-Identifier: BUSL-1.1

package ssh

import (
	"context"
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/auditsink"
)

func TestCR024SSHCertificateIsNotReturnedWithoutItsAuditEvent(t *testing.T) {
	ca, _ := newCA(t, auditsink.AuditorFunc(func(context.Context, string, string, []byte) error {
		return errors.New("event log temporarily unavailable")
	}))
	for _, kind := range []string{"user", "host"} {
		t.Run(kind, func(t *testing.T) {
			profile := Profile{Name: kind, MaxTTL: time.Hour, AllowUserCerts: kind == "user", AllowHostCerts: kind == "host"}
			req := IssueRequest{SubjectPublicKey: subjectKey(t), KeyID: "audit-bound-" + kind, Principals: []string{"audit-bound-" + kind}, TTL: 30 * time.Minute}
			var got Issued
			var err error
			if kind == "user" {
				got, err = ca.IssueUserCert(context.Background(), profile, req)
			} else {
				got, err = ca.IssueHostCert(context.Background(), profile, req)
			}
			if err == nil || len(got.Certificate) != 0 {
				t.Fatalf("SSH %s certificate returned without its audit event: bytes=%d err=%v", kind, len(got.Certificate), err)
			}
			if !errors.Is(err, ErrAuditUnavailable) {
				t.Fatalf("SSH %s audit append error lost its retryable type: %v", kind, err)
			}
		})
	}
}
