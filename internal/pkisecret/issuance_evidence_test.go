// SPDX-License-Identifier: BUSL-1.1

package pkisecret_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/pkisecret"
)

type publicIssuanceSink struct {
	*recordingSink
	der    []byte
	serial string
	fail   error
}

func (s *publicIssuanceSink) RecordIssuedCertificate(_ context.Context, _, _, serial string, der []byte) error {
	s.der = append([]byte(nil), der...)
	s.serial = serial
	return s.fail
}

func TestPKIIssuanceRequiresPublicEvidenceBeforeReturningCredential(t *testing.T) {
	for _, failed := range []bool{false, true} {
		name := "recorded"
		if failed {
			name = "recording_failed"
		}
		t.Run(name, func(t *testing.T) {
			caDER, caKey := caFixture(t)
			sink := &publicIssuanceSink{recordingSink: newRecordingSink()}
			if failed {
				sink.fail = errors.New("owned recording fault")
			}
			p := pkisecret.NewPKIProvider(caDER, caKey, pkisecret.Profile{Name: "web", MaxTTL: time.Hour}, nil, pkisecret.WithRevocationSink("t1", "ca-1", sink))
			cred, err := p.Generate(t.Context(), dynsecret.GenerateRequest{Role: "web.example", TTL: time.Hour})
			if len(sink.der) == 0 {
				t.Error("public issuance evidence was not recorded")
			}
			if failed {
				if !errors.Is(err, sink.fail) {
					t.Errorf("recording failure = %v, want original failure", err)
				}
				if len(cred.Secret) != 0 || cred.BackendRef != "" {
					t.Error("credential returned despite recording failure")
				}
				if p.IsLive(sink.serial) {
					t.Error("failed issuance marked live")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			actual, err := certinfo.Inspect(cred.Secret)
			if err != nil {
				t.Fatal(err)
			}
			recorded, err := certinfo.Inspect(sink.der)
			if err != nil {
				t.Fatal(err)
			}
			if actual.SHA256Fingerprint != recorded.SHA256Fingerprint || actual.SerialNumber != sink.serial || cred.BackendRef != sink.serial {
				t.Error("recorded public evidence differs from returned credential")
			}
		})
	}
}
