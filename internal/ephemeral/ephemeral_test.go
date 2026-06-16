package ephemeral

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/crypto"
)

type stubAtt struct{}

func (stubAtt) Method() string { return "stub" }
func (stubAtt) Attest(_ context.Context, p []byte) (attest.Attestation, error) {
	if string(p) != "genuine" {
		return attest.Attestation{}, errors.New("forged proof")
	}
	return attest.Attestation{Subject: "wl-1", Selectors: []string{"stub:1"}}, nil
}

func newTestIssuer(t *testing.T, pool *bulkhead.Pool, rec auditsink.Auditor) (*Issuer, []byte) {
	t.Helper()
	ca, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ca.Destroy)
	caDER, err := crypto.SelfSignedCACert(ca, "Ephemeral CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	v, err := attest.NewVerifier(attest.Config{TenantID: "t1", Attestors: []attest.Attestor{stubAtt{}}})
	if err != nil {
		t.Fatal(err)
	}
	sign := func(_ context.Context, att attest.Attestation, pubDER []byte, ttl time.Duration) ([]byte, error) {
		return crypto.SignSVID(caDER, ca, pubDER, "spiffe://example.org/"+att.Subject, ttl)
	}
	iss, err := New(Config{
		TenantID: "t1", Verifier: v, Sign: sign,
		Policy: TTLPolicy{Default: 10 * time.Minute, Max: time.Hour},
		Idem:   NewMemoryIdempotencer(), Pool: pool, Audit: rec,
	})
	if err != nil {
		t.Fatal(err)
	}
	return iss, caDER
}

func TestEphemeralRefusedWithoutValidAttestation(t *testing.T) {
	iss, _ := newTestIssuer(t, nil, &auditsink.Recorder{})
	wl, _ := crypto.GenerateLockedKey(crypto.ECDSAP256)
	defer wl.Destroy()
	if _, err := iss.Issue(context.Background(), Request{
		Method: "stub", Payload: []byte("forged"), PublicKeyDER: wl.Public().DER, IdempotencyKey: "k1",
	}); err == nil {
		t.Fatal("issued a credential without a valid attestation")
	}
}

func TestEphemeralIssuesAndHonorsTTL(t *testing.T) {
	rec := &auditsink.Recorder{}
	iss, caDER := newTestIssuer(t, nil, rec)
	wl, _ := crypto.GenerateLockedKey(crypto.ECDSAP256)
	defer wl.Destroy()
	r, err := iss.Issue(context.Background(), Request{
		Method: "stub", Payload: []byte("genuine"), PublicKeyDER: wl.Public().DER, IdempotencyKey: "k2",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := crypto.VerifyLeafSignedByCA(r.CertDER, caDER); err != nil {
		t.Fatalf("issued cert does not chain to CA: %v", err)
	}
	life := time.Until(r.NotAfter)
	if life < 8*time.Minute || life > 12*time.Minute {
		t.Errorf("credential lifetime = %v, want ~10m (short TTL)", life)
	}
	if rec.Count("ephemeral.issued") != 1 {
		t.Error("issuance was not audited")
	}
}

func TestEphemeralIdempotentReplay(t *testing.T) {
	iss, _ := newTestIssuer(t, nil, &auditsink.Recorder{})
	wl, _ := crypto.GenerateLockedKey(crypto.ECDSAP256)
	defer wl.Destroy()
	req := Request{Method: "stub", Payload: []byte("genuine"), PublicKeyDER: wl.Public().DER, IdempotencyKey: "same"}
	r1, err := iss.Issue(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := iss.Issue(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(r1.CertDER, r2.CertDER) {
		t.Error("idempotent replay minted a different certificate (AN-5 violated)")
	}
}

func TestEphemeralSustainsConcurrentLoad(t *testing.T) {
	pool := bulkhead.New(bulkhead.Config{Name: "eph", Workers: 8, Queue: 128})
	defer pool.Close()
	iss, _ := newTestIssuer(t, pool, &auditsink.Recorder{})
	wl, _ := crypto.GenerateLockedKey(crypto.ECDSAP256)
	defer wl.Destroy()
	pub := wl.Public().DER

	const N = 60
	var wg sync.WaitGroup
	errs := make(chan error, N)
	for n := 0; n < N; n++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			_, err := iss.Issue(context.Background(), Request{
				Method: "stub", Payload: []byte("genuine"), PublicKeyDER: pub, IdempotencyKey: fmt.Sprintf("load-%d", n),
			})
			errs <- err
		}(n)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("issuance under concurrent load failed: %v", err)
		}
	}
}
