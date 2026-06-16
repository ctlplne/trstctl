package awskms_test

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/kms/awskms"
)

// signThenBlockDoer answers the key-creation round-trips (CreateKey / GetPublicKey)
// immediately so a signer can be built, but BLOCKS forever on the Sign call until
// the request's context is cancelled — modelling a KMS that wedges on the signing
// operation specifically. It performs no SigV4 verification (the test asserts
// cancellation, not auth) and returns no crypto material it does not have to.
type signThenBlockDoer struct {
	mu      sync.Mutex
	key     *crypto.LockedSigner
	signHit chan struct{} // signalled the first time a Sign request arrives
}

func newSignThenBlockDoer(t *testing.T) *signThenBlockDoer {
	t.Helper()
	k, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("gen locked key: %v", err)
	}
	t.Cleanup(k.Destroy)
	return &signThenBlockDoer{key: k, signHit: make(chan struct{})}
}

func (d *signThenBlockDoer) Do(r *http.Request) (*http.Response, error) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	switch r.Header.Get("X-Amz-Target") {
	case "TrentService.CreateKey":
		return jsonResp(`{"KeyMetadata":{"KeyId":"k-blocking"}}`), nil
	case "TrentService.GetPublicKey":
		pub := d.key.Public()
		return jsonResp(`{"PublicKey":"` + base64.StdEncoding.EncodeToString(pub.DER) + `"}`), nil
	case "TrentService.Sign":
		_ = body
		select {
		case <-d.signHit:
		default:
			close(d.signHit)
		}
		// Block until the caller's context (deadline/cancel) fires, exactly as an
		// in-flight net/http request would on a wedged endpoint.
		<-r.Context().Done()
		return nil, r.Context().Err()
	default:
		return jsonResp(`{}`), nil
	}
}

func jsonResp(body string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/x-amz-json-1.1"}},
		Body:       io.NopCloser(stringReader(body)),
	}
}

type stringReader string

func (s stringReader) Read(p []byte) (int, error) {
	n := copy(p, s)
	if n == len(s) {
		return n, io.EOF
	}
	return n, nil
}

// TestSignContextHonorsCallerDeadline is the CODE-002 acceptance for the
// context-bearing signer: a caller that threads a short deadline through
// SignContext gets a deadline error promptly against a wedged KMS, instead of
// blocking forever. It FAILS on the pre-fix tree (Sign synthesized
// context.Background(), so the caller deadline could not bound the remote call).
func TestSignContextHonorsCallerDeadline(t *testing.T) {
	doer := newSignThenBlockDoer(t)
	// A large op-timeout so the FLOOR does not mask the caller's own deadline —
	// this test proves the caller's context is what bounds the call.
	b := awskms.New("us-east-1", awskms.Credentials{AccessKeyID: testAK, SecretAccessKey: testSK},
		awskms.WithEndpoint("https://kms.us-east-1.amazonaws.com"),
		awskms.WithHTTPClient(doer), awskms.WithOpTimeout(time.Hour))
	signer, err := b.GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	cs, ok := signer.(crypto.ContextSigner)
	if !ok {
		t.Fatal("aws-kms signer does not implement crypto.ContextSigner; CODE-002 not wired")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	start := time.Now()
	done := make(chan error, 1)
	go func() {
		_, sErr := cs.SignContext(ctx, []byte("payload"), crypto.SignOptions{Hash: crypto.SHA256})
		done <- sErr
	}()

	select {
	case sErr := <-done:
		if sErr == nil {
			t.Fatal("SignContext returned nil error against a wedged KMS; want a deadline error")
		}
		if !errors.Is(sErr, context.DeadlineExceeded) {
			t.Fatalf("SignContext error = %v; want context.DeadlineExceeded", sErr)
		}
		if elapsed := time.Since(start); elapsed > time.Second {
			t.Fatalf("SignContext took %v to honor a 150ms deadline — caller deadline not propagated", elapsed)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("SignContext did not return within 3s of a 150ms deadline — the caller deadline was not honored (CODE-002 regressed)")
	}
}

// TestSignOpTimeoutFloorBoundsContextLessCall is the CODE-002 acceptance for the
// interface-forced path: a caller reaching Sign through the context-less
// crypto.Signer interface (which synthesizes context.Background()) is still
// protected by the backend's per-operation timeout floor, so a wedged KMS cannot
// hang a worker goroutine forever (AN-7). It FAILS on the pre-fix tree (Sign used
// an unbounded context.Background()).
func TestSignOpTimeoutFloorBoundsContextLessCall(t *testing.T) {
	doer := newSignThenBlockDoer(t)
	b := awskms.New("us-east-1", awskms.Credentials{AccessKeyID: testAK, SecretAccessKey: testSK},
		awskms.WithEndpoint("https://kms.us-east-1.amazonaws.com"),
		awskms.WithHTTPClient(doer), awskms.WithOpTimeout(150*time.Millisecond))
	signer, err := b.GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		// The context-LESS interface call — no caller deadline; only the floor protects it.
		_, sErr := signer.Sign([]byte("payload"), crypto.SignOptions{Hash: crypto.SHA256})
		done <- sErr
	}()

	select {
	case sErr := <-done:
		if sErr == nil {
			t.Fatal("Sign returned nil error against a wedged KMS; want a timeout-floor error")
		}
		if !errors.Is(sErr, context.DeadlineExceeded) {
			t.Fatalf("Sign error = %v; want context.DeadlineExceeded from the op-timeout floor", sErr)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Sign did not return within 3s despite a 150ms op-timeout floor (CODE-002 regressed)")
	}
}
