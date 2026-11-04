// SPDX-License-Identifier: BUSL-1.1

package validity

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	// Fabricated key IDs in AWS's shape, built from two literals so secret
	// scanners do not take the fixtures for credentials.
	activeKey      = "AKIA" + "P14ACTIVE0000001"
	deactivatedKey = "AKIA" + "P14DEACTIVATED01"
)

// stsStandIn verifies each GetCallerIdentity's SigV4 signature against the
// secret it knows for the key ID, the way STS does: a deactivated key or a
// wrong secret is refused. It never sees a secret, only signatures.
type stsStandIn struct {
	mu      sync.Mutex
	secrets map[string]string
	active  map[string]bool
	calls   []time.Time
}

func (s *stsStandIn) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	s.mu.Lock()
	s.calls = append(s.calls, time.Now())
	s.mu.Unlock()
	auth := r.Header.Get("Authorization")
	keyID := strings.TrimPrefix(strings.SplitN(auth, "/", 2)[0], "AWS4-HMAC-SHA256 Credential=")
	refuse := func(code string) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `<ErrorResponse><Error><Code>`+code+`</Code></Error></ErrorResponse>`)
	}
	secretKey, known := s.secrets[keyID]
	if !known || !s.active[keyID] {
		refuse("InvalidClientTokenId")
		return
	}
	at, err := time.Parse("20060102T150405Z", r.Header.Get("X-Amz-Date"))
	if err != nil {
		refuse("IncompleteSignature")
		return
	}
	check := httptest.NewRequest(r.Method, "https://"+r.Host+r.URL.Path, strings.NewReader(string(body)))
	check.Host = r.Host
	check.Header.Set("Content-Type", r.Header.Get("Content-Type"))
	signAWS(check, body, keyID, []byte(secretKey), "us-east-1", "sts", at)
	if check.Header.Get("Authorization") != auth || string(body) != "Action=GetCallerIdentity&Version=2011-06-15" {
		refuse("SignatureDoesNotMatch")
		return
	}
	_, _ = io.WriteString(w, `<GetCallerIdentityResponse><GetCallerIdentityResult><Account>111122223333</Account><Arn>arn:aws:iam::111122223333:user/p14</Arn></GetCallerIdentityResult></GetCallerIdentityResponse>`)
}

func newSTS(t *testing.T) (*stsStandIn, *httptest.Server) {
	t.Helper()
	sts := &stsStandIn{
		secrets: map[string]string{activeKey: "p14ActiveSecretKeyValue0000000000000abc/", deactivatedKey: "p14DeactivatedSecretKey000000000000xyz+/"},
		active:  map[string]bool{activeKey: true},
	}
	srv := httptest.NewTLSServer(sts)
	t.Cleanup(srv.Close)
	return sts, srv
}

// writeLeak writes a scanned file holding a key pair the way a credentials file
// does, and returns the scan root and the access key ID's line.
func writeLeak(t *testing.T, keyID, secretKey string) (string, int) {
	t.Helper()
	root := t.TempDir()
	content := "[default]\nregion = us-east-1\naws_access_key_id = " + keyID + "\naws_secret_access_key = " + secretKey + "\n"
	if err := os.WriteFile(filepath.Join(root, "credentials"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return root, 3
}

// P14: a live key is valid, a deactivated one invalid, and the secret never
// leaves the host — the stand-in sees only a signature.
func TestAWSCheckMarksALiveKeyValidAndADeactivatedOneInvalidP14(t *testing.T) {
	sts, srv := newSTS(t)
	c := New(Config{Endpoints: map[string]string{ProviderAWS: srv.URL}, Allowlist: []string{srv.URL}, Client: srv.Client(), Rates: map[string]float64{ProviderAWS: 100}})
	for _, tc := range []struct {
		key, secret, want string
	}{
		{activeKey, sts.secrets[activeKey], StateValid},
		{deactivatedKey, sts.secrets[deactivatedKey], StateInvalid},
		{activeKey, "p14WrongSecretKeyValue000000000000000ab/", StateInvalid},
	} {
		root, line := writeLeak(t, tc.key, tc.secret)
		got := c.CheckAWSFinding(context.Background(), root, "credentials", line)
		if got.State != tc.want || got.Provider != ProviderAWS {
			t.Fatalf("%s = %+v, want %s", tc.key, got, tc.want)
		}
		if strings.Contains(got.Detail, tc.secret) {
			t.Fatal("the verdict carries the secret")
		}
	}
	root, line := writeLeak(t, activeKey, sts.secrets[activeKey])
	if valid := c.CheckAWSFinding(context.Background(), root, "credentials", line); !strings.Contains(valid.Detail, "111122223333") {
		t.Fatalf("valid detail = %q", valid.Detail)
	}
}

// P14: a check to an endpoint outside the declared allowlist is refused before
// anything is sent.
func TestAWSCheckToAnUndeclaredHostIsRefusedP14(t *testing.T) {
	sts, srv := newSTS(t)
	c := New(Config{Endpoints: map[string]string{ProviderAWS: srv.URL}, Client: srv.Client()})
	root, line := writeLeak(t, activeKey, sts.secrets[activeKey])
	got := c.CheckAWSFinding(context.Background(), root, "credentials", line)
	if got.State != StateUnchecked || !strings.Contains(got.Detail, "allowlist") || len(sts.calls) != 0 {
		t.Fatalf("undeclared endpoint = %+v after %d calls", got, len(sts.calls))
	}
}

// P14: checks keep to the provider's rate: past the budget a check is recorded
// unchecked instead of exceeding it.
func TestAWSChecksStayWithinTheProviderRateP14(t *testing.T) {
	sts, srv := newSTS(t)
	root, line := writeLeak(t, activeKey, sts.secrets[activeKey])
	// A pass that may not wait for the next token holds the rest back.
	hurried := New(Config{Endpoints: map[string]string{ProviderAWS: srv.URL}, Allowlist: []string{srv.URL}, Client: srv.Client(),
		Rates: map[string]float64{ProviderAWS: 2}, Wait: 100 * time.Millisecond})
	states := map[string]int{}
	for i := 0; i < 3; i++ {
		got := hurried.CheckAWSFinding(context.Background(), root, "credentials", line)
		states[got.State]++
		if got.State == StateUnchecked && !strings.Contains(got.Detail, "rate limited") {
			t.Fatalf("held back with %q", got.Detail)
		}
	}
	if states[StateValid] != 1 || states[StateUnchecked] != 2 {
		t.Fatalf("hurried states = %v; want one check made and two held back", states)
	}
	// A pass that may wait is paced to the rate.
	sts.mu.Lock()
	sts.calls = nil
	sts.mu.Unlock()
	paced := New(Config{Endpoints: map[string]string{ProviderAWS: srv.URL}, Allowlist: []string{srv.URL}, Client: srv.Client(),
		Rates: map[string]float64{ProviderAWS: 2}, Wait: time.Second})
	for i := 0; i < 4; i++ {
		if got := paced.CheckAWSFinding(context.Background(), root, "credentials", line); got.State != StateValid {
			t.Fatalf("paced check %d = %+v", i, got)
		}
	}
	sts.mu.Lock()
	defer sts.mu.Unlock()
	for i := 2; i < len(sts.calls); i++ {
		if sts.calls[i].Sub(sts.calls[i-2]) < 900*time.Millisecond {
			t.Fatalf("three checks within a second at a 2/s rate: %v", sts.calls)
		}
	}
}

func TestAWSPairAndTreeConfinementP14(t *testing.T) {
	if _, _, ok := AWSPair([]byte("aws_access_key_id = " + activeKey + "\n")); ok {
		t.Fatal("a key ID alone made a pair")
	}
	id, secretKey, ok := AWSPair([]byte(`export AWS_ACCESS_KEY_ID=` + activeKey + "\nexport AWS_SECRET_ACCESS_KEY=p14ActiveSecretKeyValue0000000000000abc/\n"))
	if !ok || id != activeKey || string(secretKey) != "p14ActiveSecretKeyValue0000000000000abc/" {
		t.Fatalf("pair = %q %q %v", id, secretKey, ok)
	}
	c := New(Config{})
	root := t.TempDir()
	if got := c.CheckAWSFinding(context.Background(), root, "../outside", 1); got.State != StateUnchecked {
		t.Fatalf("a file outside the scanned tree = %+v", got)
	}
}
