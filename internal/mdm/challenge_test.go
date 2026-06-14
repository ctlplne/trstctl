package mdm_test

import (
	"testing"
	"time"

	"trustctl.io/trustctl/internal/mdm"
)

var testKey = []byte("intune-challenge-hmac-key-0123456789")

func TestChallengeRoundTrip(t *testing.T) {
	ch := mdm.New(testKey, time.Minute)
	tok, err := ch.Issue()
	if err != nil {
		t.Fatal(err)
	}
	if err := ch.Validate(tok); err != nil {
		t.Fatalf("freshly issued challenge must validate: %v", err)
	}
}

func TestChallengeTampered(t *testing.T) {
	ch := mdm.New(testKey, time.Minute)
	tok, _ := ch.Issue()
	tampered := tok[:len(tok)-1] + flip(tok[len(tok)-1])
	if err := ch.Validate(tampered); err == nil {
		t.Fatal("a tampered challenge must be rejected")
	}
}

func TestChallengeWrongKey(t *testing.T) {
	tok, _ := mdm.New(testKey, time.Minute).Issue()
	if err := mdm.New([]byte("a-totally-different-hmac-key-9876"), time.Minute).Validate(tok); err == nil {
		t.Fatal("a challenge signed with another key must be rejected")
	}
}

func TestChallengeExpired(t *testing.T) {
	clk := time.Unix(1_000_000, 0)
	ch := mdm.New(testKey, time.Minute, mdm.WithClock(func() time.Time { return clk }))
	tok, _ := ch.Issue() // valid until +60s
	clk = clk.Add(2 * time.Minute)
	if err := ch.Validate(tok); err == nil {
		t.Fatal("an expired challenge must be rejected")
	}
}

func TestChallengeMalformed(t *testing.T) {
	ch := mdm.New(testKey, time.Minute)
	for _, bad := range []string{"", "garbage", "a.b", "a.b.c.d"} {
		if err := ch.Validate(bad); err == nil {
			t.Errorf("malformed challenge %q must be rejected", bad)
		}
	}
}

func flip(b byte) string {
	if b == 'A' {
		return "B"
	}
	return "A"
}
