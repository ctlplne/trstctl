// SPDX-License-Identifier: BUSL-1.1

package challenge_test

import (
	"strings"
	"testing"
	"time"

	mdmchallenge "trstctl.com/trstctl/internal/mdm/challenge"
)

var testKey = []byte("intune-challenge-hmac-key-0123456789")

func TestChallengeRoundTrip(t *testing.T) {
	ch := mdmchallenge.New(testKey, time.Minute)
	tok, err := ch.Issue()
	if err != nil {
		t.Fatal(err)
	}
	if err := ch.Validate(tok); err != nil {
		t.Fatalf("freshly issued challenge must validate: %v", err)
	}
}

func TestChallengeTampered(t *testing.T) {
	ch := mdmchallenge.New(testKey, time.Minute)
	tok, _ := ch.Issue()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 || parts[2] == "" {
		t.Fatalf("issued malformed test challenge: %q", tok)
	}
	parts[2] = flip(parts[2][0]) + parts[2][1:]
	tampered := strings.Join(parts, ".")
	if err := ch.Validate(tampered); err == nil {
		t.Fatal("a tampered challenge must be rejected")
	}
}

func TestChallengeWrongKey(t *testing.T) {
	tok, _ := mdmchallenge.New(testKey, time.Minute).Issue()
	if err := mdmchallenge.New([]byte("a-totally-different-hmac-key-9876"), time.Minute).Validate(tok); err == nil {
		t.Fatal("a challenge signed with another key must be rejected")
	}
}

func TestChallengeExpired(t *testing.T) {
	clk := time.Unix(1_000_000, 0)
	ch := mdmchallenge.New(testKey, time.Minute, mdmchallenge.WithClock(func() time.Time { return clk }))
	tok, _ := ch.Issue() // valid until +60s
	clk = clk.Add(2 * time.Minute)
	if err := ch.Validate(tok); err == nil {
		t.Fatal("an expired challenge must be rejected")
	}
}

func TestChallengeMalformed(t *testing.T) {
	ch := mdmchallenge.New(testKey, time.Minute)
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
