// Package ari implements ACME Renewal Information (RFC 9773) — the shared types
// and logic used by both certctl's ACME server (which emits per-certificate
// renewal windows) and its renewal client (which consumes them from upstream
// CAs). ARI lets clients renew on the CA's schedule, smoothing renewal load and,
// critically, signaling early renewal ahead of a mass-revocation event — and it
// is unsupported by cert-manager and acme.sh, the two most common ACME clients.
//
// A certificate is identified by its RFC 9773 certificate identifier
// (base64url(AKI) "." base64url(serial)); building it from a certificate is the
// crypto boundary's job (certinfo.ARICertID), while parsing the string form is
// here, since it is pure decoding.
package ari

import (
	"encoding/base64"
	"errors"
	"fmt"
	"math/rand/v2"
	"strings"
	"time"
)

// Window is a suggested renewal window (RFC 9773 suggestedWindow).
type Window struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// RenewalInfo is the body of an ARI renewalInfo response.
type RenewalInfo struct {
	SuggestedWindow Window `json:"suggestedWindow"`
	ExplanationURL  string `json:"explanationURL,omitempty"`
}

// ParseCertID decodes an RFC 9773 certificate identifier into its Authority Key
// Identifier and serial-number bytes.
func ParseCertID(certID string) (akid, serial []byte, err error) {
	parts := strings.Split(certID, ".")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return nil, nil, errors.New("ari: malformed certificate identifier")
	}
	if akid, err = base64.RawURLEncoding.DecodeString(parts[0]); err != nil {
		return nil, nil, fmt.Errorf("ari: decode AKI: %w", err)
	}
	if serial, err = base64.RawURLEncoding.DecodeString(parts[1]); err != nil {
		return nil, nil, fmt.Errorf("ari: decode serial: %w", err)
	}
	if len(akid) == 0 || len(serial) == 0 {
		return nil, nil, errors.New("ari: empty certificate identifier component")
	}
	return akid, serial, nil
}

// ValidCertID reports whether certID is a well-formed RFC 9773 identifier.
func ValidCertID(certID string) bool {
	_, _, err := ParseCertID(certID)
	return err == nil
}

// SuggestWindow computes the renewal window for a certificate. Normally it covers
// the last third before expiry; for early renewal (a mass-revocation signal) it
// starts in the immediate past so clients renew right away.
func SuggestWindow(notBefore, notAfter, now time.Time, early bool) Window {
	if early {
		return Window{Start: now.Add(-time.Minute), End: laterOf(now.Add(time.Hour), notAfter)}
	}
	lifetime := notAfter.Sub(notBefore)
	if lifetime <= 0 {
		return Window{Start: notBefore, End: notAfter}
	}
	return Window{
		Start: notAfter.Add(-lifetime / 3),
		End:   notAfter.Add(-lifetime / 6),
	}
}

// RenewNow reports whether now has reached the renewal window's start — the
// client should renew within the window, not on a fixed timer.
func RenewNow(info RenewalInfo, now time.Time) bool {
	return !now.Before(info.SuggestedWindow.Start)
}

// RenewAt picks a deterministic time within the suggested window. Seeding it per
// certificate gives each a stable renewal point, spreading renewal load across
// the window rather than bunching at its start.
func RenewAt(info RenewalInfo, seed int64) time.Time {
	w := info.SuggestedWindow
	span := w.End.Sub(w.Start)
	if span <= 0 {
		return w.Start
	}
	r := rand.New(rand.NewPCG(uint64(seed), 0x9E3779B97F4A7C15))
	return w.Start.Add(time.Duration(r.Int64N(int64(span))))
}

func laterOf(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}
