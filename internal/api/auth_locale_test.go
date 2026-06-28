package api

import "testing"

func TestPreferredWebLocaleNegotiatesProductionAndPseudoLocales(t *testing.T) {
	tests := []struct {
		header string
		want   string
	}{
		{header: "es-MX,es;q=0.9,en;q=0.8", want: "es-ES"},
		{header: "en;q=0.1,es;q=0.9", want: "es-ES"},
		{header: "fr-CA,en-GB;q=0.8", want: "en-US"},
		{header: "ar-SA,es;q=0.5", want: "ar-XB"},
		{header: "en-XA,en;q=0.9", want: "en-XA"},
		{header: "es;q=0,en;q=0.8", want: "en-US"},
		{header: "fr-CA,de-DE;q=0.9", want: ""},
	}
	for _, tc := range tests {
		if got := preferredWebLocale(tc.header); got != tc.want {
			t.Fatalf("preferredWebLocale(%q) = %q, want %q", tc.header, got, tc.want)
		}
	}
}
